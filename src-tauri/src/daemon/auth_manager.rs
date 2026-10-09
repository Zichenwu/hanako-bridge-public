// src-tauri/src/daemon/auth_manager.rs
//! 授权管理器（票 14）：把「发起授权 → 打开浏览器 → 轮询 → 落钥匙串」与「到期前续期」
//! 串成一个可被托盘/设置窗驱动的状态机。
//!
//! # 设计
//! - **纯逻辑核心**：时钟、休眠、打开浏览器、HTTP 传输、钥匙串全部注入，不依赖 Tauri，
//!   可脱离 GUI 测试（测试里休眠是空函数，瞬间跑完）。
//! - **状态只经 [`AuthState`] 对外**：托盘变黄、通知属于票 17，这里只报状态，不碰 UI。
//! - **单飞**：同一时刻只允许一个授权流程。用户连点「用浏览器登录」不得连开多个浏览器标签、
//!   也不得并发多个 start（每个 start 都会占 hub 的待处理码配额）。
//! - **凭据变更后 daemon 必须换新凭据**：授权成功或续期成功后通过 `on_credential` 回调通知，
//!   由 supervisor 据此热重启 daemon（旧连接握手用的还是旧 token，续期后旧 token 已被吊销，
//!   不重启则下次重连必 403）。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::auth_flow::{
    initial_state, maybe_renew, persist_granted, poll_until_done, start_login, AuthState,
    AuthTransport, LoginRequest, ReauthReason, RenewStep,
};
use super::credential_store::CredentialStore;

/// 续期检查周期。到期前 24h 才真正续期，这里只是「多久看一眼」。
/// 取 30 分钟：既保证窗口内（24h）有几十次机会重试，又不会白打 hub。
pub const RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// 注入的外部能力。
pub struct AuthDeps {
    pub transport: Arc<dyn AuthTransport>,
    pub store: Arc<dyn CredentialStore>,
    /// 打开系统浏览器；返回 Err 不致命（用户可手动复制地址），只记日志
    pub open_url: Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>,
    /// 休眠（轮询间隔用）；测试注入空实现
    pub sleep: Arc<dyn Fn(Duration) + Send + Sync>,
    pub now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    /// 凭据发生变化（授权成功 / 续期成功）→ 通知 supervisor 用新凭据重启 daemon
    pub on_credential: Arc<dyn Fn() + Send + Sync>,
    /// 状态变化回调（托盘 / 设置窗订阅）
    pub on_state: Arc<dyn Fn(&AuthState) + Send + Sync>,
    /// 已退出登录 → 通知 supervisor 停掉 daemon。
    /// 运行中的 WS 连接只在握手时用凭据，清钥匙串并不会断开它；不停就是「假退出」
    pub on_signed_out: Arc<dyn Fn() + Send + Sync>,
}

pub struct AuthManager {
    deps: AuthDeps,
    hub_url: String,
    machine_name: String,
    app_version: String,
    state: Mutex<AuthState>,
    /// 单飞标记：true = 已有授权流程在跑
    login_running: Mutex<bool>,
    /// 最近一次登录失败原因（给设置窗展示；开始新登录或成功时清空）
    last_error: Mutex<Option<String>>,
}

/// 发起授权的结果（给调用方决定要不要提示用户）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// 已拿到凭据并落盘
    SignedIn,
    /// 已有授权流程在进行，本次调用被忽略
    AlreadyRunning,
    /// 失败（原因进 AuthState::NeedReauth 或 Err 文案）
    Failed(String),
}

impl AuthManager {
    pub fn new(deps: AuthDeps, hub_url: String, machine_name: String, app_version: String) -> Arc<Self> {
        let st = initial_state(deps.store.as_ref(), (deps.now)());
        Arc::new(Self {
            deps,
            hub_url,
            machine_name,
            app_version,
            state: Mutex::new(st),
            login_running: Mutex::new(false),
            last_error: Mutex::new(None),
        })
    }

    /// 最近一次登录失败原因（无则 None）。
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    pub fn state(&self) -> AuthState {
        self.state.lock().unwrap().clone()
    }

    fn set_state(&self, st: AuthState) {
        {
            let mut g = self.state.lock().unwrap();
            if *g == st {
                return; // 无变化不回调，避免托盘重复刷新/重复通知
            }
            *g = st.clone();
        }
        (self.deps.on_state)(&st);
    }

    /// 发起浏览器授权码登录（阻塞直到终态；调用方应放在 blocking 线程）。
    ///
    /// `agent_id`：发起时正在使用的执行体（US5），确认页据此默认只勾它。
    pub fn login(&self, agent_id: Option<String>) -> LoginOutcome {
        let r = self.login_inner(agent_id);
        *self.last_error.lock().unwrap() = match &r {
            LoginOutcome::Failed(e) => Some(e.clone()),
            LoginOutcome::SignedIn => None,
            LoginOutcome::AlreadyRunning => return r,
        };
        r
    }

    fn login_inner(&self, agent_id: Option<String>) -> LoginOutcome {
        {
            let mut running = self.login_running.lock().unwrap();
            if *running {
                return LoginOutcome::AlreadyRunning;
            }
            *running = true;
        }
        // 无论从哪条路径返回都必须释放单飞标记，否则一次失败后再也无法登录
        struct Guard<'a>(&'a Mutex<bool>);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = false;
            }
        }
        let _guard = Guard(&self.login_running);
        *self.last_error.lock().unwrap() = None;

        let req = LoginRequest {
            hub_url: self.hub_url.clone(),
            machine_name: self.machine_name.clone(),
            app_version: self.app_version.clone(),
            agent_id,
        };
        let start = match start_login(self.deps.transport.as_ref(), &req) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[auth] 发起授权失败: {e}");
                return LoginOutcome::Failed(e);
            }
        };

        self.set_state(AuthState::AwaitingApproval {
            user_code: start.user_code.clone(),
            verification_url: start.verification_url.clone(),
        });
        if let Err(e) = (self.deps.open_url)(&start.verification_url) {
            // 不致命：设置窗会展示 verification_url 与码，用户可手动打开
            log::warn!("[auth] 打开浏览器失败（用户可手动打开确认页）: {e}");
        }

        match poll_until_done(
            self.deps.transport.as_ref(),
            &self.hub_url,
            &start,
            self.deps.sleep.as_ref(),
            || {},
        ) {
            Ok(granted) => match persist_granted(self.deps.store.as_ref(), &granted, &self.machine_name) {
                Ok(cred) => {
                    self.set_state(AuthState::SignedIn { agent_id: cred.agent_id, expires_at: cred.expires_at });
                    (self.deps.on_credential)();
                    LoginOutcome::SignedIn
                }
                Err(e) => {
                    // 拿到了凭据却存不住：不能假装登录成功，否则重启后又要重新授权且用户不知道为什么
                    log::error!("[auth] 凭据写入钥匙串失败: {e}");
                    self.set_state(AuthState::NeedReauth { reason: ReauthReason::StoreCorrupt });
                    LoginOutcome::Failed(e)
                }
            },
            Err(reason) => {
                self.set_state(AuthState::NeedReauth { reason });
                LoginOutcome::Failed(format!("{reason:?}"))
            }
        }
    }

    /// 续期检查一次（调度器周期性调用）。返回本次步骤，供测试与日志断言。
    pub fn tick_renew(&self) -> RenewStep {
        // 没登录或正在授权中时不续期：续期用的是钥匙串里的当前凭据，授权中它可能即将被替换
        match self.state() {
            AuthState::SignedIn { .. } => {}
            AuthState::NeedReauth { .. } | AuthState::SignedOut | AuthState::AwaitingApproval { .. } => {
                return RenewStep::NotDue;
            }
        }
        let step = maybe_renew(self.deps.transport.as_ref(), self.deps.store.as_ref(), &self.hub_url, (self.deps.now)());
        match &step {
            RenewStep::Renewed { expires_at } => {
                if let AuthState::SignedIn { agent_id, .. } = self.state() {
                    self.set_state(AuthState::SignedIn { agent_id, expires_at: expires_at.clone() });
                }
                // 旧凭据已被 hanako 吊销；必须让 daemon 换新凭据重连，否则下次重连 403
                (self.deps.on_credential)();
            }
            RenewStep::NeedReauth(reason) => self.set_state(AuthState::NeedReauth { reason: *reason }),
            RenewStep::Retry { reason, already_expired } => {
                log::warn!("[auth] 续期暂时失败（将重试）: {reason}");
                if *already_expired {
                    // 已过期且续不了：握手必 403，别让托盘还显示「已登录」
                    self.set_state(AuthState::NeedReauth { reason: ReauthReason::LocalExpired });
                }
            }
            RenewStep::NotDue => {}
        }
        step
    }

    /// 登出（幂等，阻塞：含一次网络请求，调用方应放在 blocking 线程）。
    ///
    /// 顺序：① 通知服务端吊销当前凭据并踢下线 → ② 清钥匙串 → ③ 停 daemon。
    /// ① 尽力而为：断网也必须能退出（本地凭据清掉、连接停掉），只是服务端凭据要等自然过期。
    /// ③ 无论钥匙串清没清成都要做——用户点了退出，连接就不该还在接活。
    pub fn logout(&self) -> Result<(), String> {
        if let Ok(Some(cur)) = self.deps.store.load() {
            let url = format!("{}/api/node-login/revoke", self.hub_url.trim_end_matches('/'));
            match self.deps.transport.post(&url, Some(&cur.secret), &serde_json::json!({})) {
                Ok((200, _)) => log::info!("[auth] 服务端已吊销本机凭据"),
                // 401 = 凭据本就失效，等同已退出
                Ok((401, _)) => log::info!("[auth] 服务端凭据已失效，无需吊销"),
                Ok((s, _)) => log::warn!("[auth] 服务端吊销失败（HTTP {s}），凭据将自然过期"),
                Err(e) => log::warn!("[auth] 服务端吊销请求失败，凭据将自然过期: {e}"),
            }
        }
        let cleared = self.deps.store.clear().map_err(|e| e.to_string());
        (self.deps.on_signed_out)();
        cleared?;
        self.set_state(AuthState::SignedOut);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::credential_store::{MemoryStore, StoredCredential};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Script {
        replies: Mutex<Vec<Result<(u16, String), String>>>,
        urls: Mutex<Vec<String>>,
    }
    impl Script {
        fn new(r: Vec<Result<(u16, String), String>>) -> Arc<Self> {
            let mut r = r;
            r.reverse();
            Arc::new(Self { replies: Mutex::new(r), urls: Mutex::new(vec![]) })
        }
    }
    impl AuthTransport for Script {
        fn post(&self, url: &str, _b: Option<&str>, _j: &serde_json::Value) -> Result<(u16, String), String> {
            self.urls.lock().unwrap().push(url.to_string());
            self.replies.lock().unwrap().pop().expect("脚本响应用完")
        }
    }
    fn ok(s: u16, b: &str) -> Result<(u16, String), String> {
        Ok((s, b.to_string()))
    }
    const START: &str = r#"{"deviceCode":"DEV1234567890123","userCode":"ABCD-2345","verificationUrl":"https://x/hapi/node-login?code=ABCD-2345","expiresIn":600,"interval":5}"#;
    fn approved() -> String {
        serde_json::json!({"status":"approved","serverUrl":"https://x/hapi/hanako","agentId":"bi--w","nodeName":"lap",
            "credentialSecret":"SEC","credentialId":"c1","expiresAt":"2026-10-12T00:00:00Z"}).to_string()
    }

    struct Harness {
        mgr: Arc<AuthManager>,
        store: Arc<MemoryStore>,
        states: Arc<Mutex<Vec<AuthState>>>,
        opened: Arc<Mutex<Vec<String>>>,
        cred_changes: Arc<AtomicUsize>,
        signed_out: Arc<AtomicUsize>,
    }
    fn harness(transport: Arc<dyn AuthTransport>, store: Arc<MemoryStore>, now: &'static str) -> Harness {
        let states = Arc::new(Mutex::new(vec![]));
        let opened = Arc::new(Mutex::new(vec![]));
        let cred_changes = Arc::new(AtomicUsize::new(0));
        let signed_out = Arc::new(AtomicUsize::new(0));
        let (s2, o2, c2, so2) = (states.clone(), opened.clone(), cred_changes.clone(), signed_out.clone());
        let deps = AuthDeps {
            transport,
            store: store.clone(),
            open_url: Arc::new(move |u| { o2.lock().unwrap().push(u.to_string()); Ok(()) }),
            sleep: Arc::new(|_| {}),
            now: Arc::new(move || DateTime::parse_from_rfc3339(now).unwrap().with_timezone(&Utc)),
            on_credential: Arc::new(move || { c2.fetch_add(1, Ordering::SeqCst); }),
            on_state: Arc::new(move |st| s2.lock().unwrap().push(st.clone())),
            on_signed_out: Arc::new(move || { so2.fetch_add(1, Ordering::SeqCst); }),
        };
        let mgr = AuthManager::new(deps, "https://x/hapi".into(), "lap".into(), "0.1.0".into());
        Harness { mgr, store, states, opened, cred_changes, signed_out }
    }
    fn stored(secret: &str, exp: &str) -> StoredCredential {
        StoredCredential { server_url: "https://x/hapi/hanako".into(), agent_id: "bi--w".into(), secret: secret.into(),
            credential_id: Some("c1".into()), expires_at: exp.into(), node_name: Some("lap".into()) }
    }

    #[test]
    fn 启动时_钥匙串有凭据即为已登录() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        let h = harness(Script::new(vec![]), store, "2026-10-05T00:00:00Z");
        assert!(matches!(h.mgr.state(), AuthState::SignedIn { .. }));
    }

    #[test]
    fn 完整登录_开浏览器_轮询_落钥匙串_通知_daemon_换凭据() {
        let t = Script::new(vec![ok(200, START), ok(200, r#"{"status":"pending"}"#), ok(200, &approved())]);
        let h = harness(t.clone(), Arc::new(MemoryStore::new()), "2026-10-05T00:00:00Z");
        assert_eq!(h.mgr.login(Some("bi--w".into())), LoginOutcome::SignedIn);

        assert_eq!(*h.opened.lock().unwrap(), vec!["https://x/hapi/node-login?code=ABCD-2345".to_string()], "必须打开确认页");
        assert_eq!(h.store.load().unwrap().unwrap().secret, "SEC");
        assert_eq!(h.cred_changes.load(Ordering::SeqCst), 1, "拿到新凭据必须通知 supervisor 重启 daemon");
        let st = h.states.lock().unwrap().clone();
        assert!(matches!(st[0], AuthState::AwaitingApproval { .. }), "先进入等待确认（设置窗据此展示码）");
        assert!(matches!(st.last().unwrap(), AuthState::SignedIn { .. }));
    }

    #[test]
    fn 用户拒绝_进入需重新授权_不动钥匙串_不通知() {
        let t = Script::new(vec![ok(200, START), ok(200, r#"{"status":"denied"}"#)]);
        let h = harness(t, Arc::new(MemoryStore::new()), "2026-10-05T00:00:00Z");
        assert!(matches!(h.mgr.login(None), LoginOutcome::Failed(_)));
        assert_eq!(h.mgr.state(), AuthState::NeedReauth { reason: ReauthReason::Denied });
        assert!(h.store.load().unwrap().is_none());
        assert_eq!(h.cred_changes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn 浏览器打不开_不致命_流程继续() {
        let t = Script::new(vec![ok(200, START), ok(200, &approved())]);
        let st = Arc::new(MemoryStore::new());
        let states = Arc::new(Mutex::new(vec![]));
        let deps = AuthDeps {
            transport: t, store: st.clone(),
            open_url: Arc::new(|_| Err("no browser".into())),
            sleep: Arc::new(|_| {}),
            now: Arc::new(|| Utc::now()),
            on_credential: Arc::new(|| {}),
            on_state: { let s = states.clone(); Arc::new(move |x| s.lock().unwrap().push(x.clone())) },
            on_signed_out: Arc::new(|| {}),
        };
        let m = AuthManager::new(deps, "https://x/hapi".into(), "lap".into(), "v".into());
        assert_eq!(m.login(None), LoginOutcome::SignedIn);
    }

    #[test]
    fn start_失败_不开浏览器() {
        let t = Script::new(vec![ok(500, "")]);
        let h = harness(t, Arc::new(MemoryStore::new()), "2026-10-05T00:00:00Z");
        assert!(matches!(h.mgr.login(None), LoginOutcome::Failed(_)));
        assert!(h.opened.lock().unwrap().is_empty());
    }

    #[test]
    fn 单飞_授权进行中再次发起被忽略_且失败后可重新发起() {
        // 用一个会在 poll 里回调「再次 login」的 sleep 来复现重入
        let t = Script::new(vec![ok(200, START), ok(200, r#"{"status":"denied"}"#), ok(200, START), ok(200, &approved())]);
        let store = Arc::new(MemoryStore::new());
        let reentered: Arc<Mutex<Option<LoginOutcome>>> = Arc::new(Mutex::new(None));
        let mgr_slot: Arc<Mutex<Option<Arc<AuthManager>>>> = Arc::new(Mutex::new(None));
        let (r2, m2) = (reentered.clone(), mgr_slot.clone());
        let deps = AuthDeps {
            transport: t, store: store.clone(),
            open_url: Arc::new(|_| Ok(())),
            sleep: Arc::new(move |_| {
                if r2.lock().unwrap().is_none() {
                    if let Some(m) = m2.lock().unwrap().as_ref() { *r2.lock().unwrap() = Some(m.login(None)); }
                }
            }),
            now: Arc::new(|| Utc::now()), on_credential: Arc::new(|| {}), on_state: Arc::new(|_| {}), on_signed_out: Arc::new(|| {}),
        };
        let mgr = AuthManager::new(deps, "https://x/hapi".into(), "lap".into(), "v".into());
        *mgr_slot.lock().unwrap() = Some(mgr.clone());
        assert!(matches!(mgr.login(None), LoginOutcome::Failed(_))); // 第一次：denied
        assert_eq!(*reentered.lock().unwrap(), Some(LoginOutcome::AlreadyRunning), "进行中的重入必须被拒绝");
        // 失败返回后标记已释放，可再次发起并成功
        assert_eq!(mgr.login(None), LoginOutcome::SignedIn, "失败后单飞标记必须释放");
    }

    #[test]
    fn 续期成功_更新状态_并通知_daemon_换凭据() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let t = Script::new(vec![ok(200, r#"{"credentialSecret":"NEW","credentialId":"c2","expiresAt":"2026-10-13T00:00:00Z"}"#)]);
        let h = harness(t, store, "2026-10-05T12:00:00Z");
        assert!(matches!(h.mgr.tick_renew(), RenewStep::Renewed { .. }));
        assert_eq!(h.store.load().unwrap().unwrap().secret, "NEW");
        assert_eq!(h.cred_changes.load(Ordering::SeqCst), 1, "续期后旧凭据已吊销，daemon 必须换新凭据重连");
        assert_eq!(h.mgr.state(), AuthState::SignedIn { agent_id: "bi--w".into(), expires_at: "2026-10-13T00:00:00Z".into() });
    }

    #[test]
    fn 续期被拒_进入需重新授权_托盘变黄的依据() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let h = harness(Script::new(vec![ok(401, "{}")]), store, "2026-10-05T12:00:00Z");
        h.mgr.tick_renew();
        assert_eq!(h.mgr.state(), AuthState::NeedReauth { reason: ReauthReason::RenewRejected });
        assert_eq!(h.cred_changes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn 续期暂时失败_保持已登录_不吓用户() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let h = harness(Script::new(vec![Err("超时".into())]), store, "2026-10-05T12:00:00Z");
        h.mgr.tick_renew();
        assert!(matches!(h.mgr.state(), AuthState::SignedIn { .. }));
    }

    #[test]
    fn 续期暂时失败但凭据已过期_标记需重新授权() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("OLD", "2026-10-01T00:00:00Z")).unwrap();
        let h = harness(Script::new(vec![ok(503, "")]), store, "2026-10-05T12:00:00Z");
        h.mgr.tick_renew();
        assert_eq!(h.mgr.state(), AuthState::NeedReauth { reason: ReauthReason::LocalExpired });
    }

    #[test]
    fn 未到续期窗口_不发请求_不通知() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        let t = Script::new(vec![]);
        let h = harness(t.clone(), store, "2026-10-05T00:00:00Z");
        assert_eq!(h.mgr.tick_renew(), RenewStep::NotDue);
        assert!(t.urls.lock().unwrap().is_empty());
    }

    #[test]
    fn 未登录或授权中_不续期() {
        let h = harness(Script::new(vec![]), Arc::new(MemoryStore::new()), "2026-10-05T00:00:00Z");
        assert_eq!(h.mgr.tick_renew(), RenewStep::NotDue); // SignedOut
    }

    #[test]
    fn 状态无变化不重复回调() {
        // 第二次登录会经过 AwaitingApproval 再回到 NeedReauth{Denied}，所以 Denied 会「合法地」出现两次。
        // 要测去重，必须让同一状态**连续**到达：登出两次 → SignedOut 第二次是空操作。
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        // 只有第一次登出钥匙串里有凭据 → 只发一次吊销
        let h = harness(Script::new(vec![ok(200, r#"{"revoked":true,"kicked":1}"#)]), store, "2026-10-05T00:00:00Z");
        h.mgr.logout().unwrap();
        h.mgr.logout().unwrap();
        h.mgr.logout().unwrap();
        let st = h.states.lock().unwrap().clone();
        assert_eq!(st, vec![AuthState::SignedOut], "连续相同状态只回调一次，实际 {st:?}（票 17 通知去抖的前提）");
    }

    #[test]
    fn 拿到凭据但钥匙串写不进去_不能假装登录成功() {
        use crate::daemon::credential_store::StoreError;
        struct Locked;
        impl CredentialStore for Locked {
            fn load(&self) -> Result<Option<StoredCredential>, StoreError> { Ok(None) }
            fn save(&self, _: &StoredCredential) -> Result<(), StoreError> { Err(StoreError::Unavailable("keychain locked".into())) }
            fn clear(&self) -> Result<(), StoreError> { Ok(()) }
        }
        let t = Script::new(vec![ok(200, START), ok(200, &approved())]);
        let changes = Arc::new(AtomicUsize::new(0));
        let c2 = changes.clone();
        let deps = AuthDeps {
            transport: t, store: Arc::new(Locked),
            open_url: Arc::new(|_| Ok(())), sleep: Arc::new(|_| {}), now: Arc::new(|| Utc::now()),
            on_credential: Arc::new(move || { c2.fetch_add(1, Ordering::SeqCst); }),
            on_state: Arc::new(|_| {}),
            on_signed_out: Arc::new(|| {}),
        };
        let m = AuthManager::new(deps, "https://x/hapi".into(), "lap".into(), "v".into());
        assert!(matches!(m.login(None), LoginOutcome::Failed(_)), "存不住就是失败，否则重启后又要重新授权且用户不知道为什么");
        assert_eq!(m.state(), AuthState::NeedReauth { reason: ReauthReason::StoreCorrupt });
        assert_eq!(changes.load(Ordering::SeqCst), 0, "没存住的凭据不能通知 daemon 去用");
    }

    #[test]
    fn 登出_先请求服务端吊销_再清钥匙串_再停_daemon_且幂等() {
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        let t = Script::new(vec![ok(200, r#"{"revoked":true,"kicked":1}"#)]);
        let h = harness(t.clone(), store, "2026-10-05T00:00:00Z");
        h.mgr.logout().unwrap();
        assert_eq!(h.mgr.state(), AuthState::SignedOut);
        assert!(h.store.load().unwrap().is_none());
        assert_eq!(*t.urls.lock().unwrap(), vec!["https://x/hapi/api/node-login/revoke".to_string()],
            "必须通知服务端吊销，否则凭据仍有效到过期");
        assert_eq!(h.signed_out.load(Ordering::SeqCst), 1, "必须停 daemon，否则 WS 连接还在接活（假退出）");
        // 第二次：钥匙串已空，不再打网络（Script 没有多余响应，打了会 panic）
        h.mgr.logout().unwrap();
    }

    #[test]
    fn 登出_吊销带的是当前凭据() {
        struct Capture(Mutex<Option<String>>);
        impl AuthTransport for Capture {
            fn post(&self, _u: &str, b: Option<&str>, _j: &serde_json::Value) -> Result<(u16, String), String> {
                *self.0.lock().unwrap() = b.map(str::to_string);
                Ok((200, "{}".into()))
            }
        }
        let store = Arc::new(MemoryStore::new());
        store.save(&stored("CUR_SECRET", "2026-10-12T00:00:00Z")).unwrap();
        let cap = Arc::new(Capture(Mutex::new(None)));
        let h = harness(cap.clone(), store, "2026-10-05T00:00:00Z");
        h.mgr.logout().unwrap();
        assert_eq!(cap.0.lock().unwrap().as_deref(), Some("CUR_SECRET"));
    }

    #[test]
    fn 登出_断网或服务端报错也必须退出成功并停_daemon() {
        for reply in [Err("连不上".to_string()), ok(502, "{}"), ok(401, "{}"), ok(403, "{}")] {
            let store = Arc::new(MemoryStore::new());
            store.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
            let h = harness(Script::new(vec![reply.clone()]), store, "2026-10-05T00:00:00Z");
            assert!(h.mgr.logout().is_ok(), "服务端吊销失败不能挡住本地退出: {reply:?}");
            assert_eq!(h.mgr.state(), AuthState::SignedOut);
            assert!(h.store.load().unwrap().is_none());
            assert_eq!(h.signed_out.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn 登出_钥匙串清不掉也要停_daemon() {
        use crate::daemon::credential_store::StoreError;
        struct Stuck;
        impl CredentialStore for Stuck {
            fn load(&self) -> Result<Option<StoredCredential>, StoreError> { Ok(None) }
            fn save(&self, _: &StoredCredential) -> Result<(), StoreError> { Ok(()) }
            fn clear(&self) -> Result<(), StoreError> { Err(StoreError::Unavailable("keychain locked".into())) }
        }
        let stopped = Arc::new(AtomicUsize::new(0));
        let s2 = stopped.clone();
        let deps = AuthDeps {
            transport: Script::new(vec![]), store: Arc::new(Stuck),
            open_url: Arc::new(|_| Ok(())), sleep: Arc::new(|_| {}), now: Arc::new(|| Utc::now()),
            on_credential: Arc::new(|| {}), on_state: Arc::new(|_| {}),
            on_signed_out: Arc::new(move || { s2.fetch_add(1, Ordering::SeqCst); }),
        };
        let m = AuthManager::new(deps, "https://x/hapi".into(), "lap".into(), "v".into());
        assert!(m.logout().is_err(), "钥匙串失败要报给用户");
        assert_eq!(stopped.load(Ordering::SeqCst), 1, "但连接必须断开");
    }
}
