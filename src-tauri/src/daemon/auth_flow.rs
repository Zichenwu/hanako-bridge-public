// src-tauri/src/daemon/auth_flow.rs
//! 授权码登录与续期的编排（票 14）：把 device_auth 的纯函数、CredentialStore、HTTP 粘在一起。
//!
//! 传输层 [`AuthTransport`] 做成 trait：生产用 [`UreqTransport`]，测试用脚本化假实现，
//! 这样「轮询 N 次才 approved」「中途网络抖动」「续期 403」都能确定性复现，不靠睡眠和真网络。
//!
//! # 本票范围
//! 只产出 [`AuthState`] 让托盘/设置窗读取；托盘变黄、系统通知、点击开授权页属于票 17，
//! 这里不碰 UI。状态变化通过 `on_state` 回调向外报，不依赖任何 Tauri 类型（可脱离 GUI 测试）。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::credential_store::{CredentialStore, StoredCredential};
use super::device_auth::{
    next_poll_delay, parse_poll, parse_renew, should_renew, GrantedCredential, PollOutcome,
    RenewOutcome, StartResponse,
};

/// 对外可见的登录状态（票 17 据此渲染托盘；不含任何 secret）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    /// 钥匙串里没有凭据，需要发起授权
    SignedOut,
    /// 已发起授权，等待用户在网页点「允许」。user_code 供本机窗口展示核对
    AwaitingApproval { user_code: String, verification_url: String },
    /// 已登录
    SignedIn { agent_id: String, expires_at: String },
    /// 凭据失效，需要重新授权（托盘黄）
    NeedReauth { reason: ReauthReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthReason {
    /// 续期被 401/403 拒绝
    RenewRejected,
    /// 用户在网页点了拒绝
    Denied,
    /// 授权码过期用户没处理
    CodeExpired,
    /// 本地凭据已过期且无法续期
    LocalExpired,
    /// 钥匙串里的凭据损坏
    StoreCorrupt,
}

/// HTTP 传输抽象。返回 (状态码, body)；网络层失败返回 Err。
pub trait AuthTransport: Send + Sync {
    fn post(&self, url: &str, bearer: Option<&str>, json_body: &serde_json::Value) -> Result<(u16, String), String>;
}

/// 生产传输：ureq（同步，rustls）。调用方须在 blocking 线程里用。
///
/// 出网策略见 [`super::net_proxy`]：先按默认（直连 / 环境变量代理）发；**只有网络层失败**
/// 才依次试系统代理。某条路通了就记住，后续轮询直接走它，避免每次都等直连超时。
pub struct UreqTransport;

/// 上次走通的代理（None = 直连可用）。进程内记忆，重启后重新探测。
static STICKY_PROXY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn ureq_post(
    url: &str,
    bearer: Option<&str>,
    json_body: &serde_json::Value,
    proxy: Option<&str>,
) -> Result<(u16, String), String> {
    let mut b = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        // 直连不通时别干等满 15s 才退代理
        .timeout_connect(Some(Duration::from_secs(6)))
        // 4xx/5xx 不当作 Err 抛出：状态码本身就是契约的一部分（429/401/403）
        .http_status_as_error(false);
    if let Some(p) = proxy {
        b = b.proxy(Some(ureq::Proxy::new(p).map_err(|e| format!("代理地址无效 {p}: {e}"))?));
    }
    let agent: ureq::Agent = b.build().into();
    let mut req = agent.post(url);
    if let Some(t) = bearer {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let mut resp = req.send_json(json_body).map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    Ok((status, body))
}

impl AuthTransport for UreqTransport {
    fn post(&self, url: &str, bearer: Option<&str>, json_body: &serde_json::Value) -> Result<(u16, String), String> {
        let sticky = STICKY_PROXY.lock().unwrap().clone();
        let first = ureq_post(url, bearer, json_body, sticky.as_deref());
        let first_err = match first {
            Ok(r) => return Ok(r),
            Err(e) => e,
        };
        // 网络层失败：试其它路（直连 + 各候选代理，跳过刚失败的那条）
        let mut routes: Vec<Option<String>> = vec![None];
        routes.extend(super::net_proxy::fallback_proxies().into_iter().map(Some));
        for route in routes.into_iter().filter(|r| *r != sticky) {
            match ureq_post(url, bearer, json_body, route.as_deref()) {
                Ok(r) => {
                    log::info!("[net] 改走 {}", route.as_deref().unwrap_or("直连"));
                    *STICKY_PROXY.lock().unwrap() = route;
                    return Ok(r);
                }
                Err(e) => log::warn!("[net] {} 也失败: {e}", route.as_deref().unwrap_or("直连")),
            }
        }
        Err(format!("连不上 Hanako 服务器：{first_err}"))
    }
}

/// 发起授权所需信息。
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub hub_url: String,
    pub machine_name: String,
    pub app_version: String,
    /// US5：发起登录时正在用的执行体，确认页默认只勾它
    pub agent_id: Option<String>,
}

fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// 发起授权码流程（第一步）。
pub fn start_login(t: &dyn AuthTransport, req: &LoginRequest) -> Result<StartResponse, String> {
    let body = serde_json::json!({
        "machineName": req.machine_name,
        "appVersion": req.app_version,
        "agentId": req.agent_id,
    });
    let (status, text) = t.post(&join(&req.hub_url, "/api/node-login/start"), None, &body)?;
    if !(200..300).contains(&status) {
        return Err(format!("发起授权失败 HTTP {status}"));
    }
    let r: StartResponse = serde_json::from_str(&text).map_err(|e| format!("start 响应格式异常: {e}"))?;
    if r.device_code.is_empty() || r.verification_url.is_empty() {
        return Err("start 响应缺少 deviceCode 或 verificationUrl".into());
    }
    // 安全：verification_url 会被交给系统浏览器打开，只接受 http(s)，拒绝 file:// javascript: 等
    if !(r.verification_url.starts_with("https://") || r.verification_url.starts_with("http://")) {
        return Err("verificationUrl 不是 http(s)，拒绝打开".into());
    }
    Ok(r)
}

/// 轮询直到终态。`sleep` 可注入，测试里传空函数即可瞬间跑完；返回 Ok(凭据) 或终止原因。
///
/// 网络错误**不终止**（合盖/切网很常见），只累计计入下次等待；码过期（`expires_in` 用尽）才放弃。
pub fn poll_until_done(
    t: &dyn AuthTransport,
    hub_url: &str,
    start: &StartResponse,
    sleep: &dyn Fn(Duration),
    mut on_tick: impl FnMut(),
) -> Result<GrantedCredential, ReauthReason> {
    let mut waited = Duration::ZERO;
    let budget = Duration::from_secs(start.expires_in.max(1));
    let mut slowed = 0u32;
    let url = join(hub_url, "/api/node-login/poll");
    let body = serde_json::json!({ "deviceCode": start.device_code });

    loop {
        let delay = next_poll_delay(start.interval, slowed);
        sleep(delay);
        waited += delay;
        on_tick();

        match t.post(&url, None, &body).and_then(|(s, b)| parse_poll(s, &b)) {
            Ok(PollOutcome::Approved(g)) => return Ok(g),
            Ok(PollOutcome::Denied) => return Err(ReauthReason::Denied),
            Ok(PollOutcome::Expired) => return Err(ReauthReason::CodeExpired),
            Ok(PollOutcome::SlowDown) => slowed = slowed.saturating_add(1),
            Ok(PollOutcome::Pending) => {}
            Err(e) => log::warn!("[auth] 轮询暂时失败（将继续）: {e}"),
        }
        if waited >= budget {
            return Err(ReauthReason::CodeExpired);
        }
    }
}

/// 把领取到的凭据落钥匙串。失败必须向上抛——拿到凭据却没存住，下次启动就又要重新授权。
pub fn persist_granted(store: &dyn CredentialStore, g: &GrantedCredential, machine_name: &str) -> Result<StoredCredential, String> {
    let cred = StoredCredential {
        server_url: g.server_url.clone(),
        agent_id: g.agent_id.clone(),
        secret: g.credential_secret.clone(),
        credential_id: g.credential_id.clone(),
        expires_at: g.expires_at.clone(),
        node_name: g.node_name.clone().or_else(|| Some(machine_name.to_string())),
    };
    store.save(&cred).map_err(|e| e.to_string())?;
    Ok(cred)
}

/// 启动时的登录态判定（纯读，不发网络）。
pub fn initial_state(store: &dyn CredentialStore, now: DateTime<Utc>) -> AuthState {
    match store.load() {
        Ok(None) => AuthState::SignedOut,
        Err(_) => AuthState::NeedReauth { reason: ReauthReason::StoreCorrupt },
        Ok(Some(c)) => {
            if is_expired(&c.expires_at, now) {
                // 已过期也先尝试续期（服务端可能仍接受刚过期的旧凭据），交给 maybe_renew 裁决；
                // 这里只标记「已登录但需要立刻续」，由调用方随后调用 maybe_renew
                AuthState::SignedIn { agent_id: c.agent_id, expires_at: c.expires_at }
            } else {
                AuthState::SignedIn { agent_id: c.agent_id, expires_at: c.expires_at }
            }
        }
    }
}

fn is_expired(expires_at: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|e| e.with_timezone(&Utc) <= now)
        .unwrap_or(false)
}

/// 续期的一次尝试结果（给调度器用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewStep {
    /// 还没到续期窗口，什么也没做
    NotDue,
    /// 续期成功，新凭据已落钥匙串
    Renewed { expires_at: String },
    /// 暂时失败，稍后重试；携带是否已过期（已过期则握手必 403，调用方应提示）
    Retry { reason: String, already_expired: bool },
    /// 凭据失效（401/403）或本地已过期且续不了：需要重新授权
    NeedReauth(ReauthReason),
}

/// 若到了续期窗口则续期并落盘。**只在确认拿到新凭据并成功写入钥匙串后才算成功**。
pub fn maybe_renew(
    t: &dyn AuthTransport,
    store: &dyn CredentialStore,
    hub_url: &str,
    now: DateTime<Utc>,
) -> RenewStep {
    let cur = match store.load() {
        Ok(Some(c)) => c,
        Ok(None) => return RenewStep::NeedReauth(ReauthReason::LocalExpired),
        Err(_) => return RenewStep::NeedReauth(ReauthReason::StoreCorrupt),
    };
    if !should_renew(&cur.expires_at, now) {
        return RenewStep::NotDue;
    }
    let expired = is_expired(&cur.expires_at, now);

    let url = join(hub_url, "/api/node-login/renew");
    let outcome = match t.post(&url, Some(&cur.secret), &serde_json::json!({})) {
        Ok((s, b)) => parse_renew(s, &b),
        Err(e) => RenewOutcome::Retry(e),
    };
    match outcome {
        RenewOutcome::Renewed { secret, credential_id, expires_at } => {
            let next = StoredCredential { secret, credential_id, expires_at: expires_at.clone(), ..cur };
            match store.save(&next) {
                Ok(()) => RenewStep::Renewed { expires_at },
                // 旧凭据服务端已作废而新凭据没存住：这是最坏的一种失败，必须显式报，不能静默
                Err(e) => RenewStep::Retry { reason: format!("续期成功但写入钥匙串失败: {e}"), already_expired: expired },
            }
        }
        RenewOutcome::NeedReauth => RenewStep::NeedReauth(ReauthReason::RenewRejected),
        RenewOutcome::Retry(r) => {
            if expired {
                // 已过期 + 续期暂时失败：继续重试但也要让上层知道握手已经不可能成功
                RenewStep::Retry { reason: r, already_expired: true }
            } else {
                RenewStep::Retry { reason: r, already_expired: false }
            }
        }
    }
}

/// 便捷：Arc 包装后跨线程共享。
pub type SharedStore = Arc<dyn CredentialStore>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::credential_store::MemoryStore;
    use std::sync::Mutex;

    /// 脚本化传输：按调用顺序依次返回预置响应，并记录每次请求。
    struct Script {
        replies: Mutex<Vec<Result<(u16, String), String>>>,
        calls: Mutex<Vec<(String, Option<String>, serde_json::Value)>>,
    }
    impl Script {
        fn new(replies: Vec<Result<(u16, String), String>>) -> Self {
            let mut r = replies;
            r.reverse();
            Self { replies: Mutex::new(r), calls: Mutex::new(vec![]) }
        }
        fn ok(status: u16, body: &str) -> Result<(u16, String), String> {
            Ok((status, body.to_string()))
        }
    }
    impl AuthTransport for Script {
        fn post(&self, url: &str, bearer: Option<&str>, b: &serde_json::Value) -> Result<(u16, String), String> {
            self.calls.lock().unwrap().push((url.into(), bearer.map(str::to_string), b.clone()));
            self.replies.lock().unwrap().pop().expect("脚本响应用完了，调用次数超出预期")
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn start_resp(interval: u64, expires_in: u64) -> StartResponse {
        StartResponse {
            device_code: "DEV".into(),
            user_code: "ABCD-2345".into(),
            verification_url: "https://x/hapi/device?c=ABCD-2345".into(),
            expires_in,
            interval,
        }
    }

    fn approved() -> String {
        serde_json::json!({"status":"approved","serverUrl":"https://x/hapi/hanako","agentId":"team--alice",
            "nodeName":"laptop","credentialSecret":"SEC","credentialId":"c1","expiresAt":"2026-10-12T00:00:00Z"}).to_string()
    }

    fn stored(secret: &str, exp: &str) -> StoredCredential {
        StoredCredential { server_url: "https://x/hapi/hanako".into(), agent_id: "team--alice".into(),
            secret: secret.into(), credential_id: Some("c1".into()), expires_at: exp.into(), node_name: Some("laptop".into()) }
    }

    // ── start ───────────────────────────────────────────────
    #[test]
    fn start_请求体带机器名_版本_及发起时的执行体() {
        let t = Script::new(vec![Script::ok(200, r#"{"deviceCode":"D","userCode":"U","verificationUrl":"https://x/v","expiresIn":600,"interval":5}"#)]);
        let req = LoginRequest { hub_url: "https://x/hapi/".into(), machine_name: "laptop".into(), app_version: "0.1.0".into(), agent_id: Some("team--alice".into()) };
        start_login(&t, &req).unwrap();
        let calls = t.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://x/hapi/api/node-login/start", "hub_url 尾斜杠不得造成双斜杠");
        assert_eq!(calls[0].2["agentId"], "team--alice", "US5：确认页默认只勾发起时的执行体，必须随请求上报");
        assert_eq!(calls[0].2["machineName"], "laptop");
    }

    #[test]
    fn start_拒绝非_http_的验证地址() {
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "ms-msdt:/x", "//evil.com/x"] {
            let body = serde_json::json!({"deviceCode":"D","userCode":"U","verificationUrl":bad,"expiresIn":600,"interval":5}).to_string();
            let t = Script::new(vec![Script::ok(200, &body)]);
            let req = LoginRequest { hub_url: "https://x".into(), machine_name: "m".into(), app_version: "v".into(), agent_id: None };
            assert!(start_login(&t, &req).is_err(), "应拒绝打开 {bad}");
        }
    }

    #[test]
    fn start_服务端错误_报错() {
        let t = Script::new(vec![Script::ok(500, "")]);
        let req = LoginRequest { hub_url: "https://x".into(), machine_name: "m".into(), app_version: "v".into(), agent_id: None };
        assert!(start_login(&t, &req).is_err());
    }

    // ── poll ────────────────────────────────────────────────
    #[test]
    fn 轮询_pending_若干次后_approved() {
        let t = Script::new(vec![
            Script::ok(200, r#"{"status":"pending"}"#),
            Script::ok(200, r#"{"status":"pending"}"#),
            Script::ok(200, &approved()),
        ]);
        let mut ticks = 0;
        let g = poll_until_done(&t, "https://x", &start_resp(5, 600), &|_| {}, || ticks += 1).unwrap();
        assert_eq!(g.credential_secret, "SEC");
        assert_eq!(ticks, 3);
        assert_eq!(t.calls.lock().unwrap().len(), 3);
        // 轮询请求体只带 deviceCode，不带 userCode（userCode 只给人看）
        assert_eq!(t.calls.lock().unwrap()[0].2, serde_json::json!({"deviceCode":"DEV"}));
    }

    #[test]
    fn 轮询_用户拒绝_立即终止() {
        let t = Script::new(vec![Script::ok(200, r#"{"status":"denied"}"#)]);
        assert_eq!(poll_until_done(&t, "https://x", &start_resp(5, 600), &|_| {}, || {}).unwrap_err(), ReauthReason::Denied);
        assert_eq!(t.calls.lock().unwrap().len(), 1, "denied 后不得继续轮询");
    }

    #[test]
    fn 轮询_码过期_立即终止() {
        let t = Script::new(vec![Script::ok(200, r#"{"status":"expired"}"#)]);
        assert_eq!(poll_until_done(&t, "https://x", &start_resp(5, 600), &|_| {}, || {}).unwrap_err(), ReauthReason::CodeExpired);
    }

    #[test]
    fn 轮询_网络抖动不终止() {
        let t = Script::new(vec![Err("连接超时".into()), Err("dns 失败".into()), Script::ok(200, &approved())]);
        assert!(poll_until_done(&t, "https://x", &start_resp(5, 600), &|_| {}, || {}).is_ok(), "合盖/切网的网络错误不应放弃授权");
    }

    #[test]
    fn 轮询_slow_down_后间隔翻倍() {
        let t = Script::new(vec![Script::ok(429, ""), Script::ok(429, ""), Script::ok(200, &approved())]);
        let slept = Mutex::new(vec![]);
        poll_until_done(&t, "https://x", &start_resp(5, 600), &|d| slept.lock().unwrap().push(d.as_secs()), || {}).unwrap();
        // 睡眠在请求之前：第 1 次睡 5s→收到 429；第 2 次睡 10s→又 429；第 3 次睡 20s→approved。
        // 即「每收到一次 429，之后的等待翻倍」。若 429 不生效，这里会是 [5,5,5]。
        assert_eq!(*slept.lock().unwrap(), vec![5, 10, 20], "每收到一次 429，下一次等待翻倍");
    }

    #[test]
    fn 轮询_一直_pending_超过码有效期_放弃() {
        let replies = (0..100).map(|_| Script::ok(200, r#"{"status":"pending"}"#)).collect();
        let t = Script::new(replies);
        // interval 5s、有效期 20s → 约 4 次后放弃
        let r = poll_until_done(&t, "https://x", &start_resp(5, 20), &|_| {}, || {});
        assert_eq!(r.unwrap_err(), ReauthReason::CodeExpired);
        assert!(t.calls.lock().unwrap().len() <= 5, "超出有效期不得无限轮询");
    }

    // ── persist / initial_state ─────────────────────────────
    #[test]
    fn 领取后落钥匙串() {
        let store = MemoryStore::new();
        let g = match parse_poll(200, &approved()).unwrap() { PollOutcome::Approved(g) => g, _ => unreachable!() };
        persist_granted(&store, &g, "laptop").unwrap();
        let got = store.load().unwrap().unwrap();
        assert_eq!(got.secret, "SEC");
        assert_eq!(got.expires_at, "2026-10-12T00:00:00Z");
    }

    #[test]
    fn 初始状态() {
        let now = at("2026-10-05T00:00:00Z");
        let s = MemoryStore::new();
        assert_eq!(initial_state(&s, now), AuthState::SignedOut);
        s.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        assert!(matches!(initial_state(&s, now), AuthState::SignedIn { .. }));
        s.put_raw("{ broken");
        assert_eq!(initial_state(&s, now), AuthState::NeedReauth { reason: ReauthReason::StoreCorrupt });
    }

    // ── 续期 ────────────────────────────────────────────────
    #[test]
    fn 续期_未到窗口_不发请求() {
        let s = MemoryStore::new();
        s.save(&stored("S", "2026-10-12T00:00:00Z")).unwrap();
        let t = Script::new(vec![]);
        assert_eq!(maybe_renew(&t, &s, "https://x", at("2026-10-05T00:00:00Z")), RenewStep::NotDue);
        assert!(t.calls.lock().unwrap().is_empty(), "没到窗口就打 hub = 白白消耗限流额度");
    }

    #[test]
    fn 续期_到窗口_带旧凭据续期并整体更新钥匙串() {
        let s = MemoryStore::new();
        s.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let t = Script::new(vec![Script::ok(200, r#"{"credentialSecret":"NEW","credentialId":"c2","expiresAt":"2026-10-13T00:00:00Z"}"#)]);
        let r = maybe_renew(&t, &s, "https://x", at("2026-10-05T12:00:00Z"));
        assert_eq!(r, RenewStep::Renewed { expires_at: "2026-10-13T00:00:00Z".into() });
        assert_eq!(t.calls.lock().unwrap()[0].1.as_deref(), Some("OLD"), "续期必须用当前凭据做 Bearer");
        let got = s.load().unwrap().unwrap();
        assert_eq!((got.secret.as_str(), got.expires_at.as_str()), ("NEW", "2026-10-13T00:00:00Z"));
        assert_eq!(got.agent_id, "team--alice", "续期不得丢失执行体等其它字段");
    }

    #[test]
    fn 续期_被拒_需重新授权_且不动钥匙串() {
        let s = MemoryStore::new();
        s.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let t = Script::new(vec![Script::ok(403, "{}")]);
        assert_eq!(maybe_renew(&t, &s, "https://x", at("2026-10-05T12:00:00Z")), RenewStep::NeedReauth(ReauthReason::RenewRejected));
        assert_eq!(s.load().unwrap().unwrap().secret, "OLD", "续期失败不得清掉现有凭据（可能只是对端暂时问题误判）");
    }

    #[test]
    fn 续期_网络错误_只是重试_不是失效() {
        let s = MemoryStore::new();
        s.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let t = Script::new(vec![Err("超时".into())]);
        assert!(matches!(maybe_renew(&t, &s, "https://x", at("2026-10-05T12:00:00Z")), RenewStep::Retry { already_expired: false, .. }));
    }

    #[test]
    fn 续期_已过期且续不了_标记已过期() {
        let s = MemoryStore::new();
        s.save(&stored("OLD", "2026-10-01T00:00:00Z")).unwrap();
        let t = Script::new(vec![Ok((503, String::new()))]);
        assert!(matches!(maybe_renew(&t, &s, "https://x", at("2026-10-05T12:00:00Z")), RenewStep::Retry { already_expired: true, .. }));
    }

    #[test]
    fn 续期_钥匙串里没有凭据() {
        let s = MemoryStore::new();
        let t = Script::new(vec![]);
        assert_eq!(maybe_renew(&t, &s, "https://x", at("2026-10-05T00:00:00Z")), RenewStep::NeedReauth(ReauthReason::LocalExpired));
    }

    #[test]
    fn 续期_成功但钥匙串写失败_必须显式报出() {
        struct FailingSave(MemoryStore);
        impl CredentialStore for FailingSave {
            fn load(&self) -> Result<Option<StoredCredential>, crate::daemon::credential_store::StoreError> { self.0.load() }
            fn save(&self, _: &StoredCredential) -> Result<(), crate::daemon::credential_store::StoreError> {
                Err(crate::daemon::credential_store::StoreError::Unavailable("locked".into()))
            }
            fn clear(&self) -> Result<(), crate::daemon::credential_store::StoreError> { self.0.clear() }
        }
        let inner = MemoryStore::new();
        inner.save(&stored("OLD", "2026-10-06T00:00:00Z")).unwrap();
        let s = FailingSave(inner);
        let t = Script::new(vec![Script::ok(200, r#"{"credentialSecret":"NEW","expiresAt":"2026-10-13T00:00:00Z"}"#)]);
        match maybe_renew(&t, &s, "https://x", at("2026-10-05T12:00:00Z")) {
            RenewStep::Retry { reason, .. } => assert!(reason.contains("钥匙串"), "应明确指出是写钥匙串失败: {reason}"),
            o => panic!("写钥匙串失败不能当作成功，实际 {o:?}"),
        }
    }
}
