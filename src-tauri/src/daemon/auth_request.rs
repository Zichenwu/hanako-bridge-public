// src-tauri/src/daemon/auth_request.rs
//! 授权请求（网页「请求使用这台电脑」→ 本机弹窗确认 → 写 grants）。
//!
//! 服务端在 `/api/execution-node/auth-request` 限频后经节点 WS 下发
//! `{type:"auth_request", requestId, agentId, origin}`；本模块负责：
//!
//! 1. 解析并校验帧（agentId 必须像执行体 ID；缺失/畸形一律丢弃，不弹窗）
//! 2. 把请求挂到 `AuthRequestBridge`，交给 UI 层弹窗
//! 3. 等用户选择；**超时 60 秒 = 拒绝**，没有 UI 句柄 = 拒绝，绝不默认允许
//! 4. 允许时按所选目录写 `policy.json`（调用 `policy::apply_auth_grant`，校验失败整体不写）
//!
//! 放宽权限只能发生在这里（本机），网页侧没有任何路径能直接改 grants（故事 20）。
//! 写入成功后由 client 的 2s 策略比对自然推送 `grants_changed`，本模块不直接碰 WS。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 授权请求弹窗等待上限；超时 = 拒绝。
pub const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// 请求来源。本票只区分服务端标注的 web；跨设备判别在票 16。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthRequest {
    pub request_id: String,
    /// 发起的执行体（`{team}--{username}`）
    pub agent_id: String,
    /// "web" | "web_cross"（后者由票 16 的服务端标注）
    pub origin: String,
}

/// 用户的处理结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// 允许，并给出勾选的 rootId（非空）
    Allow(Vec<String>),
    Reject,
}

/// 解析服务端 `auth_request` 帧。不合法返回 None（调用方丢弃，不弹窗）。
///
/// 校验 agentId 形状是为了挡住「帧里塞任意字符串进弹窗 / 进 policy.json」：
/// 只接受 `{team}--{username}`，两段都非空、无空白与路径分隔符、总长有限。
pub fn parse_frame(v: &serde_json::Value) -> Option<AuthRequest> {
    if v.get("type")?.as_str()? != "auth_request" {
        return None;
    }
    let request_id = v.get("requestId")?.as_str()?.trim().to_string();
    let agent_id = v.get("agentId")?.as_str()?.trim().to_string();
    if request_id.is_empty() || request_id.len() > 64 || !is_agent_id(&agent_id) {
        return None;
    }
    let origin = match v.get("origin").and_then(|o| o.as_str()) {
        Some("web_cross") => "web_cross",
        _ => "web",
    }
    .to_string();
    Some(AuthRequest { request_id, agent_id, origin })
}

/// `{team}--{username}` 形状校验。
pub fn is_agent_id(s: &str) -> bool {
    if s.len() > 128 {
        return false;
    }
    let Some((team, user)) = s.split_once("--") else { return false };
    let ok = |p: &str| {
        !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    };
    ok(team) && ok(user)
}

/// 把用户决策落到 `policy.json`。只有 `Allow(非空)` 会写；写盘走「读→校验→原子写→读回」，
/// 任何一步失败都返回 Err 且磁盘保持原样。返回是否真的改了授权。
pub fn apply_decision(
    req: &AuthRequest,
    decision: &AuthDecision,
    dirs: &[std::path::PathBuf],
    default_agent: Option<&str>,
    path: &std::path::Path,
) -> Result<bool, String> {
    let AuthDecision::Allow(picked) = decision else { return Ok(false) };
    let mut file = super::policy::PolicyFile::load_from(path)?;
    super::policy::apply_auth_grant(&mut file, dirs, default_agent, &req.agent_id, picked)?;
    file.save_to(path)?;
    Ok(true)
}

struct Pending {
    request: AuthRequest,
    tx: tokio::sync::oneshot::Sender<AuthDecision>,
}

/// daemon ↔ 弹窗 的桥。`show` 由 lib.rs 注入（真实实现创建窗口；测试注入假实现）。
pub struct AuthRequestBridge {
    pending: Mutex<HashMap<String, Pending>>,
    show: Mutex<Option<Arc<dyn Fn(&AuthRequest) -> bool + Send + Sync>>>,
}

impl AuthRequestBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(HashMap::new()), show: Mutex::new(None) })
    }

    /// 注入弹窗实现（返回 false = 窗口没能打开）。
    pub fn set_presenter(&self, f: Arc<dyn Fn(&AuthRequest) -> bool + Send + Sync>) {
        *self.show.lock().unwrap() = Some(f);
    }

    /// 当前待处理的请求（弹窗页面取数据）。
    pub fn peek(&self) -> Option<AuthRequest> {
        self.pending.lock().unwrap().values().next().map(|p| p.request.clone())
    }

    /// 弹窗页面提交决策。请求已超时/不存在返回 Err。
    pub fn respond(&self, request_id: &str, decision: AuthDecision) -> Result<(), String> {
        let entry = self.pending.lock().unwrap().remove(request_id);
        match entry {
            None => Err(format!("授权请求不存在或已超时: {request_id}")),
            Some(p) => {
                let _ = p.tx.send(decision);
                Ok(())
            }
        }
    }

    /// 发起一次授权请求并等待结果。任何异常路径都是 Reject。
    pub async fn ask(&self, req: AuthRequest) -> AuthDecision {
        self.ask_with_timeout(req, AUTH_REQUEST_TIMEOUT).await
    }

    pub(crate) async fn ask_with_timeout(&self, req: AuthRequest, timeout: Duration) -> AuthDecision {
        let presenter = self.show.lock().unwrap().clone();
        let Some(present) = presenter else {
            log::warn!("[auth-request] 没有可用的弹窗实现（headless），拒绝 agent={}", req.agent_id);
            return AuthDecision::Reject;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = req.request_id.clone();
        {
            let mut g = self.pending.lock().unwrap();
            // 同时只处理一个请求：新的来了就替换旧的（旧的 tx 被 drop → 旧 ask 得到 Reject）
            g.clear();
            g.insert(id.clone(), Pending { request: req.clone(), tx });
        }
        if !present(&req) {
            self.pending.lock().unwrap().remove(&id);
            return AuthDecision::Reject;
        }
        let out = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => AuthDecision::Reject,
            Err(_) => {
                log::info!("[auth-request] {id} 超时，按拒绝处理");
                AuthDecision::Reject
            }
        };
        // 超时后清理，避免迟到的点击还能生效
        self.pending.lock().unwrap().remove(&id);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(id: &str) -> AuthRequest {
        AuthRequest { request_id: id.into(), agent_id: "bi--zhangsan".into(), origin: "web".into() }
    }

    fn bridge_with(show_ok: bool) -> Arc<AuthRequestBridge> {
        let b = AuthRequestBridge::new();
        b.set_presenter(Arc::new(move |_| show_ok));
        b
    }

    // ── 帧解析 ──

    #[test]
    fn 合法帧解析() {
        let r = parse_frame(&json!({"type":"auth_request","requestId":"authreq_1","agentId":"bi--zhangsan","origin":"web"})).unwrap();
        assert_eq!(r, req("authreq_1"));
    }

    #[test]
    fn 畸形帧丢弃_不弹窗() {
        for v in [
            json!({"type":"auth_request","requestId":"x","agentId":null}),
            json!({"type":"auth_request","requestId":"x"}),
            json!({"type":"auth_request","requestId":"","agentId":"bi--z"}),
            json!({"type":"auth_request","requestId":"x","agentId":"no-double-dash"}),
            json!({"type":"auth_request","requestId":"x","agentId":"bi--"}),
            json!({"type":"auth_request","requestId":"x","agentId":"--z"}),
            json!({"type":"auth_request","requestId":"x","agentId":"bi--z/../etc"}),
            json!({"type":"auth_request","requestId":"x","agentId":"bi--a b"}),
            json!({"type":"auth_request","requestId":"x","agentId":format!("bi--{}", "a".repeat(200))}),
            json!({"type":"other","requestId":"x","agentId":"bi--z"}),
        ] {
            assert!(parse_frame(&v).is_none(), "应丢弃: {v}");
        }
    }

    #[test]
    fn 未知来源按_web_处理_且只认已知跨设备标记() {
        let r = parse_frame(&json!({"type":"auth_request","requestId":"x","agentId":"bi--z","origin":"whatever"})).unwrap();
        assert_eq!(r.origin, "web");
        let r = parse_frame(&json!({"type":"auth_request","requestId":"x","agentId":"bi--z","origin":"web_cross"})).unwrap();
        assert_eq!(r.origin, "web_cross");
    }

    // ── 桥：超时 = 拒绝 ──

    #[tokio::test]
    async fn 无人响应_超时即拒绝() {
        let b = bridge_with(true);
        let d = b.ask_with_timeout(req("a"), Duration::from_millis(30)).await;
        assert_eq!(d, AuthDecision::Reject);
        assert!(b.peek().is_none(), "超时后必须清理 pending");
    }

    #[tokio::test]
    async fn 超时后迟到的允许无效() {
        let b = bridge_with(true);
        let _ = b.ask_with_timeout(req("late"), Duration::from_millis(20)).await;
        let r = b.respond("late", AuthDecision::Allow(vec!["r_1".into()]));
        assert!(r.is_err(), "超时后点允许不得再生效");
    }

    #[tokio::test]
    async fn 没有弹窗实现_拒绝() {
        let b = AuthRequestBridge::new();
        assert_eq!(b.ask_with_timeout(req("a"), Duration::from_millis(30)).await, AuthDecision::Reject);
    }

    #[tokio::test]
    async fn 窗口打不开_立即拒绝而不是等超时() {
        let b = bridge_with(false);
        let t = std::time::Instant::now();
        let d = b.ask_with_timeout(req("a"), Duration::from_secs(5)).await;
        assert_eq!(d, AuthDecision::Reject);
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn 用户允许_拿到所选目录() {
        let b = bridge_with(true);
        let b2 = b.clone();
        let h = tokio::spawn(async move { b2.ask_with_timeout(req("ok"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(b.peek().unwrap().agent_id, "bi--zhangsan");
        b.respond("ok", AuthDecision::Allow(vec!["r_a".into()])).unwrap();
        assert_eq!(h.await.unwrap(), AuthDecision::Allow(vec!["r_a".into()]));
    }

    #[tokio::test]
    async fn 新请求顶掉旧请求_旧的得到拒绝() {
        let b = bridge_with(true);
        let b1 = b.clone();
        let h1 = tokio::spawn(async move { b1.ask_with_timeout(req("old"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        let b2 = b.clone();
        let h2 = tokio::spawn(async move { b2.ask_with_timeout(req("new"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(h1.await.unwrap(), AuthDecision::Reject);
        b.respond("new", AuthDecision::Reject).unwrap();
        assert_eq!(h2.await.unwrap(), AuthDecision::Reject);
    }

    #[test]
    fn 超时常量为60秒() {
        assert_eq!(AUTH_REQUEST_TIMEOUT, Duration::from_secs(60));
    }

    // ── 落盘 ──

    use crate::daemon::policy::{Policy, PolicyFile, TaskScope};
    use crate::daemon::register::root_id_for;

    fn one_dir() -> (tempfile::TempDir, Vec<std::path::PathBuf>, String) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().canonicalize().unwrap();
        let id = root_id_for(&p);
        (d, vec![p], id)
    }

    #[test]
    fn 允许_写盘后该助手立刻被授权() {
        let (_d, dirs, id) = one_dir();
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("policy.json");
        let r = req("a");
        let changed = apply_decision(&r, &AuthDecision::Allow(vec![id.clone()]), &dirs, Some("other--zhangsan"), &path).unwrap();
        assert!(changed);
        let pol = Policy::build(&dirs, &PolicyFile::load_from(&path).unwrap(), Some("other--zhangsan"));
        assert!(pol.authorize(&TaskScope { agent_id: r.agent_id, root_id: Some(id) }, "x.txt", false).is_ok());
    }

    #[test]
    fn 拒绝_不写任何文件() {
        let (_d, dirs, _id) = one_dir();
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("policy.json");
        assert!(!apply_decision(&req("a"), &AuthDecision::Reject, &dirs, None, &path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn 允许但选了空_或不存在的目录_磁盘保持原样() {
        let (_d, dirs, id) = one_dir();
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("policy.json");
        let mut f = PolicyFile::default();
        f.agents.push("keep--me".into());
        f.save_to(&path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(apply_decision(&req("a"), &AuthDecision::Allow(vec![]), &dirs, None, &path).is_err());
        assert!(apply_decision(&req("a"), &AuthDecision::Allow(vec![id, "r_ghost0000000".into()]), &dirs, None, &path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn 策略文件损坏_不覆盖() {
        let (_d, dirs, id) = one_dir();
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("policy.json");
        std::fs::write(&path, "{ broken").unwrap();
        assert!(apply_decision(&req("a"), &AuthDecision::Allow(vec![id]), &dirs, None, &path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ broken", "损坏文件留给用户处理，不能被静默覆盖");
    }
}
