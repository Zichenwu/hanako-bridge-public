// src-tauri/src/daemon/tools/upload.rs
//! `local_upload_to_workspace`：把本机文件搬到云端工作区（票 18，决策文档 §3.1/§3.3）。
//!
//! 管线（顺序不可调换，任一步失败都不会读出文件内容）：
//!   ① lease 校验 → ② 策略复核(authorize, write=false) → ③ 解析真实路径/大小 → ④ `upload_gate::decide`
//!   → ⑤ 需要问则弹窗 → ⑥ 读字节 → ⑦ 审计 → ⑧ 返回 `upload` 独立字段
//!
//! 为什么按「写类」要求 lease：数据出境与写同等敏感，lease 把这次搬运绑定到会话 + 目录，
//! 防止被挂到别的目录的任务帧上。读文件内容发生在**用户同意之后**。

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::Value;

use super::{ToolResult, UploadPayload};
use crate::daemon::audit::{AuditEntry, AuditLogger};
use crate::daemon::lease::{validate_scope, Lease, LeaseValidator};
use crate::daemon::policy::{Policy, PolicyFile, TaskScope};
use crate::daemon::upload_bridge::{UploadAsk, UploadBridge};
use crate::daemon::upload_gate::{self, DenyReason, Pref, SessionGrants, UploadFacts, Verdict};

/// 任务局部上下文：弹窗桥 + 来源。由 client 在执行任务前 scope 进来。
#[derive(Clone)]
pub struct UploadCtx {
    pub bridge: Arc<UploadBridge>,
    /// "local_web" | "other_device" | "web"
    pub origin: String,
}

tokio::task_local! {
    pub static UPLOAD_CTX: UploadCtx;
}

/// 机读错误码前缀（服务端据此映射 LOCAL_UPLOAD_REJECTED）。
pub const ERR_PREFIX: &str = "LOCAL_UPLOAD_REJECTED";

/// 会话内上传授权：进程级、内存态、不落盘，重启即清。
pub fn session_grants() -> &'static Mutex<SessionGrants> {
    static G: std::sync::OnceLock<Mutex<SessionGrants>> = std::sync::OnceLock::new();
    G.get_or_init(|| Mutex::new(SessionGrants::new()))
}

fn rejected(reason: &str) -> ToolResult {
    ToolResult::err(format!("{ERR_PREFIX}: {reason}"))
}

/// 读取某目录的上传偏好。读失败/损坏 → 每次问（放宽方向 fail-closed）。
fn pref_for(root_id: &str) -> Pref {
    match PolicyFile::load() {
        Ok(f) => f.upload.get(root_id).map(|s| Pref::parse(s)).unwrap_or(Pref::Ask),
        Err(_) => Pref::Ask,
    }
}

pub async fn local_upload_to_workspace(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    bridge: &Arc<UploadBridge>,
    audit: &Arc<AuditLogger>,
    origin: &str,
) -> ToolResult {
    let agent_id = params.get("_agent_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let task_id = params.get("_task_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let session = params.get("_session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let purpose = params.get("purpose").and_then(|v| v.as_str()).map(|s| s.chars().take(200).collect::<String>());
    // 审计来源（票 07）：与读类 / 写类同一口径——取 params._origin（网页浏览 web_browse / 缺省 agent）。
    // 与函数入参 `origin`（任务帧顶层，跨机提醒用的 local_web|other_device|web）是两条不同的轴，勿混。
    let audit_origin = params.get("_origin").and_then(|v| v.as_str()).unwrap_or("agent").to_string();

    let log = |decision: Option<&str>, lease_id: Option<String>, ok: bool, err: Option<String>| {
        audit.log(&AuditEntry {
            ts: crate::daemon::audit::now_ts(),
            agent_id: agent_id.clone(),
            tool: "local_upload_to_workspace".into(),
            path: path.clone(),
            lease_id,
            task_id: task_id.clone(),
            decision: decision.map(str::to_string),
            backup_path: None,
            ok,
            error: err,
            origin: audit_origin.clone(),
        });
    };
    let fail = |decision: Option<&str>, lease_id: Option<String>, msg: String| {
        log(decision, lease_id, false, Some(msg.clone()));
        ToolResult::err(msg)
    };

    if path.is_empty() {
        return ToolResult::err("path required".into());
    }

    // ① lease（必须）
    let Some(lease) = lease else {
        return fail(None, None, format!("{ERR_PREFIX}: requires lease"));
    };
    let lease_id = lease.lease_id.clone();
    if let Err(e) = LeaseValidator::new().validate(&lease, node_id, "write_files") {
        return fail(None, Some(lease_id), format!("{ERR_PREFIX}: lease validation failed: {e}"));
    }
    let scope = TaskScope::from_params(params);
    if let Err(e) = validate_scope(&lease, &scope.agent_id, scope.root_id.as_deref()) {
        return fail(None, Some(lease_id), format!("{ERR_PREFIX}: lease validation failed: {e}"));
    }

    // ② 策略复核：只读授权即可（上传不改本机文件），但执行体必须被授权该目录
    let resolved = match policy.authorize(&scope, &path, false) {
        Ok(r) => r,
        // 审核 #12：OutOfFence 的 Display 带命中的敏感规则（如「sensitive path rejected: .env」），
        // 回给模型 = 把本机有什么敏感文件告诉云端。塌缩成粗粒度码（同预览闸 preview_gate 的口径）；
        // 其它 GateError 不含规则名，保持原样（模型要据此区分未授权 / 只读 / 撤销）。
        Err(crate::daemon::policy::GateError::OutOfFence(_)) => {
            return fail(None, Some(lease_id), format!("{ERR_PREFIX}: {}", DenyReason::OutOfFence.code()))
        }
        Err(e) => return fail(None, Some(lease_id), format!("{ERR_PREFIX}: {e}")),
    };

    // ③ 事实：真实路径（authorize 已 canonicalize）、大小、是否普通文件、命中目录
    let meta = match std::fs::metadata(&resolved.path) {
        Ok(m) => m,
        Err(e) => return fail(None, Some(lease_id), format!("{ERR_PREFIX}: stat failed: {e}")),
    };
    let Some(root) = policy.roots.iter().find(|r| r.path == resolved.root) else {
        return fail(None, Some(lease_id), format!("{ERR_PREFIX}: {}", DenyReason::OutOfFence.code()));
    };
    let facts = UploadFacts {
        real_path: resolved.path.clone(),
        size: meta.len(),
        is_file: meta.is_file(),
        root_id: Some(root.root_id.clone()),
        actor_granted: policy.grants.get(&scope.agent_id).map(|ids| ids.contains(&root.root_id)).unwrap_or(false),
    };
    // 兜底：真实路径必须确实落在命中目录内（authorize 已保证，这里是独立的第二道）
    if !upload_gate::within_root(&facts.real_path, &resolved.root) {
        return fail(None, Some(lease_id), format!("{ERR_PREFIX}: {}", DenyReason::OutOfFence.code()));
    }

    // ④ 闸决策
    let verdict = {
        let mut g = session_grants().lock().unwrap();
        upload_gate::decide(&facts, pref_for(&root.root_id), &session, &mut g)
    };
    let decision_label = match &verdict {
        Verdict::Allow => "auto",
        Verdict::Ask => "approved",
        Verdict::Deny(_) => "rejected",
    };
    match verdict {
        Verdict::Deny(why) => {
            let detail = match &why {
                DenyReason::TooBig { size, limit } => format!("{} (size={size} limit={limit})", why.code()),
                _ => why.code().to_string(),
            };
            return fail(Some("rejected"), Some(lease_id), format!("{ERR_PREFIX}: {detail}"));
        }
        Verdict::Ask => {
            // ⑤ 弹窗（超时/无窗口 = 拒绝）
            let file_name = resolved.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let ask = UploadAsk {
                ask_id: format!("up_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()),
                file_name,
                size: facts.size,
                folder_name: root.name.clone(),
                root_id: root.root_id.clone(),
                agent_id: scope.agent_id.clone(),
                purpose,
                origin: origin.to_string(),
            };
            let choice = bridge.ask(ask).await;
            let allowed = {
                let mut g = session_grants().lock().unwrap();
                upload_gate::apply_choice(choice, &session, &root.root_id, &mut g)
            };
            if !allowed {
                return fail(Some("rejected"), Some(lease_id), format!("{ERR_PREFIX}: user_rejected"));
            }
        }
        Verdict::Allow => {}
    }

    // ⑥ 读字节：此时用户已同意（或永久/会话信任）。读失败如实报错。
    let bytes = match std::fs::read(&resolved.path) {
        Ok(b) => b,
        Err(e) => return fail(Some(decision_label), Some(lease_id), format!("{ERR_PREFIX}: read failed: {e}")),
    };
    // 读取后再校验一次大小：stat 与 read 之间文件可能变大
    if bytes.len() as u64 > upload_gate::effective_limit() {
        return fail(Some("rejected"), Some(lease_id), format!("{ERR_PREFIX}: too_big (changed while reading)"));
    }
    let name = resolved.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    // ⑦ 审计（不含字节、不含绝对路径之外的内容）
    log(Some(decision_label), Some(lease_id), true, None);

    // ⑧ 返回：result 只有一句人话；字节走独立 upload 字段
    let mut r = ToolResult::ok(format!("已将「{name}」（{} 字节）传到云端工作区的「本机文件」文件夹。", bytes.len()));
    r.upload = Some(UploadPayload { name, base64: b64 });
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::upload_gate::UserChoice;
    use std::sync::atomic::{AtomicU32, Ordering};

    const AGENT: &str = "bi--zhangsan";
    const NODE: &str = "node_t18";

    /// 会话内授权是进程级全局，各用例用不同 session 隔离；偏好读的是 ~/.hanako-tauri/policy.json，
    /// 测试统一把 HOME 指到临时目录（串行，避免互相污染）。
    static ENV: Mutex<()> = Mutex::new(());

    struct Env {
        _g: std::sync::MutexGuard<'static, ()>,
        _home: tempfile::TempDir,
        dir: tempfile::TempDir,
        policy: Policy,
        bridge: Arc<UploadBridge>,
        audit: Arc<AuditLogger>,
        asked: Arc<AtomicU32>,
        old_home: Option<std::ffi::OsString>,
    }
    impl Drop for Env {
        fn drop(&mut self) {
            match self.old_home.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            // 清除策略路径覆盖（Windows 上 home_dir 不读环境变量，靠 HANAKO_POLICY_PATH 隔离）
            std::env::remove_var(crate::daemon::policy::POLICY_PATH_ENV);
        }
    }

    /// `answer`：弹窗里用户的选择；None = 不该弹窗（弹了就记数，测试据此断言）。
    fn env(answer: Option<UserChoice>, upload_pref: Option<&str>) -> Env {
        let g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut pf = PolicyFile::default();
        let pol0 = Policy::build(&[root.clone()], &pf, Some(AGENT));
        let rid = pol0.roots[0].root_id.clone();
        if let Some(p) = upload_pref {
            pf.upload.insert(rid.clone(), p.into());
        }
        // 把策略文件真实写到临时目录，并用 HANAKO_POLICY_PATH 让 PolicyFile::path() 指向它。
        // Windows 上 dirs_next::home_dir() 走 KNOWNFOLDER 不读 HOME/USERPROFILE，
        // 那两个变量隔离不了策略路径，必须用这个显式覆盖（CI windows-x64 曾因此失败）。
        let pp = home.path().join(".hanako-tauri");
        std::fs::create_dir_all(&pp).unwrap();
        let policy_path = pp.join("policy.json");
        pf.save_to(&policy_path).unwrap();
        std::env::set_var(crate::daemon::policy::POLICY_PATH_ENV, &policy_path);
        let policy = Policy::build(&[root], &pf, Some(AGENT));
        let bridge = UploadBridge::new();
        let asked = Arc::new(AtomicU32::new(0));
        let (b2, a2) = (bridge.clone(), asked.clone());
        bridge.set_presenter(Arc::new(move |ask| {
            a2.fetch_add(1, Ordering::SeqCst);
            let (b3, id) = (b2.clone(), ask.ask_id.clone());
            if let Some(c) = answer {
                tokio::spawn(async move { tokio::task::yield_now().await; let _ = b3.respond(&id, c); });
            }
            true
        }));
        let audit = Arc::new(AuditLogger::new(home.path().to_path_buf()));
        Env { _g: g, _home: home, dir, policy, bridge, audit, asked, old_home }
    }

    fn lease(root_ids: Vec<String>) -> Lease {
        Lease {
            schema_version: 1,
            lease_id: format!("l-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
            target_server_node_id: NODE.into(),
            command_class: "write_files".into(),
            backup_policy: "snapshot_before_write".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            agent_id: Some(AGENT.into()),
            resource_ids: root_ids,
        }
    }

    fn params(path: &str, session: &str) -> Value {
        serde_json::json!({ "path": path, "_agent_id": AGENT, "_task_id": "t1", "_session_id": session, "purpose": "改透视表" })
    }

    async fn run(e: &Env, p: &Value, l: Option<Lease>) -> ToolResult {
        local_upload_to_workspace(p, &e.policy, l, NODE, &e.bridge, &e.audit, "web").await
    }

    #[tokio::test]
    async fn 用户同意_字节走独立_upload_字段_result_不含字节() {
        let e = env(Some(UserChoice::Once), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"hello-bytes").unwrap();
        let r = run(&e, &params("a.xlsx", "s-ok"), Some(lease(vec![]))).await;
        assert!(r.ok, "{:?}", r.error);
        let u = r.upload.expect("必须有 upload 字段");
        assert_eq!(u.name, "a.xlsx");
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&u.base64).unwrap(), b"hello-bytes");
        let text = r.result.unwrap();
        assert!(!text.contains(&u.base64), "字节绝不能出现在会被交给模型的 result 里");
        assert_eq!(e.asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn 审计_origin_默认_agent_带_origin_记_web_browse() {
        // 票 07：upload 审计 origin 取 params._origin（缺省 agent），与读/写同一口径
        let e = env(Some(UserChoice::Once), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        // 默认（无 _origin）
        let p1 = params("a.xlsx", "s-o1");
        assert!(run(&e, &p1, Some(lease(vec![]))).await.ok);
        // 显式 _origin
        let mut p2 = params("a.xlsx", "s-o2");
        p2["_origin"] = serde_json::json!("web_browse");
        assert!(run(&e, &p2, Some(lease(vec![]))).await.ok);

        let lines = std::fs::read_to_string(e.audit.today_file()).unwrap();
        let origins: Vec<String> = lines.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["tool"] == "local_upload_to_workspace")
            .map(|v| v["origin"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(origins, vec!["agent".to_string(), "web_browse".to_string()]);
    }

    #[tokio::test]
    async fn 用户拒绝_不读文件_无_upload_字段() {
        let e = env(Some(UserChoice::Reject), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"secret").unwrap();
        let r = run(&e, &params("a.xlsx", "s-rej"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
        assert!(r.error.unwrap().starts_with(ERR_PREFIX));
    }

    #[tokio::test]
    async fn 弹窗打不开_拒绝() {
        // 超时路径由 upload_bridge 自己的单测覆盖（超时_拒绝_且迟到的点击无效）；这里验证工具层把「打不开」当拒绝
        let e = env(None, None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        e.bridge.set_presenter(Arc::new(|_| false));
        let r = run(&e, &params("a.xlsx", "s-np"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
    }

    #[tokio::test]
    async fn 没有_lease_直接拒绝_且不弹窗() {
        let e = env(Some(UserChoice::Once), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        let r = run(&e, &params("a.xlsx", "s-nl"), None).await;
        assert!(!r.ok && r.upload.is_none());
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lease_执行体不符_拒绝() {
        let e = env(Some(UserChoice::Once), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        let mut l = lease(vec![]);
        l.agent_id = Some("wallet--zhangsan".into());
        let r = run(&e, &params("a.xlsx", "s-am"), Some(l)).await;
        assert!(!r.ok);
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn 目录外与穿越_拒绝_且不弹窗() {
        let e = env(Some(UserChoice::Once), None);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("x.xlsx"), b"x").unwrap();
        for p in [outside.path().join("x.xlsx").to_string_lossy().to_string(), "../x.xlsx".to_string()] {
            let r = run(&e, &params(&p, "s-oof"), Some(lease(vec![]))).await;
            assert!(!r.ok && r.upload.is_none(), "{p}");
        }
        assert_eq!(e.asked.load(Ordering::SeqCst), 0, "围栏外不该打扰用户");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 符号链接指向目录外_拒绝() {
        let e = env(Some(UserChoice::Once), None);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("real.xlsx"), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.path().join("real.xlsx"), e.dir.path().join("ln.xlsx")).unwrap();
        let r = run(&e, &params("ln.xlsx", "s-sym"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn 审核12_敏感文件拒绝_不把命中规则名回给模型() {
        let e = env(Some(UserChoice::Once), None);
        std::fs::write(e.dir.path().join(".env"), b"K=V").unwrap();
        let r = run(&e, &params(".env", "s-sens"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
        let err = r.error.unwrap();
        assert_eq!(err, format!("{ERR_PREFIX}: out_of_fence"), "只回粗粒度码：{err}");
        assert!(!err.contains("sensitive") && !err.contains(".env"));
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn 超限_直接拒绝_不弹窗_不读() {
        let e = env(Some(UserChoice::Once), Some("always")); // 即使永久信任
        let f = std::fs::File::create(e.dir.path().join("big.bin")).unwrap();
        f.set_len(upload_gate::effective_limit() + 1).unwrap();
        let r = run(&e, &params("big.bin", "s-big"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
        assert!(r.error.unwrap().contains("too_big"));
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn 目录是目录不是文件_拒绝() {
        let e = env(Some(UserChoice::Once), None);
        std::fs::create_dir(e.dir.path().join("sub")).unwrap();
        let r = run(&e, &params("sub", "s-dir"), Some(lease(vec![]))).await;
        assert!(!r.ok && r.upload.is_none());
    }

    #[tokio::test]
    async fn 永久信任_不弹窗直接放行() {
        let e = env(None, Some("always"));
        std::fs::write(e.dir.path().join("a.xlsx"), b"trusted").unwrap();
        let r = run(&e, &params("a.xlsx", "s-alw"), Some(lease(vec![]))).await;
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(e.asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn 策略文件里偏好写成乱值_按每次问() {
        let e = env(Some(UserChoice::Reject), Some("ALWAYS"));
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        let r = run(&e, &params("a.xlsx", "s-bad"), Some(lease(vec![]))).await;
        assert!(!r.ok);
        assert_eq!(e.asked.load(Ordering::SeqCst), 1, "乱值不能被当成永久放行");
    }

    #[tokio::test]
    async fn 选本会话_后续同会话同目录不再弹_换会话仍弹() {
        let e = env(Some(UserChoice::Session), None);
        std::fs::write(e.dir.path().join("a.xlsx"), b"1").unwrap();
        std::fs::write(e.dir.path().join("b.xlsx"), b"2").unwrap();
        assert!(run(&e, &params("a.xlsx", "s-A"), Some(lease(vec![]))).await.ok);
        assert_eq!(e.asked.load(Ordering::SeqCst), 1);
        assert!(run(&e, &params("b.xlsx", "s-A"), Some(lease(vec![]))).await.ok);
        assert_eq!(e.asked.load(Ordering::SeqCst), 1, "同会话同目录直接放行");
        assert!(run(&e, &params("b.xlsx", "s-B"), Some(lease(vec![]))).await.ok);
        assert_eq!(e.asked.load(Ordering::SeqCst), 2, "换会话必须重新问");
    }

    #[tokio::test]
    async fn 没有弹窗桥_任务上下文缺失_分发器拒绝() {
        // execute_tool 分发：无 UPLOAD_CTX 时必须拒绝而不是放行
        let e = env(Some(UserChoice::Once), Some("always"));
        std::fs::write(e.dir.path().join("a.xlsx"), b"x").unwrap();
        let mgr = crate::daemon::approval::ApprovalManager::new(
            crate::daemon::approval::ApprovalMode::Strict,
            Box::new(crate::daemon::approval::AutoApprover) as Box<dyn crate::daemon::approval::Approver>,
        );
        let r = crate::daemon::tools::execute_tool("local_upload_to_workspace", &params("a.xlsx", "s-nc"), &e.policy, Some(lease(vec![])), NODE, &mgr, &e.audit).await;
        assert!(!r.ok && r.upload.is_none());
        assert!(r.error.unwrap().contains("bridge unavailable"));
    }
}
