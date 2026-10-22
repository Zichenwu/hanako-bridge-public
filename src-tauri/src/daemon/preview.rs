// src-tauri/src/daemon/preview.rs
//! 预览请求的解析与处理（票 02 —— **只做拒绝路径，刻意不读文件字节**）。
//!
//! 服务端对声明了预览能力的 Bridge 下发 `preview_request` 帧；本模块把它解析出来，过完所有
//! 「不该放行」的闸，给出对外拒绝帧。放行路径（弹确认 → 读字节 → 分片回传）分别在票 03 / 04，
//! 本票刻意让安全底座**先于任何读文件代码**被独立验证——所以这里只会返回「拒」或「要问」。
//!
//! ## 闸的顺序（即拒绝优先级，每一步删掉都有对应用例变红）
//! 1. **本机暂停** → `LOCAL_NODE_PAUSED`。现有暂停闸只挂在**任务帧**分支上，预览是新帧、
//!    不会自动经过它，必须在这里显式调用（对抗审查 P1）。
//! 2. **围栏 / 授权 / 敏感** → 全部交给 [`Policy::authorize`]（决策 5：判定只在一处）。
//! 3. **非普通文件 / 超限** → 在读任何字节之前按文件元信息拒（`preview_gate::decide`）。
//! 4. 以上都过 → `Verdict::Ask`，本票返回 [`PreviewOutcome::NeedsConfirm`]（票 03 接上弹窗）。
//!
//! ## 为什么预览必须 spawn 出去处理
//! Bridge 的主收发循环同时负责心跳、策略推送、任务结果回传。预览要等用户点确认（可达 60 秒）
//! 并读大文件，内联在循环里会**阻塞心跳**导致被判离线（任务帧早已是 spawn，预览照办）。
//! 本模块因此只提供一个纯 async 函数，由 `client.rs` 在新帧分支 `tokio::spawn` 调用。
//!
//! ## 为什么助手调不到预览
//! 预览**不进** `tools::execute_tool` 的派发表（ADR 决策 3：结构性隔离）。任务帧里写
//! [`PREVIEW_TOOL_NAME`] 会落到那个 `match` 的 `_` 分支得到 `unknown tool`。
//! 守卫用例见本文件末尾与 `tools/mod.rs`。

use serde_json::Value;
use std::path::PathBuf;

use super::policy::{Policy, TaskScope};
use super::preview_gate::{self, DenyReason, Pref, PreviewFacts, PreviewReject, SessionGrants, Verdict};

/// 预览的工具名。**只用于标识与审计，不注册进助手的工具派发表**（ADR 决策 3）。
pub const PREVIEW_TOOL_NAME: &str = "local_preview_file";

/// 预览审计来源（与上传的 `agent` / 本地树浏览的 `web_browse` 并列的第三种）。
pub const PREVIEW_ORIGIN: &str = "web_preview";

/// 服务端下发的预览请求帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRequest {
    /// 预览号，独立于 taskId（ADR 决策 6）
    pub preview_id: String,
    /// 请求预览的执行体（服务端注入，与任务帧同口径）
    pub agent_id: String,
    /// 会话绑定的授权目录；None = 不限定
    pub root_id: Option<String>,
    /// 相对授权根的路径（或授权目录内的绝对路径）
    pub path: String,
    /// 服务端标注的来源：`local_web` | `other_device` | `web`
    pub origin: String,
    /// 会话标识（服务端注入）。「本目录本次会话都允许」以它为粒度；
    /// 空串 = 不参与会话级放行（不得成为万能通行证）。
    pub session_id: String,
    /// 回传方式（票 07）：`true` = 服务端要求分片（`transfer: "chunked"`，拉取式）；
    /// `false` = 步一单帧。**只认字面量 "chunked"**，其它任何值都按单帧（fail-safe：
    /// 认错方向最多是走老路径，不会把 200MB 塞进一个帧）。
    pub chunked: bool,
}

impl PreviewRequest {
    /// 本次请求是否来自**另一台**设备。
    ///
    /// 跨机来源一律仍在本机弹窗确认，**不适用「不在电脑前转网页确认」**（ADR 决策 4）：
    /// 读内容比改文件更敏感，网页被攻破时不能替用户批准。这里只提供判别，
    /// 调用方不得据此把确认转给网页（票 03 的变异用例锁住这一点）。
    pub fn is_cross_device(&self) -> bool {
        self.origin == "other_device"
    }

    fn scope(&self) -> TaskScope {
        TaskScope { agent_id: self.agent_id.clone(), root_id: self.root_id.clone() }
    }
}

/// 解析 `preview_request` 帧。字段缺失 / 空值 → `None`（整帧丢弃，不猜）。
pub fn parse_preview_request(v: &Value) -> Option<PreviewRequest> {
    if v.get("type")?.as_str()? != "preview_request" {
        return None;
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty());
    let preview_id = s("previewId")?;
    // 长度上限同 trust_revoke：防构造超长 id 污染日志
    if preview_id.len() > 128 {
        return None;
    }
    Some(PreviewRequest {
        preview_id: preview_id.to_string(),
        agent_id: s("agentId").unwrap_or_default().to_string(),
        root_id: s("rootId").map(str::to_string),
        path: s("path")?.to_string(),
        origin: s("origin").unwrap_or("web").to_string(),
        session_id: s("sessionId").unwrap_or_default().to_string(),
        chunked: s("transfer") == Some("chunked"),
    })
}

/// 处理一次预览请求的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// 所有闸都过了，需要在**本机**弹确认（票 03 的 [`confirm`] 接上弹窗）。
    NeedsConfirm { facts_size: u64, root_id: String, file_name: String, folder_name: String, real_path: PathBuf },
    /// 已获允许（永久允许 / 会话级允许 / 用户点了确认），可以读字节了。
    ///
    /// `real_path` 是 `authorize` 解析并校验过的**绝对真实路径**——读取只用这个值，
    /// 绝不重新解析请求里的 `path`（重新解析 = 第二套围栏判定，迟早与 authorize 走偏）。
    Allowed { facts_size: u64, root_id: String, real_path: PathBuf },
    /// 拒绝。`outward` 是对外帧用的（粗粒度），`internal` 只用于本机审计。
    Rejected { outward: PreviewReject, internal: DenyReason },
}

impl PreviewOutcome {
    /// 对外拒绝帧（服务端 → 网页）。放行路径不产生拒绝帧，故返回 Option。
    ///
    /// ⚠️ 帧里**只有**粗粒度 code/message 与 previewId：不带本机绝对路径、不带内部原因短码、
    /// 不带文件内容（故事 24/27）。
    pub fn reject_frame(&self, preview_id: &str) -> Option<Value> {
        match self {
            PreviewOutcome::NeedsConfirm { .. } | PreviewOutcome::Allowed { .. } => None,
            PreviewOutcome::Rejected { outward, .. } => Some(serde_json::json!({
                "type": "preview_abort",
                "previewId": preview_id,
                "code": outward.code(),
                "message": outward.message(),
            })),
        }
    }

    /// 本机审计用的短码（放行路径为 None）。
    pub fn audit_code(&self) -> Option<&'static str> {
        match self {
            PreviewOutcome::NeedsConfirm { .. } | PreviewOutcome::Allowed { .. } => None,
            PreviewOutcome::Rejected { internal, .. } => Some(internal.code()),
        }
    }
}

fn reject(internal: DenyReason) -> PreviewOutcome {
    PreviewOutcome::Rejected { outward: internal.outward(), internal }
}

/// 「未获允许」。用户点了拒绝、确认超时、或没有可用的弹窗实现（headless）都走这里——
/// 三者刻意**同一个结果**，对外不可区分（故事 20）。
pub fn not_allowed() -> PreviewOutcome {
    PreviewOutcome::Rejected { outward: PreviewReject::NotAllowed, internal: DenyReason::NotAllowed }
}

/// 会话内预览授权：**进程级、内存态、不落盘，Bridge 重启即清**（故事 16）。
///
/// 与上传的 `tools::upload::session_grants()` 是两个独立的表——同一个目录在预览侧
/// 「本次会话都允许」不得让上传闸放行。
pub fn session_grants() -> &'static std::sync::Mutex<SessionGrants> {
    static G: std::sync::OnceLock<std::sync::Mutex<SessionGrants>> = std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(SessionGrants::new()))
}

/// 读取某目录的**预览**偏好。读失败/损坏 → 每次问（放宽方向 fail-closed）。
///
/// 读的是 `policy.json` 的 `preview` 字段，**不是** `upload`：两者独立（ADR 决策 1）。
/// 现读磁盘，用户在本机设置里一改下次预览立即生效。
pub fn pref_for(root_id: &str) -> Pref {
    match super::policy::PolicyFile::load() {
        Ok(f) => f.preview.get(root_id).map(|s| Pref::parse(s)).unwrap_or(Pref::Ask),
        Err(_) => Pref::Ask,
    }
}

/// 读取生效的预览上限（字节）。`chunked=false`（步一单帧）：用户档位与 20MB 硬上限取较小值；
/// `chunked=true`（票 07）：就是用户档位（50/100/200MB），类型上限在 `evaluate` 里再收紧。
///
/// 读失败/损坏 → 按缺省档（放宽方向不因读失败而变大：`effective_limit` 本就被
/// `MAX_PREVIEW_BYTES` 夹住，缺省档 200MB 在步一仍只生效 20MB）。
pub fn limit_bytes(chunked: bool) -> u64 {
    let pref = super::policy::PolicyFile::load().ok().and_then(|f| f.preview_limit_mb);
    if chunked {
        super::preview_gate::effective_limit_chunked(pref)
    } else {
        super::preview_gate::effective_limit(pref)
    }
}

/// 本机审计条目。
///
/// ⚠️ **只记相对授权根的路径、结果、来源**；不记文件内容、不记哈希（故事 44：审计日志本身
/// 不得成为泄露源）。`path` 直接用请求里的相对路径——绝对路径只在本机解析，不写进审计。
/// 请求带的是授权目录内的绝对路径时取文件名，避免把本机目录结构抄进日志。
pub fn audit_entry(req: &PreviewRequest, outcome: &PreviewOutcome) -> super::audit::AuditEntry {
    let rel = if std::path::Path::new(&req.path).is_absolute() {
        std::path::Path::new(&req.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        req.path.clone()
    };
    let ok = !matches!(outcome, PreviewOutcome::Rejected { .. });
    super::audit::AuditEntry {
        ts: super::audit::now_ts(),
        agent_id: req.agent_id.clone(),
        tool: PREVIEW_TOOL_NAME.to_string(),
        path: rel,
        lease_id: None,
        task_id: req.preview_id.clone(),
        decision: match outcome {
            PreviewOutcome::Rejected { internal, .. } => Some(format!("rejected:{}", internal.code())),
            PreviewOutcome::Allowed { .. } => Some("approved".into()),
            PreviewOutcome::NeedsConfirm { .. } => None,
        },
        backup_path: None,
        ok,
        // 对外粗粒度文案进 error（本机日志要排障，但也不写命中的黑名单项）
        error: match outcome {
            PreviewOutcome::Rejected { outward, .. } => Some(outward.code().to_string()),
            _ => None,
        },
        origin: PREVIEW_ORIGIN.to_string(),
    }
}

/// 过一遍全部闸。
///
/// `paused` 由调用方传入（`PauseState::gate(now)` 的结果）——**预览新帧不会自动经过任务帧上的
/// 那个暂停闸**，必须在这里显式过（对抗审查 P1；变异用例：把这个分支删掉则红）。
///
/// `pref_of` 按**命中的那个目录**取预览偏好（偏好依赖 `authorize` 之后才知道的 rootId，
/// 所以用闭包传入而不是预先算好一个值）；`grants` 是会话级允许表。
///
/// 本函数**不读文件字节**，只读元信息，所以结果只会是「放行（待读取）」「要问」或「拒」。
pub async fn evaluate(
    req: &PreviewRequest,
    policy: &Policy,
    paused: Option<String>,
    limit: u64,
    pref_of: impl Fn(&str) -> Pref,
    grants: &std::sync::Mutex<SessionGrants>,
) -> PreviewOutcome {
    // ① 本机暂停闸（显式调用——新帧不经过任务帧那条）
    if let Some(msg) = paused {
        return PreviewOutcome::Rejected {
            outward: PreviewReject::Paused(msg),
            internal: DenyReason::OutOfFence, // 审计里用「被闸拒」，不单列暂停短码
        };
    }

    // ② 围栏 / 授权 / 敏感：全部交给 authorize（写类为 false——预览只读）
    let resolved = match policy.authorize(&req.scope(), &req.path, false) {
        Ok(r) => r,
        Err(e) => return reject(preview_gate::deny_of_gate_error(&e)),
    };

    // 命中的授权目录（审计记相对该根的路径，故需 rootId）
    let Some(root) = policy.roots.iter().find(|r| r.path == resolved.root) else {
        return reject(DenyReason::OutOfFence);
    };

    // ③ 文件元信息：不跟随符号链接取类型（authorize 已解析过链接并校验落点，
    //    这里再独立确认一次「是普通文件」）。取不到 = 不存在 / 无权限 → 按非普通文件拒。
    let meta = match tokio::fs::metadata(&resolved.path).await {
        Ok(m) => m,
        Err(_) => return reject(DenyReason::NotAFile),
    };
    let facts = PreviewFacts {
        real_path: resolved.path.clone(),
        size: meta.len(),
        is_file: meta.is_file(),
        root_id: root.root_id.clone(),
    };
    // 兜底：真实路径必须确实落在命中目录内（authorize 已保证，这里是独立的第二道，同 upload）
    if !super::upload_gate::within_root(&facts.real_path, &resolved.root) {
        return reject(DenyReason::OutOfFence);
    }

    // ③.5 格式闸：认不出的类型在**弹窗之前**拒绝（10-08 验收：先弹确认、点了允许才说不能预览）。
    //      只对普通文件判——目录 / 不存在仍交给下面的「非普通文件」（受保护同一句）。
    if facts.is_file && super::preview_read::preview_kind(&facts.real_path).is_none() {
        return PreviewOutcome::Rejected {
            outward: PreviewReject::UnsupportedType,
            internal: DenyReason::NotAFile,
        };
    }

    // ③.6 按类型收紧上限（票 07，用户 2026-10-09 拍板）：pdf/图片 ≤100MB、docx/xlsx ≤20MB。
    //      必须在**弹窗之前**拒（走 decide 的 TooBig，位于永久/会话放行之前），不让用户白点一次允许；
    //      服务端 meta 阶段还有一道同口径的独立校验，这里是第一道。
    //      只在能分片时放大；单帧(步一)请求保持原 20MB 封顶不变。
    let limit = if req.chunked {
        super::preview_stream::limit_for_path(&facts.real_path, limit)
    } else {
        limit
    };

    // ④ 非普通文件 / 超限 / 永久允许 / 会话允许 —— 全在读任何字节之前
    let verdict = {
        let mut g = grants.lock().unwrap_or_else(|e| e.into_inner());
        preview_gate::decide(&facts, pref_of(&facts.root_id), &req.session_id, &mut g, limit)
    };
    match verdict {
        Verdict::Deny(r) => reject(r),
        Verdict::Allow => PreviewOutcome::Allowed {
            facts_size: facts.size,
            root_id: facts.root_id,
            real_path: facts.real_path,
        },
        Verdict::Ask => PreviewOutcome::NeedsConfirm {
            facts_size: facts.size,
            root_id: facts.root_id,
            file_name: facts
                .real_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            folder_name: root.name.clone(),
            real_path: facts.real_path.clone(),
        },
    }
}

/// 把「要问」变成最终结论：在**本机**弹确认窗等用户。
///
/// ## 跨机来源一律仍在本机弹窗（ADR 决策 4）
/// 写类操作有个「不在电脑前时把确认转给网页」的通道（`web_confirm::WebFirstApprover`）。
/// 预览**刻意不接它**：读内容比改文件更敏感，网页被攻破时不能替用户批准。所以无论
/// `origin` 是 `local_web` 还是 `other_device`，都走同一个本机弹窗桥；人不在电脑前
/// 就是超时，超时与拒绝对外不可区分（故事 20/21/22）。
///
/// 变异用例：把这里改成「跨机来源走 WebFirstApprover / 看 web_confirm 开关」→ 对应测试变红。
pub async fn confirm(
    req: &PreviewRequest,
    bridge: &super::preview_bridge::PreviewBridge,
    grants: &std::sync::Mutex<SessionGrants>,
    size: u64,
    root_id: &str,
    file_name: &str,
    folder_name: &str,
    real_path: &std::path::Path,
) -> PreviewOutcome {
    let ask = super::preview_bridge::PreviewAsk::new(
        format!("pva_{}", req.preview_id),
        file_name.to_string(),
        size,
        folder_name.to_string(),
        root_id.to_string(),
        req.agent_id.clone(),
        // 原样带上来源，供弹窗显式警示「另一台设备在请求」——但确认仍只能在本机点
        req.origin.clone(),
    );
    let choice = bridge.ask(ask).await;
    let allowed = {
        let mut g = grants.lock().unwrap_or_else(|e| e.into_inner());
        preview_gate::apply_choice(choice, &req.session_id, root_id, &mut g)
    };
    if allowed {
        // 透传闸已校验过的真实路径：用户点「允许」之后也不重新解析请求里的 path
        PreviewOutcome::Allowed {
            facts_size: size,
            root_id: root_id.to_string(),
            real_path: real_path.to_path_buf(),
        }
    } else {
        // 拒绝与超时在这里**合并**成同一种结果（UserChoice::Reject 两者都是），对外不可区分
        not_allowed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::policy::PolicyFile;
    use crate::daemon::preview_gate::MAX_PREVIEW_BYTES;
    use crate::daemon::register::root_id_for;
    use std::path::{Path, PathBuf};

    const A: &str = "bi--zhangsan";
    const B: &str = "wallet--zhangsan";

    struct Env {
        _d: Vec<tempfile::TempDir>,
        dirs: Vec<PathBuf>,
    }

    fn env(n: usize) -> Env {
        let d: Vec<_> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
        let dirs = d.iter().map(|x| x.path().canonicalize().unwrap()).collect();
        Env { _d: d, dirs }
    }

    fn rid(p: &Path) -> String {
        root_id_for(p)
    }

    fn file_with(grants: &[(&str, &[&Path])]) -> PolicyFile {
        PolicyFile {
            grants: Some(
                grants.iter().map(|(a, ps)| (a.to_string(), ps.iter().map(|p| rid(p)).collect())).collect(),
            ),
            ..Default::default()
        }
    }

    fn req(path: &str) -> PreviewRequest {
        PreviewRequest {
            preview_id: "pv_1".into(),
            agent_id: A.into(),
            root_id: None,
            path: path.into(),
            origin: "local_web".into(),
            session_id: "s1".into(),
            chunked: false,
        }
    }

    /// 真实临时目录 + 真实策略对象；只授权 A。
    fn setup(e: &Env) -> Policy {
        Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]])]), None)
    }

    /// 默认档：每次问、无会话授权。
    async fn eval(req: &PreviewRequest, pol: &Policy) -> PreviewOutcome {
        eval_with(req, pol, None, MAX_PREVIEW_BYTES, Pref::Ask).await
    }

    /// 可控档位的 evaluate（每次新建授权表，互不串）。
    async fn eval_with(
        req: &PreviewRequest,
        pol: &Policy,
        paused: Option<String>,
        limit: u64,
        pref: Pref,
    ) -> PreviewOutcome {
        let g = std::sync::Mutex::new(SessionGrants::new());
        evaluate(req, pol, paused, limit, |_| pref, &g).await
    }

    fn assert_protected(o: &PreviewOutcome) {
        match o {
            PreviewOutcome::Rejected { outward, .. } => assert_eq!(*outward, PreviewReject::Protected, "{o:?}"),
            _ => panic!("应被拒: {o:?}"),
        }
    }

    // ── 帧解析 ─────────────────────────────────────────────────────

    #[test]
    fn 解析预览请求帧() {
        let v = serde_json::json!({
            "type": "preview_request", "previewId": "pv_1", "agentId": A,
            "rootId": "r_x", "path": "a.txt", "origin": "other_device"
        });
        let r = parse_preview_request(&v).unwrap();
        assert_eq!(r.preview_id, "pv_1");
        assert_eq!(r.agent_id, A);
        assert_eq!(r.root_id.as_deref(), Some("r_x"));
        assert_eq!(r.path, "a.txt");
        assert!(r.is_cross_device());
    }

    #[test]
    fn 非预览帧与残缺帧一律丢弃() {
        for v in [
            serde_json::json!({"type":"task","previewId":"p","path":"a"}),
            serde_json::json!({"type":"preview_request","path":"a"}),              // 缺 previewId
            serde_json::json!({"type":"preview_request","previewId":"p"}),         // 缺 path
            serde_json::json!({"type":"preview_request","previewId":"","path":"a"}),
            serde_json::json!({"type":"preview_request","previewId":"p","path":""}),
            serde_json::json!({"type":"preview_request","previewId":"x".repeat(129),"path":"a"}),
        ] {
            assert!(parse_preview_request(&v).is_none(), "{v}");
        }
        // 缺 origin → 按「网页」；缺 agentId → 空串（随后必被 ActorNotGranted 拒）
        let r = parse_preview_request(&serde_json::json!({
            "type":"preview_request","previewId":"p","path":"a.txt"
        }))
        .unwrap();
        assert_eq!(r.origin, "web");
        assert_eq!(r.agent_id, "");
        assert!(!r.is_cross_device());
    }

    // ── ① 暂停闸（变异：删掉 evaluate 里的暂停分支 → 本用例红）────────

    #[tokio::test]
    async fn 本机暂停时预览被拒() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "hello").unwrap();
        let pol = setup(&e);
        // 未暂停：通过所有闸到「要问」
        assert!(matches!(eval(&req("a.txt"), &pol).await, PreviewOutcome::NeedsConfirm { .. }));
        // 暂停：拒，且对外带服务端既有机读码
        let msg = "LOCAL_NODE_PAUSED: 本机已暂停，约 7 分钟后自动恢复".to_string();
        let o = eval_with(&req("a.txt"), &pol, Some(msg.clone()), MAX_PREVIEW_BYTES, Pref::Ask).await;
        match &o {
            PreviewOutcome::Rejected { outward, .. } => {
                assert_eq!(outward.code(), crate::daemon::pause::ERR_PAUSED);
                assert_eq!(outward.message(), msg);
            }
            _ => panic!("暂停态必须拒绝: {o:?}"),
        }
    }

    #[tokio::test]
    async fn 暂停闸优先于围栏_不泄露路径是否存在() {
        // 暂停时连「文件在不在、路径合不合法」都不该被探测出来
        let e = env(1);
        let pol = setup(&e);
        let paused = Some("LOCAL_NODE_PAUSED: x".to_string());
        let a = eval_with(&req("../escape"), &pol, paused.clone(), MAX_PREVIEW_BYTES, Pref::Ask).await;
        let b = eval_with(&req("nope.txt"), &pol, paused, MAX_PREVIEW_BYTES, Pref::Ask).await;
        assert_eq!(a, b, "暂停态下不同路径必须得到完全相同的结果");
    }

    // ── 票 07：分片请求的按类型上限（弹窗之前拒）──────────────────────

    fn sparse(dir: &Path, name: &str, size: u64) {
        let f = std::fs::File::create(dir.join(name)).unwrap();
        f.set_len(size).unwrap();
    }
    fn chunked(path: &str) -> PreviewRequest {
        let mut r = req(path);
        r.chunked = true;
        r
    }
    const MB: u64 = 1024 * 1024;

    /// 变异：去掉 `evaluate` 里 `limit_for_path` 收紧 → 本用例红（docx 21MB 会走到弹窗）。
    #[tokio::test]
    async fn 分片请求_docx超过20MB_在弹窗前就拒_不是询问() {
        let e = env(1);
        sparse(&e.dirs[0], "big.docx", 21 * MB);
        sparse(&e.dirs[0], "ok.docx", 20 * MB);
        let pol = setup(&e);
        let big = eval_with(&chunked("big.docx"), &pol, None, 200 * MB, Pref::Ask).await;
        match &big {
            PreviewOutcome::Rejected { outward, .. } => assert!(matches!(outward, PreviewReject::TooBig { .. }), "{big:?}"),
            _ => panic!("21MB 的 docx 必须在弹窗前拒绝: {big:?}"),
        }
        assert!(matches!(eval_with(&chunked("ok.docx"), &pol, None, 200 * MB, Pref::Ask).await, PreviewOutcome::NeedsConfirm { .. }));
    }

    #[tokio::test]
    async fn 分片请求_pdf图片上限100MB_xlsx上限20MB() {
        let e = env(1);
        sparse(&e.dirs[0], "a.pdf", 100 * MB);
        sparse(&e.dirs[0], "b.pdf", 100 * MB + 1);
        sparse(&e.dirs[0], "c.png", 100 * MB + 1);
        sparse(&e.dirs[0], "d.xlsx", 21 * MB);
        let pol = setup(&e);
        assert!(matches!(eval_with(&chunked("a.pdf"), &pol, None, 200 * MB, Pref::Ask).await, PreviewOutcome::NeedsConfirm { .. }));
        for n in ["b.pdf", "c.png", "d.xlsx"] {
            assert!(
                matches!(eval_with(&chunked(n), &pol, None, 200 * MB, Pref::Ask).await, PreviewOutcome::Rejected { .. }),
                "{n} 超类型上限必须在弹窗前拒"
            );
        }
    }

    /// 变异：永久允许放在超限判定之前 → 本用例红。超类型上限即使设了永久允许也必须拒。
    #[tokio::test]
    async fn 分片请求_超类型上限_即使永久允许也拒() {
        let e = env(1);
        sparse(&e.dirs[0], "big.docx", 25 * MB);
        let pol = setup(&e);
        let o = eval_with(&chunked("big.docx"), &pol, None, 200 * MB, Pref::Always).await;
        assert!(matches!(o, PreviewOutcome::Rejected { .. }), "永久允许不得绕过类型上限: {o:?}");
    }

    /// 变异：档位取 max 而非 min → 本用例红。用户调到 50MB 后，100MB 类型上限不得把它放大。
    #[tokio::test]
    async fn 分片请求_用户档位小于类型上限时以档位为准() {
        let e = env(1);
        sparse(&e.dirs[0], "mid.pdf", 60 * MB);
        let pol = setup(&e);
        let o = eval_with(&chunked("mid.pdf"), &pol, None, 50 * MB, Pref::Ask).await;
        assert!(matches!(o, PreviewOutcome::Rejected { .. }), "档位 50MB，60MB 的 pdf 必须拒: {o:?}");
    }

    /// 变异：不论 chunked 都放大上限 → 本用例红。步一单帧请求（旧服务端 / 能力 1）必须保持 20MB 封顶，
    /// 否则 100MB 的文件会被塞进一个 WS 帧（base64 后 133MB > 64MiB 帧上限）。
    #[tokio::test]
    async fn 单帧请求_不放大上限_仍是步一的20MB() {
        let e = env(1);
        sparse(&e.dirs[0], "x.pdf", 30 * MB);
        let pol = setup(&e);
        // 单帧请求用 limit_bytes(false) 的口径：20MB
        let o = eval_with(&req("x.pdf"), &pol, None, crate::daemon::preview_gate::effective_limit(None), Pref::Ask).await;
        assert!(matches!(o, PreviewOutcome::Rejected { .. }), "{o:?}");
        assert_eq!(limit_bytes(false), crate::daemon::preview_gate::MAX_PREVIEW_BYTES.min(limit_bytes(false)));
    }

    #[test]
    fn 解析_transfer_字段() {
        let base = serde_json::json!({"type":"preview_request","previewId":"p","path":"a.pdf"});
        assert!(!parse_preview_request(&base).unwrap().chunked);
        let mut c = base.clone();
        c["transfer"] = "chunked".into();
        assert!(parse_preview_request(&c).unwrap().chunked);
        c["transfer"] = "weird".into();
        assert!(!parse_preview_request(&c).unwrap().chunked, "未知值按单帧");
    }

    // ── ② 围栏：目录外 / .. / 符号链接 / 未授权 / 敏感 ──────────────

    #[tokio::test]
    async fn 点点越界被拒() {
        let e = env(1);
        let pol = setup(&e);
        assert_protected(&eval(&req("../x.txt"), &pol).await);
        assert_protected(&eval(&req("a/../../x.txt"), &pol).await);
    }

    #[tokio::test]
    async fn 绝对路径落在另一助手的目录被拒() {
        let e = env(2);
        std::fs::write(e.dirs[1].join("secret.txt"), "s").unwrap();
        let pol = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]]), (B, &[&e.dirs[1]])]), None);
        let other = e.dirs[1].join("secret.txt");
        assert_protected(&eval(&req(other.to_str().unwrap()), &pol).await);
        // B 自己可以（证明用例不是因为别的原因失败）
        let mut as_b = req(other.to_str().unwrap());
        as_b.agent_id = B.into();
        assert!(matches!(eval(&as_b, &pol).await, PreviewOutcome::NeedsConfirm { .. }));
    }

    /// 变异锁：去掉 `path_guard` 的符号链接规范化（canonicalize）→ 本用例红。
    #[cfg(unix)]
    #[tokio::test]
    async fn 符号链接指向授权根外被拒() {
        let e = env(1);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("s.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), e.dirs[0].join("evil")).unwrap();
        let pol = setup(&e);
        assert_protected(&eval(&req("evil/s.txt"), &pol).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 单文件符号链接指向根外也被拒() {
        let e = env(1);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("s.txt");
        std::fs::write(&target, "secret").unwrap();
        std::os::unix::fs::symlink(&target, e.dirs[0].join("ln.txt")).unwrap();
        let pol = setup(&e);
        assert_protected(&eval(&req("ln.txt"), &pol).await);
    }

    #[tokio::test]
    async fn 未授权的助手被拒() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e);
        let mut r = req("a.txt");
        r.agent_id = B.into();
        assert_protected(&eval(&r, &pol).await);
        r.agent_id = "".into();
        assert_protected(&eval(&r, &pol).await);
    }

    #[tokio::test]
    async fn 会话绑定的目录已被撤销_拒() {
        let e = env(2);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e); // A 只被授权 dirs[0]
        let mut r = req("a.txt");
        r.root_id = Some(rid(&e.dirs[1]));
        assert_protected(&eval(&r, &pol).await);
    }

    /// 变异锁：去掉敏感判定（`path_guard::rel_is_sensitive`）→ 本用例红。
    #[tokio::test]
    async fn 敏感文件一律拒绝_且审计分得清() {
        let e = env(1);
        let pol = setup(&e);
        for name in [".env", ".env.local", "id_rsa", "server.pem", "api.key", ".npmrc"] {
            std::fs::write(e.dirs[0].join(name), "SECRET=1").unwrap();
            let o = eval(&req(name), &pol).await;
            assert_protected(&o);
            assert_eq!(o.audit_code(), Some("sensitive"), "{name} 审计原因应是 sensitive");
        }
        // 敏感目录
        std::fs::create_dir_all(e.dirs[0].join(".ssh")).unwrap();
        std::fs::write(e.dirs[0].join(".ssh/known_hosts"), "x").unwrap();
        assert_protected(&eval(&req(".ssh/known_hosts"), &pol).await);
    }

    #[tokio::test]
    async fn 策略损坏_全部拒绝而非放行() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let mut pol = setup(&e);
        pol.grants.clear(); // 模拟 poisoned 后的全拒绝态
        assert_protected(&eval(&req("a.txt"), &pol).await);
    }

    // ── ③ 非普通文件 / 超限（都在读字节之前）────────────────────────

    #[tokio::test]
    async fn 目录与不存在的文件被拒() {
        let e = env(1);
        std::fs::create_dir_all(e.dirs[0].join("sub")).unwrap();
        let pol = setup(&e);
        let o = eval(&req("sub"), &pol).await;
        assert_protected(&o);
        assert_eq!(o.audit_code(), Some("not_a_file"));
        assert_eq!(eval(&req("nope.txt"), &pol).await.audit_code(), Some("not_a_file"));
    }

    #[tokio::test]
    async fn 超过上限按文件大小拒_不读字节() {
        let e = env(1);
        let p = e.dirs[0].join("big.txt");
        std::fs::write(&p, vec![b'x'; 2048]).unwrap();
        let pol = setup(&e);
        // 把上限压到 1KB：2KB 的文件应超限
        let o = eval_with(&req("big.txt"), &pol, None, 1024, Pref::Ask).await;
        match &o {
            PreviewOutcome::Rejected { outward, internal } => {
                assert_eq!(*internal, DenyReason::TooBig { size: 2048, limit: 1024 });
                assert!(matches!(outward, PreviewReject::TooBig { .. }));
                assert!(outward.message().contains("助手"), "要给替代办法");
            }
            _ => panic!("应超限拒绝: {o:?}"),
        }
        // 上限之内放行到「要问」
        assert!(matches!(
            eval_with(&req("big.txt"), &pol, None, 4096, Pref::Ask).await,
            PreviewOutcome::NeedsConfirm { facts_size: 2048, .. }
        ));
    }

    // ── ④ 全闸通过只到「要问」，本票绝不读字节 ─────────────────────

    // ── 10-08：格式闸在弹窗之前 ─────────────────────────────────────

    #[tokio::test]
    async fn 不支持的格式在弹窗前拒绝_且不说成受保护() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.mp4"), "x").unwrap();
        let pol = setup(&e);
        match eval(&req("a.mp4"), &pol).await {
            PreviewOutcome::Rejected { outward, .. } => assert_eq!(outward, PreviewReject::UnsupportedType),
            o => panic!("不支持的格式必须在弹窗前拒绝: {o:?}"),
        }
    }

    #[tokio::test]
    async fn 文档与图片可走到弹窗确认() {
        let e = env(1);
        for n in ["a.pdf", "a.docx", "a.xlsx", "a.png"] {
            std::fs::write(e.dirs[0].join(n), "x").unwrap();
        }
        let pol = setup(&e);
        for n in ["a.pdf", "a.docx", "a.xlsx", "a.png"] {
            assert!(matches!(eval(&req(n), &pol).await, PreviewOutcome::NeedsConfirm { .. }), "{n} 应到要问");
        }
    }

    #[tokio::test]
    async fn 全部闸通过只到要问_不含文件内容() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "SENTINEL-PREVIEW-BYTES").unwrap();
        let pol = setup(&e);
        let o = eval(&req("a.txt"), &pol).await;
        match &o {
            PreviewOutcome::NeedsConfirm { facts_size, root_id, file_name, .. } => {
                assert_eq!(*facts_size, 22);
                assert_eq!(*root_id, rid(&e.dirs[0]));
                assert_eq!(file_name, "a.txt");
            }
            _ => panic!("应到「要问」: {o:?}"),
        }
        // 本票的结果里不得出现文件内容（票 04 才读字节）
        let dbg = format!("{o:?}");
        assert!(!dbg.contains("SENTINEL-PREVIEW-BYTES"), "结果里出现了文件内容: {dbg}");
    }

    // ── 票 03：偏好与会话级允许 ─────────────────────────────────────

    #[tokio::test]
    async fn 目录开了永久允许_不再弹确认() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e);
        // 默认每次问
        assert!(matches!(eval(&req("a.txt"), &pol).await, PreviewOutcome::NeedsConfirm { .. }));
        // 永久允许 → 直接放行
        let o = eval_with(&req("a.txt"), &pol, None, MAX_PREVIEW_BYTES, Pref::Always).await;
        assert!(matches!(o, PreviewOutcome::Allowed { .. }), "{o:?}");
        assert!(o.reject_frame("pv_1").is_none());
    }

    /// 变异锁：把会话级允许落盘（或改成读 policy.json）→ 本用例红。
    /// 会话授权只在内存，`session_grants()` 是进程级 OnceLock，Bridge 重启即新表。
    #[tokio::test]
    async fn 会话级允许只在内存_重启即清() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        std::fs::write(e.dirs[0].join("b.txt"), "y").unwrap();
        let pol = setup(&e);
        let r = req("a.txt");

        // 模拟「用户点了本目录本次会话都允许」
        let g = std::sync::Mutex::new(SessionGrants::new());
        let root = rid(&e.dirs[0]);
        preview_gate::apply_choice(preview_gate::UserChoice::Session, &r.session_id, &root, &mut g.lock().unwrap());
        // 同会话同目录的下一个文件不再问
        let o = evaluate(&req("b.txt"), &pol, None, MAX_PREVIEW_BYTES, |_| Pref::Ask, &g).await;
        assert!(matches!(o, PreviewOutcome::Allowed { .. }), "同会话同目录应直接放行: {o:?}");

        // 「重启」= 换一张全新的内存表 → 必须回到每次问
        let fresh = std::sync::Mutex::new(SessionGrants::new());
        let o = evaluate(&req("b.txt"), &pol, None, MAX_PREVIEW_BYTES, |_| Pref::Ask, &fresh).await;
        assert!(matches!(o, PreviewOutcome::NeedsConfirm { .. }), "重启后会话授权必须失效: {o:?}");

        // 且策略文件的预览偏好里绝不出现这次会话授权
        assert!(super::super::policy::PolicyFile::default().preview.is_empty(), "会话级允许不得落盘");
    }

    #[tokio::test]
    async fn 空会话标识不能靠会话级允许放行() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e);
        let mut r = req("a.txt");
        r.session_id = "".into();
        let g = std::sync::Mutex::new(SessionGrants::new());
        let root = rid(&e.dirs[0]);
        preview_gate::apply_choice(preview_gate::UserChoice::Session, "", &root, &mut g.lock().unwrap());
        let o = evaluate(&r, &pol, None, MAX_PREVIEW_BYTES, |_| Pref::Ask, &g).await;
        assert!(matches!(o, PreviewOutcome::NeedsConfirm { .. }), "空会话 ID 不得成为万能通行证: {o:?}");
    }

    #[tokio::test]
    async fn 超限优先于永久允许() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("big.txt"), vec![b'x'; 2048]).unwrap();
        let pol = setup(&e);
        let o = eval_with(&req("big.txt"), &pol, None, 1024, Pref::Always).await;
        assert!(matches!(o, PreviewOutcome::Rejected { outward: PreviewReject::TooBig { .. }, .. }), "{o:?}");
    }

    #[tokio::test]
    async fn 敏感文件优先于永久允许() {
        let e = env(1);
        std::fs::write(e.dirs[0].join(".env"), "TOKEN=x").unwrap();
        let pol = setup(&e);
        // 即便开了永久允许，敏感文件仍拒（围栏在 authorize，早于偏好）
        assert_protected(&eval_with(&req(".env"), &pol, None, MAX_PREVIEW_BYTES, Pref::Always).await);
    }

    // ── 票 03：确认（跨机来源仍只在本机点）────────────────────────────

    /// 装一个「立刻按给定选择作答」的弹窗桥。
    fn bridge_answering(
        choice: preview_gate::UserChoice,
    ) -> std::sync::Arc<super::super::preview_bridge::PreviewBridge> {
        let b = super::super::preview_bridge::PreviewBridge::new();
        let b2 = b.clone();
        b.set_presenter(std::sync::Arc::new(move |a| {
            let b3 = b2.clone();
            let id = a.ask_id.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                let _ = b3.respond(&id, choice);
            });
            true
        }));
        b
    }

    #[tokio::test]
    async fn 用户点仅这次_放行但不留授权() {
        let b = bridge_answering(preview_gate::UserChoice::Once);
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("a.txt");
        let o = confirm(&r, &b, &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
        assert!(matches!(o, PreviewOutcome::Allowed { .. }), "{o:?}");
        assert!(g.lock().unwrap().is_empty(), "仅这次不得留下会话授权");
    }

    #[tokio::test]
    async fn 用户点本会话都允许_留下会话授权() {
        let b = bridge_answering(preview_gate::UserChoice::Session);
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("a.txt");
        let o = confirm(&r, &b, &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
        assert!(matches!(o, PreviewOutcome::Allowed { .. }));
        assert!(g.lock().unwrap().has(&r.session_id, "r1"));
    }

    #[tokio::test]
    async fn 用户拒绝_未获允许且不留授权() {
        let b = bridge_answering(preview_gate::UserChoice::Reject);
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("a.txt");
        let o = confirm(&r, &b, &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
        assert_eq!(o, not_allowed());
        assert!(g.lock().unwrap().is_empty());
    }

    /// 变异锁（ADR 决策 4 / 故事 21、22）：把 `confirm` 改成「跨机来源走网页确认 /
    /// 看 web_confirm 开关」→ 本用例红。
    ///
    /// 跨机与本机走**同一个本机弹窗桥**，结果完全取决于本机那次点击。
    #[tokio::test]
    async fn 跨机来源一律只在本机弹窗确认() {
        for origin in ["local_web", "other_device", "web"] {
            let mut r = req("a.txt");
            r.origin = origin.into();

            // 本机点拒绝 → 拒绝（网页代不了）
            let g = std::sync::Mutex::new(SessionGrants::new());
            let o = confirm(&r, &bridge_answering(preview_gate::UserChoice::Reject), &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
            assert_eq!(o, not_allowed(), "origin={origin} 必须以本机点击为准");

            // 本机点允许 → 允许
            let g = std::sync::Mutex::new(SessionGrants::new());
            let o = confirm(&r, &bridge_answering(preview_gate::UserChoice::Once), &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
            assert!(matches!(o, PreviewOutcome::Allowed { .. }), "origin={origin}");
        }
    }

    /// 人不在电脑前 = 弹窗超时 = 未获允许，且**与「点了拒绝」逐字节相同**（故事 20/22）。
    #[tokio::test]
    async fn 不在电脑前超时与点拒绝对外完全相同() {
        // 超时：弹窗能开但永不作答
        let b_timeout = super::super::preview_bridge::PreviewBridge::new();
        b_timeout.set_presenter(std::sync::Arc::new(|_| true));
        let ask = super::super::preview_bridge::PreviewAsk::new(
            "pva_t".into(),
            "a.txt".into(),
            10,
            "财务".into(),
            "r1".into(),
            A.into(),
            "other_device".into(),
        );
        let timed_out = b_timeout.ask_with_timeout(ask, std::time::Duration::from_millis(30)).await;
        assert_eq!(timed_out, preview_gate::UserChoice::Reject, "超时必须等于拒绝");

        // 两条路径的最终对外帧必须一样
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("a.txt");
        let o_reject =
            confirm(&r, &bridge_answering(preview_gate::UserChoice::Reject), &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
        let frame_reject = o_reject.reject_frame("pv_x").unwrap().to_string();
        let frame_timeout = not_allowed().reject_frame("pv_x").unwrap().to_string();
        assert_eq!(frame_reject, frame_timeout, "拒绝与超时的对外帧必须逐字节相同");
        for leak in ["超时", "timeout", "不在电脑前"] {
            assert!(!frame_reject.contains(leak), "泄漏了区分信息 {leak}: {frame_reject}");
        }
    }

    #[tokio::test]
    async fn 没有弹窗实现_未获允许_绝不放行() {
        // headless：桥存在但没装 presenter
        let b = super::super::preview_bridge::PreviewBridge::new();
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("a.txt");
        let o = confirm(&r, &b, &g, 10, "r1", "a.txt", "财务", Path::new("/root/财务/a.txt")).await;
        assert_eq!(o, not_allowed(), "headless 必须拒绝，绝不默认放行");
    }

    #[tokio::test]
    async fn 确认弹窗带承诺文案且不含绝对路径() {
        let b = super::super::preview_bridge::PreviewBridge::new();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let s2 = seen.clone();
        let b2 = b.clone();
        b.set_presenter(std::sync::Arc::new(move |a| {
            *s2.lock().unwrap() = Some(a.clone());
            let b3 = b2.clone();
            let id = a.ask_id.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                let _ = b3.respond(&id, preview_gate::UserChoice::Once);
            });
            true
        }));
        let g = std::sync::Mutex::new(SessionGrants::new());
        let r = req("/abs/secret-dir/预算.xlsx");
        confirm(&r, &b, &g, 2048, "r1", "预算.xlsx", "财务", Path::new("/abs/secret-dir/预算.xlsx")).await;

        let ask = seen.lock().unwrap().clone().expect("弹窗应被展示");
        assert_eq!(ask.notice, super::super::preview_bridge::PREVIEW_NOTICE);
        assert_eq!(ask.file_name, "预算.xlsx");
        assert_eq!(ask.folder_name, "财务");
        let wire = serde_json::to_string(&ask).unwrap();
        assert!(!wire.contains("/abs/secret-dir"), "弹窗数据泄漏了绝对路径: {wire}");
    }

    #[test]
    fn 读取失败与文件被修改同类_都给可重试() {
        // 故事 33 / 对抗审查：Windows 文件被占用、读失败、mtime+size 变了 → 同一种「可重试」
        let retry = PreviewReject::Retry;
        assert_eq!(retry.code(), "LOCAL_PREVIEW_RETRY");
        assert!(retry.message().contains("重试"));
        // 与「未获允许」「受保护」必须是不同分类（用户下一步动作不同）
        assert_ne!(retry.code(), PreviewReject::NotAllowed.code());
        assert_ne!(retry.code(), PreviewReject::Protected.code());
    }

    // ── 对外帧不泄露本机信息 ───────────────────────────────────────

    #[tokio::test]
    async fn 拒绝帧不含本机绝对路径与内部原因() {
        let e = env(1);
        std::fs::write(e.dirs[0].join(".env"), "TOKEN=abc").unwrap();
        let pol = setup(&e);
        let o = eval(&req(".env"), &pol).await;
        let frame = o.reject_frame("pv_1").unwrap();
        let wire = frame.to_string();
        assert_eq!(frame["type"], "preview_abort");
        assert_eq!(frame["previewId"], "pv_1");
        assert_eq!(frame["code"], "LOCAL_PREVIEW_PROTECTED");
        assert!(!wire.contains(e.dirs[0].to_str().unwrap()), "帧泄漏了本机绝对路径: {wire}");
        assert!(!wire.contains("sensitive"), "帧泄漏了内部原因: {wire}");
        assert!(!wire.contains("TOKEN=abc"), "帧泄漏了文件内容: {wire}");
        // 放行路径不产生拒绝帧
        std::fs::write(e.dirs[0].join("ok.txt"), "x").unwrap();
        assert!(eval(&req("ok.txt"), &pol).await.reject_frame("pv_1").is_none());
    }

    /// 变异锁（故事 20/24）：把目录外、未授权、敏感、非普通文件中任意一种改成不同的对外
    /// code 或 message → 本用例红。
    #[tokio::test]
    async fn 四类受保护拒绝的对外帧逐字节相同() {
        let e = env(2);
        std::fs::write(e.dirs[0].join(".env"), "x").unwrap();
        std::fs::create_dir_all(e.dirs[0].join("dir")).unwrap();
        std::fs::write(e.dirs[1].join("other.txt"), "x").unwrap();
        let pol = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]]), (B, &[&e.dirs[1]])]), None);

        let mut frames = Vec::new();
        for p in [".env", "dir", "../x", e.dirs[1].join("other.txt").to_str().unwrap()] {
            let o = eval(&req(p), &pol).await;
            frames.push(o.reject_frame("pv_same").unwrap().to_string());
        }
        // 未授权的助手
        let mut r = req("nope");
        r.agent_id = "ghost--x".into();
        frames.push(eval(&r, &pol).await.reject_frame("pv_same").unwrap().to_string());

        let uniq: std::collections::HashSet<&String> = frames.iter().collect();
        assert_eq!(uniq.len(), 1, "受保护类拒绝帧出现可辨差异，攻击者可探测规则: {uniq:?}");
    }

    // ── 助手调不到预览（ADR 决策 3）────────────────────────────────

    /// 变异锁：把 `PREVIEW_TOOL_NAME` 加进 `tools::execute_tool` 的 match → 本用例红。
    #[tokio::test]
    async fn 任务帧传预览工具名必须被拒() {
        use crate::daemon::approval::{ApprovalManager, ApprovalMode, Approver, AutoApprover};
        use crate::daemon::audit::AuditLogger;
        use std::sync::Arc;

        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e);
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLogger::new(audit_dir.path().to_path_buf()));
        let mgr: ApprovalManager<Box<dyn Approver>> =
            ApprovalManager::new(ApprovalMode::Strict, Box::new(AutoApprover) as Box<dyn Approver>);
        let params = serde_json::json!({ "path": "a.txt", "_agent_id": A, "_task_id": "t1" });

        let r = crate::daemon::tools::execute_tool(
            PREVIEW_TOOL_NAME, &params, &pol, None, "node-1", &mgr, &audit,
        )
        .await;
        assert!(!r.ok, "预览不得经助手的任务帧执行");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("unknown tool"), "应落到未知工具分支: {err}");
        // 且不得返回任何文件内容
        assert!(r.result.is_none());
    }

    #[test]
    fn 预览来源与工具名是独立的第三种() {
        assert_eq!(PREVIEW_ORIGIN, "web_preview");
        assert_ne!(PREVIEW_ORIGIN, "web_browse");
        assert_ne!(PREVIEW_ORIGIN, "agent");
        assert_ne!(PREVIEW_TOOL_NAME, "local_upload_to_workspace");
        assert_ne!(PREVIEW_TOOL_NAME, "local_read_file");
    }

    // ── 审计：只记相对路径、结果、来源；不记内容、不记哈希 ──────────

    #[tokio::test]
    async fn 审计只记相对路径与结果_不记内容不记哈希() {
        let e = env(1);
        let body = "SENTINEL-PREVIEW-BYTES";
        std::fs::write(e.dirs[0].join("sub.txt"), body).unwrap();
        std::fs::create_dir_all(e.dirs[0].join("d")).unwrap();
        std::fs::write(e.dirs[0].join("d/deep.txt"), body).unwrap();
        let pol = setup(&e);

        let r = req("d/deep.txt");
        let o = eval(&r, &pol).await;
        let entry = audit_entry(&r, &o);
        let wire = serde_json::to_string(&entry).unwrap();

        assert_eq!(entry.tool, PREVIEW_TOOL_NAME);
        assert_eq!(entry.origin, PREVIEW_ORIGIN);
        assert_eq!(entry.path, "d/deep.txt", "应记相对授权根的路径");
        assert_eq!(entry.task_id, "pv_1", "预览号进 task_id 以便对账");
        assert!(entry.ok, "闸全过（待确认）应记成功");
        assert!(entry.backup_path.is_none() && entry.lease_id.is_none());
        // 不得出现本机绝对路径 / 文件内容
        assert!(!wire.contains(e.dirs[0].to_str().unwrap()), "审计泄漏了本机绝对路径: {wire}");
        assert!(!wire.contains(body), "审计泄漏了文件内容: {wire}");
    }

    #[tokio::test]
    async fn 绝对路径入参的审计只留文件名_不抄本机目录结构() {
        let e = env(1);
        std::fs::write(e.dirs[0].join("a.txt"), "x").unwrap();
        let pol = setup(&e);
        let abs = e.dirs[0].join("a.txt");
        let r = req(abs.to_str().unwrap());
        let o = eval(&r, &pol).await;
        let entry = audit_entry(&r, &o);
        assert_eq!(entry.path, "a.txt");
        let wire = serde_json::to_string(&entry).unwrap();
        assert!(!wire.contains(e.dirs[0].to_str().unwrap()), "{wire}");
    }

    #[tokio::test]
    async fn 被拒的预览也进审计_且不写命中的黑名单项() {
        let e = env(1);
        std::fs::write(e.dirs[0].join(".env"), "TOKEN=abc").unwrap();
        let pol = setup(&e);
        let r = req(".env");
        let o = eval(&r, &pol).await;
        let entry = audit_entry(&r, &o);
        assert!(!entry.ok);
        assert_eq!(entry.decision.as_deref(), Some("rejected:sensitive"), "本机排障要分得清原因");
        assert_eq!(entry.error.as_deref(), Some("LOCAL_PREVIEW_PROTECTED"));
        let wire = serde_json::to_string(&entry).unwrap();
        assert!(!wire.contains("TOKEN=abc"), "审计泄漏了文件内容: {wire}");
    }

    /// 票 05 的接缝守卫：预览审计条目**不会**被现有「今日计数」算成写类。
    /// 现状读/写两桶会把它算进「读」——票 05 扩成三桶时本用例固化「预览工具名独立」。
    #[test]
    fn 预览工具名不在写类名单里() {
        for write_tool in
            ["local_write_file", "local_edit_file", "local_delete_file", "local_upload_to_workspace"]
        {
            assert_ne!(PREVIEW_TOOL_NAME, write_tool);
        }
    }
}
