// src-tauri/src/daemon/register.rs
//! 节点注册载荷：构造 ServerNodeLink（沿用作者上游 schema）+ 新协议帧字段（票 13）。
//! link 字段与 openhanako-upstream/core/remote-execution-boundary.ts:20-47 对齐。
//!
//! # 新注册帧（protocolVersion ≥ 1）
//! 帧顶层除 `link` 外再带 `protocolVersion / appVersion / roots / grants`。
//! 服务端以「有无 protocolVersion」区分新旧帧：旧帧键 `{userId}::{serverNodeId}` 且不互顶，
//! 新帧键 `{账号人}::{机器名}` 且同账号人后连顶先连。**所以发了 protocolVersion 就意味着
//! 加入互顶**——被顶后必须不重连（见 client.rs），否则两台机器会无限互顶。
//!
//! - `roots` 只带 `{rootId, name, mode}`，**绝不含绝对路径**（路径只在本机，决策 §4.1）
//! - `rootId` 由规范化路径派生，同一目录跨重启恒定（会话绑定 rootId，重连不能变）
//! - `grants` 为 `{ 执行体ID: [rootId...] }`；服务端只收用户名段 = 账号人的执行体

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

use super::config::DaemonConfig;

/// 本机实现的注册协议版本（服务端 `PROTOCOL_VERSION` 当前为 1，低于其 MIN 会被拒）。
pub const PROTOCOL_VERSION: u32 = 1;

/// 节点角色：执行节点（只执行、不持有数据）。
pub const NODE_ROLE: &str = "execution_node";
/// 传输类型：自定义远程（daemon 出站连云端）。
pub const TRANSPORT_KIND: &str = "custom_remote";
/// 本阶段能力：仅资源读写；不声明 execution.command（那是 run_script 后续阶段）。
pub const CAPABILITIES: [&str; 2] = ["resources.read", "resources.write"];

/// 本地文件预览能力版本（注册帧**顶层**字段 `previewCapability`，不进 `capabilities` 白名单——
/// 服务端对未知能力名直接拒绝注册）。1 = 单帧（步一：文本 ≤20MB）；2 = 分片（票 07：4MB 拉取式，最大 200MB）。
///
/// 发布顺序硬约束：服务端（`PREVIEW_CAPABILITY_SUPPORTED=2`）必须先于本值=2 的 Bridge 上线。
/// 反过来则旧服务端把 2 截成 1，请求不带 transfer，本 Bridge 走单帧，行为与步一一致（无害）。
/// 缺这个字段服务端 fail-closed 判「不支持」，网页点文件永远只会写路径（2026-10-08 漏报事故）。
pub const PREVIEW_CAPABILITY: u32 = 2;

/// ServerNodeLink 注册载荷（serde 序列化为 camelCase JSON）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeLink {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "linkId")]
    pub link_id: String,
    #[serde(rename = "studioId")]
    pub studio_id: String,
    #[serde(rename = "serverNodeId")]
    pub server_node_id: String,
    #[serde(rename = "nodeRole")]
    pub node_role: String,
    #[serde(rename = "transportKind")]
    pub transport_kind: String,
    pub capabilities: Vec<String>,
    pub status: String,
}

impl NodeLink {
    /// 从 daemon 配置构造注册载荷。
    /// studio_id 本阶段占位（后续从 device credential 解析）。
    pub fn new(cfg: &DaemonConfig) -> Self {
        Self {
            schema_version: 1,
            link_id: format!("link_{}", uuid_v4()),
            studio_id: "studio_placeholder".into(),
            server_node_id: cfg.node_id.clone(),
            node_role: NODE_ROLE.into(),
            transport_kind: TRANSPORT_KIND.into(),
            capabilities: CAPABILITIES.iter().map(|s| s.to_string()).collect(),
            status: "active".into(),
        }
    }
}

/// 授权目录的服务端可见视图（不含绝对路径）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootView {
    #[serde(rename = "rootId")]
    pub root_id: String,
    /// 显示名：目录末级名；取不到时回落 rootId
    pub name: String,
    /// "rw" | "ro"。来自本机策略（设置窗按目录设置），缺省读写
    pub mode: String,
    /// 审核 #2（加法字段，旧服务端忽略）：该目录是否开了「一直允许传到云端」。
    /// 网页据此列出永久允许并给「撤销」（撤销帧带 kind=upload）。只为 true 时下发，保持帧小、旧快照 diff 不抖。
    #[serde(rename = "uploadAlways", default, skip_serializing_if = "std::ops::Not::not")]
    pub upload_always: bool,
    /// 同上，「一直允许在网页预览」（撤销帧带 kind=preview）。与 upload 两个独立字段（ADR 0009 决策 1）。
    #[serde(rename = "previewAlways", default, skip_serializing_if = "std::ops::Not::not")]
    pub preview_always: bool,
}

/// 新协议 register 帧（序列化后直接作为 WS 文本帧）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterFrame {
    #[serde(rename = "type")]
    pub kind: String,
    pub link: NodeLink,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    #[serde(rename = "appVersion")]
    pub app_version: String,
    pub roots: Vec<RootView>,
    /// BTreeMap 保证序列化顺序稳定，便于测试与排障 diff
    pub grants: BTreeMap<String, Vec<String>>,
    /// 给人看的电脑名（设置窗可改）；None 不发，服务端回退机器名去 `node_` 前缀。旧服务端忽略此字段。
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// 预览能力版本，见 [`PREVIEW_CAPABILITY`]。旧服务端忽略此字段。
    #[serde(rename = "previewCapability")]
    pub preview_capability: u32,
    /// 能预览的种类（见 `preview_read::PREVIEW_KINDS`）。缺字段的旧 Bridge 服务端按「只有 text」处理。
    #[serde(rename = "previewKinds")]
    pub preview_kinds: Vec<String>,
}

/// 由目录路径派生稳定 rootId：`r_` + 规范化路径 sha256 前 12 位十六进制。
///
/// 路径先 canonicalize（解析 symlink，防「同一目录两个入口两个 id」）；
/// 目录已不存在时用原串兜底（此时 roots 构造会过滤掉它，这里只保证纯函数不 panic）。
/// Windows 下大小写不敏感，统一小写后再哈希，避免同目录因盘符大小写得到不同 id。
pub fn root_id_for(path: &Path) -> String {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut norm = canon.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        norm = norm.to_lowercase();
    }
    let digest = Sha256::digest(norm.as_bytes());
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("r_{hex}")
}

impl RegisterFrame {
    /// 构造新协议注册帧（目录与授权直接取本机策略，是云端快照的唯一来源）。
    ///
    /// grants 为空（没配执行体 / 没有目录）时服务端规则 6 会拒派活并给出 ACTOR_NOT_GRANTED，
    /// 这是预期行为而非故障。
    pub fn from_policy(cfg: &DaemonConfig, policy: &super::policy::Policy, app_version: &str) -> Self {
        Self {
            kind: "register".into(),
            link: NodeLink::new(cfg),
            protocol_version: PROTOCOL_VERSION,
            app_version: app_version.into(),
            roots: policy.roots_view(),
            grants: policy.grants.clone(),
            display_name: None,
            preview_capability: PREVIEW_CAPABILITY,
            preview_kinds: super::preview_read::PREVIEW_KINDS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 由目录列表构造（默认口径：凭据执行体独占全部目录，全部读写）。测试与无策略文件场景用。
    pub fn new(cfg: &DaemonConfig, dirs: &[std::path::PathBuf], app_version: &str) -> Self {
        let policy = super::policy::Policy::build(dirs, &super::policy::PolicyFile::default(), cfg.agent_id.as_deref());
        Self::from_policy(cfg, &policy, app_version)
    }
}

/// 授权目录变化推送帧（`roots_changed`）：整表替换云端快照。
pub fn roots_changed_frame(policy: &super::policy::Policy) -> serde_json::Value {
    serde_json::json!({ "type": "roots_changed", "roots": policy.roots_view() })
}

/// 执行体授权变化推送帧（`grants_changed`）：整表替换云端快照。
pub fn grants_changed_frame(policy: &super::policy::Policy) -> serde_json::Value {
    serde_json::json!({ "type": "grants_changed", "grants": policy.grants })
}

/// 生成简易 UUIDv4（本阶段不引入 uuid crate，避免过早加依赖）。
/// 用纳秒时间戳 + PID 派生，保证同进程内唯一；后续如需更强随机性再换 uuid crate。
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}",
        (nanos & 0xffff_ffff) as u32,
        (pid & 0xffff) as u16,
        (nanos & 0xfff) as u16,
        ((nanos >> 12) & 0xffff) as u16
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::config::DaemonConfig;

    fn cfg() -> DaemonConfig {
        DaemonConfig {
            base_url: "https://x.example.com".into(),
            token: "tok".into(),
            node_id: "node_test_1".into(),
            agent_id: None,
        }
    }

    #[test]
    fn 载荷字段符合_schema() {
        let link = NodeLink::new(&cfg());
        assert_eq!(link.schema_version, 1);
        assert_eq!(link.node_role, "execution_node");
        assert_eq!(link.transport_kind, "custom_remote");
        assert_eq!(link.server_node_id, "node_test_1");
        assert_eq!(link.status, "active");
        assert_eq!(link.capabilities, vec!["resources.read", "resources.write"]);
        assert!(link.link_id.starts_with("link_"));
    }

    #[test]
    fn 注册帧_顶层带_previewCapability_且不进能力列表() {
        let v = serde_json::to_value(RegisterFrame::new(&cfg(), &[], "0.1.0")).unwrap();
        assert_eq!(v["previewCapability"], 2, "缺它服务端判不支持预览，网页点文件只会写路径；2=支持分片");
        let caps = v["link"]["capabilities"].as_array().unwrap();
        assert!(caps.iter().all(|c| c != "files.preview"), "进能力列表会被服务端白名单拒绝注册");
        let kinds: Vec<&str> = v["previewKinds"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
        for k in ["text", "pdf", "docx", "xlsx", "image"] {
            assert!(kinds.contains(&k), "注册帧须上报预览种类 {k}，网页据此决定点文件是否走预览");
        }
    }

    #[test]
    fn 注册帧_displayName_有值才发_None不出现() {
        let dirs: Vec<std::path::PathBuf> = vec![];
        let mut f = RegisterFrame::new(&cfg(), &dirs, "0.1.0");
        assert!(serde_json::to_value(&f).unwrap().get("displayName").is_none());
        f.display_name = Some("Alice 的 MacBook".into());
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["displayName"], "Alice 的 MacBook");
        assert_eq!(v["link"]["serverNodeId"], "node_test_1", "身份不随显示名变");
    }

    #[test]
    fn 序列化为_camelCase_json() {
        let link = NodeLink::new(&cfg());
        let v = serde_json::to_value(&link).unwrap();
        // 与作者 TS schema 字段名一致（camelCase）
        assert!(v.get("schemaVersion").is_some());
        assert!(v.get("linkId").is_some());
        assert!(v.get("serverNodeId").is_some());
        assert!(v.get("nodeRole").is_some());
        assert!(v.get("transportKind").is_some());
        // 不应出现 snake_case 键
        assert!(v.get("server_node_id").is_none());
    }

    // ─── 新注册帧（票 13）────────────────────────────────────

    fn cfg_with_agent(agent: Option<&str>) -> DaemonConfig {
        DaemonConfig {
            base_url: "https://x.example.com".into(),
            token: "tok".into(),
            node_id: "node_test_1".into(),
            agent_id: agent.map(str::to_string),
        }
    }

    #[test]
    fn 新帧带协议版本与应用版本() {
        let f = RegisterFrame::new(&cfg_with_agent(None), &[], "0.1.0");
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["type"], "register");
        assert_eq!(v["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["appVersion"], "0.1.0");
        assert!(v["link"]["serverNodeId"].is_string());
    }

    #[test]
    fn root_id_同目录恒定_不同目录不同() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert_eq!(root_id_for(a.path()), root_id_for(a.path()));
        assert_ne!(root_id_for(a.path()), root_id_for(b.path()));
        assert!(root_id_for(a.path()).starts_with("r_"));
    }

    #[cfg(unix)]
    #[test]
    fn root_id_符号链接与真路径同值() {
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("alias");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        assert_eq!(root_id_for(&link), root_id_for(real.path()));
    }

    #[test]
    fn roots_不含绝对路径() {
        let d = tempfile::tempdir().unwrap();
        let f = RegisterFrame::new(&cfg_with_agent(Some("t--u")), &[d.path().to_path_buf()], "0.1.0");
        let wire = serde_json::to_string(&f).unwrap();
        let abs = d.path().canonicalize().unwrap().to_string_lossy().to_string();
        assert!(!wire.contains(&abs), "注册帧泄漏了本机绝对路径: {wire}");
        assert_eq!(f.roots.len(), 1);
        assert_eq!(f.roots[0].mode, "rw");
    }

    #[test]
    fn 不存在的目录被跳过_重复目录去重() {
        let d = tempfile::tempdir().unwrap();
        let gone = d.path().join("not-exist");
        let roots = crate::daemon::policy::Policy::build(&[gone, d.path().to_path_buf(), d.path().to_path_buf()], &Default::default(), None).roots_view();
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn grants_执行体独占全部目录() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let f = RegisterFrame::new(
            &cfg_with_agent(Some("team--alice")),
            &[a.path().to_path_buf(), b.path().to_path_buf()],
            "0.1.0",
        );
        let ids: Vec<String> = f.roots.iter().map(|r| r.root_id.clone()).collect();
        assert_eq!(f.grants.get("team--alice"), Some(&ids));
        assert_eq!(f.grants.len(), 1);
    }

    #[test]
    fn 无执行体或无目录_grants_为空() {
        let d = tempfile::tempdir().unwrap();
        assert!(RegisterFrame::new(&cfg_with_agent(None), &[d.path().to_path_buf()], "v").grants.is_empty());
        assert!(RegisterFrame::new(&cfg_with_agent(Some("t--u")), &[], "v").grants.is_empty());
    }

    #[test]
    fn 两次生成_link_id_不同() {
        let a = NodeLink::new(&cfg());
        let b = NodeLink::new(&cfg());
        assert_ne!(a.link_id, b.link_id);
    }
}
