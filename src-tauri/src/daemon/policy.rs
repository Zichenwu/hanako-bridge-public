// src-tauri/src/daemon/policy.rs
//! 本机策略真源（S3 本机闸的决策层）。
//!
//! 本机是安全配置**唯一真源**；云端持有的只是注册时与 `roots_changed` / `grants_changed`
//! 推送的快照，仅用于第一道拦截与网页展示（决策 §4.1）。所以每个任务帧到达时，本机都要
//! 用**自己当下的**策略重新复核一遍，不信任云端已经放行过。
//!
//! 数据来源（每次 `load` 现读磁盘，设置窗改完下个任务立即生效）：
//! - 授权目录：`Workspace::from_env()`（env ∪ workspaces.json）
//! - 读写模式 / 执行体授权：`~/.hanako-tauri/policy.json`（缺省 = 全部读写、凭据执行体独占全部目录）
//!
//! 复核链（`authorize`，顺序即拒绝优先级，任一步删掉都有对应用例变红）：
//! 1. 执行体必须出现在 grants 且名下至少一个目录 → `LOCAL_ACTOR_NOT_GRANTED`
//! 2. 任务帧带 rootId 时，它必须在该执行体的授权目录里 → `LOCAL_ROOT_REVOKED`
//! 3. 路径必须落在该执行体**可见目录**内（词法归一 + 符号链接解析 + 敏感黑名单）→ `LOCAL_PATH_OUT_OF_FENCE`
//! 4. 写类操作命中的目录必须是读写 → `LOCAL_ROOT_READ_ONLY`
//!
//! 第 3 步只在「该执行体被授权的目录」里找，别的执行体的目录对它等于不存在（故事 77）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::path_guard::{PathError, PathGuard};
use super::register::{root_id_for, RootView};
use super::workspace::Workspace;

// ── 策略路径覆盖（测试 / 集成测试共用）──────────────────────────────
// Windows 上 dirs_next::home_dir() 走 KNOWNFOLDER，不读 HOME/USERPROFILE 环境变量，
// 测试无法用那两个变量隔离策略文件路径。提供 `HANAKO_POLICY_PATH` 环境变量覆盖：
// 生产不设 → 走 home_dir；测试（含集成测试，独立 binary 链接非 test 的 lib）设它指向临时目录。
// 不用 cfg(test) 静态注入，因为集成测试链接的是**非 test** 的 lib，cfg(test) 代码根本不进那个 binary。
/// 覆盖 `PolicyFile::path()` 的环境变量名（仅测试/集成测试用；生产不设置）。
pub const POLICY_PATH_ENV: &str = "HANAKO_POLICY_PATH";

/// 目录读写模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootMode {
    ReadWrite,
    ReadOnly,
}

impl RootMode {
    /// 线上/落盘的字符串形态。
    pub fn as_wire(self) -> &'static str {
        match self {
            RootMode::ReadWrite => "rw",
            RootMode::ReadOnly => "ro",
        }
    }

    /// 未知值一律按只读解释（先紧后松）。
    pub fn from_wire(s: &str) -> Self {
        if s == "rw" {
            RootMode::ReadWrite
        } else {
            RootMode::ReadOnly
        }
    }
}

/// 一个已生效的授权目录（路径只在本机，不上云）。
#[derive(Debug, Clone)]
pub struct PolicyRoot {
    /// 已 canonicalize 的绝对路径。
    pub path: PathBuf,
    pub root_id: String,
    /// 显示名：目录末级名，取不到回落 rootId。
    pub name: String,
    pub mode: RootMode,
    /// 「一直允许传到云端」（policy.json `upload[rootId]=="always"`）。只用于向云端快照上报，闸仍现读磁盘。
    pub upload_always: bool,
    /// 「一直允许在网页预览」（policy.json `preview[rootId]=="always"`）。同上。
    pub preview_always: bool,
}

/// `policy.json` 的落盘形态。字段都可缺省，缺省 = 旧口径。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFile {
    /// `{ rootId: "ro"|"rw" }`；缺省的目录为读写。
    #[serde(default)]
    pub modes: BTreeMap<String, String>,
    /// `{ 执行体ID: [rootId...] }`。`None` = 没配过，走「凭据执行体独占全部目录」过渡口径；
    /// `Some(空)` = 用户明确不授权任何执行体。
    #[serde(default)]
    pub grants: Option<BTreeMap<String, Vec<String>>>,
    /// 本机已知的助手（执行体 ID）。设置窗「可以使用的助手」的候选集合：
    /// 凭据绑定的执行体 + 用户在授权请求弹窗里勾选过的执行体。只增不减（移除授权不等于忘记）。
    #[serde(default)]
    pub agents: Vec<String>,
    /// `{ rootId: "ask"|"always" }` 原文件上云偏好；缺省每次问。本票只落盘，闸在票 18。
    #[serde(default)]
    pub upload: BTreeMap<String, String>,
    /// `{ rootId: "ask"|"always" }` **网页预览**偏好；缺省每次问。
    ///
    /// ⚠️ 与 `upload` 是**两个独立字段**（本地文件预览 ADR 决策 1）：用户为方便预览而开
    /// 「永久允许在网页预览」时，不得同时放开「允许助手把原文件传到云端」。
    /// 放宽方向只能由本机设置写入（`set_preview`），网页侧只能收回。
    #[serde(default)]
    pub preview: BTreeMap<String, String>,
    /// 网页预览的大小上限（MB）。只接受 50 / 100 / 200 三档；缺省 200（见 [`PREVIEW_LIMIT_DEFAULT_MB`]）。
    ///
    /// 与「上传到云端」的上限（`upload_gate::MAX_UPLOAD_BYTES`，50MB 写死）**互不影响**：
    /// 预览字节不落云端存储，上限由用户按自己的网络和习惯调。
    #[serde(default, rename = "previewLimitMb", skip_serializing_if = "Option::is_none")]
    pub preview_limit_mb: Option<u64>,
    /// 不在电脑前时允许网页确认（默认关）。本票只落盘，转发在后续票。
    #[serde(default, rename = "webConfirm")]
    pub web_confirm: bool,
    /// 给人看的电脑名（设置窗可改，经注册帧 `displayName` 上报）。缺省 = 网页端回退机器名去 `node_` 前缀。
    /// **只用于展示**：身份仍是 `serverNodeId`（会话绑定靠它），改这个不影响已绑定会话。
    #[serde(default, rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// 显示名清洗：去控制字符、首尾空白，最长 32 个字符（按字符不按字节，中文不劈）。空 → None（= 恢复默认）。
pub fn clean_display_name(raw: &str) -> Option<String> {
    let s: String = raw.chars().filter(|c| !c.is_control()).collect();
    let s = s.trim();
    if s.is_empty() { None } else { Some(s.chars().take(32).collect()) }
}

impl PolicyFile {
    /// `~/.hanako-tauri/policy.json`。
    ///
    /// 可被 `HANAKO_POLICY_PATH` 环境变量覆盖（测试/集成测试隔离用；生产不设置）。
    /// Windows 上 `dirs_next::home_dir()` 走 KNOWNFOLDER 不读 HOME/USERPROFILE，
    /// 所以隔离必须靠这个显式覆盖，不能靠 HOME。
    pub fn path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os(POLICY_PATH_ENV) {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        dirs_next::home_dir().map(|h| h.join(".hanako-tauri").join("policy.json"))
    }

    /// 读取；文件不存在视为默认，**文件损坏视为「全部拒绝」**而不是默认放行——
    /// 否则一次写坏文件会把「只读」目录悄悄变回可写。
    pub fn load() -> Result<Self, String> {
        let Some(p) = Self::path() else { return Ok(Self::default()) };
        Self::load_from(&p)
    }

    /// 原子写（临时文件 + rename）并读回校验。写失败/读回不一致都返回 Err——
    /// 设置窗据此提示「没保存成功」，而不是让用户以为收紧了权限其实没生效。
    pub fn save_to(&self, p: &Path) -> Result<(), String> {
        self.save_to_with(p, Self::load_from)
    }

    /// 同 `save_to`，读回函数可注入（测试用来模拟「写入后内容被改走/落盘损坏」）。
    pub(crate) fn save_to_with(&self, p: &Path, read_back: impl Fn(&Path) -> Result<Self, String>) -> Result<(), String> {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {e}"))?;
        }
        let data = serde_json::to_string_pretty(self).map_err(|e| format!("序列化失败: {e}"))?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, &data).map_err(|e| format!("写临时文件失败: {e}"))?;
        std::fs::rename(&tmp, p).map_err(|e| format!("rename 失败: {e}"))?;
        let back = read_back(p)?;
        if &back != self {
            return Err("policy.json 读回与写入不一致".into());
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::path().ok_or("无法确定 home 目录")?;
        self.save_to(&p)
    }

    pub fn load_from(p: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(p) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| format!("policy.json 损坏: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("policy.json 读取失败: {e}")),
        }
    }
}

// ────────────────────────────────────────────────────────────────
// 变更 API：设置窗 / 引导 / 授权请求弹窗共用。全部是「读当前 → 改 → 校验 → 写」，
// 放宽权限只能从这里（本机）发生；网页侧没有任何路径能走到这些函数。
// ────────────────────────────────────────────────────────────────

/// 设置窗一张目录卡的数据（含绝对路径——只给本机窗口，绝不上云）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FolderCard {
    pub root_id: String,
    pub name: String,
    pub path: String,
    /// "rw" | "ro"
    pub mode: String,
    /// 被授权使用它的执行体
    pub agents: Vec<String>,
    /// "ask" | "always"：允许助手把原文件传到云端
    pub upload: String,
    /// "ask" | "always"：允许在网页预览。
    ///
    /// 与 `upload` 在设置页**并列成两行**、各自独立（本地文件预览 ADR 决策 1）。
    pub preview: String,
}

/// 设置窗整体视图。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyView {
    pub folders: Vec<FolderCard>,
    /// 候选助手（执行体 ID）；UI 用 Team 标签显示，单个时隐藏整行
    pub agents: Vec<String>,
    pub web_confirm: bool,
    /// 预览大小上限档位（MB）。缺省回填成默认档，UI 不需要自己知道默认值是多少。
    pub preview_limit_mb: u64,
}

/// 把原始目录列表与文件合并成视图。
pub fn view_of(dirs: &[PathBuf], file: &PolicyFile, default_agent: Option<&str>) -> PolicyView {
    let pol = Policy::build(dirs, file, default_agent);
    let folders = pol
        .roots
        .iter()
        .map(|r| FolderCard {
            root_id: r.root_id.clone(),
            name: r.name.clone(),
            path: r.path.to_string_lossy().to_string(),
            mode: r.mode.as_wire().into(),
            agents: pol
                .grants
                .iter()
                .filter(|(_, ids)| ids.contains(&r.root_id))
                .map(|(a, _)| a.clone())
                .collect(),
            upload: file.upload.get(&r.root_id).cloned().unwrap_or_else(|| "ask".into()),
            preview: file.preview.get(&r.root_id).cloned().unwrap_or_else(|| "ask".into()),
        })
        .collect();
    let mut agents: Vec<String> = file.agents.clone();
    if let Some(a) = default_agent {
        if !agents.iter().any(|x| x == a) {
            agents.insert(0, a.to_string());
        }
    }
    for a in pol.grants.keys() {
        if !agents.contains(a) {
            agents.push(a.clone());
        }
    }
    PolicyView {
        folders,
        agents,
        web_confirm: file.web_confirm,
        // 显示的档位必须等于生效的档位（坏值回落 50 时设置页也显示 50，审核 #13）
        preview_limit_mb: super::preview_gate::effective_limit_chunked(file.preview_limit_mb) / (1024 * 1024),
    }
}

/// 把「尚未显式配置 grants」的文件固化成显式 grants：
/// 过渡口径（凭据执行体独占全部目录）一旦用户动手改任何一张卡，就必须变成显式数据，
/// 否则之后新增目录会被默认口径自动塞给凭据执行体，用户以为没授权其实授权了。
fn materialize_grants(file: &mut PolicyFile, dirs: &[PathBuf], default_agent: Option<&str>) {
    if file.grants.is_none() {
        file.grants = Some(Policy::build(dirs, file, default_agent).grants);
    }
}

fn remember_agent(file: &mut PolicyFile, agent: &str) {
    if !agent.trim().is_empty() && !file.agents.iter().any(|a| a == agent) {
        file.agents.push(agent.to_string());
    }
}

/// 设置某目录的读写模式。`root_id` 必须存在于当前目录，否则报错（不静默创建孤儿配置）。
pub fn set_mode(file: &mut PolicyFile, dirs: &[PathBuf], root_id: &str, mode: RootMode) -> Result<(), String> {
    ensure_root(dirs, root_id)?;
    file.modes.insert(root_id.to_string(), mode.as_wire().into());
    Ok(())
}

/// 勾选 / 取消勾选某助手使用某目录。
pub fn set_agent_access(
    file: &mut PolicyFile,
    dirs: &[PathBuf],
    default_agent: Option<&str>,
    root_id: &str,
    agent: &str,
    allowed: bool,
) -> Result<(), String> {
    ensure_root(dirs, root_id)?;
    if agent.trim().is_empty() {
        return Err("agent 为空".into());
    }
    materialize_grants(file, dirs, default_agent);
    remember_agent(file, agent);
    let g = file.grants.get_or_insert_with(Default::default);
    let ids = g.entry(agent.to_string()).or_default();
    ids.retain(|i| i != root_id);
    if allowed {
        ids.push(root_id.to_string());
    }
    if ids.is_empty() {
        g.remove(agent);
    }
    Ok(())
}

/// 设置原文件上云偏好（"ask" | "always"）。
pub fn set_upload(file: &mut PolicyFile, dirs: &[PathBuf], root_id: &str, pref: &str) -> Result<(), String> {
    ensure_root(dirs, root_id)?;
    match pref {
        "ask" => {
            file.upload.remove(root_id);
        }
        "always" => {
            file.upload.insert(root_id.to_string(), "always".into());
        }
        other => return Err(format!("未知上云偏好: {other}")),
    }
    Ok(())
}

/// 设置**网页预览**偏好（"ask" | "always"）。
///
/// 与 [`set_upload`] 是两个独立入口、写两个独立字段：开预览的永久允许不得带动上传。
pub fn set_preview(file: &mut PolicyFile, dirs: &[PathBuf], root_id: &str, pref: &str) -> Result<(), String> {
    ensure_root(dirs, root_id)?;
    match pref {
        "ask" => {
            file.preview.remove(root_id);
        }
        "always" => {
            file.preview.insert(root_id.to_string(), "always".into());
        }
        other => return Err(format!("未知预览偏好: {other}")),
    }
    Ok(())
}

/// 设置预览大小上限档位（MB，只认 50/100/200）。
///
/// 与 `set_preview`（按目录的 ask/always）是两件事：这是全局一个值，不按目录。
pub fn set_preview_limit(file: &mut PolicyFile, mb: u64) -> Result<(), String> {
    let mb = super::preview_gate::validate_limit_mb(mb)?;
    if mb == super::preview_gate::PREVIEW_LIMIT_DEFAULT_MB {
        // 与缺省相同就不落盘，保持 policy.json 干净（也让「从没设过」与「设回默认」等价）
        file.preview_limit_mb = None;
    } else {
        file.preview_limit_mb = Some(mb);
    }
    Ok(())
}

/// 移除目录后清理所有以它为键的配置（模式 / 上云偏好 / 预览偏好 / grants）。
/// 不清理会留下孤儿：用户之后重新添加同一目录，会悄悄继承旧的「看和改」+「一直允许上云」+「永久允许预览」。
pub fn forget_root(file: &mut PolicyFile, root_id: &str) {
    file.modes.remove(root_id);
    file.upload.remove(root_id);
    file.preview.remove(root_id);
    if let Some(g) = file.grants.as_mut() {
        for ids in g.values_mut() {
            ids.retain(|i| i != root_id);
        }
    }
}

/// 新增目录后，为新目录套用初始授权：只授权给 `agent`（引导第一步默认只勾登录时的助手）。
/// `agent` 为 None 时不授权任何助手——下一次由用户在卡上勾。
pub fn grant_new_root(
    file: &mut PolicyFile,
    dirs_after: &[PathBuf],
    default_agent: Option<&str>,
    root_id: &str,
    agent: Option<&str>,
) -> Result<(), String> {
    ensure_root(dirs_after, root_id)?;
    // 新增前就已显式配置过 grants 的保持原样；没配置过的，先固化「新增前」的口径再追加，
    // 避免默认口径把新目录也自动给凭据执行体。
    // 未登录（无默认执行体）且没有指定授权对象：保持 grants=None，登录后默认口径自然生效。
    // 否则会固化成空表，登录后凭据执行体拿不到任何目录（2026-10-07 真机）。
    if file.grants.is_none() && default_agent.is_none() && agent.is_none() {
        return Ok(());
    }
    if file.grants.is_none() {
        let before: Vec<PathBuf> = dirs_after.iter().filter(|d| root_id_for(d) != root_id).cloned().collect();
        file.grants = Some(Policy::build(&before, file, default_agent).grants);
    }
    if let Some(a) = agent {
        set_agent_access(file, dirs_after, default_agent, root_id, a, true)?;
    }
    Ok(())
}

/// 授权请求弹窗「允许」：把 `agent` 授权给所选目录（追加，不影响它已有的其它目录）。
/// `picked` 为空直接拒绝——UI 已禁用按钮，这里是最后一道（故事 16：至少勾一个才可允许）。
pub fn apply_auth_grant(
    file: &mut PolicyFile,
    dirs: &[PathBuf],
    default_agent: Option<&str>,
    agent: &str,
    picked: &[String],
) -> Result<(), String> {
    if picked.is_empty() {
        return Err("至少选择一个文件夹".into());
    }
    // 先整体校验再写入：逐个写到一半才发现某个目录已不存在，会留下半截授权
    for rid in picked {
        ensure_root(dirs, rid)?;
    }
    for rid in picked {
        set_agent_access(file, dirs, default_agent, rid, agent, true)?;
    }
    Ok(())
}

fn ensure_root(dirs: &[PathBuf], root_id: &str) -> Result<(), String> {
    if Policy::build(dirs, &PolicyFile::default(), None).roots.iter().any(|r| r.root_id == root_id) {
        Ok(())
    } else {
        Err(format!("目录不存在或未授权: {root_id}"))
    }
}

/// 任务帧携带的「谁、落在哪个目录」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskScope {
    /// 空串 = 任务帧没带执行体，一律拒绝。
    pub agent_id: String,
    pub root_id: Option<String>,
}

impl TaskScope {
    /// 从任务帧 params（服务端注入 `_agent_id` / `_root_id`）取。
    pub fn from_params(params: &Value) -> Self {
        let s = |k: &str| {
            params
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        Self { agent_id: s("_agent_id").unwrap_or_default(), root_id: s("_root_id") }
    }
}

/// 复核拒绝原因。`Display` 以机读错误码开头，task_result 的 error 直接带上它，
/// 服务端/模型据此区分「权限问题」与「文件不存在」。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateError {
    #[error("LOCAL_NO_ROOTS: 本机没有可用的授权目录，请先在 Hanako Bridge里选择文件夹")]
    NoRoots,
    #[error("LOCAL_ACTOR_NOT_GRANTED: 该助手未被授权使用本机文件夹")]
    ActorNotGranted,
    #[error("LOCAL_ROOT_REVOKED: 本会话绑定的本机目录已被撤销授权")]
    RootRevoked,
    #[error("LOCAL_PATH_OUT_OF_FENCE: {0}")]
    OutOfFence(String),
    #[error("LOCAL_ROOT_READ_ONLY: 该目录为只读，不允许写入")]
    ReadOnly,
    #[error("LOCAL_POLICY_UNAVAILABLE: {0}")]
    PolicyUnavailable(String),
    #[error("LOCAL_PATH_ERROR: {0}")]
    Path(String),
}

/// `authorize` 通过后的结果：真实落点 + 命中的目录 + 本次可见的围栏（供递归遍历复用）。
#[derive(Debug, Clone)]
pub struct Resolved {
    /// canonicalize 后的目标路径（写新文件时为「已存在祖先 canonical + 剩余段」）。
    pub path: PathBuf,
    /// 命中的授权目录（备份存放在这个目录下，而不是「第一个目录」）。
    pub root: PathBuf,
    /// 该执行体本次可见的目录围栏。
    pub fence: PathGuard,
}

/// 本机策略快照。
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub roots: Vec<PolicyRoot>,
    /// `{ 执行体ID: [rootId...] }`，只含存在的目录。
    pub grants: BTreeMap<String, Vec<String>>,
    /// 策略文件损坏等导致的全拒绝原因。
    poisoned: Option<String>,
}

impl Policy {
    /// 现读磁盘构造。`default_agent` = 凭据绑定的执行体（过渡口径里独占全部目录）。
    pub fn load(default_agent: Option<&str>) -> Self {
        let dirs = Workspace::from_env().roots;
        match PolicyFile::load() {
            Ok(file) => Self::build(&dirs, &file, default_agent),
            Err(e) => {
                let mut p = Self::build(&dirs, &PolicyFile::default(), None);
                p.grants.clear();
                p.poisoned = Some(e);
                p
            }
        }
    }

    /// 纯函数构造（测试与 `RegisterFrame::new` 共用）。
    ///
    /// 不存在的目录跳过（报一个本机进不去的 root 会造成「网页能选、派活必失败」）；
    /// canonicalize 后相同的目录按 rootId 去重。
    pub fn build(dirs: &[PathBuf], file: &PolicyFile, default_agent: Option<&str>) -> Self {
        let mut seen = std::collections::HashSet::new();
        let mut roots = Vec::new();
        for d in dirs {
            if !d.is_dir() {
                continue;
            }
            let Ok(canonical) = d.canonicalize() else { continue };
            let root_id = root_id_for(&canonical);
            if !seen.insert(root_id.clone()) {
                continue;
            }
            let name = canonical
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| root_id.clone());
            let mode = file
                .modes
                .get(&root_id)
                .map(|m| RootMode::from_wire(m))
                .unwrap_or(RootMode::ReadWrite);
            let upload_always = file.upload.get(&root_id).map(|v| v == "always").unwrap_or(false);
            let preview_always = file.preview.get(&root_id).map(|v| v == "always").unwrap_or(false);
            roots.push(PolicyRoot { path: canonical, root_id, name, mode, upload_always, preview_always });
        }

        let known: std::collections::HashSet<&str> = roots.iter().map(|r| r.root_id.as_str()).collect();
        let mut grants: BTreeMap<String, Vec<String>> = BTreeMap::new();
        match &file.grants {
            Some(g) => {
                for (agent, ids) in g {
                    let ids: Vec<String> = ids.iter().filter(|i| known.contains(i.as_str())).cloned().collect();
                    if !agent.trim().is_empty() && !ids.is_empty() {
                        grants.insert(agent.clone(), ids);
                    }
                }
            }
            None => {
                if let (Some(agent), false) = (default_agent, roots.is_empty()) {
                    grants.insert(agent.to_string(), roots.iter().map(|r| r.root_id.clone()).collect());
                }
            }
        }
        Self { roots, grants, poisoned: None }
    }

    /// 没有任何授权目录。
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// 服务端可见视图（不含绝对路径）。
    pub fn roots_view(&self) -> Vec<RootView> {
        self.roots
            .iter()
            .map(|r| RootView {
                root_id: r.root_id.clone(),
                name: r.name.clone(),
                mode: r.mode.as_wire().into(),
                upload_always: r.upload_always,
                preview_always: r.preview_always,
            })
            .collect()
    }

    /// 任务复核：返回真实落点，或带机读码的拒绝原因。
    pub fn authorize(&self, scope: &TaskScope, rel_path: &str, write: bool) -> Result<Resolved, GateError> {
        if let Some(why) = &self.poisoned {
            return Err(GateError::PolicyUnavailable(why.clone()));
        }
        if self.roots.is_empty() {
            return Err(GateError::NoRoots);
        }
        // ① 执行体授权
        let granted = match self.grants.get(&scope.agent_id) {
            Some(ids) if !scope.agent_id.is_empty() && !ids.is_empty() => ids,
            _ => return Err(GateError::ActorNotGranted),
        };
        // ② 会话绑定的 rootId 必须仍在授权里
        if let Some(rid) = &scope.root_id {
            if !granted.contains(rid) {
                return Err(GateError::RootRevoked);
            }
        }
        // ③ 可见目录：绑定了 rootId 就只看那一个，否则看该执行体全部授权目录
        let visible: Vec<&PolicyRoot> = self
            .roots
            .iter()
            .filter(|r| match &scope.root_id {
                Some(rid) => &r.root_id == rid,
                None => granted.contains(&r.root_id),
            })
            .collect();
        if visible.is_empty() {
            return Err(GateError::RootRevoked);
        }
        let fence = PathGuard::new(visible.iter().map(|r| r.path.clone()).collect());
        let (path, root_path) = fence.resolve_with_root(rel_path).map_err(|e| match e {
            PathError::EscapesWorkspace => GateError::OutOfFence("path escapes the authorized folder".into()),
            PathError::Sensitive(p) => GateError::OutOfFence(format!("sensitive path rejected: {p}")),
            PathError::Io(e) => GateError::Path(e.to_string()),
        })?;
        // ④ 写类命中目录必须读写
        if write {
            let hit = visible.iter().find(|r| r.path == root_path);
            if hit.map(|r| r.mode) != Some(RootMode::ReadWrite) {
                return Err(GateError::ReadOnly);
            }
        }
        Ok(Resolved { path, root: root_path, fence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

    fn scope(agent: &str, root: Option<&str>) -> TaskScope {
        TaskScope { agent_id: agent.into(), root_id: root.map(str::to_string) }
    }

    fn rid(p: &Path) -> String {
        root_id_for(p)
    }

    fn file_with(grants: &[(&str, &[&Path])], modes: &[(&Path, &str)]) -> PolicyFile {
        PolicyFile {
            modes: modes.iter().map(|(p, m)| (rid(p), m.to_string())).collect(),
            grants: Some(
                grants
                    .iter()
                    .map(|(a, ps)| (a.to_string(), ps.iter().map(|p| rid(p)).collect()))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    // ── 复核链各步 ─────────────────────────────────────────

    #[test]
    fn 无目录_拒() {
        let p = Policy::build(&[], &PolicyFile::default(), Some(A));
        assert_eq!(p.authorize(&scope(A, None), "a.txt", false).unwrap_err(), GateError::NoRoots);
    }

    #[test]
    fn 缺执行体或未授权_拒() {
        let e = env(1);
        let p = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]])], &[]), None);
        assert_eq!(p.authorize(&scope("", None), "a.txt", false).unwrap_err(), GateError::ActorNotGranted);
        assert_eq!(p.authorize(&scope(B, None), "a.txt", false).unwrap_err(), GateError::ActorNotGranted);
        assert!(p.authorize(&scope(A, None), "a.txt", false).is_ok());
    }

    #[test]
    fn 默认口径_凭据执行体独占全部目录() {
        let e = env(2);
        let p = Policy::build(&e.dirs, &PolicyFile::default(), Some(A));
        assert!(p.authorize(&scope(A, None), "a.txt", true).is_ok());
        assert_eq!(p.authorize(&scope(B, None), "a.txt", false).unwrap_err(), GateError::ActorNotGranted);
    }

    #[test]
    fn 显式空授权_不回落到默认口径() {
        let e = env(1);
        let f = PolicyFile { grants: Some(Default::default()), ..Default::default() };
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.authorize(&scope(A, None), "a.txt", false).unwrap_err(), GateError::ActorNotGranted);
    }

    #[test]
    fn 会话绑定的目录已被撤销_拒() {
        let e = env(2);
        // A 只被授权 dirs[0]；会话却绑着 dirs[1]
        let p = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]])], &[]), None);
        let r = p.authorize(&scope(A, Some(&rid(&e.dirs[1]))), "a.txt", false);
        assert_eq!(r.unwrap_err(), GateError::RootRevoked);
        // 绑着一个压根不存在（已被移除）的 rootId 同样是 REVOKED，而不是回落到别的目录
        let r = p.authorize(&scope(A, Some("r_gone00000000")), "a.txt", false);
        assert_eq!(r.unwrap_err(), GateError::RootRevoked);
    }

    #[test]
    fn 绑定目录时只在该目录内解析() {
        let e = env(2);
        let p = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0], &e.dirs[1]])], &[]), None);
        let got = p.authorize(&scope(A, Some(&rid(&e.dirs[1]))), "x.txt", true).unwrap();
        assert_eq!(got.root, e.dirs[1]);
        assert!(got.path.starts_with(&e.dirs[1]));
    }

    #[test]
    fn 绝对路径落在另一执行体的目录_拒() {
        // 故事 77：A 不能通过绝对路径碰到只授权给 B 的目录
        let e = env(2);
        let p = Policy::build(&e.dirs, &file_with(&[(A, &[&e.dirs[0]]), (B, &[&e.dirs[1]])], &[]), None);
        let other = e.dirs[1].join("secret.txt");
        let r = p.authorize(&scope(A, None), other.to_str().unwrap(), false);
        assert!(matches!(r, Err(GateError::OutOfFence(_))), "{r:?}");
        assert!(p.authorize(&scope(B, None), other.to_str().unwrap(), false).is_ok());
    }

    #[test]
    fn 点点与敏感路径_拒_且带机读码() {
        let e = env(1);
        let p = Policy::build(&e.dirs, &PolicyFile::default(), Some(A));
        let err = p.authorize(&scope(A, None), "../x", false).unwrap_err();
        assert!(matches!(err, GateError::OutOfFence(_)));
        assert!(err.to_string().starts_with("LOCAL_PATH_OUT_OF_FENCE"));
        assert!(matches!(p.authorize(&scope(A, None), ".ssh/id", false), Err(GateError::OutOfFence(_))));
    }

    #[cfg(unix)]
    #[test]
    fn 符号链接指向根外_拒() {
        let e = env(1);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("s.txt"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), e.dirs[0].join("evil")).unwrap();
        let p = Policy::build(&e.dirs, &PolicyFile::default(), Some(A));
        assert!(matches!(p.authorize(&scope(A, None), "evil/s.txt", false), Err(GateError::OutOfFence(_))));
    }

    #[test]
    fn 只读根_读通过_写被拒() {
        let e = env(1);
        let f = file_with(&[(A, &[&e.dirs[0]])], &[(&e.dirs[0], "ro")]);
        let p = Policy::build(&e.dirs, &f, None);
        assert!(p.authorize(&scope(A, None), "a.txt", false).is_ok());
        assert_eq!(p.authorize(&scope(A, None), "a.txt", true).unwrap_err(), GateError::ReadOnly);
    }

    #[test]
    fn 多根时_只读判定按命中的根() {
        let e = env(2);
        let f = file_with(&[(A, &[&e.dirs[0], &e.dirs[1]])], &[(&e.dirs[0], "ro")]);
        let p = Policy::build(&e.dirs, &f, None);
        // 绝对路径命中第二个（读写）根 → 可写；命中第一个（只读）根 → 不可写
        let w = e.dirs[1].join("ok.txt");
        let r = e.dirs[0].join("no.txt");
        assert!(p.authorize(&scope(A, None), w.to_str().unwrap(), true).is_ok());
        assert_eq!(p.authorize(&scope(A, None), r.to_str().unwrap(), true).unwrap_err(), GateError::ReadOnly);
    }

    #[test]
    fn 未知模式值按只读() {
        assert_eq!(RootMode::from_wire("whatever"), RootMode::ReadOnly);
        assert_eq!(RootMode::from_wire("rw"), RootMode::ReadWrite);
    }

    #[test]
    fn 策略文件损坏_全部拒绝而非放行() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.json");
        fs::write(&p, "{ not json").unwrap();
        assert!(PolicyFile::load_from(&p).is_err());
        // 不存在 = 默认
        assert_eq!(PolicyFile::load_from(&dir.path().join("none.json")).unwrap(), PolicyFile::default());
    }

    #[test]
    fn poisoned_策略_授权一律拒() {
        let e = env(1);
        let mut p = Policy::build(&e.dirs, &PolicyFile::default(), Some(A));
        p.poisoned = Some("损坏".into());
        assert!(matches!(p.authorize(&scope(A, None), "a.txt", false), Err(GateError::PolicyUnavailable(_))));
    }

    #[test]
    fn grants_只保留存在的目录() {
        let e = env(1);
        let mut g = BTreeMap::new();
        g.insert(A.to_string(), vec![rid(&e.dirs[0]), "r_dead00000000".to_string()]);
        g.insert(B.to_string(), vec!["r_dead00000000".to_string()]);
        let p = Policy::build(&e.dirs, &PolicyFile { grants: Some(g), ..Default::default() }, None);
        assert_eq!(p.grants.get(A).unwrap().len(), 1);
        assert!(!p.grants.contains_key(B), "全是失效目录的执行体不应留在 grants 里");
    }

    #[test]
    fn roots_view_不含绝对路径() {
        let e = env(1);
        let p = Policy::build(&e.dirs, &PolicyFile::default(), Some(A));
        let wire = serde_json::to_string(&p.roots_view()).unwrap();
        assert!(!wire.contains(e.dirs[0].to_str().unwrap()));
    }

    #[test]
    fn scope_从任务帧取() {
        let s = TaskScope::from_params(&serde_json::json!({"_agent_id":" bi--z ","_root_id":"r_1"}));
        assert_eq!(s, scope("bi--z", Some("r_1")));
        let s = TaskScope::from_params(&serde_json::json!({"_root_id":""}));
        assert_eq!(s, scope("", None));
    }

    // ── 变更 API（设置窗 / 引导 / 授权请求弹窗）──────────────────────────

    #[test]
    fn 原子写_读回一致_损坏文件不被覆盖成功() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/policy.json");
        let mut f = PolicyFile::default();
        f.modes.insert("r_a".into(), "ro".into());
        f.agents.push(A.into());
        f.web_confirm = true;
        f.save_to(&p).unwrap();
        assert_eq!(PolicyFile::load_from(&p).unwrap(), f);
        assert!(!p.with_extension("json.tmp").exists(), "临时文件应已 rename 掉");
    }

    #[test]
    fn 旧版_policy_json_无新字段仍可读() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("policy.json");
        fs::write(&p, r#"{"modes":{"r_a":"ro"}}"#).unwrap();
        let f = PolicyFile::load_from(&p).unwrap();
        assert!(f.agents.is_empty() && f.upload.is_empty() && !f.web_confirm && f.grants.is_none());
    }

    #[test]
    fn set_mode_不存在的目录_报错而非造孤儿() {
        let e = env(1);
        let mut f = PolicyFile::default();
        assert!(set_mode(&mut f, &e.dirs, "r_ghost0000000", RootMode::ReadOnly).is_err());
        assert!(f.modes.is_empty());
        set_mode(&mut f, &e.dirs, &rid(&e.dirs[0]), RootMode::ReadOnly).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.authorize(&scope(A, None), "a.txt", true).unwrap_err(), GateError::ReadOnly);
    }

    #[test]
    fn 取消最后一个目录的勾选_助手不再被授权_且不回落默认口径() {
        // 关键陷阱：grants 还是 None 时取消勾选，若不先固化，默认口径会立刻把它加回来
        let e = env(1);
        let mut f = PolicyFile::default();
        set_agent_access(&mut f, &e.dirs, Some(A), &rid(&e.dirs[0]), A, false).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.authorize(&scope(A, None), "a.txt", false).unwrap_err(), GateError::ActorNotGranted);
        assert!(f.agents.contains(&A.to_string()), "取消授权不等于忘记这个助手");
    }

    #[test]
    fn 勾选第二个助手_不影响第一个() {
        let e = env(1);
        let mut f = PolicyFile::default();
        set_agent_access(&mut f, &e.dirs, Some(A), &rid(&e.dirs[0]), B, true).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert!(p.authorize(&scope(A, None), "a.txt", false).is_ok(), "固化默认口径后 A 仍被授权");
        assert!(p.authorize(&scope(B, None), "a.txt", false).is_ok());
    }

    #[test]
    fn 新增目录只授权给指定助手_不被默认口径自动塞给凭据执行体() {
        let e = env(2);
        let mut f = PolicyFile::default();
        // 首个目录：登录时的助手 A
        grant_new_root(&mut f, &e.dirs[..1], Some(A), &rid(&e.dirs[0]), Some(A)).unwrap();
        // 第二个目录：用户取消勾选 A（即不授权任何助手）
        grant_new_root(&mut f, &e.dirs, Some(A), &rid(&e.dirs[1]), None).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.grants.get(A).unwrap(), &vec![rid(&e.dirs[0])]);
        let r = p.authorize(&scope(A, Some(&rid(&e.dirs[1]))), "x.txt", false);
        assert_eq!(r.unwrap_err(), GateError::RootRevoked);
    }

    #[test]
    fn 移除目录后重新添加_不继承旧的看和改与上云偏好() {
        let e = env(1);
        let id = rid(&e.dirs[0]);
        let mut f = PolicyFile::default();
        set_mode(&mut f, &e.dirs, &id, RootMode::ReadWrite).unwrap();
        set_upload(&mut f, &e.dirs, &id, "always").unwrap();
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
        set_agent_access(&mut f, &e.dirs, Some(A), &id, A, true).unwrap();
        forget_root(&mut f, &id);
        assert!(!f.modes.contains_key(&id) && !f.upload.contains_key(&id));
        assert!(!f.preview.contains_key(&id), "预览偏好也必须清理，否则重新添加会悄悄继承永久允许");
        assert!(f.grants.as_ref().unwrap().values().all(|v| !v.contains(&id)));
    }

    // ── 预览偏好与上传偏好互相独立（本地文件预览 票 03）──────────────

    /// 变异锁：让 `set_preview` 写 `upload` 字段（或两者共用一个 map）→ 本用例红。
    #[test]
    fn 预览偏好与上传偏好是两个独立字段() {
        let e = env(1);
        let id = rid(&e.dirs[0]);
        let mut f = PolicyFile::default();

        // 只开预览的永久允许
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
        assert_eq!(f.preview.get(&id).map(String::as_str), Some("always"));
        assert!(f.upload.is_empty(), "开预览永久允许不得带动上传");

        // 只开上传的永久允许（先把预览收回）
        set_preview(&mut f, &e.dirs, &id, "ask").unwrap();
        set_upload(&mut f, &e.dirs, &id, "always").unwrap();
        assert_eq!(f.upload.get(&id).map(String::as_str), Some("always"));
        assert!(f.preview.is_empty(), "开上传永久允许不得带动预览");

        // 收回其中一个不影响另一个
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
        set_upload(&mut f, &e.dirs, &id, "ask").unwrap();
        assert_eq!(f.preview.get(&id).map(String::as_str), Some("always"));
        assert!(f.upload.is_empty());
    }

    #[test]
    fn 设置预览偏好_未知值报错_不存在的目录报错() {
        let e = env(1);
        let id = rid(&e.dirs[0]);
        let mut f = PolicyFile::default();
        assert!(set_preview(&mut f, &e.dirs, &id, "yes").is_err(), "未知值必须报错而非静默放行");
        assert!(set_preview(&mut f, &e.dirs, &id, "permanent").is_err());
        assert!(f.preview.is_empty());
        assert!(set_preview(&mut f, &e.dirs, "r_ghost0000000", "always").is_err(), "不造孤儿配置");
        assert!(f.preview.is_empty());
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
    }

    #[test]
    fn 旧版_policy_json_无预览字段仍可读_且默认每次问() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("policy.json");
        fs::write(&p, r#"{"modes":{"r_a":"ro"},"upload":{"r_a":"always"}}"#).unwrap();
        let f = PolicyFile::load_from(&p).unwrap();
        assert!(f.preview.is_empty(), "缺字段 = 每次问（fail-closed）");
        assert_eq!(f.upload.get("r_a").map(String::as_str), Some("always"), "旧字段不受影响");
    }

    #[test]
    fn 视图_两个开关并列且各自独立() {
        let e = env(1);
        let id = rid(&e.dirs[0]);
        let mut f = PolicyFile::default();
        // 默认都是每次问
        let v = view_of(&e.dirs, &f, Some(A));
        assert_eq!(v.folders[0].upload, "ask");
        assert_eq!(v.folders[0].preview, "ask");
        // 只开预览
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
        let v = view_of(&e.dirs, &f, Some(A));
        assert_eq!(v.folders[0].preview, "always");
        assert_eq!(v.folders[0].upload, "ask", "设置页两行必须各自显示自己的值");
    }

    // ── 预览大小上限档位（票 05）────────────────────────────

    #[test]
    fn 预览上限_只认三档_非法值报错() {
        let mut f = PolicyFile::default();
        for mb in super::super::preview_gate::PREVIEW_LIMIT_CHOICES_MB {
            set_preview_limit(&mut f, mb).unwrap_or_else(|e| panic!("{mb}MB 应合法: {e}"));
        }
        // 非法值报错，且不改动已落盘的值（不静默取最近档）
        set_preview_limit(&mut f, 50).unwrap();
        for bad in [0u64, 20, 51, 150, 500, u64::MAX] {
            assert!(set_preview_limit(&mut f, bad).is_err(), "{bad}MB 必须报错");
        }
        assert_eq!(f.preview_limit_mb, Some(50), "非法值不得覆盖已设的档位");
    }

    #[test]
    fn 预览上限_缺省不落盘_设回默认即清空() {
        let mut f = PolicyFile::default();
        assert_eq!(f.preview_limit_mb, None, "从没设过");
        set_preview_limit(&mut f, 50).unwrap();
        assert_eq!(f.preview_limit_mb, Some(50));
        set_preview_limit(&mut f, super::super::preview_gate::PREVIEW_LIMIT_DEFAULT_MB).unwrap();
        assert_eq!(f.preview_limit_mb, None, "设回默认 = 回到「没设过」，policy.json 保持干净");
    }

    /// 变异锁：让 `set_preview_limit` 去动 `upload`/`preview` 字段 → 本用例红。
    ///
    /// 断言用「整个 map 快照不变」而不是「我关心的那个键不变」——后者抓不住
    /// 「顺手写进别的键」这种变异（实测：只断言单键时变异不红）。
    #[test]
    fn 预览上限与两个并列开关互不影响() {
        let e = env(1);
        let id = rid(&e.dirs[0]);
        let mut f = PolicyFile::default();
        set_preview(&mut f, &e.dirs, &id, "always").unwrap();
        set_upload(&mut f, &e.dirs, &id, "always").unwrap();
        let preview_before = f.preview.clone();
        let upload_before = f.upload.clone();
        let modes_before = f.modes.clone();

        set_preview_limit(&mut f, 50).unwrap();

        assert_eq!(f.preview, preview_before, "改上限不得动预览开关的任何一个键");
        assert_eq!(f.upload, upload_before, "改上限不得动上传开关的任何一个键");
        assert_eq!(f.modes, modes_before, "改上限不得动读写模式");
        assert_eq!(f.preview_limit_mb, Some(50));

        // 反向：改两个开关不得动上限
        set_preview(&mut f, &e.dirs, &id, "ask").unwrap();
        set_upload(&mut f, &e.dirs, &id, "ask").unwrap();
        assert_eq!(f.preview_limit_mb, Some(50), "改开关不得把上限重置掉");
    }

    #[test]
    fn 视图_回填默认档位() {
        let e = env(1);
        let mut f = PolicyFile::default();
        assert_eq!(
            view_of(&e.dirs, &f, Some(A)).preview_limit_mb,
            super::super::preview_gate::PREVIEW_LIMIT_DEFAULT_MB,
            "没设过时视图回填默认档，UI 不需要自己知道默认值"
        );
        set_preview_limit(&mut f, 100).unwrap();
        assert_eq!(view_of(&e.dirs, &f, Some(A)).preview_limit_mb, 100);
        // 审核 #13：policy.json 被手改成坏值 → 视图显示的就是实际生效的最窄档
        f.preview_limit_mb = Some(5000);
        assert_eq!(view_of(&e.dirs, &f, Some(A)).preview_limit_mb, 50);
    }

    /// 设置窗 JS 读的是 snake_case 字段名（`o.policy.preview_limit_mb` / `f.preview`）。
    /// 这个结构体没有 `rename_all`，字段名就是线上契约——改名会让设置窗静默读到
    /// `undefined`（三档一个都不高亮、点了也看不出），没有任何报错。
    #[test]
    fn 视图序列化字段名与设置窗_js_一致() {
        let e = env(1);
        let mut f = PolicyFile::default();
        set_preview_limit(&mut f, 50).unwrap();
        set_preview(&mut f, &e.dirs, &rid(&e.dirs[0]), "always").unwrap();
        let v = serde_json::to_value(view_of(&e.dirs, &f, Some(A))).unwrap();

        assert_eq!(v["preview_limit_mb"], 50, "settings.js 读 o.policy.preview_limit_mb");
        assert_eq!(v["folders"][0]["preview"], "always", "ui-common.js 读 f.preview");
        assert_eq!(v["folders"][0]["upload"], "ask", "两行各读自己的字段");
        // 既有字段不被改名（设置窗其余部分依赖它们）
        assert!(v.get("web_confirm").is_some(), "settings.js 读 o.policy.web_confirm");
        assert!(v["folders"][0].get("root_id").is_some());
    }

    #[test]
    fn 旧版_policy_json_无上限字段仍可读() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("policy.json");
        fs::write(&p, r#"{"modes":{"r_a":"ro"},"preview":{"r_a":"always"}}"#).unwrap();
        let f = PolicyFile::load_from(&p).unwrap();
        assert_eq!(f.preview_limit_mb, None, "缺字段 = 用默认档");
        assert_eq!(f.preview.get("r_a").map(String::as_str), Some("always"));
    }

    #[test]
    fn 授权请求允许_追加不覆盖_且空选择被拒() {
        let e = env(2);
        let mut f = file_with(&[(A, &[&e.dirs[0]])], &[]);
        assert!(apply_auth_grant(&mut f, &e.dirs, Some(A), B, &[]).is_err(), "至少勾一个才可允许");
        assert!(f.grants.as_ref().unwrap().get(B).is_none(), "被拒后不得留下半截授权");
        apply_auth_grant(&mut f, &e.dirs, Some(A), B, &[rid(&e.dirs[1])]).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.grants.get(A).unwrap(), &vec![rid(&e.dirs[0])], "A 不受影响");
        assert_eq!(p.grants.get(B).unwrap(), &vec![rid(&e.dirs[1])]);
        assert!(f.agents.contains(&B.to_string()), "B 进入候选集合，之后设置窗可勾");
    }

    #[test]
    fn 授权请求选了不存在的目录_整体失败不半写() {
        let e = env(1);
        let mut f = file_with(&[(A, &[&e.dirs[0]])], &[]);
        let before = f.clone();
        let r = apply_auth_grant(&mut f, &e.dirs, Some(A), B, &[rid(&e.dirs[0]), "r_ghost0000000".into()]);
        assert!(r.is_err());
        assert_eq!(f, before, "校验失败时文件对象必须原样不动（含不得记住 B）");
    }

    #[test]
    fn 视图_候选助手含凭据执行体与已知集合() {
        let e = env(1);
        let mut f = PolicyFile::default();
        f.agents.push(B.into());
        let v = view_of(&e.dirs, &f, Some(A));
        assert_eq!(v.agents, vec![A.to_string(), B.to_string()]);
        assert_eq!(v.folders.len(), 1);
        assert_eq!(v.folders[0].agents, vec![A.to_string()]);
        assert_eq!(v.folders[0].mode, "rw");
        assert_eq!(v.folders[0].upload, "ask");
    }

    #[test]
    fn 视图_只有一个助手时候选只有一个() {
        let e = env(1);
        let v = view_of(&e.dirs, &PolicyFile::default(), Some(A));
        assert_eq!(v.agents.len(), 1, "UI 据此隐藏「可以使用的助手」行");
    }

    #[test]
    fn 首次加目录且不授权任何助手_不被默认口径自动给凭据执行体() {
        // grants 仍为 None（用户从没配过）时加第一个目录并选择"谁都不给"：
        // 默认口径会把它整个给凭据执行体——必须在新增前固化，否则"没勾"等于"全给"
        let e = env(1);
        let mut f = PolicyFile::default();
        assert!(f.grants.is_none());
        grant_new_root(&mut f, &e.dirs, Some(A), &rid(&e.dirs[0]), None).unwrap();
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert_eq!(p.authorize(&scope(A, None), "x.txt", false).unwrap_err(), GateError::ActorNotGranted);
    }

    #[test]
    fn 未登录时加目录_登录后默认归凭据执行体() {
        // 2026-10-07 真机：先加「报销」再登录 → grants 被固化成 {} → 网页「未授权」、派活 ACTOR_NOT_GRANTED。
        // 未登录（无默认执行体）时不应固化，登录后默认口径让凭据执行体拿到全部目录。
        let e = env(1);
        let mut f = PolicyFile::default();
        grant_new_root(&mut f, &e.dirs, None, &rid(&e.dirs[0]), None).unwrap();
        assert!(f.grants.is_none(), "未登录不得固化空 grants");
        let p = Policy::build(&e.dirs, &f, Some(A));
        assert!(p.authorize(&scope(A, None), "x.txt", false).is_ok());
    }

    #[test]
    fn 原子写_读回不一致必须报错() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("policy.json");
        let mut f = PolicyFile::default();
        f.modes.insert("r_a".into(), "ro".into());
        // 读回时拿到被篡改的内容（例如同步盘/杀软把文件改写）→ 必须报错，不能让用户以为收紧已生效
        let r = f.save_to_with(&p, |_| Ok(PolicyFile::default()));
        assert!(r.unwrap_err().contains("读回与写入不一致"));
        // 读回失败同样报错
        assert!(f.save_to_with(&p, |_| Err("io".into())).is_err());
    }

    #[test]
    fn 目标是目录_rename失败_报错() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("policy.json");
        fs::create_dir_all(&target).unwrap();
        assert!(PolicyFile::default().save_to(&target).is_err());
    }
}
