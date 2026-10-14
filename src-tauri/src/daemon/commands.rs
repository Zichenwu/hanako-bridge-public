// src-tauri/src/daemon/commands.rs
//! 原生窗口（引导 / 设置窗 / 授权请求弹窗）背后的"存储层"函数。
//!
//! Tauri 命令（lib.rs）只做参数转发；所有读改写逻辑在这里，参数里显式带
//! `workspaces.json` / `policy.json` 的路径，所以能用临时目录做单测，不碰真实 HOME。
//!
//! 统一流程：读 policy.json（损坏即报错，不覆盖）→ 改 → 原子写 + 读回校验。
//! 任何一步失败都返回 Err，磁盘保持原样，窗口据此提示「没保存成功」。
//!
//! 放宽权限（加目录 / 看和改 / 一直允许上云 / 授权助手）只能从这里走——
//! 网页侧没有任何路径能到达这些函数（故事 20）。

use std::path::{Path, PathBuf};

use super::policy::{self, PolicyFile, PolicyView, RootMode};
use super::register::root_id_for;

/// 两个存储文件的位置。
#[derive(Debug, Clone)]
pub struct Paths {
    pub workspaces: PathBuf,
    pub policy: PathBuf,
}

impl Paths {
    /// 真实位置：`~/.hanako-tauri/{workspaces,policy}.json`。
    pub fn real() -> Result<Self, String> {
        let ws = super::workspace::workspaces_json_path().ok_or("无法确定 home 目录")?;
        let po = PolicyFile::path().ok_or("无法确定 home 目录")?;
        Ok(Self { workspaces: ws, policy: po })
    }
}

/// 读授权目录列表（canonicalize 后、去重、过滤不存在）。
///
/// 真实运行时还会并入环境变量 `HANA_LOCAL_WORKSPACES`（与 daemon 同口径）；
/// `Paths` 显式传入时只读该文件，便于测试隔离。
pub fn read_dirs(paths: &Paths, include_env: bool) -> Vec<PathBuf> {
    let mut raw: Vec<PathBuf> = Vec::new();
    if include_env {
        if let Ok(e) = std::env::var("HANA_LOCAL_WORKSPACES") {
            raw.extend(e.split(',').filter(|s| !s.trim().is_empty()).map(|s| PathBuf::from(s.trim())));
        }
    }
    if let Ok(data) = std::fs::read_to_string(&paths.workspaces) {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&data) {
            raw.extend(list.into_iter().map(PathBuf::from));
        }
    }
    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .filter_map(|p| p.canonicalize().ok())
        .filter(|p| p.is_dir() && seen.insert(p.clone()))
        .collect()
}

fn save_dirs(paths: &Paths, dirs: &[PathBuf]) -> Result<(), String> {
    let strs: Vec<String> = dirs.iter().map(|p| p.to_string_lossy().to_string()).collect();
    if let Some(dir) = paths.workspaces.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let data = serde_json::to_string_pretty(&strs).map_err(|e| e.to_string())?;
    let tmp = paths.workspaces.with_extension("json.tmp");
    std::fs::write(&tmp, &data).map_err(|e| format!("写临时文件失败: {e}"))?;
    std::fs::rename(&tmp, &paths.workspaces).map_err(|e| format!("rename 失败: {e}"))?;
    Ok(())
}

/// 设置窗 / 引导的整体视图。
pub fn get_view(paths: &Paths, default_agent: Option<&str>, include_env: bool) -> Result<PolicyView, String> {
    let file = PolicyFile::load_from(&paths.policy)?;
    Ok(policy::view_of(&read_dirs(paths, include_env), &file, default_agent))
}

/// 新增授权目录。`grant_to` = 初始授权的助手（引导默认只给登录时的助手）。
///
/// 已存在的目录（canonicalize 后相同）幂等返回其 rootId，不改任何配置——
/// 否则"重复添加"会悄悄覆盖用户已设好的模式。
pub fn add_folder(
    paths: &Paths,
    dir: &Path,
    default_agent: Option<&str>,
    grant_to: Option<&str>,
    include_env: bool,
) -> Result<String, String> {
    let canonical = dir.canonicalize().map_err(|e| format!("无法访问该文件夹: {e}"))?;
    if !canonical.is_dir() {
        return Err("请选择文件夹".into());
    }
    reject_too_broad(&canonical)?;
    let id = root_id_for(&canonical);
    let mut dirs = read_dirs(paths, include_env);
    if dirs.iter().any(|d| root_id_for(d) == id) {
        return Ok(id);
    }
    let mut file = PolicyFile::load_from(&paths.policy)?;
    dirs.push(canonical);
    policy::grant_new_root(&mut file, &dirs, default_agent, &id, grant_to)?;
    // 先写策略再写目录列表：中途失败时"有授权无目录"是无害的（孤儿授权被 build 过滤），
    // 反过来"有目录无授权配置"会让默认口径把它整个给凭据执行体。
    file.save_to(&paths.policy)?;
    // 落盘集合 = 文件里原有的 + 本次新增的；env 来源的目录不固化成永久授权
    let mut persisted = read_dirs(paths, false);
    persisted.push(dirs.last().cloned().expect("刚 push 过"));
    save_dirs(paths, &persisted)?;
    Ok(id)
}

/// 移除授权目录，并清理它的全部配置（见 `policy::forget_root`）。
pub fn remove_folder(paths: &Paths, root_id: &str, default_agent: Option<&str>, include_env: bool) -> Result<(), String> {
    let dirs = read_dirs(paths, include_env);
    if !dirs.iter().any(|d| root_id_for(d) == root_id) {
        return Err(format!("目录不存在: {root_id}"));
    }
    let mut file = PolicyFile::load_from(&paths.policy)?;
    // 先固化：没显式 grants 时直接 forget 会留下 None，之后默认口径又把别的目录给凭据执行体——
    // 这点本来就是默认口径，不变。但要保证用户此前看到的授权关系不因移除而改变，所以固化。
    if file.grants.is_none() {
        file.grants = Some(policy::Policy::build(&dirs, &file, default_agent).grants);
    }
    policy::forget_root(&mut file, root_id);
    file.save_to(&paths.policy)?;
    let kept: Vec<PathBuf> = read_dirs(paths, false).into_iter().filter(|d| root_id_for(d) != root_id).collect();
    save_dirs(paths, &kept)?;
    Ok(())
}

/// 拒绝明显过宽的目录：根目录 / 整个用户主目录 / 应用自身数据目录。引导文案"不要选整个用户目录"是建议，
/// 这里把最危险的几种直接挡掉——助手拿到整个 home 等于交出 ssh 密钥以外的一切。
fn reject_too_broad(canonical: &Path) -> Result<(), String> {
    if canonical.parent().is_none() {
        return Err("不能选择磁盘根目录，请选具体的工作文件夹".into());
    }
    if let Some(home) = dirs_next::home_dir().and_then(|h| h.canonicalize().ok()) {
        if canonical == home {
            return Err("不能选择整个用户目录，请选具体的工作文件夹".into());
        }
        // 审核 P2「授权根可选 ~/.hanako-tauri」：应用自身数据目录（钥匙串引用 / 审计日志 /
        // 策略 / 备份）被授权后，agent 能读到自己的审计与策略、甚至备份里的敏感文件副本。
        // 挡掉它自身与其任意子目录。
        let app_data = home.join(".hanako-tauri");
        if canonical == app_data || canonical.starts_with(&app_data) {
            return Err("不能选择 Hanako 自身的数据目录".into());
        }
    }
    Ok(())
}

pub fn set_mode(paths: &Paths, root_id: &str, mode: &str, include_env: bool) -> Result<(), String> {
    let dirs = read_dirs(paths, include_env);
    let mut file = PolicyFile::load_from(&paths.policy)?;
    policy::set_mode(&mut file, &dirs, root_id, RootMode::from_wire(mode))?;
    file.save_to(&paths.policy)
}

pub fn set_agent_access(
    paths: &Paths,
    root_id: &str,
    agent: &str,
    allowed: bool,
    default_agent: Option<&str>,
    include_env: bool,
) -> Result<(), String> {
    if !super::auth_request::is_agent_id(agent) {
        return Err(format!("不是合法的助手 ID: {agent}"));
    }
    let dirs = read_dirs(paths, include_env);
    let mut file = PolicyFile::load_from(&paths.policy)?;
    policy::set_agent_access(&mut file, &dirs, default_agent, root_id, agent, allowed)?;
    file.save_to(&paths.policy)
}

pub fn set_upload(paths: &Paths, root_id: &str, pref: &str, include_env: bool) -> Result<(), String> {
    let dirs = read_dirs(paths, include_env);
    let mut file = PolicyFile::load_from(&paths.policy)?;
    policy::set_upload(&mut file, &dirs, root_id, pref)?;
    file.save_to(&paths.policy)
}

/// 设置某目录的**网页预览**偏好（"ask" | "always"）。
///
/// 放宽方向（`always`）只能从这里发生——这是本机设置窗唯一的入口，网页侧没有任何路径能到达
/// （网页只能发 `trust_revoke` 把它收回成 `ask`，见 `remote_frames::apply_trust_revoke`）。
/// 与 [`set_upload`] 写两个独立字段：开预览的永久允许不得带动上传。
pub fn set_preview(paths: &Paths, root_id: &str, pref: &str, include_env: bool) -> Result<(), String> {
    let dirs = read_dirs(paths, include_env);
    let mut file = PolicyFile::load_from(&paths.policy)?;
    policy::set_preview(&mut file, &dirs, root_id, pref)?;
    file.save_to(&paths.policy)
}

/// 设置预览大小上限档位（MB，只认 50/100/200）。全局一个值，不按目录。
pub fn set_preview_limit(paths: &Paths, mb: u64) -> Result<(), String> {
    let mut file = PolicyFile::load_from(&paths.policy)?;
    policy::set_preview_limit(&mut file, mb)?;
    file.save_to(&paths.policy)
}

/// 设置给人看的电脑名；空串 = 恢复默认（删字段）。返回清洗后的值。
pub fn set_display_name(paths: &Paths, name: &str) -> Result<Option<String>, String> {
    let mut file = PolicyFile::load_from(&paths.policy)?;
    file.display_name = policy::clean_display_name(name);
    file.save_to(&paths.policy)?;
    Ok(file.display_name)
}

/// 读当前显示名（文件损坏 / 未设 → None）。
pub fn display_name(paths: &Paths) -> Option<String> {
    PolicyFile::load_from(&paths.policy).ok().and_then(|f| f.display_name)
}

/// 授权成功后：把确认页上的名字当**显示名**兜底（身份恒为主机名，见 `DaemonConfig::from_store`）。
///
/// - 设置窗已改过名 → 不动（用户在本机的选择优先）
/// - 名字与默认显示名（主机名去 `node_`）或机器名本身相同 → 不写（避免把默认值固化成自定义名）
///
/// 返回是否写入。
pub fn adopt_auth_name_as_display(paths: &Paths, auth_name: Option<&str>, machine: &str) -> Result<bool, String> {
    let Some(name) = auth_name.and_then(policy::clean_display_name) else { return Ok(false) };
    if name == machine || name == machine.trim_start_matches("node_") {
        return Ok(false);
    }
    let mut file = PolicyFile::load_from(&paths.policy)?;
    if file.display_name.is_some() {
        return Ok(false);
    }
    file.display_name = Some(name);
    file.save_to(&paths.policy)?;
    Ok(true)
}

pub fn set_web_confirm(paths: &Paths, on: bool) -> Result<(), String> {
    let mut file = PolicyFile::load_from(&paths.policy)?;
    file.web_confirm = on;
    file.save_to(&paths.policy)
}

/// 备份占用（字节）：遍历所有授权目录下的 `.hanako-backup`。
pub fn backup_size(paths: &Paths, include_env: bool) -> u64 {
    fn dir_size(p: &Path) -> u64 {
        let Ok(rd) = std::fs::read_dir(p) else { return 0 };
        rd.flatten()
            .map(|e| match e.file_type() {
                Ok(t) if t.is_dir() => dir_size(&e.path()),
                Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => 0, // 符号链接不跟随
            })
            .sum()
    }
    read_dirs(paths, include_env).iter().map(|d| dir_size(&d.join(".hanako-backup"))).sum()
}

/// 把字节数格式化成 "128 MB" / "12 KB" / "0 KB"。
pub fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.0} MB", b / (KB * KB))
    } else {
        format!("{:.0} KB", (b / KB).max(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::policy::{GateError, Policy, TaskScope};

    const A: &str = "bi--zhangsan";
    const B: &str = "wallet--zhangsan";

    struct Env {
        _home: tempfile::TempDir,
        paths: Paths,
    }

    fn env() -> Env {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths {
            workspaces: home.path().join(".hanako-tauri/workspaces.json"),
            policy: home.path().join(".hanako-tauri/policy.json"),
        };
        Env { _home: home, paths }
    }

    fn folder() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().canonicalize().unwrap();
        (d, p)
    }

    #[test]
    fn 电脑显示名_落盘读回_空串恢复默认_不碰其它策略() {
        let e = env();
        set_web_confirm(&e.paths, true).unwrap();
        assert_eq!(display_name(&e.paths), None);
        assert_eq!(set_display_name(&e.paths, "  Alice 的 MacBook\u{7} ").unwrap().as_deref(), Some("Alice 的 MacBook"));
        assert_eq!(display_name(&e.paths).as_deref(), Some("Alice 的 MacBook"));
        let raw = std::fs::read_to_string(&e.paths.policy).unwrap();
        assert!(raw.contains("\"displayName\""), "字段名须为 camelCase displayName");
        assert!(PolicyFile::load_from(&e.paths.policy).unwrap().web_confirm, "改名不得冲掉其它策略");
        assert_eq!(set_display_name(&e.paths, "   ").unwrap(), None);
        assert_eq!(display_name(&e.paths), None);
        assert!(!std::fs::read_to_string(&e.paths.policy).unwrap().contains("displayName"), "恢复默认 = 删字段");
    }

    #[test]
    fn 授权页名字_只作显示名兜底_不覆盖本机改名_不固化默认值() {
        let e = env();
        // 与默认显示名相同 → 不写
        assert!(!adopt_auth_name_as_display(&e.paths, Some("AliceMac"), "node_AliceMac").unwrap());
        assert!(!adopt_auth_name_as_display(&e.paths, Some("node_AliceMac"), "node_AliceMac").unwrap());
        assert!(!adopt_auth_name_as_display(&e.paths, None, "node_AliceMac").unwrap());
        assert_eq!(display_name(&e.paths), None);
        // 自定义名 → 写成显示名
        assert!(adopt_auth_name_as_display(&e.paths, Some("Alice 的 Mac"), "node_AliceMac").unwrap());
        assert_eq!(display_name(&e.paths).as_deref(), Some("Alice 的 Mac"));
        // 已有显示名（设置窗改过）→ 不覆盖
        set_display_name(&e.paths, "本机改的").unwrap();
        assert!(!adopt_auth_name_as_display(&e.paths, Some("另一个"), "node_AliceMac").unwrap());
        assert_eq!(display_name(&e.paths).as_deref(), Some("本机改的"));
    }

    #[test]
    fn 电脑显示名_超长按字符截到32() {
        let e = env();
        let n = set_display_name(&e.paths, &"电".repeat(40)).unwrap().unwrap();
        assert_eq!(n.chars().count(), 32);
    }

    fn scope(a: &str) -> TaskScope {
        TaskScope { agent_id: a.into(), root_id: None }
    }

    fn effective(e: &Env) -> Policy {
        let file = PolicyFile::load_from(&e.paths.policy).unwrap();
        Policy::build(&read_dirs(&e.paths, false), &file, Some(A))
    }

    #[test]
    fn 授权根拒绝_应用自身数据目录及其子目录() {
        // 审核 P2「授权根可选 ~/.hanako-tauri」：应用自身数据目录被授权后，
        // agent 能读到审计日志 / 策略 / 备份里的敏感文件副本。
        let e = env();
        let home = dirs_next::home_dir().unwrap();
        let app_data = home.join(".hanako-tauri");
        std::fs::create_dir_all(app_data.join("audit")).unwrap();
        for bad in [app_data.clone(), app_data.join("audit")] {
            let r = add_folder(&e.paths, &bad, Some(A), Some(A), false);
            assert!(r.is_err(), "{bad:?} 不应可授权");
            assert!(r.unwrap_err().contains("Hanako 自身的数据目录"), "错误文案应指明原因");
        }
    }

    #[test]
    fn 引导第一个目录_只授权登录时的助手_且写落盘() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        assert_eq!(id, root_id_for(&dir));
        let p = effective(&e);
        assert!(p.authorize(&scope(A), "x.txt", true).is_ok());
        assert_eq!(p.authorize(&scope(B), "x.txt", false).unwrap_err(), GateError::ActorNotGranted);
        // 重启后（重新读盘）仍然成立
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders.len(), 1);
    }

    #[test]
    fn 重复添加同一目录_幂等且不覆盖已设的模式() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        set_mode(&e.paths, &id, "ro", false).unwrap();
        let id2 = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        assert_eq!(id, id2);
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders[0].mode, "ro");
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders.len(), 1);
    }

    #[test]
    fn 新增第二个目录_不被默认口径自动塞给凭据执行体() {
        let e = env();
        let (_d1, d1) = folder();
        let (_d2, d2) = folder();
        add_folder(&e.paths, &d1, Some(A), Some(A), false).unwrap();
        let id2 = add_folder(&e.paths, &d2, Some(A), None, false).unwrap();
        let p = effective(&e);
        let r = p.authorize(&TaskScope { agent_id: A.into(), root_id: Some(id2) }, "x.txt", false);
        assert_eq!(r.unwrap_err(), GateError::RootRevoked);
    }

    #[test]
    fn 拒绝磁盘根与整个用户主目录() {
        let e = env();
        assert!(add_folder(&e.paths, Path::new("/"), Some(A), Some(A), false).is_err());
        if let Some(home) = dirs_next::home_dir() {
            if home.is_dir() {
                assert!(add_folder(&e.paths, &home, Some(A), Some(A), false).is_err());
            }
        }
        assert!(!e.paths.workspaces.exists() && !e.paths.policy.exists(), "被拒后不得留下任何文件");
    }

    #[test]
    fn 不是文件夹_或不存在_报错() {
        let e = env();
        let (_d, dir) = folder();
        let f = dir.join("a.txt");
        std::fs::write(&f, "x").unwrap();
        assert!(add_folder(&e.paths, &f, Some(A), Some(A), false).is_err());
        assert!(add_folder(&e.paths, &dir.join("nope"), Some(A), Some(A), false).is_err());
    }

    /// 本机设置窗是「永久允许在网页预览」的**唯一**入口（本地文件预览 票 03）。
    /// 变异锁：让 `set_preview` 写 upload 字段 → 本用例红。
    #[test]
    fn 设置预览偏好_落盘且与上传互不影响() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();

        // 默认两个开关都是「每次问」
        let v = get_view(&e.paths, Some(A), false).unwrap();
        assert_eq!(v.folders[0].preview, "ask");
        assert_eq!(v.folders[0].upload, "ask");

        // 只开预览
        set_preview(&e.paths, &id, "always", false).unwrap();
        let v = get_view(&e.paths, Some(A), false).unwrap();
        assert_eq!(v.folders[0].preview, "always");
        assert_eq!(v.folders[0].upload, "ask", "开预览永久允许不得带动上传");

        // 再开上传，两者并存且各自独立
        set_upload(&e.paths, &id, "always", false).unwrap();
        let v = get_view(&e.paths, Some(A), false).unwrap();
        assert_eq!(v.folders[0].preview, "always");
        assert_eq!(v.folders[0].upload, "always");

        // 收回预览不影响上传
        set_preview(&e.paths, &id, "ask", false).unwrap();
        let v = get_view(&e.paths, Some(A), false).unwrap();
        assert_eq!(v.folders[0].preview, "ask");
        assert_eq!(v.folders[0].upload, "always");

        // 未知值报错，不静默放行
        assert!(set_preview(&e.paths, &id, "yes", false).is_err());
        assert!(set_preview(&e.paths, "r_ghost0000000", "always", false).is_err());
    }

    #[test]
    fn 移除目录_配置清干净_重新添加不继承旧权限() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        set_mode(&e.paths, &id, "rw", false).unwrap();
        set_upload(&e.paths, &id, "always", false).unwrap();
        remove_folder(&e.paths, &id, Some(A), false).unwrap();
        assert!(get_view(&e.paths, Some(A), false).unwrap().folders.is_empty());
        let file = PolicyFile::load_from(&e.paths.policy).unwrap();
        assert!(file.modes.is_empty() && file.upload.is_empty());
        // 重新添加：上云偏好回到"每次问"，助手授权需重新给
        let id2 = add_folder(&e.paths, &dir, Some(A), None, false).unwrap();
        assert_eq!(id, id2);
        let v = get_view(&e.paths, Some(A), false).unwrap();
        assert_eq!(v.folders[0].upload, "ask");
        assert!(v.folders[0].agents.is_empty());
    }

    #[test]
    fn 移除目录后该助手对它立刻REVOKED() {
        let e = env();
        let (_d1, d1) = folder();
        let (_d2, d2) = folder();
        let id1 = add_folder(&e.paths, &d1, Some(A), Some(A), false).unwrap();
        let id2 = add_folder(&e.paths, &d2, Some(A), Some(A), false).unwrap();
        remove_folder(&e.paths, &id1, Some(A), false).unwrap();
        let p = effective(&e);
        let r = p.authorize(&TaskScope { agent_id: A.into(), root_id: Some(id1) }, "x", false);
        assert_eq!(r.unwrap_err(), GateError::RootRevoked);
        assert!(p.authorize(&TaskScope { agent_id: A.into(), root_id: Some(id2) }, "x", false).is_ok());
    }

    #[test]
    fn 移除不存在的目录_报错且不动文件() {
        let e = env();
        let (_d, dir) = folder();
        add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        let before = std::fs::read_to_string(&e.paths.policy).unwrap();
        assert!(remove_folder(&e.paths, "r_ghost0000000", Some(A), false).is_err());
        assert_eq!(std::fs::read_to_string(&e.paths.policy).unwrap(), before);
    }

    #[test]
    fn 策略文件损坏_所有写操作都拒绝且不覆盖() {
        let e = env();
        let (_d, dir) = folder();
        std::fs::create_dir_all(e.paths.policy.parent().unwrap()).unwrap();
        std::fs::write(&e.paths.policy, "{ broken").unwrap();
        assert!(add_folder(&e.paths, &dir, Some(A), Some(A), false).is_err());
        assert!(set_web_confirm(&e.paths, true).is_err());
        assert!(get_view(&e.paths, Some(A), false).is_err());
        assert_eq!(std::fs::read_to_string(&e.paths.policy).unwrap(), "{ broken");
        assert!(!e.paths.workspaces.exists(), "策略没写成功就不该把目录写进去");
    }

    #[test]
    fn 设置助手授权_拒绝畸形助手ID() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        for bad in ["", "no-dash", "a--b/../c", "x--y z"] {
            assert!(set_agent_access(&e.paths, &id, bad, true, Some(A), false).is_err(), "{bad}");
        }
        set_agent_access(&e.paths, &id, B, true, Some(A), false).unwrap();
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders[0].agents.len(), 2);
    }

    #[test]
    fn 上云偏好只认ask与always() {
        let e = env();
        let (_d, dir) = folder();
        let id = add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        assert!(set_upload(&e.paths, &id, "yes", false).is_err());
        set_upload(&e.paths, &id, "always", false).unwrap();
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders[0].upload, "always");
        set_upload(&e.paths, &id, "ask", false).unwrap();
        assert_eq!(get_view(&e.paths, Some(A), false).unwrap().folders[0].upload, "ask");
    }

    #[test]
    fn 备份占用统计_不跟随符号链接() {
        let e = env();
        let (_d, dir) = folder();
        add_folder(&e.paths, &dir, Some(A), Some(A), false).unwrap();
        let b = dir.join(".hanako-backup/2026-01-01");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("a.bin"), vec![0u8; 3000]).unwrap();
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("huge.bin"), vec![0u8; 1_000_000]).unwrap();
            std::os::unix::fs::symlink(outside.path(), dir.join(".hanako-backup/evil")).unwrap();
        }
        assert_eq!(backup_size(&e.paths, false), 3000);
    }

    #[test]
    fn 字节数格式化() {
        assert_eq!(human_size(0), "0 KB");
        assert_eq!(human_size(2048), "2 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
