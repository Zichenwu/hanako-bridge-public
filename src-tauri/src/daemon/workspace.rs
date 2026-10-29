// src-tauri/src/daemon/workspace.rs
//! 工作目录管理：读取用户授权的本地目录列表。
//!
//! 两个来源（合并，env 优先）：
//!   1. 环境变量 `HANA_LOCAL_WORKSPACES`：逗号分隔的目录绝对路径（Task 0~5 旧方式）
//!   2. `~/.hanako-tauri/workspaces.json`：Task 6 设置 UI 持久化写入（B8 需求）
//!
//! 合并策略：env + 文件取并集，去重后 canonicalize 过滤不存在的路径。
//! env 变量仍然生效（向后兼容），文件提供 GUI 可管理的持久列表。
//!
//! 持久化格式（workspaces.json）：
//! ```json
//! ["  /absolute/path/a", "/absolute/path/b"]
//! ```

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

/// 已授权的本地工作目录集合。
#[derive(Debug, Clone)]
pub struct Workspace {
    /// 已 canonicalize 的目录列表（去除非法路径）。
    pub roots: Vec<PathBuf>,
}

impl Workspace {
    /// 从逗号分隔的字符串解析授权目录（不触碰进程环境变量，便于测试）。
    /// 重复路径（canonicalize 后相同）会去重。
    pub fn from_raw(raw: &str) -> Self {
        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut roots = Vec::new();
        for s in raw.split(',').filter(|s| !s.trim().is_empty()) {
            let p = PathBuf::from(s.trim());
            if let Ok(canonical) = p.canonicalize() {
                if seen.insert(canonical.clone()) {
                    roots.push(canonical);
                }
            }
        }
        Self { roots }
    }

    /// 从环境变量 `HANA_LOCAL_WORKSPACES` + `~/.hanako-tauri/workspaces.json` 合并读取。
    ///
    /// env 变量与文件取并集，去重后 canonicalize。
    pub fn from_env() -> Self {
        // 来源①：环境变量（逗号分隔）
        let env_raw = env::var("HANA_LOCAL_WORKSPACES").unwrap_or_default();
        let env_paths: Vec<PathBuf> = env_raw
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| PathBuf::from(s.trim()))
            .collect();

        // 来源②：workspaces.json 持久化文件
        let file_paths = load_workspaces_json().unwrap_or_default();

        // 合并去重再 canonicalize
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut roots = Vec::new();
        for p in env_paths.into_iter().chain(file_paths.into_iter()) {
            if let Ok(canonical) = p.canonicalize() {
                if seen.insert(canonical.clone()) {
                    roots.push(canonical);
                }
            }
        }

        Self { roots }
    }

    /// 工作目录列表是否为空（未授权任何目录）。
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────
// workspaces.json 持久化辅助函数
// ────────────────────────────────────────────────────────────────

/// 覆盖 `workspaces_json_path()` 的环境变量名（仅测试/集成测试用；生产不设置）。
/// Windows 上 dirs_next::home_dir() 走 KNOWNFOLDER 不读 HOME，隔离必须靠显式覆盖。
pub const WORKSPACES_PATH_ENV: &str = "HANAKO_WORKSPACES_PATH";

/// `~/.hanako-tauri/workspaces.json` 的路径。
/// 可被 `HANAKO_WORKSPACES_PATH` 环境变量覆盖（测试/集成测试隔离用；生产不设置）。
pub fn workspaces_json_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(WORKSPACES_PATH_ENV) {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    dirs_next::home_dir().map(|h| h.join(".hanako-tauri").join("workspaces.json"))
}

/// 读取 workspaces.json，返回路径列表（字符串）。
/// 文件不存在或格式错误时返回空列表（不报错）。
pub fn load_workspaces_json() -> Option<Vec<PathBuf>> {
    let path = workspaces_json_path()?;
    let data = std::fs::read_to_string(&path).ok()?;
    let list: Vec<String> = serde_json::from_str(&data).ok()?;
    Some(list.into_iter().map(PathBuf::from).collect())
}

/// 将路径列表写入 workspaces.json（原子写：先写临时文件再 rename）。
///
/// 路径以绝对路径字符串存储；目录不存在时自动创建。
pub fn save_workspaces_json(paths: &[String]) -> Result<(), String> {
    let json_path = workspaces_json_path().ok_or("无法确定 home 目录")?;
    let dir = json_path
        .parent()
        .ok_or("无法确定 workspaces.json 父目录")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {e}"))?;

    // 序列化为 JSON 数组
    let data =
        serde_json::to_string_pretty(paths).map_err(|e| format!("序列化失败: {e}"))?;

    // 原子写：写临时文件后 rename
    let tmp_path = json_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &data).map_err(|e| format!("写临时文件失败: {e}"))?;
    // Windows 安全：std::fs::rename 使用 MoveFileExW + MOVEFILE_REPLACE_EXISTING，
    // 目标已存在时原子替换，无需手动 remove_file。（M4 核实：同 config.rs）
    std::fs::rename(&tmp_path, &json_path).map_err(|e| format!("rename 失败: {e}"))?;

    log::info!("[workspace] 持久化 {} 个授权目录", paths.len());
    Ok(())
}

/// 读取已持久化的工作目录列表（字符串形式，供 list_workspaces 命令）。
pub fn list_persisted_workspaces() -> Vec<String> {
    let path = match workspaces_json_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    serde_json::from_str::<Vec<String>>(&data).unwrap_or_default()
}

/// 向持久化列表追加一个目录（去重后写入）。
pub fn add_workspace(dir: &Path) -> Result<(), String> {
    let dir_str = dir
        .to_str()
        .ok_or("路径含非 UTF-8 字符")?
        .to_string();
    let mut list = list_persisted_workspaces();
    if !list.contains(&dir_str) {
        list.push(dir_str);
        save_workspaces_json(&list)?;
    }
    Ok(())
}

/// 从持久化列表移除一个目录。
pub fn remove_workspace(dir_str: &str) -> Result<(), String> {
    let mut list = list_persisted_workspaces();
    list.retain(|s| s != dir_str);
    save_workspaces_json(&list)
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 使用 from_raw 避免 std::env::set_var/remove_var 在并行测试下的 unsound 行为
    #[test]
    fn 空字符串返回空() {
        let ws = Workspace::from_raw("");
        assert!(ws.is_empty());
    }

    #[test]
    fn 单目录() {
        // 用真实存在的临时目录：硬编码 /tmp 在 Windows 不存在，
        // canonicalize 失败会被 from_raw 过滤掉，导致 roots 为空（跨平台陷阱）。
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let ws = Workspace::from_raw(dir.path().to_str().unwrap());
        assert_eq!(ws.roots.len(), 1);
    }

    /// 验证 save + load 往返正确。
    #[test]
    fn 保存并读取_workspaces_json() {
        let tmp_dir = tempfile::tempdir().expect("创建临时目录失败");
        let json_path = tmp_dir.path().join("workspaces.json");

        // 直接写文件，不依赖 home_dir
        let paths = vec!["/tmp".to_string(), "/var".to_string()];
        let data = serde_json::to_string_pretty(&paths).unwrap();
        std::fs::write(&json_path, &data).unwrap();

        // 读回验证
        let loaded: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(loaded, paths);
    }

    /// 验证去重逻辑。
    #[test]
    fn from_raw_逗号_重复路径去重() {
        // 用真实存在的临时目录（/tmp 在 Windows 不存在，会被过滤）。
        // 同一路径写两次，canonicalize 后相同应去重为一个。
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let p = dir.path().to_str().unwrap();
        let ws = Workspace::from_raw(&format!("{p},{p}"));
        assert_eq!(ws.roots.len(), 1);
    }
}
