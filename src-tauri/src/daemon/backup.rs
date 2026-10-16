// src-tauri/src/daemon/backup.rs
//! 备份模块（闸③）：写/删操作前快照原文件，支持回滚与定期清理。
//!
//! 备份根目录：`<workspace>/.hanako-backup/<timestamp>/`
//! 每次 snapshot 生成一个带时间戳的子目录，并在其中写入 `.meta.json`。
//! 回滚时依据 `was_new` 语义：新建文件 → 删除；已有文件 → 从备份恢复。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// 备份元信息，随 snapshot 写入 `.meta.json`，也通过 `rollback` 消费。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMeta {
    /// 操作类型："write" | "edit" | "delete"
    pub op: String,
    /// 原文件相对路径（仅供展示/日志，不用于回滚寻址）
    pub rel_path: String,
    /// 是否新建文件（回滚即删）
    pub was_new: bool,
    pub lease_id: String,
    pub task_id: String,
    /// 备份文件绝对路径。
    /// 仅当 was_new=false 时磁盘上真实存在；was_new=true 时该路径未写入（回滚走 target_path 删除分支）
    pub backup_path: PathBuf,
    /// 原文件绝对路径，用于回滚时寻址目标（避免相对路径在不同 CWD 下失效）
    pub target_path: PathBuf,
    pub timestamp: String,
}

/// 备份操作失败原因。
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup failed: {0}")]
    Failed(String),
    #[error("rollback failed: {0}")]
    RollbackFailed(String),
}

/// 备份保留天数（spec：保留最近 N 天，默认 7）。
pub const BACKUP_RETENTION_DAYS: u32 = 7;
/// 清理节流：距上次清理短于此间隔则跳过（避免每次写操作都扫一遍备份目录）。
const CLEANUP_THROTTLE: Duration = Duration::from_secs(3600);

/// 备份管理器，持有备份根目录路径。
pub struct BackupManager {
    /// 备份根目录：`<workspace>/.hanako-backup`
    backup_root: PathBuf,
    /// 上次清理时刻（节流用；BackupManager 按 workspace 每次写操作新建，故实际上是「每任务最多清一次」）
    last_cleanup: std::sync::Mutex<Option<std::time::Instant>>,
    /// 保留天数（生产恒为 [`BACKUP_RETENTION_DAYS`]；测试可覆盖）
    retention_days: u32,
}

impl BackupManager {
    /// 构造备份管理器，指向工作区根目录下的 `.hanako-backup` 子目录。
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            backup_root: workspace_root.join(".hanako-backup"),
            last_cleanup: std::sync::Mutex::new(None),
            retention_days: BACKUP_RETENTION_DAYS,
        }
    }

    /// 测试专用：覆盖保留天数（验证 snapshot 顺带清理的行为）。
    #[cfg(test)]
    fn new_for_test(workspace_root: &Path, retention_days: u32) -> Self {
        let mut m = Self::new(workspace_root);
        m.retention_days = retention_days;
        m
    }

    /// 节流到 [`CLEANUP_THROTTLE`] 一次的 [`Self::cleanup_old`]（保留 [`BACKUP_RETENTION_DAYS`] 天）。
    fn maybe_cleanup_old(&self) {
        let mut last = self.last_cleanup.lock().unwrap();
        if last.map(|t| t.elapsed() < CLEANUP_THROTTLE).unwrap_or(false) {
            return;
        }
        *last = Some(std::time::Instant::now());
        drop(last);
        self.cleanup_old(self.retention_days);
    }

    /// 快照目标文件，返回备份元信息。
    ///
    /// # 参数
    /// - `target`: 原文件绝对路径（写操作前调用，target 可能尚不存在）
    /// - `op`: 操作类型，如 "write" / "edit" / "delete"
    /// - `rel_path`: 原文件相对路径（仅日志/展示用）
    /// - `task_id`: 关联任务 ID
    /// - `lease_id`: 关联租约 ID
    pub fn snapshot(
        &self,
        target: &Path,
        op: &str,
        rel_path: &str,
        task_id: &str,
        lease_id: &str,
    ) -> Result<BackupMeta, BackupError> {
        // 审核 P2「备份从不清理」：cleanup_old 曾无调用方，`.hanako-backup` 只增不减撑爆磁盘。
        // 在 snapshot 入口顺带清理（节流：距上次清理 <1h 跳过，避免每次写都扫目录）。
        // 清理失败不阻断备份（备份是写操作的安全网，不能因子任务失败而拒主流程）。
        self.maybe_cleanup_old();
        // 调用方约定：target 必须为绝对路径，回滚时 target_path 依赖绝对路径实现 CWD 无关性
        debug_assert!(
            target.is_absolute(),
            "snapshot 的 target 参数必须为绝对路径（回滚依赖绝对寻址）"
        );

        // 时间戳格式中时间部分用连字符间隔，以兼容 Windows 路径命名规范
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H-%M-%S%.3fZ")
            .to_string();
        let backup_dir = self.backup_root.join(&timestamp);
        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| BackupError::Failed(e.to_string()))?;

        let was_new = !target.exists();

        // 备份文件路径：<backup_dir>/<rel_path>（保留子目录结构）
        let backup_path = backup_dir.join(rel_path);
        if let Some(parent) = backup_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BackupError::Failed(e.to_string()))?;
        }

        // 已有文件才需要复制快照；新建文件快照目录仅作存在记录
        if !was_new {
            std::fs::copy(target, &backup_path)
                .map_err(|e| BackupError::Failed(e.to_string()))?;
        }

        let meta = BackupMeta {
            op: op.to_string(),
            rel_path: rel_path.to_string(),
            was_new,
            lease_id: lease_id.to_string(),
            task_id: task_id.to_string(),
            backup_path,
            // 存储绝对路径，回滚时可跨 CWD 正确寻址
            target_path: target.to_path_buf(),
            timestamp,
        };

        // 将元信息持久化到 .meta.json，供外部审计与跨进程回滚使用
        let meta_path = backup_dir.join(".meta.json");
        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|e| BackupError::Failed(e.to_string()))?;
        std::fs::write(&meta_path, meta_json)
            .map_err(|e| BackupError::Failed(e.to_string()))?;

        Ok(meta)
    }

    /// 回滚到 snapshot 之前的状态。
    ///
    /// - `was_new=true`：目标文件由本次写操作新建 → 回滚即删除
    /// - `was_new=false`：目标文件原已存在 → 从 backup_path 恢复
    pub fn rollback(&self, meta: &BackupMeta) -> Result<(), BackupError> {
        if meta.was_new {
            // 新建文件回滚 = 删除（用绝对路径 target_path，不依赖 CWD）
            if meta.target_path.exists() {
                std::fs::remove_file(&meta.target_path)
                    .map_err(|e| BackupError::RollbackFailed(e.to_string()))?;
            }
        } else {
            // 已存在文件回滚 = 从备份恢复到原始绝对路径
            std::fs::copy(&meta.backup_path, &meta.target_path)
                .map_err(|e| BackupError::RollbackFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// 清理超过 `days` 天的备份目录。
    ///
    /// 使用文件系统 mtime 判断年龄，而非解析目录名时间戳（解析有歧义且脆弱）。
    pub fn cleanup_old(&self, days: u32) {
        // 系统时钟早于 UNIX_EPOCH 时（极罕见），降级为安全删除所有哨兵值
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(days as u64 * 86_400))
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let entries = match std::fs::read_dir(&self.backup_root) {
            Ok(e) => e,
            Err(_) => return, // 备份根目录尚不存在，静默返回
        };

        for entry in entries.flatten() {
            // 只处理目录（跳过 .meta.json 等杂文件）
            if !entry.path().is_dir() {
                continue;
            }
            // 取目录 mtime；失败则保守跳过（不误删）
            let modified = match entry.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if modified < cutoff {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 验证：对已存在的文件执行 snapshot，备份文件应存在且内容一致。
    #[test]
    fn 备份已存在文件() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("a.txt");
        fs::write(&target, "original").unwrap();

        let mgr = BackupManager::new(root);
        let meta = mgr
            .snapshot(&target, "write", "a.txt", "task1", "lease1")
            .unwrap();

        assert!(!meta.was_new, "已存在文件应 was_new=false");
        assert!(
            meta.backup_path.exists(),
            "备份文件应已写入 backup_path"
        );
        assert_eq!(
            fs::read_to_string(&meta.backup_path).unwrap(),
            "original",
            "备份内容应与原文件一致"
        );
        // target_path 应为绝对路径
        assert!(meta.target_path.is_absolute(), "target_path 应为绝对路径");
        assert_eq!(meta.target_path, target);
    }

    /// 验证：新建文件 snapshot 后，rollback 应删除该文件（was_new=true 语义）。
    #[test]
    fn 新建文件回滚即删() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("new.txt");

        let mgr = BackupManager::new(root);
        let meta = mgr
            .snapshot(&target, "write", "new.txt", "task1", "lease1")
            .unwrap();

        assert!(meta.was_new, "文件不存在时应 was_new=true");

        // 模拟写操作之后创建了文件
        fs::write(&target, "new content").unwrap();

        // 回滚应删除该文件
        mgr.rollback(&meta).unwrap();
        assert!(!target.exists(), "rollback 后新建文件应被删除");
    }

    /// 验证：cleanup_old(days=0) 删除刚创建的备份目录（任何 mtime < now）。
    #[test]
    fn cleanup_old_零天删除所有() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("x.txt");
        fs::write(&target, "data").unwrap();

        let mgr = BackupManager::new(root);
        mgr.snapshot(&target, "write", "x.txt", "t1", "l1").unwrap();

        // days=0 → cutoff=now，任何已有 mtime 均 < cutoff
        mgr.cleanup_old(0);

        // 备份子目录应已被删除（backup_root 可能仍存在但应为空）
        let remaining_dirs: Vec<_> = fs::read_dir(root.join(".hanako-backup"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        assert!(
            remaining_dirs.is_empty(),
            "days=0 后备份目录应全部被清理"
        );
    }

    /// 验证：cleanup_old(days=9999) 保留刚创建的备份目录。
    #[test]
    fn cleanup_old_超长保留期不删除() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("y.txt");
        fs::write(&target, "data").unwrap();

        let mgr = BackupManager::new(root);
        mgr.snapshot(&target, "write", "y.txt", "t1", "l1").unwrap();

        mgr.cleanup_old(9999);

        // 备份目录应仍存在
        let remaining_dirs: Vec<_> = fs::read_dir(root.join(".hanako-backup"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        assert!(
            !remaining_dirs.is_empty(),
            "days=9999 后备份目录不应被删除"
        );
    }

    /// 审核 P2「备份从不清理」：snapshot 入口应顺带调 cleanup_old。
    /// 用 days=0 的测试专用构造（保留 0 天 = 清掉所有旧备份），验证 snapshot 后旧备份被清、新备份保留。
    #[test]
    fn snapshot_顺带清理超期备份() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("z.txt");
        fs::write(&target, "data").unwrap();

        // 先造一个旧备份目录（内容无所谓，cleanup_old 按 mtime 判）
        let backup_root = root.join(".hanako-backup");
        let old_dir = backup_root.join("2000-01-01T00-00-00.000Z");
        fs::create_dir_all(&old_dir).unwrap();

        // days=0：cutoff=now，任何已有 mtime 均 < cutoff → 旧备份必被清
        let mgr = BackupManager::new_for_test(root, 0);
        mgr.snapshot(&target, "write", "z.txt", "t1", "l1").unwrap();

        assert!(!old_dir.exists(), "超期备份应被 snapshot 顺带清理");
        let dirs: Vec<_> = fs::read_dir(&backup_root).unwrap().flatten().filter(|e| e.path().is_dir()).collect();
        assert_eq!(dirs.len(), 1, "应只剩本次 snapshot 的备份目录");
    }
}
