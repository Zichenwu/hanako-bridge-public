// src-tauri/src/daemon/tools/write.rs
//! 本地写工具实现：`local_write_file` / `local_edit_file` / `local_delete_file`。
//!
//! 四道闸（顺序不可调换）：
//!   闸① lease 校验 — 租约必须由服务端签发且未被消费
//!   闸② path 校验 — 路径越界/敏感路径拒绝
//!   闸③ backup — 快照备份，永远执行，不可绕过（红线：免确认≠免备份）
//!   闸④ approval — 用户确认策略，失败则回滚备份
//!
//! 写操作执行失败时同样回滚备份，确保磁盘状态一致。
//!
//! 审计：每次 execute_write 结束（成功或失败）后写一条 AuditEntry：
//!   - decision：approved / rejected（来自 approval 结果）
//!   - backup_path：备份路径（闸③完成后填入）
//!   这两个字段仅在 execute_write 内部才完整可用，故审计写在此处而非 execute_tool。

use std::sync::Arc;

use serde_json::Value;

use super::ToolResult;
use crate::daemon::approval::{ApprovalManager, Approver, WriteRequest};
use crate::daemon::audit::{AuditEntry, AuditLogger};
use crate::daemon::backup::BackupManager;
use crate::daemon::lease::{validate_scope, Lease, LeaseValidator};
use crate::daemon::policy::{Policy, TaskScope};

/// 写入或新建本地文件。
pub async fn local_write_file(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    approval_mgr: &ApprovalManager<Box<dyn Approver>>,
    audit: &Arc<AuditLogger>,
) -> ToolResult {
    execute_write(params, policy, lease, node_id, approval_mgr, audit, "write", |target, params| {
        let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
        std::fs::write(target, content).map_err(|e| e.to_string())
    })
    .await
}

/// 精确替换本地文件内容（old_string 必须唯一匹配）。
pub async fn local_edit_file(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    approval_mgr: &ApprovalManager<Box<dyn Approver>>,
    audit: &Arc<AuditLogger>,
) -> ToolResult {
    execute_write(params, policy, lease, node_id, approval_mgr, audit, "edit", |target, params| {
        let old_string = params
            .get("old_string")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let new_string = params
            .get("new_string")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let content = std::fs::read_to_string(target).map_err(|e| e.to_string())?;
        let match_count = content.matches(old_string).count();
        if match_count != 1 {
            return Err(format!(
                "old_string must match exactly once (found {})",
                match_count
            ));
        }
        let updated = content.replacen(old_string, new_string, 1);
        std::fs::write(target, updated).map_err(|e| e.to_string())
    })
    .await
}

/// 删除本地文件（移入备份区，非真删，可回滚）。
pub async fn local_delete_file(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    approval_mgr: &ApprovalManager<Box<dyn Approver>>,
    audit: &Arc<AuditLogger>,
) -> ToolResult {
    execute_write(params, policy, lease, node_id, approval_mgr, audit, "delete", |target, _params| {
        std::fs::remove_file(target).map_err(|e| e.to_string())
    })
    .await
}

/// 四道闸共享执行管线。
///
/// 按 lease → path → backup → approval → write 的顺序执行，
/// 任何一步失败都回滚已完成的副作用（备份回滚），保证磁盘状态一致。
///
/// 审计写在管线末尾，此时 decision / backup_path / ok / error 都已确定。
/// 早期失败（lease/path/backup 阶段）因尚无 decision，decision 字段置 None。
async fn execute_write<F>(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    approval_mgr: &ApprovalManager<Box<dyn Approver>>,
    audit: &Arc<AuditLogger>,
    op: &str,
    write_fn: F,
) -> ToolResult
where
    F: Fn(&std::path::Path, &Value) -> Result<(), String>,
{
    // 从 params 提取公共元数据（审计 / 备份共用）
    let agent_id = params
        .get("_agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let task_id = params
        .get("_task_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // 来源标注（票 07）：写类工具由模型派发（agent），网页浏览只走只读 local_list_dir，
    // 但统一从 params._origin 取、缺省 "agent"，与读类 / 搬运口径一致。
    let origin = params
        .get("_origin")
        .and_then(|v| v.as_str())
        .unwrap_or("agent")
        .to_string();

    // 没有授权目录时提前返回（无需审计，配置问题不是工具操作）
    if policy.is_empty() {
        return ToolResult::err(crate::daemon::policy::GateError::NoRoots.to_string());
    }

    if path.is_empty() {
        return ToolResult::err("path required".into());
    }

    // ── 闸①：lease 校验 ──
    let lease = match lease {
        Some(l) => l,
        None => {
            // lease 缺失：审计（无 decision / backup_path）
            let result = ToolResult::err("write operation requires lease".into());
            audit.log(&AuditEntry {
                ts: crate::daemon::audit::now_ts(),
                agent_id,
                origin: origin.clone(),
                tool: format!("local_{}_file", op),
                path,
                lease_id: None,
                task_id,
                decision: None,
                backup_path: None,
                ok: false,
                error: result.error.clone(),
            });
            return result;
        }
    };
    let lease_id = lease.lease_id.clone();

    // TODO(二期): 持久化 consumed 集合——当前每次新建 LeaseValidator，重放防护弱（一期可接受）
    let mut validator = LeaseValidator::new();
    if let Err(e) = validator.validate(&lease, node_id, "write_files") {
        let result = ToolResult::err(format!("lease validation failed: {}", e));
        audit.log(&AuditEntry {
            ts: crate::daemon::audit::now_ts(),
            agent_id,
            origin: origin.clone(),
            tool: format!("local_{}_file", op),
            path,
            lease_id: Some(lease_id),
            task_id,
            decision: None,
            backup_path: None,
            ok: false,
            error: result.error.clone(),
        });
        return result;
    }

    // ── 闸①b：lease 与任务帧声明的执行体 / 目录必须一致 ──
    let scope = TaskScope::from_params(params);
    if let Err(e) = validate_scope(&lease, &scope.agent_id, scope.root_id.as_deref()) {
        let result = ToolResult::err(format!("lease validation failed: {}", e));
        audit.log(&AuditEntry {
            ts: crate::daemon::audit::now_ts(),
            agent_id,
            origin: origin.clone(),
            tool: format!("local_{}_file", op),
            path,
            lease_id: Some(lease_id),
            task_id,
            decision: None,
            backup_path: None,
            ok: false,
            error: result.error.clone(),
        });
        return result;
    }

    // ── 闸②：本机策略复核（执行体授权 → 目录撤销 → 围栏 → 只读根）──
    let resolved = match policy.authorize(&scope, &path, true) {
        Ok(r) => r,
        Err(e) => {
            let result = ToolResult::err(e.to_string());
            audit.log(&AuditEntry {
                ts: crate::daemon::audit::now_ts(),
                agent_id,
                origin: origin.clone(),
                tool: format!("local_{}_file", op),
                path,
                lease_id: Some(lease_id),
                task_id,
                decision: None,
                backup_path: None,
                ok: false,
                error: result.error.clone(),
            });
            return result;
        }
    };
    let target = resolved.path.clone();

    // ── 闸③：备份（永远执行，不可绕过） ──
    // 备份放在**命中的授权目录**下，而不是「第一个目录」：多目录时后者会把 B 目录的
    // 备份写进 A 目录，既污染 A，又让「移除 B 后备份也随之可清」的预期落空。
    let backup_mgr = BackupManager::new(&resolved.root);
    // 传给备份的相对路径必须是「相对命中根」的：入参可能是绝对路径，
    // `backup_dir.join(绝对路径)` 会整体替换成该绝对路径，备份就落到了备份目录之外。
    let rel_in_root = target
        .strip_prefix(&resolved.root)
        .map(|r| r.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.clone());
    let backup_meta = match backup_mgr.snapshot(&target, op, &rel_in_root, &task_id, &lease_id) {
        Ok(m) => m,
        Err(e) => {
            let result = ToolResult::err(format!("backup failed: {}", e));
            audit.log(&AuditEntry {
                ts: crate::daemon::audit::now_ts(),
                agent_id,
                origin: origin.clone(),
                tool: format!("local_{}_file", op),
                path,
                lease_id: Some(lease_id),
                task_id,
                decision: None,
                backup_path: None,
                ok: false,
                error: result.error.clone(),
            });
            return result;
        }
    };
    let backup_path_str = backup_meta.backup_path.to_string_lossy().to_string();

    // ── 闸④：确认 ──
    let req = WriteRequest {
        op: op.to_string(),
        path: path.clone(),
        diff_preview: None, // TODO: edit 时生成 diff 预览
        backup_path: Some(backup_path_str.clone()),
    };
    if let Err(e) = approval_mgr.check(&req).await {
        // 确认失败（拒绝/超时）时写操作**尚未执行**，目标文件一个字节都没被我们动过——
        // 绝不能 rollback：等待确认的最长 45s 里用户可能自己改了这个文件（或新建了同名文件），
        // rollback 会用旧快照覆盖 / 删除它（审核 R2-N8）。rollback 只用于下方「写执行失败」。
        // 审计：decision = "rejected"，backup_path 保留可追溯
        let result = ToolResult::err(format!("approval failed: {}", e));
        audit.log(&AuditEntry {
            ts: crate::daemon::audit::now_ts(),
            agent_id,
            origin: origin.clone(),
            tool: format!("local_{}_file", op),
            path,
            lease_id: Some(lease_id),
            task_id,
            decision: Some("rejected".into()),
            backup_path: Some(backup_path_str),
            ok: false,
            error: result.error.clone(),
        });
        return result;
    }

    // ── 执行写操作 ──
    match write_fn(&target, params) {
        Ok(()) => {
            let result = ToolResult::ok(format!("{} succeeded: {}", op, path));
            // 审计：decision = "approved"，ok = true
            audit.log(&AuditEntry {
                ts: crate::daemon::audit::now_ts(),
                agent_id,
                origin: origin.clone(),
                tool: format!("local_{}_file", op),
                path,
                lease_id: Some(lease_id),
                task_id,
                decision: Some("approved".into()),
                backup_path: Some(backup_path_str),
                ok: true,
                error: None,
            });
            result
        }
        Err(e) => {
            // 写失败 → 回滚
            let _ = backup_mgr.rollback(&backup_meta);
            let result = ToolResult::err(format!("{} failed: {}", op, e));
            // 审计：decision = "approved"（用户已批准），但实际写入失败
            audit.log(&AuditEntry {
                ts: crate::daemon::audit::now_ts(),
                agent_id,
                origin: origin.clone(),
                tool: format!("local_{}_file", op),
                path,
                lease_id: Some(lease_id),
                task_id,
                decision: Some("approved".into()),
                backup_path: Some(backup_path_str),
                ok: false,
                error: result.error.clone(),
            });
            result
        }
    }
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::approval::{ApprovalMode, AutoApprover, Decision};
    use crate::daemon::audit::AuditLogger;
    use crate::daemon::lease::Lease;
    use crate::daemon::policy::PolicyFile;
    use std::fs;

    const AGENT: &str = "bi--zhangsan";

    /// 构造带一个临时目录的策略（AGENT 独占，读写）。
    fn temp_workspace() -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let pol = Policy::build(&[root], &PolicyFile::default(), Some(AGENT));
        (dir, pol)
    }

    /// 补上服务端注入的 `_agent_id`。
    fn p(mut v: serde_json::Value) -> serde_json::Value {
        v["_agent_id"] = serde_json::json!(AGENT);
        v
    }

    /// 构造合法 lease（node_id 匹配，不过期）。
    fn valid_lease(node_id: &str) -> Lease {
        Lease {
            schema_version: 1,
            lease_id: "test-lease-001".into(),
            target_server_node_id: node_id.into(),
            command_class: "write_files".into(),
            backup_policy: "snapshot_before_write".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            agent_id: Some(AGENT.into()),
            resource_ids: vec![],
        }
    }

    /// 构造使用 AutoApprover 的 ApprovalManager（Strict 模式）。
    fn auto_approval_mgr() -> ApprovalManager<Box<dyn Approver>> {
        ApprovalManager::new(
            ApprovalMode::Strict,
            Box::new(AutoApprover) as Box<dyn Approver>,
        )
    }

    /// 构造临时目录 AuditLogger（测试专用）。
    fn temp_audit() -> (tempfile::TempDir, Arc<AuditLogger>) {
        let dir = tempfile::tempdir().unwrap();
        let logger = Arc::new(AuditLogger::new(dir.path().to_path_buf()));
        (dir, logger)
    }

    /// 始终拒绝的确认器（用于测试确认失败场景）。
    struct RejectApprover;

    #[async_trait::async_trait]
    impl Approver for RejectApprover {
        async fn ask(&self, _req: &WriteRequest) -> Decision {
            Decision::Rejected
        }
    }

    /// 构造使用 RejectApprover 的 ApprovalManager。
    fn reject_approval_mgr() -> ApprovalManager<Box<dyn Approver>> {
        ApprovalManager::new(
            ApprovalMode::Strict,
            Box::new(RejectApprover) as Box<dyn Approver>,
        )
    }

    // ── 写入成功 ──

    #[tokio::test]
    async fn 写入成功_文件已创建() {
        let (_dir, ws) = temp_workspace();
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "new.txt", "content": "hello world"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(r.ok, "写入应成功: {:?}", r.error);
        // 文件应已创建
        let written = fs::read_to_string(ws.roots[0].path.join("new.txt")).unwrap();
        assert_eq!(written, "hello world");
        // 备份 meta 应存在（.hanako-backup 下有 .meta.json）
        let backup_root = ws.roots[0].path.join(".hanako-backup");
        assert!(backup_root.exists(), "备份根目录应存在");
    }

    // ── 写入成功后审计文件应有一条记录 ──

    #[tokio::test]
    async fn 写入成功_审计已记录() {
        let (_dir, ws) = temp_workspace();
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "audit_test.txt", "content": "test"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(r.ok);

        let content = fs::read_to_string(audit.today_file()).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["decision"], "approved");
        assert!(parsed["backup_path"].is_string(), "backup_path 应为字符串");
    }

    // ── 无 lease 拒绝 ──

    #[tokio::test]
    async fn 无lease_拒绝() {
        let (_dir, ws) = temp_workspace();
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, None, "node1", &mgr, &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("requires lease"));
    }

    // ── 路径穿越拒绝 ──

    #[tokio::test]
    async fn 路径穿越_拒绝() {
        let (_dir, ws) = temp_workspace();
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "../escape.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok);
    }

    // ── 编辑 old_string 不唯一拒绝 ──

    #[tokio::test]
    async fn 编辑_old_string不唯一_拒绝() {
        let (dir, ws) = temp_workspace();
        // 先创建文件，内容为 "aaa bbb aaa"
        let target = dir.path().join("dup.txt");
        fs::write(&target, "aaa bbb aaa").unwrap();

        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({
            "path": "dup.txt",
            "old_string": "aaa",
            "new_string": "ccc"
        }));
        let r = local_edit_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok, "old_string 不唯一应拒绝");
        assert!(r.error.unwrap().contains("exactly once"));
    }

    // ── 编辑成功 ──

    #[tokio::test]
    async fn 编辑成功_内容已替换() {
        let (dir, ws) = temp_workspace();
        let target = dir.path().join("edit.txt");
        fs::write(&target, "hello world").unwrap();

        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({
            "path": "edit.txt",
            "old_string": "world",
            "new_string": "rust"
        }));
        let r = local_edit_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(r.ok, "编辑应成功: {:?}", r.error);
        let updated = fs::read_to_string(&target).unwrap();
        assert_eq!(updated, "hello rust");
    }

    // ── 删除成功 ──

    #[tokio::test]
    async fn 删除成功_文件已移除() {
        let (dir, ws) = temp_workspace();
        let target = dir.path().join("del.txt");
        fs::write(&target, "to delete").unwrap();
        assert!(target.exists());

        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "del.txt"}));
        let r = local_delete_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(r.ok, "删除应成功: {:?}", r.error);
        assert!(!target.exists(), "文件应已删除");
    }

    // ── 删除后回滚可恢复 ──

    #[tokio::test]
    async fn 删除_回滚恢复() {
        let (dir, ws) = temp_workspace();
        let target = dir.path().join("restore.txt");
        fs::write(&target, "original content").unwrap();

        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "restore.txt"}));
        let r = local_delete_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(r.ok, "删除应成功: {:?}", r.error);
        assert!(!target.exists(), "文件应已删除");

        // 用 BackupManager 回滚
        let backup_root = ws.roots[0].path.join(".hanako-backup");
        let backup_mgr = BackupManager::new(&ws.roots[0].path);
        // 读取最新的 .meta.json
        let mut meta_files: Vec<_> = fs::read_dir(&backup_root)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        meta_files.sort_by_key(|e| e.file_name());
        let latest_dir = meta_files.last().expect("应有备份目录");
        let meta_path = latest_dir.path().join(".meta.json");
        let meta_json = fs::read_to_string(meta_path).unwrap();
        let meta: crate::daemon::backup::BackupMeta = serde_json::from_str(&meta_json).unwrap();

        assert!(!meta.was_new, "已存在文件应 was_new=false");
        backup_mgr.rollback(&meta).unwrap();
        let restored = fs::read_to_string(&target).unwrap();
        assert_eq!(restored, "original content", "回滚后应恢复原内容");
    }

    // ── 确认拒绝 → 回滚 ──

    #[tokio::test]
    async fn 确认拒绝_回滚_文件未创建() {
        let (_dir, ws) = temp_workspace();
        let mgr = reject_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "rejected.txt", "content": "should not exist"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok, "确认拒绝应返回错误");
        assert!(r.error.unwrap().contains("approval failed"));
        // 文件不应被创建（回滚已清除）
        assert!(
            !ws.roots[0].path.join("rejected.txt").exists(),
            "确认拒绝后文件不应存在"
        );
    }

    // ── 确认拒绝后审计应记录 decision=rejected ──

    #[tokio::test]
    async fn 确认拒绝_审计记录_decision_rejected() {
        let (_dir, ws) = temp_workspace();
        let mgr = reject_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "rej_audit.txt", "content": "x"}));
        let _r =
            local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;

        let content = fs::read_to_string(audit.today_file()).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["decision"], "rejected");
    }

    // ── 工作目录为空拒绝 ──

    #[tokio::test]
    async fn 空工作目录_拒绝() {
        let ws = Policy::build(&[], &PolicyFile::default(), Some(AGENT));
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("LOCAL_NO_ROOTS"));
    }

    // ── lease 节点不匹配拒绝 ──

    #[tokio::test]
    async fn lease节点不匹配_拒绝() {
        let (_dir, ws) = temp_workspace();
        let mgr = auto_approval_mgr();
        let (_adir, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node2", &mgr, &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("lease validation failed"));
    }

    // ── S3 本机闸（写侧）──────────────────────────────────────────────────────

    use crate::daemon::register::root_id_for;

    fn one_root_policy(mode: &str, agent: &str) -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut f = PolicyFile::default();
        f.modes.insert(root_id_for(&root), mode.into());
        (dir, Policy::build(&[root], &f, Some(agent)))
    }

    #[tokio::test]
    async fn 只读根_写被拒_文件不出现_且带机读码() {
        let (dir, pol) = one_root_policy("ro", AGENT);
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        let r = local_write_file(&params, &pol, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("LOCAL_ROOT_READ_ONLY"));
        assert!(!dir.path().join("a.txt").exists());
        assert!(!dir.path().join(".hanako-backup").exists(), "只读根不应产生备份目录");
    }

    #[tokio::test]
    async fn 未授权执行体_写被拒() {
        let (dir, pol) = one_root_policy("rw", "wallet--zhangsan");
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"})); // 任务帧执行体=AGENT，未被授权
        let mut lease = valid_lease("node1");
        lease.agent_id = Some(AGENT.into());
        let r = local_write_file(&params, &pol, Some(lease), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.error.unwrap().starts_with("LOCAL_ACTOR_NOT_GRANTED"));
        assert!(!dir.path().join("a.txt").exists());
    }

    #[tokio::test]
    async fn lease执行体与任务帧不符_拒() {
        let (dir, ws) = temp_workspace();
        let (_a, audit) = temp_audit();
        let mut lease = valid_lease("node1");
        lease.agent_id = Some("wallet--zhangsan".into()); // 别的执行体的 lease 挂在本执行体任务帧上
        let params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(lease), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.error.unwrap().contains("lease agent mismatch"));
        assert!(!dir.path().join("a.txt").exists());
    }

    #[tokio::test]
    async fn lease绑定目录与任务帧不符_拒() {
        let (dir, ws) = temp_workspace();
        let (_a, audit) = temp_audit();
        let rid = root_id_for(&ws.roots[0].path);
        let mut lease = valid_lease("node1");
        lease.resource_ids = vec!["r_other0000000".into()];
        let mut params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        params["_root_id"] = serde_json::json!(rid);
        let r = local_write_file(&params, &ws, Some(lease), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.error.unwrap().contains("lease root mismatch"));
        assert!(!dir.path().join("a.txt").exists());
    }

    #[tokio::test]
    async fn 会话绑定目录已撤销_写被拒() {
        let (dir, ws) = temp_workspace();
        let (_a, audit) = temp_audit();
        let mut params = p(serde_json::json!({"path": "a.txt", "content": "x"}));
        params["_root_id"] = serde_json::json!("r_gone00000000");
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.error.unwrap().starts_with("LOCAL_ROOT_REVOKED"));
        assert!(!dir.path().join("a.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 写经符号链接到根外_被拒且根外无文件() {
        let (dir, ws) = temp_workspace();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "evil/pwn.txt", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.error.unwrap().starts_with("LOCAL_PATH_OUT_OF_FENCE"));
        assert!(!outside.path().join("pwn.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 写经悬空符号链接到根外_被拒且根外无文件() {
        let (dir, ws) = temp_workspace();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::os::unix::fs::symlink(&victim, dir.path().join("dangling")).unwrap();
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "dangling", "content": "x"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(!r.ok);
        assert!(!victim.exists(), "悬空链接把文件写到了授权目录之外");
    }

    #[tokio::test]
    async fn 备份失败_即拒写_原文件不变() {
        // .hanako-backup 被一个普通文件占位 → create_dir_all 必失败 → 不得继续写
        let (dir, ws) = temp_workspace();
        fs::write(dir.path().join("a.txt"), "orig").unwrap();
        fs::write(dir.path().join(".hanako-backup"), "i am a file").unwrap();
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "NEW"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("backup failed"));
        assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "orig");
    }

    #[tokio::test]
    async fn 确认超时_按拒绝_原文件不变() {
        struct Hang;
        #[async_trait::async_trait]
        impl Approver for Hang {
            async fn ask(&self, _r: &WriteRequest) -> Decision {
                std::future::pending::<Decision>().await
            }
        }
        let (dir, ws) = temp_workspace();
        fs::write(dir.path().join("a.txt"), "orig").unwrap();
        let mgr = ApprovalManager::new(ApprovalMode::Strict, Box::new(Hang) as Box<dyn Approver>)
            .with_timeout(std::time::Duration::from_millis(30));
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": "a.txt", "content": "NEW"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("timeout"));
        assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "orig");
    }

    #[tokio::test]
    async fn 多根_备份落在命中的根而非第一个根() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let r1 = d1.path().canonicalize().unwrap();
        let r2 = d2.path().canonicalize().unwrap();
        fs::write(r2.join("b.txt"), "orig").unwrap();
        let pol = Policy::build(&[r1.clone(), r2.clone()], &PolicyFile::default(), Some(AGENT));
        let (_a, audit) = temp_audit();
        let abs = r2.join("b.txt");
        let params = p(serde_json::json!({"path": abs.to_str().unwrap(), "content": "NEW"}));
        let r = local_write_file(&params, &pol, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.ok, "{:?}", r.error);
        assert!(r2.join(".hanako-backup").exists(), "备份应在命中的根 r2 下");
        assert!(!r1.join(".hanako-backup").exists(), "不应写进第一个根 r1");
    }

    #[tokio::test]
    async fn 绝对路径写_备份不得写出授权目录() {
        // backup_dir.join(绝对路径) 会整个替换为该绝对路径 → 备份落到根外甚至覆盖原文件
        let (dir, ws) = temp_workspace();
        let abs = ws.roots[0].path.join("abs.txt");
        fs::write(&abs, "orig").unwrap();
        let (_a, audit) = temp_audit();
        let params = p(serde_json::json!({"path": abs.to_str().unwrap(), "content": "NEW"}));
        let r = local_write_file(&params, &ws, Some(valid_lease("node1")), "node1", &auto_approval_mgr(), &audit).await;
        assert!(r.ok, "{:?}", r.error);
        let bdir = dir.path().join(".hanako-backup");
        let mut found = false;
        for e in walk_files(&bdir) {
            if fs::read_to_string(&e).map(|c| c == "orig").unwrap_or(false) {
                found = true;
            }
        }
        assert!(found, "备份应在 .hanako-backup 内保存原内容");
    }

    fn walk_files(d: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![];
        if let Ok(rd) = fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { out.extend(walk_files(&p)); } else { out.push(p); }
            }
        }
        out
    }

    #[tokio::test]
    async fn 确认拒绝_不覆盖用户在等待期间的改动() {
        // 审核 R2-N8：确认等待期间用户自己改了文件 / 新建了同名文件，拒绝后不得被旧快照覆盖或删除
        struct EditThenReject(std::path::PathBuf);
        #[async_trait::async_trait]
        impl Approver for EditThenReject {
            async fn ask(&self, _r: &WriteRequest) -> Decision {
                fs::write(&self.0, "USER-EDIT").unwrap();
                Decision::Rejected
            }
        }
        let (dir, ws) = temp_workspace();
        let (_a, audit) = temp_audit();
        // 已存在文件
        fs::write(dir.path().join("a.txt"), "orig").unwrap();
        let mgr = ApprovalManager::new(ApprovalMode::Strict, Box::new(EditThenReject(dir.path().join("a.txt"))) as Box<dyn Approver>);
        let r = local_write_file(&p(serde_json::json!({"path": "a.txt", "content": "AGENT"})), &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok);
        assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "USER-EDIT");
        // 原本不存在的文件：用户在等待期间新建
        let mgr = ApprovalManager::new(ApprovalMode::Strict, Box::new(EditThenReject(dir.path().join("b.txt"))) as Box<dyn Approver>);
        let r = local_write_file(&p(serde_json::json!({"path": "b.txt", "content": "AGENT"})), &ws, Some(valid_lease("node1")), "node1", &mgr, &audit).await;
        assert!(!r.ok);
        assert_eq!(fs::read_to_string(dir.path().join("b.txt")).unwrap(), "USER-EDIT");
    }
}
