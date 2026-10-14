// src-tauri/src/daemon/tools/mod.rs
//! 本地工具执行层：类型定义 + 分发逻辑。
//!
//! read_only 类：`local_read_file` / `local_list_dir` / `local_grep`。
//! write_files 类：`local_write_file` / `local_edit_file` / `local_delete_file`（四道闸：lease→路径→备份→确认）。
//!
//! 审计：
//! - 写类工具：审计写在 write::execute_write 内部（decision / backup_path 在那里才完整）
//! - 读类工具：审计写在此处 execute_tool 的 dispatch 之后（无 decision / backup_path）

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod extract;
pub mod upload;
pub mod read;
pub mod write;

/// 工具执行结果（直接序列化为 task_result 帧的字段）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// 是否成功。
    pub ok: bool,
    /// 成功时的文本输出。
    pub result: Option<String>,
    /// 失败时的错误消息。
    pub error: Option<String>,
    /// 搬运（票 18）：被放行上传的文件字节，**独立字段**，绝不混进 `result`——
    /// result 会被服务端当文本原样交给模型，45MB 的 base64 一旦进去就灌爆上下文。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<UploadPayload>,
}

/// 搬运载荷：只含文件名与字节，不含本机路径。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadPayload {
    pub name: String,
    pub base64: String,
}

impl ToolResult {
    /// 构造成功结果。
    pub fn ok(result: String) -> Self {
        Self { ok: true, result: Some(result), error: None, upload: None }
    }

    /// 构造失败结果。
    pub fn err(error: String) -> Self {
        Self { ok: false, result: None, error: Some(error), upload: None }
    }
}

/// 工具分发器：根据工具名派发到对应实现。
///
/// # 参数
/// - `name`: 工具名（如 `"local_read_file"`）
/// - `params`: JSON 参数对象
/// - `policy`: 本机策略快照（授权目录 / 读写模式 / 执行体授权）；调用方应为每个任务帧现读
/// - `lease`: 服务端颁发的执行租约（read_only 工具不强制；write_files 工具必须）
/// - `node_id`: 本节点 id，供写类工具校验 lease.targetServerNodeId
/// - `approval_mgr`: 确认管理器（Task 5 引入，写类工具必须经过闸④确认）
/// - `audit`: 审计日志器（Task 7 引入，成功/失败都记）
pub async fn execute_tool(
    name: &str,
    params: &Value,
    policy: &super::policy::Policy,
    lease: Option<super::lease::Lease>,
    node_id: &str,
    approval_mgr: &super::approval::ApprovalManager<Box<dyn super::approval::Approver>>,
    audit: &Arc<super::audit::AuditLogger>,
) -> ToolResult {
    // 读类工具在此处审计（写类工具在 execute_write 内部审计，包含 decision/backup_path）
    let result = match name {
        "local_read_file" => read::local_read_file(params, policy).await,
        "local_list_dir" => read::local_list_dir(params, policy).await,
        "local_grep" => read::local_grep(params, policy).await,
        "local_write_file" => {
            write::local_write_file(params, policy, lease, node_id, approval_mgr, audit).await
        }
        "local_edit_file" => {
            write::local_edit_file(params, policy, lease, node_id, approval_mgr, audit).await
        }
        "local_delete_file" => {
            write::local_delete_file(params, policy, lease, node_id, approval_mgr, audit).await
        }
        // 票 18：搬运。弹窗桥与来源经任务局部上下文传入（不改 execute_tool 签名，避免波及所有调用点）；
        // 缺上下文（headless / 测试未注入）= 拒绝，绝不放行。
        "local_upload_to_workspace" => match upload::UPLOAD_CTX.try_with(|c| c.clone()) {
            Ok(ctx) => upload::local_upload_to_workspace(params, policy, lease, node_id, &ctx.bridge, audit, &ctx.origin).await,
            Err(_) => ToolResult::err(format!("{}: upload bridge unavailable", upload::ERR_PREFIX)),
        },
        _ => ToolResult::err(format!("unknown tool: {}", name)),
    };

    // 读类工具（以及未知工具）：在此处写审计条目
    // 写类工具审计已在 execute_write 内部完成，此处不重复
    if !matches!(name, "local_write_file" | "local_edit_file" | "local_delete_file" | "local_upload_to_workspace") {
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
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // 来源标注（票 07）：网页本地树浏览为 "web_browse"（来自 params._origin），
        // 模型派发缺省 "agent"。据此在本机审计里区分「网页浏览」与「助手读文件」。
        let origin = params
            .get("_origin")
            .and_then(|v| v.as_str())
            .unwrap_or("agent")
            .to_string();
        audit.log(&super::audit::AuditEntry {
            ts: super::audit::now_ts(),
            agent_id,
            tool: name.to_string(),
            path,
            lease_id: None,    // 读类工具无 lease
            task_id,
            decision: None,    // 读类工具无审批
            backup_path: None, // 读类工具无备份
            ok: result.ok,
            error: result.error.clone(),
            origin,
        });
    }

    result
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::approval::{ApprovalManager, ApprovalMode, Approver, AutoApprover};
    use crate::daemon::audit::AuditLogger;
    use crate::daemon::policy::PolicyFile;

    const AGENT: &str = "bi--zhangsan";

    /// 读类工具经 execute_tool 派发时，审计条目 origin 取自 params._origin（票 07）。
    /// 变异锁：把提取字段名写错（如 `_originx`）→ 本用例红。
    #[tokio::test]
    async fn 读类审计_origin_取自_params() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let pol = crate::daemon::policy::Policy::build(&[root], &PolicyFile::default(), Some(AGENT));

        let audit_dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLogger::new(audit_dir.path().to_path_buf()));
        let mgr: ApprovalManager<Box<dyn Approver>> =
            ApprovalManager::new(ApprovalMode::Strict, Box::new(AutoApprover) as Box<dyn Approver>);

        let params = serde_json::json!({
            "path": ".",
            "_agent_id": AGENT,
            "_task_id": "task-x",
            "_origin": "web_browse",
        });
        let r = execute_tool("local_list_dir", &params, &pol, None, "node-1", &mgr, &audit).await;
        assert!(r.ok, "{:?}", r.error);

        let line = std::fs::read_to_string(audit.today_file()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line.lines().last().unwrap()).unwrap();
        assert_eq!(parsed["origin"], "web_browse");
        assert_eq!(parsed["tool"], "local_list_dir");
    }

    /// 不传 _origin → 审计记 "agent"（模型派发缺省）。
    #[tokio::test]
    async fn 读类审计_无_origin_缺省_agent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let pol = crate::daemon::policy::Policy::build(&[root], &PolicyFile::default(), Some(AGENT));
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLogger::new(audit_dir.path().to_path_buf()));
        let mgr: ApprovalManager<Box<dyn Approver>> =
            ApprovalManager::new(ApprovalMode::Strict, Box::new(AutoApprover) as Box<dyn Approver>);

        let params = serde_json::json!({ "path": ".", "_agent_id": AGENT, "_task_id": "task-y" });
        let _ = execute_tool("local_list_dir", &params, &pol, None, "node-1", &mgr, &audit).await;

        let line = std::fs::read_to_string(audit.today_file()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line.lines().last().unwrap()).unwrap();
        assert_eq!(parsed["origin"], "agent");
    }
}
