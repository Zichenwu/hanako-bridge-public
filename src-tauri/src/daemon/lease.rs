// src-tauri/src/daemon/lease.rs
//! lease 校验模块（闸①）。
//!
//! 服务端通过 task 帧附带 `Lease` 对象，daemon 在执行写操作前必须通过本模块校验。
//! 校验顺序：schema 版本 → 过期 → 节点匹配 → 命令类别匹配 → 写类备份策略 → 重放防护。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 服务端颁发的执行租约（camelCase 字段与服务端 schema 一致）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "leaseId")]
    pub lease_id: String,
    #[serde(rename = "targetServerNodeId")]
    pub target_server_node_id: String,
    #[serde(rename = "commandClass")]
    pub command_class: String,
    #[serde(rename = "backupPolicy")]
    pub backup_policy: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    /// 签发时绑定的执行体（服务端始终带；缺失视为不合法，见 `validate_scope`）。
    #[serde(rename = "agentId", default)]
    pub agent_id: Option<String>,
    /// 签发时绑定的本机目录 rootId（会话绑定了目录时为 `[rootId]`，否则空）。
    #[serde(rename = "resourceIds", default)]
    pub resource_ids: Vec<String>,
}

/// lease 校验失败原因。
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("invalid schema version")]
    InvalidSchema,
    #[error("lease expired")]
    Expired,
    #[error("lease not for this node")]
    WrongNode,
    #[error("command class mismatch")]
    WrongClass,
    #[error("backup policy required for write")]
    NoBackup,
    #[error("lease already consumed")]
    Replayed,
    #[error("lease agent mismatch")]
    AgentMismatch,
    #[error("lease root mismatch")]
    RootMismatch,
}

/// lease 校验器（单实例，per-write-op 创建；consumed 为内存集合，提供一期单机重放防护）。
pub struct LeaseValidator {
    consumed: HashSet<String>,
}

/// 复核 lease 与任务帧声明的「执行体 / 目录」一致（S3：lease 执行体/rootId 不符即拒）。
///
/// 任务帧的 `_agent_id` / `_root_id` 与 lease 由服务端分别填写；本机不假设它们一致，
/// 否则一个为 A 签发的 lease 可以被挂在 B 的任务帧上，借 A 的写授权动 B 的目录。
/// - lease 必须带 agentId 且与任务帧执行体相同
/// - lease 绑定了目录（resourceIds 非空）时，任务帧的 rootId 必须在其中；
///   任务帧没带 rootId 也算不符（不允许把「限定某目录」的 lease 放宽成「任意授权目录」）
pub fn validate_scope(
    lease: &Lease,
    task_agent_id: &str,
    task_root_id: Option<&str>,
) -> Result<(), LeaseError> {
    match lease.agent_id.as_deref() {
        Some(a) if !a.is_empty() && a == task_agent_id => {}
        _ => return Err(LeaseError::AgentMismatch),
    }
    if !lease.resource_ids.is_empty() {
        match task_root_id {
            Some(r) if lease.resource_ids.iter().any(|x| x == r) => {}
            _ => return Err(LeaseError::RootMismatch),
        }
    }
    Ok(())
}

impl LeaseValidator {
    /// 构造新校验器。
    pub fn new() -> Self {
        Self { consumed: HashSet::new() }
    }

    /// 校验 lease 并将其标记为已消费（一次性）。
    ///
    /// # 参数
    /// - `lease`: 待校验的租约
    /// - `expected_node_id`: 本节点 id（取自 DaemonConfig.node_id）
    /// - `expected_class`: 期望的命令类别（如 `"write_files"`）
    pub fn validate(
        &mut self,
        lease: &Lease,
        expected_node_id: &str,
        expected_class: &str,
    ) -> Result<(), LeaseError> {
        if lease.schema_version != 1 {
            return Err(LeaseError::InvalidSchema);
        }
        // 过期检查（ISO 8601 字符串比较即可，服务端始终生成 RFC3339 格式）
        let now = chrono::Utc::now().to_rfc3339();
        if lease.expires_at <= now {
            return Err(LeaseError::Expired);
        }
        if lease.target_server_node_id != expected_node_id {
            return Err(LeaseError::WrongNode);
        }
        if lease.command_class != expected_class {
            return Err(LeaseError::WrongClass);
        }
        // 写类操作必须有备份策略（backup_policy != "none"）
        if expected_class == "write_files" && lease.backup_policy == "none" {
            return Err(LeaseError::NoBackup);
        }
        // 重放防护：同一 leaseId 只允许使用一次
        if self.consumed.contains(&lease.lease_id) {
            return Err(LeaseError::Replayed);
        }
        self.consumed.insert(lease.lease_id.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_lease() -> Lease {
        Lease {
            schema_version: 1,
            lease_id: "lease_1".into(),
            target_server_node_id: "node1".into(),
            command_class: "write_files".into(),
            backup_policy: "snapshot_before_write".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            agent_id: Some("bi--zhangsan".into()),
            resource_ids: vec![],
        }
    }

    #[test]
    fn 执行体不符_拒() {
        let l = valid_lease();
        assert!(validate_scope(&l, "bi--zhangsan", None).is_ok());
        assert!(matches!(validate_scope(&l, "wallet--zhangsan", None), Err(LeaseError::AgentMismatch)));
    }

    #[test]
    fn lease_缺执行体_拒() {
        let mut l = valid_lease();
        l.agent_id = None;
        assert!(matches!(validate_scope(&l, "bi--zhangsan", None), Err(LeaseError::AgentMismatch)));
        l.agent_id = Some(String::new());
        assert!(matches!(validate_scope(&l, "", None), Err(LeaseError::AgentMismatch)));
    }

    #[test]
    fn 目录不符_拒() {
        let mut l = valid_lease();
        l.resource_ids = vec!["r_aaa".into()];
        assert!(validate_scope(&l, "bi--zhangsan", Some("r_aaa")).is_ok());
        assert!(matches!(validate_scope(&l, "bi--zhangsan", Some("r_bbb")), Err(LeaseError::RootMismatch)));
        // 任务帧不带 rootId 想放宽 → 也拒
        assert!(matches!(validate_scope(&l, "bi--zhangsan", None), Err(LeaseError::RootMismatch)));
    }

    #[test]
    fn lease_未绑目录_不限制目录() {
        let l = valid_lease();
        assert!(validate_scope(&l, "bi--zhangsan", Some("r_any")).is_ok());
    }

    #[test]
    fn 旧服务端_lease_无新字段仍可反序列化() {
        let j = r#"{"schemaVersion":1,"leaseId":"l","targetServerNodeId":"n","commandClass":"write_files","backupPolicy":"snapshot_before_write","expiresAt":"2099-01-01T00:00:00Z"}"#;
        let l: Lease = serde_json::from_str(j).unwrap();
        assert!(l.agent_id.is_none() && l.resource_ids.is_empty());
    }

    #[test]
    fn 合法_lease_通过() {
        let mut v = LeaseValidator::new();
        assert!(v.validate(&valid_lease(), "node1", "write_files").is_ok());
    }

    #[test]
    fn 过期_lease_拒() {
        let mut v = LeaseValidator::new();
        let mut l = valid_lease();
        l.expires_at = "2020-01-01T00:00:00Z".into();
        assert!(matches!(v.validate(&l, "node1", "write_files"), Err(LeaseError::Expired)));
    }

    #[test]
    fn 跨节点_lease_拒() {
        let mut v = LeaseValidator::new();
        assert!(matches!(v.validate(&valid_lease(), "node2", "write_files"), Err(LeaseError::WrongNode)));
    }

    #[test]
    fn 重放_lease_拒() {
        let mut v = LeaseValidator::new();
        let l = valid_lease();
        assert!(v.validate(&l, "node1", "write_files").is_ok());
        assert!(matches!(v.validate(&l, "node1", "write_files"), Err(LeaseError::Replayed)));
    }

    #[test]
    fn 写类无备份_lease_拒() {
        let mut v = LeaseValidator::new();
        let mut l = valid_lease();
        l.backup_policy = "none".into();
        assert!(matches!(v.validate(&l, "node1", "write_files"), Err(LeaseError::NoBackup)));
    }
}
