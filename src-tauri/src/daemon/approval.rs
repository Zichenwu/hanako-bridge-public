// src-tauri/src/daemon/approval.rs
//! 确认策略判定（闸④）：Approver trait + ApprovalManager。
//!
//! 四道闸顺序（Task 5 接线）：
//!   闸① path_guard（路径越界拒绝）
//!   闸② lease（租约校验）
//!   闸③ backup（快照，永远执行，不可绕过）
//!   闸④ approval（本模块，用户确认策略）
//!
//! 两条不可关红线：
//!   ① delete 操作永远触发逐次确认，跳过 session_trust 缓存
//!   ② 批量超 5 个文件强制逐次确认（Task 5 传入 batch_size 接线，本模块留 TODO）

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

// ────────────────────────────────────────────────────────────────
// 请求结构体
// ────────────────────────────────────────────────────────────────

/// 写操作确认请求，包含操作类型、目标路径及展示信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    /// 操作类型："write" | "edit" | "delete"
    pub op: String,
    /// 目标文件路径（可为相对路径，parent() 用于 session_trust 目录缓存）
    pub path: String,
    /// edit 时的 diff 预览，展示给用户
    pub diff_preview: Option<String>,
    /// 备份文件路径，展示给用户（由 Task 5 从 BackupMeta 填入）
    pub backup_path: Option<String>,
}

// ────────────────────────────────────────────────────────────────
// 枚举：确认决策
// ────────────────────────────────────────────────────────────────

/// 用户的确认决策。
///
/// `TrustSession(PathBuf)` 携带用户希望本 session 信任的目录路径。
/// `ApprovalManager` 收到后将该目录加入 `session_trusted` 集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 本次批准
    Approved,
    /// 本次拒绝
    Rejected,
    /// 批准，并在本 session 内信任指定目录
    TrustSession(PathBuf),
}

// ────────────────────────────────────────────────────────────────
// 枚举：确认模式
// ────────────────────────────────────────────────────────────────

/// 确认策略模式。
///
/// - `Strict`：每次操作都向 approver 请求确认（默认模式，先紧后松原则）
/// - `SessionTrust`：某目录被 TrustSession 后，该目录的后续写操作免确认；
///   delete 操作无论何种模式均强制确认（红线①）
/// - `AlwaysTrust` 二期实现，当前注释
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// 严格模式：每次都确认
    Strict,
    /// 会话信任模式：目录被用户批准后当前 session 免确认
    SessionTrust,
    // AlwaysTrust,  // 二期
}

// ────────────────────────────────────────────────────────────────
// 枚举：确认错误
// ────────────────────────────────────────────────────────────────

/// 确认环节返回的错误。
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("user rejected")]
    Rejected,
    #[error("approval timeout")]
    Timeout,
}

// ────────────────────────────────────────────────────────────────
// Approver trait
// ────────────────────────────────────────────────────────────────

/// 确认器 trait。Task 4 提供 `AutoApprover`；Task 6 替换为原生窗口确认器。
///
/// 使用 `#[async_trait]` 使 trait 对象（`Box<dyn Approver>`）可用于异步上下文。
#[async_trait::async_trait]
pub trait Approver: Send + Sync {
    /// 向用户（或自动策略）询问是否批准此次写操作。
    async fn ask(&self, req: &WriteRequest) -> Decision;
}

/// 使 `Box<dyn Approver>` 满足 `Approver` 约束，
/// 方便 Task 5 使用 `ApprovalManager<Box<dyn Approver>>` 避免泛型扩散到 client.rs。
#[async_trait::async_trait]
impl Approver for Box<dyn Approver> {
    async fn ask(&self, req: &WriteRequest) -> Decision {
        // 将调用转发给内部具体类型
        (**self).ask(req).await
    }
}

// ────────────────────────────────────────────────────────────────
// ApprovalManager
// ────────────────────────────────────────────────────────────────

/// 确认策略管理器（闸④）。
///
/// 泛型参数 `A` 为具体确认器类型（如 `AutoApprover` 或 `Box<dyn Approver>`）。
/// Task 5 使用 `ApprovalManager<Box<dyn Approver>>` 以避免泛型扩散到 client.rs。
pub struct ApprovalManager<A: Approver> {
    /// 当前确认模式
    mode: ApprovalMode,
    /// 确认器实例
    approver: A,
    /// SessionTrust 模式下已信任的目录集合
    session_trusted: std::sync::Mutex<HashSet<PathBuf>>,
    /// 等待用户响应的上限；超时 = 拒绝（绝不默认放行）
    timeout: std::time::Duration,
}

/// 写确认超时（决策：45 秒无响应按拒绝处理）。
pub const WRITE_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

impl<A: Approver> ApprovalManager<A> {
    /// 创建确认管理器。
    pub fn new(mode: ApprovalMode, approver: A) -> Self {
        Self {
            mode,
            approver,
            session_trusted: std::sync::Mutex::new(HashSet::new()),
            timeout: WRITE_CONFIRM_TIMEOUT,
        }
    }

    /// 覆盖确认超时（仅测试用，生产恒为 `WRITE_CONFIRM_TIMEOUT`）。
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 执行确认检查。
    ///
    /// 返回 `Ok(())` 表示操作被批准，`Err(ApprovalError)` 表示被拒绝或超时。
    ///
    /// 两条红线：
    /// - 红线①：`op == "delete"` 强制逐次确认，跳过 session_trusted 缓存
    /// - 红线②：批量超 5 个文件强制逐次确认（TODO: Task 5 接线时传入 batch_size 参数）
    pub async fn check(&self, req: &WriteRequest) -> Result<(), ApprovalError> {
        // 红线①：delete 操作永远强制逐次确认，不受 session_trust 豁免
        if req.op == "delete" {
            return self.ask_with_timeout(req).await.map(|_| ());
        }

        // TODO: 红线②：Task 5 接线时补充 batch_size 参数判断
        // if batch_size > 5 { return self.ask_with_timeout(req).await.map(|_| ()); }

        match self.mode {
            ApprovalMode::Strict => {
                // 严格模式：每次都向 approver 确认
                self.ask_with_timeout(req).await.map(|_| ())
            }
            ApprovalMode::SessionTrust => {
                // 从请求路径推导目录，用于 session_trusted 缓存查找
                //
                // 边界情况：req.path 为相对路径时，parent() 可能返回 Some("") 空字符串；
                // 此处将空字符串目录视为"工作区根目录"，信任范围较宽——Task 5 调用时
                // 应确保传入绝对路径以精确限定目录。
                let dir = PathBuf::from(&req.path)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_default();

                // 如果该目录已在 session_trusted 中，直接放行
                if self.session_trusted.lock().unwrap().contains(&dir) {
                    return Ok(());
                }

                // 向 approver 请求确认，超时或拒绝均返回错误
                let decision = self.ask_with_timeout(req).await?;

                // 若用户选择信任整个 session，将目录加入 session_trusted
                if let Decision::TrustSession(d) = decision {
                    self.session_trusted.lock().unwrap().insert(d);
                }

                Ok(())
            }
        }
    }

    /// 带超时（`WRITE_CONFIRM_TIMEOUT`，45 秒）的 approver 询问。
    ///
    /// 返回 `Ok(Decision)` 或 `Err(ApprovalError::Timeout)`。
    /// `Decision::Rejected` 转换为 `Err(ApprovalError::Rejected)`。
    async fn ask_with_timeout(&self, req: &WriteRequest) -> Result<Decision, ApprovalError> {
        match tokio::time::timeout(self.timeout, self.approver.ask(req))
        .await
        {
            Ok(Decision::Approved) => Ok(Decision::Approved),
            Ok(Decision::Rejected) => Err(ApprovalError::Rejected),
            Ok(Decision::TrustSession(d)) => Ok(Decision::TrustSession(d)),
            Err(_elapsed) => Err(ApprovalError::Timeout),
        }
    }
}

// ────────────────────────────────────────────────────────────────
// AutoApprover：开发/测试用自动通过确认器
// ────────────────────────────────────────────────────────────────

/// 自动批准确认器，供 Task 0~5 使用；Task 6 替换为 NativeWindowApprover。
pub struct AutoApprover;

#[async_trait::async_trait]
impl Approver for AutoApprover {
    async fn ask(&self, _req: &WriteRequest) -> Decision {
        Decision::Approved
    }
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ── 辅助 mock：每次 ask 返回 Approved 并递增计数器 ──

    struct CountingApprover {
        /// 记录 ask 被调用次数
        count: Arc<AtomicUsize>,
        /// ask 的返回值
        response: Decision,
    }

    impl CountingApprover {
        fn new(response: Decision) -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            let approver = Self {
                count: count.clone(),
                response,
            };
            (approver, count)
        }
    }

    #[async_trait::async_trait]
    impl Approver for CountingApprover {
        async fn ask(&self, _req: &WriteRequest) -> Decision {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.response.clone()
        }
    }

    // ── 辅助 mock：始终拒绝 ──

    struct RejectApprover;

    #[async_trait::async_trait]
    impl Approver for RejectApprover {
        async fn ask(&self, _req: &WriteRequest) -> Decision {
            Decision::Rejected
        }
    }

    // ── 测试 1：Strict 模式下调用 approver ──

    /// Strict 模式 + AutoApprover → 每次 check 都询问 approver，结果 Ok。
    #[tokio::test]
    async fn strict_模式调_approver() {
        let mgr = ApprovalManager::new(ApprovalMode::Strict, AutoApprover);
        let req = WriteRequest {
            op: "write".into(),
            path: "a.txt".into(),
            diff_preview: None,
            backup_path: None,
        };
        assert!(mgr.check(&req).await.is_ok());
    }

    // ── 测试 2：delete 红线——无论模式均强制确认，RejectApprover → Err ──

    /// delete 操作触发红线①：SessionTrust 模式下 delete 也强制确认；
    /// RejectApprover 返回 Rejected → check 返回 Err(Rejected)。
    #[tokio::test]
    async fn delete_强制确认() {
        let mgr = ApprovalManager::new(ApprovalMode::SessionTrust, RejectApprover);
        let req = WriteRequest {
            op: "delete".into(),
            path: "a.txt".into(),
            diff_preview: None,
            backup_path: None,
        };
        assert!(matches!(mgr.check(&req).await, Err(ApprovalError::Rejected)));
    }

    // ── 测试 3：SessionTrust 模式第二次同目录操作免确认 ──

    /// SessionTrust 模式：
    ///   - 第一次 check 触发 approver（返回 TrustSession）→ 目录加入缓存
    ///   - 第二次同目录 check 直接放行，approver 不被再次调用
    ///   - 验证 ask 只被调用一次（CountingApprover 计数器 == 1）
    #[tokio::test]
    async fn session_trust_同目录第二次免确认() {
        // CountingApprover 返回 TrustSession("/tmp/work")
        let trusted_dir = PathBuf::from("/tmp/work");
        let (approver, call_count) =
            CountingApprover::new(Decision::TrustSession(trusted_dir.clone()));

        let mgr = ApprovalManager::new(ApprovalMode::SessionTrust, approver);

        let req = WriteRequest {
            op: "write".into(),
            // 路径在 /tmp/work/ 下，parent() == /tmp/work
            path: "/tmp/work/file.txt".into(),
            diff_preview: None,
            backup_path: None,
        };

        // 第一次：approver 被调用，目录加入 session_trusted
        mgr.check(&req).await.expect("第一次 check 应 Ok");

        // 第二次：直接从缓存放行，approver 不被调用
        mgr.check(&req).await.expect("第二次 check 应 Ok");

        // 验证 approver.ask 只被调用了一次
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "SessionTrust 模式下同目录第二次请求不应再次调用 approver"
        );
    }

    // ── 测试 4：Box<dyn Approver> 与 ApprovalManager 兼容 ──

    /// 验证 ApprovalManager<Box<dyn Approver>> 可正常构造并执行 check。
    /// Strict 模式 + AutoApprover boxed → Ok。
    #[tokio::test]
    async fn boxed_approver_严格模式() {
        let boxed: Box<dyn Approver> = Box::new(AutoApprover);
        let mgr = ApprovalManager::new(ApprovalMode::Strict, boxed);
        let req = WriteRequest {
            op: "write".into(),
            path: "b.txt".into(),
            diff_preview: None,
            backup_path: None,
        };
        assert!(mgr.check(&req).await.is_ok());
    }

    // ── 超时 = 拒绝 ──

    /// 永不响应的确认器（模拟用户没看到弹窗）。
    struct HangApprover;

    #[async_trait::async_trait]
    impl Approver for HangApprover {
        async fn ask(&self, _req: &WriteRequest) -> Decision {
            std::future::pending::<Decision>().await
        }
    }

    fn req() -> WriteRequest {
        WriteRequest { op: "write".into(), path: "a.txt".into(), diff_preview: None, backup_path: None }
    }

    #[test]
    fn 写确认超时常量为45秒() {
        assert_eq!(WRITE_CONFIRM_TIMEOUT, std::time::Duration::from_secs(45));
    }

    #[tokio::test]
    async fn 无人响应_超时即拒绝() {
        let mgr = ApprovalManager::new(ApprovalMode::Strict, HangApprover)
            .with_timeout(std::time::Duration::from_millis(30));
        assert!(matches!(mgr.check(&req()).await, Err(ApprovalError::Timeout)));
    }

    #[tokio::test]
    async fn delete_无人响应_同样超时拒绝() {
        let mgr = ApprovalManager::new(ApprovalMode::SessionTrust, HangApprover)
            .with_timeout(std::time::Duration::from_millis(30));
        let mut r = req();
        r.op = "delete".into();
        assert!(matches!(mgr.check(&r).await, Err(ApprovalError::Timeout)));
    }
}
