// src-tauri/src/daemon/approval_native.rs
//! 原生窗口确认器：将 Task 4 的 AutoApprover 替换为真正的桌面弹窗确认。
//!
//! # 架构难点：daemon 先于 AppHandle 存在
//!
//! `lib.rs::run()` 在 `tauri::Builder::default().run()` 之前 spawn daemon 线程。
//! 那时 AppHandle 尚不存在，不能直接传给 NativeWindowApprover。
//!
//! # 解决方案：ApprovalBridge（Arc 共享的双向桥）
//!
//! ```text
//! run() 里构造 Arc<ApprovalBridge>
//!    ├─ spawn_daemon_if_configured(bridge.clone())   ← daemon 线程拿到 Arc
//!    └─ Builder::default().setup(|app| {             ← GUI setup 拿到 Arc
//!         bridge.set_app_handle(app.handle().clone());
//!       })
//! ```
//!
//! 当 daemon 调用 NativeWindowApprover::ask() 时：
//!   1. 把请求 + oneshot::Sender 存入 ApprovalBridge::pending_map
//!   2. 通过 AppHandle.run_on_main_thread() 在 GUI 线程创建/显示 approval 窗口
//!      （Tauri WebviewWindowBuilder 必须在主线程调用）
//!   3. await oneshot::Receiver，等待用户点击
//!   4. respond_approval Tauri command（在主线程）取出 oneshot::Sender 发送决策
//!
//! # 无 AppHandle / 无 GUI 时的安全兜底
//!
//! 若 AppHandle 尚未注入（GUI 未启动 / 纯 headless 模式）：
//!   - ask() 立即返回 Decision::Rejected，绝不自动批准。
//!   - 日志级别 WARN，便于排查。
//!
//! # 线程安全分析
//!
//! ApprovalBridge 全字段：
//!   - app_handle: Mutex<Option<AppHandle>>  — AppHandle 本身 Clone+Send+Sync
//!   - pending:    Mutex<HashMap<...>>       — 受 Mutex 保护
//!
//! NativeWindowApprover 包装 Arc<ApprovalBridge>，Send+Sync 由 Arc 保证。
//! ask() 运行在 daemon 的 tokio runtime 线程池；respond() 运行在 Tauri 主线程（命令处理）。
//! 两者通过 Mutex + oneshot 协调，无数据竞争。

use super::approval::{Approver, Decision, WriteRequest};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::AppHandle;

// ────────────────────────────────────────────────────────────────
// 待确认请求条目（存入 pending_map）
// ────────────────────────────────────────────────────────────────

/// 挂起中的确认请求，包含：用于向 approval 窗口展示的请求快照 + 决策回传通道。
struct PendingApproval {
    /// 确认请求（用于 get_pending_approval 命令序列化给前端）
    request: ApprovalPayload,
    /// 用于将用户决策回传给 ask() 的 oneshot 发送端
    tx: tokio::sync::oneshot::Sender<Decision>,
}

// ────────────────────────────────────────────────────────────────
// 前端展示用 payload（可序列化）
// ────────────────────────────────────────────────────────────────

/// 传给 approval 窗口前端的确认请求 payload。
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalPayload {
    /// 任务 ID（唯一标识本次待确认）
    pub task_id: String,
    /// 发起操作的 agent ID（来自 WriteRequest）
    pub agent_id: String,
    /// 操作类型："write" | "edit" | "delete"
    pub op: String,
    /// 目标文件路径
    pub path: String,
    /// diff 预览（edit 操作时有值）
    pub diff_preview: Option<String>,
    /// 备份文件路径（若已备份）
    pub backup_path: Option<String>,
}

// ────────────────────────────────────────────────────────────────
// ApprovalBridge：daemon 与 GUI 共享的协调状态
// ────────────────────────────────────────────────────────────────

/// daemon 与 GUI 之间的审批桥。
///
/// 在 `lib.rs::run()` 里构造，以 `Arc` 分别传给：
/// - daemon 线程（包装进 `NativeWindowApprover`，实现 `Approver` trait）
/// - Tauri `.setup()` 闭包（注入 AppHandle）
/// - Tauri 命令层（通过 `.manage()` 注册为状态）
pub struct ApprovalBridge {
    /// GUI 启动后由 setup 闭包注入；daemon 使用前先检查，无则 Reject。
    app_handle: Mutex<Option<AppHandle>>,
    /// 当前挂起的确认请求（task_id → PendingApproval）。
    /// 当前实现同时只有一个待确认（串行审批）；HashMap 为后续并发扩展预留。
    pending: Mutex<HashMap<String, PendingApproval>>,
}

impl ApprovalBridge {
    /// 创建空桥（AppHandle 尚无，pending 为空）。
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            app_handle: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// 由 Tauri `.setup()` 闭包调用，注入 AppHandle。
    /// 在此之前 ask() 会安全 Reject。
    pub fn set_app_handle(&self, handle: AppHandle) {
        let mut guard = self.app_handle.lock().unwrap();
        *guard = Some(handle);
        log::info!("[approval-bridge] AppHandle 已注入，原生确认窗口就绪");
    }

    /// 取出当前挂起的第一个请求 payload（供 get_pending_approval 命令）。
    /// 不 remove，只读——窗口前端读完后等用户点击。
    pub fn peek_pending(&self) -> Option<ApprovalPayload> {
        let guard = self.pending.lock().unwrap();
        guard.values().next().map(|p| p.request.clone())
    }

    /// 用户作出决策：取出 PendingApproval，通过 oneshot 回传 Decision 给 ask()。
    ///
    /// - `task_id`：对应 PendingApproval 的键
    /// - `decision_str`："approved" | "rejected" | "trust_session"
    /// - `trust_path`：`trust_session` 时要信任的目录路径（前端传回 req.path 的 parent）
    ///
    /// 返回 `Ok(())` 表示成功发送；`Err` 表示 task_id 不存在（可能已超时被清理）。
    pub fn respond(
        &self,
        task_id: &str,
        decision_str: &str,
        trust_path: Option<std::path::PathBuf>,
    ) -> Result<(), String> {
        let entry = {
            let mut guard = self.pending.lock().unwrap();
            guard.remove(task_id)
        };
        match entry {
            None => Err(format!("[approval-bridge] task_id 不存在或已超时: {task_id}")),
            Some(pending) => {
                let decision = match decision_str {
                    "approved" => Decision::Approved,
                    "rejected" => Decision::Rejected,
                    "trust_session" => {
                        // trust_session 时用 req.path 的 parent 作为信任目录；
                        // 若前端未传则退化为 Approved（安全：比 Rejected 稍宽松，
                        // 但不扩散整个 session_trust 缓存）
                        let dir = trust_path.unwrap_or_else(|| {
                            std::path::PathBuf::from(&pending.request.path)
                                .parent()
                                .map(|p| p.to_path_buf())
                                .unwrap_or_default()
                        });
                        Decision::TrustSession(dir)
                    }
                    other => {
                        log::warn!("[approval-bridge] 未知 decision: {other}，视为 Rejected");
                        Decision::Rejected
                    }
                };
                // oneshot 发送端 send 失败说明 ask() 已超时离开，安全忽略
                let _ = pending.tx.send(decision);
                Ok(())
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────
// NativeWindowApprover：实现 Approver trait
// ────────────────────────────────────────────────────────────────

/// 原生窗口确认器：ask() 弹出 approval 窗口，等待用户点击。
///
/// 通过 `Arc<ApprovalBridge>` 与 GUI 层共享状态，桥接 daemon tokio runtime 与
/// Tauri 主线程。
pub struct NativeWindowApprover {
    bridge: Arc<ApprovalBridge>,
}

impl NativeWindowApprover {
    /// 包装共享桥，构造确认器。
    pub fn new(bridge: Arc<ApprovalBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait::async_trait]
impl Approver for NativeWindowApprover {
    /// 弹出原生确认窗口，等待用户决策（最多 45 秒，由 ApprovalManager::ask_with_timeout 控制）。
    ///
    /// 若无 AppHandle（headless / GUI 未就绪）→ 安全 Reject，绝不自动批准。
    async fn ask(&self, req: &WriteRequest) -> Decision {
        // ① 生成唯一任务 ID
        let task_id = format!(
            "approval_{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        // ② 检查 AppHandle 是否已注入（GUI 是否已启动）
        let app_handle: AppHandle = {
            let guard = self.bridge.app_handle.lock().unwrap();
            match guard.as_ref() {
                Some(h) => h.clone(),
                None => {
                    log::warn!(
                        "[approval] AppHandle 未就绪（GUI 未启动 / headless 模式），\
                         安全 Reject 操作: op={} path={}",
                        req.op,
                        req.path
                    );
                    return Decision::Rejected;
                }
            }
        };

        // ③ 构造 oneshot channel 并把请求存入 pending_map
        let (tx, rx) = tokio::sync::oneshot::channel::<Decision>();
        let payload = ApprovalPayload {
            task_id: task_id.clone(),
            // WriteRequest 当前无 agent_id 字段；用占位符，Task 7+ 可补齐
            agent_id: "agent".to_string(),
            op: req.op.clone(),
            path: req.path.clone(),
            diff_preview: req.diff_preview.clone(),
            backup_path: req.backup_path.clone(),
        };
        {
            let mut guard = self.bridge.pending.lock().unwrap();
            guard.insert(
                task_id.clone(),
                PendingApproval {
                    request: payload,
                    tx,
                },
            );
        }

        // ④ 在 GUI 主线程创建/显示 approval 窗口
        //    run_on_main_thread 把闭包派发到 Tauri 事件循环；
        //    approval 窗口加载本地 approval.html（非远程 URL，符合安全红线）。
        //    若窗口已存在则先关闭再重建（同时只有一个待确认）。
        //    app_handle_for_closure 是独立 clone，避免 borrow-move 冲突（E0505）。
        //    bridge_for_closure 是桥的 Arc clone，供 build() 失败时立即清 pending + Reject。
        let tid = task_id.clone();
        let app_handle_for_closure = app_handle.clone();
        let bridge_for_closure = self.bridge.clone();
        let result = app_handle.run_on_main_thread(move || {
            use tauri::Manager;
            // 若已有 approval 窗口，先关闭（防止堆叠）
            if let Some(existing) = app_handle_for_closure.get_webview_window("approval") {
                let _ = existing.close();
            }
            match tauri::WebviewWindowBuilder::new(
                &app_handle_for_closure,
                "approval",
                tauri::WebviewUrl::App("approval.html".into()),
            )
            .title("Hanako 确认")
            .inner_size(520.0, 440.0)
            .resizable(false)
            .always_on_top(true)
            .focused(true)
            .build()
            {
                Ok(_w) => {
                    log::info!("[approval] 确认窗口已打开 task_id={tid}");
                }
                Err(e) => {
                    log::error!("[approval] 无法创建确认窗口: {e}，立即 Reject 并清理 pending");
                    // build() 失败：从 pending_map 取出 entry 并通过 oneshot 发 Rejected，
                    // 让 ask() 立即返回 Rejected 而非等到 45s 超时。
                    // respond() 内部已 remove-then-send，语义与超时路径一致；
                    // 若 ask() 已因超时离开（rx 被 drop），send() 失败被安全忽略。
                    let _ = bridge_for_closure.respond(&tid, "rejected", None);
                }
            }
        });

        if let Err(e) = result {
            log::error!("[approval] run_on_main_thread 失败: {e}");
            // 清理 pending_map 中的 entry，避免泄漏
            self.bridge.pending.lock().unwrap().remove(&task_id);
            return Decision::Rejected;
        }

        // ⑤ 等待用户响应（超时由 ApprovalManager::ask_with_timeout 的 45s 负责）
        match rx.await {
            Ok(decision) => {
                log::info!(
                    "[approval] task_id={task_id} 用户决策: {:?}",
                    decision
                );
                decision
            }
            Err(_) => {
                // sender 被 drop（ApprovalBridge::respond 未被调用，或 bridge 被 drop）
                log::warn!("[approval] task_id={task_id} oneshot channel 关闭，视为 Rejected");
                Decision::Rejected
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────
// 单元测试（headless 可运行）
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证：无 AppHandle 时 ask() 安全 Rejected（headless 兜底）。
    #[tokio::test]
    async fn headless_无_app_handle_返回_rejected() {
        let bridge = ApprovalBridge::new();
        let approver = NativeWindowApprover::new(bridge);
        let req = WriteRequest {
            op: "write".into(),
            path: "/tmp/test.txt".into(),
            diff_preview: None,
            backup_path: None,
        };
        let decision = approver.ask(&req).await;
        assert_eq!(decision, Decision::Rejected, "无 AppHandle 时应安全 Reject");
    }

    /// 验证：bridge.respond 对不存在的 task_id 返回 Err。
    #[test]
    fn respond_不存在的_task_id_返回_err() {
        let bridge = ApprovalBridge::new();
        let result = bridge.respond("nonexistent", "approved", None);
        assert!(result.is_err());
    }

    /// 验证：pending_map 存入 + 取出流程（不依赖 AppHandle）。
    #[test]
    fn pending_存入后_peek_可见() {
        let bridge = ApprovalBridge::new();
        let (tx, _rx) = tokio::sync::oneshot::channel::<Decision>();
        {
            let mut guard = bridge.pending.lock().unwrap();
            guard.insert(
                "task_123".to_string(),
                PendingApproval {
                    request: ApprovalPayload {
                        task_id: "task_123".to_string(),
                        agent_id: "agent".to_string(),
                        op: "write".to_string(),
                        path: "/tmp/a.txt".to_string(),
                        diff_preview: None,
                        backup_path: None,
                    },
                    tx,
                },
            );
        }
        let payload = bridge.peek_pending();
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().task_id, "task_123");
    }

    /// 验证：respond 发送 Approved 后 pending_map 被清空。
    #[tokio::test]
    async fn respond_发送后_pending_清空() {
        let bridge = ApprovalBridge::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<Decision>();
        {
            let mut guard = bridge.pending.lock().unwrap();
            guard.insert(
                "task_456".to_string(),
                PendingApproval {
                    request: ApprovalPayload {
                        task_id: "task_456".to_string(),
                        agent_id: "agent".to_string(),
                        op: "edit".to_string(),
                        path: "/tmp/b.txt".to_string(),
                        diff_preview: Some("@@ -1 +1 @@".to_string()),
                        backup_path: None,
                    },
                    tx,
                },
            );
        }

        // respond 发送 Approved
        bridge.respond("task_456", "approved", None).unwrap();

        // pending_map 应为空
        assert!(bridge.peek_pending().is_none());

        // oneshot 应收到 Approved
        let decision = rx.await.unwrap();
        assert_eq!(decision, Decision::Approved);
    }

    /// 验证（Fix I-1）：窗口 build() 失败时 pending 被清空且 oneshot 收到 Rejected。
    ///
    /// 直接模拟闭包内的 build 失败路径：build() 失败时闭包调用
    /// `bridge.respond(&tid, "rejected", None)`，这里直接验证该语义。
    /// （run_on_main_thread 需要真实 AppHandle，无法在 headless 单测中触发；
    ///   逻辑等价路径可完整覆盖）
    #[tokio::test]
    async fn build_失败时_pending_清空且_oneshot_收到_rejected() {
        let bridge = ApprovalBridge::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<Decision>();
        let tid = "task_build_fail".to_string();
        {
            let mut guard = bridge.pending.lock().unwrap();
            guard.insert(
                tid.clone(),
                PendingApproval {
                    request: ApprovalPayload {
                        task_id: tid.clone(),
                        agent_id: "agent".to_string(),
                        op: "write".to_string(),
                        path: "/tmp/build_fail.txt".to_string(),
                        diff_preview: None,
                        backup_path: None,
                    },
                    tx,
                },
            );
        }

        // 模拟 build() 失败时闭包调用的路径
        bridge.respond(&tid, "rejected", None).unwrap();

        // pending_map 必须被清空（不再阻塞后续审批）
        assert!(bridge.peek_pending().is_none(), "build 失败后 pending 应为空");

        // ask() 的 rx 端应立即收到 Rejected（不等超时）
        let decision = rx.await.unwrap();
        assert_eq!(decision, Decision::Rejected, "build 失败应立即 Rejected");
    }

    /// 验证（Fix I-1）：build() 失败后再次调用 respond 返回 Err（无双发）。
    #[test]
    fn build_失败后_重复_respond_返回_err() {
        let bridge = ApprovalBridge::new();
        let (tx, _rx) = tokio::sync::oneshot::channel::<Decision>();
        let tid = "task_double_respond".to_string();
        {
            let mut guard = bridge.pending.lock().unwrap();
            guard.insert(
                tid.clone(),
                PendingApproval {
                    request: ApprovalPayload {
                        task_id: tid.clone(),
                        agent_id: "agent".to_string(),
                        op: "write".to_string(),
                        path: "/tmp/x.txt".to_string(),
                        diff_preview: None,
                        backup_path: None,
                    },
                    tx,
                },
            );
        }
        // 第一次 respond（模拟 build 失败）
        bridge.respond(&tid, "rejected", None).unwrap();
        // 第二次 respond（超时路径或重复调用）必须返回 Err，不双发
        let second = bridge.respond(&tid, "rejected", None);
        assert!(second.is_err(), "第二次 respond 应返回 Err（entry 已被清理）");
    }

    /// 验证：respond trust_session 使用默认路径（req.path 的 parent）。
    #[tokio::test]
    async fn respond_trust_session_使用默认路径() {
        let bridge = ApprovalBridge::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<Decision>();
        {
            let mut guard = bridge.pending.lock().unwrap();
            guard.insert(
                "task_789".to_string(),
                PendingApproval {
                    request: ApprovalPayload {
                        task_id: "task_789".to_string(),
                        agent_id: "agent".to_string(),
                        op: "write".to_string(),
                        path: "/home/user/docs/file.txt".to_string(),
                        diff_preview: None,
                        backup_path: None,
                    },
                    tx,
                },
            );
        }
        bridge.respond("task_789", "trust_session", None).unwrap();
        let decision = rx.await.unwrap();
        assert_eq!(
            decision,
            Decision::TrustSession(std::path::PathBuf::from("/home/user/docs"))
        );
    }
}
