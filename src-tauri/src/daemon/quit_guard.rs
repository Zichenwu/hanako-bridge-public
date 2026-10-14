// src-tauri/src/daemon/quit_guard.rs
//! 退出保护（票 17：「退出时有进行中写先确认」）。
//!
//! 进行中的写操作被强杀，可能留下写到一半的文件（虽然有备份可回滚，但用户不知道发生了什么）。
//! 读操作被打断无害，不需要拦。所以只统计**写类**任务。
//!
//! 设计：计数器由 client 在写类任务开始/结束时增减；退出菜单先问 `decide()`：
//! - 没有进行中写 → 直接退；
//! - 有 → 返回需要确认的文案，由 UI 层弹原生确认，确认后调用方自行退出。
//!
//! 计数用 RAII 守卫（`WriteGuard`）：任务 panic / 提前返回时也会减，避免计数漏减导致「永远提示有进行中写」。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// 写类工具名（与 tools/mod.rs 的派发一致）。
/// 审核 P2：原列表漏了 `local_upload_to_workspace`——它把本机文件字节传出境，
/// 强杀会留下传了一半的上传（云端「本机文件/」里出现残缺文件），与写文件同等需要退出确认。
pub const WRITE_TOOLS: [&str; 4] = [
    "local_write_file",
    "local_edit_file",
    "local_delete_file",
    "local_upload_to_workspace",
];

pub fn is_write_tool(name: &str) -> bool {
    WRITE_TOOLS.contains(&name)
}

#[derive(Debug, Default)]
pub struct QuitGuard {
    writing: AtomicU32,
}

/// 退出决策。
#[derive(Debug, PartialEq, Eq)]
pub enum QuitDecision {
    /// 可以直接退出
    Proceed,
    /// 有 n 个写操作正在进行，需用户确认
    ConfirmNeeded { count: u32, message: String },
}

impl QuitGuard {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 写类任务开始：返回守卫，drop 时自动计数 -1。读类工具返回 None（不占计数）。
    pub fn begin(self: &Arc<Self>, tool: &str) -> Option<WriteGuard> {
        if !is_write_tool(tool) {
            return None;
        }
        self.writing.fetch_add(1, Ordering::SeqCst);
        Some(WriteGuard { g: self.clone() })
    }

    pub fn writing(&self) -> u32 {
        self.writing.load(Ordering::SeqCst)
    }

    pub fn decide(&self) -> QuitDecision {
        let n = self.writing();
        if n == 0 {
            QuitDecision::Proceed
        } else {
            QuitDecision::ConfirmNeeded {
                count: n,
                message: format!("有 {n} 个修改文件的操作正在进行，现在退出可能让文件停在修改一半的状态（已有备份，可在设置里找回）。仍要退出吗？"),
            }
        }
    }
}

pub struct WriteGuard {
    g: Arc<QuitGuard>,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        // 饱和减：理论上不会下溢，防御性保证 drop 永不 panic
        let _ = self.g.writing.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 只有写类工具计数_读类不拦退出() {
        let g = QuitGuard::new();
        assert!(g.begin("local_read_file").is_none());
        assert!(g.begin("local_list_dir").is_none());
        assert!(g.begin("local_grep").is_none());
        assert_eq!(g.decide(), QuitDecision::Proceed);
        let _w = g.begin("local_write_file").unwrap();
        assert!(matches!(g.decide(), QuitDecision::ConfirmNeeded { count: 1, .. }));
    }

    #[test]
    fn 写工具都算_含上传() {
        // 审核 P2：上传（local_upload_to_workspace）也是写类——强杀留下传了一半的出境文件。
        let g = QuitGuard::new();
        let _a = g.begin("local_write_file");
        let _b = g.begin("local_edit_file");
        let _c = g.begin("local_delete_file");
        let _d = g.begin("local_upload_to_workspace");
        assert_eq!(g.writing(), 4);
    }

    #[test]
    fn 守卫_drop_自动减_含_panic_路径() {
        let g = QuitGuard::new();
        {
            let _w = g.begin("local_edit_file").unwrap();
            assert_eq!(g.writing(), 1);
        }
        assert_eq!(g.writing(), 0);
        assert_eq!(g.decide(), QuitDecision::Proceed);

        // 任务 panic 也必须减回去，否则退出菜单永远提示「有进行中写」
        let g2 = g.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _w = g2.begin("local_write_file").unwrap();
            panic!("工具执行中途崩溃");
        }));
        assert!(r.is_err());
        assert_eq!(g.writing(), 0, "panic 后计数必须归零");
    }

    #[test]
    fn 确认文案含数量与备份提示() {
        let g = QuitGuard::new();
        let _a = g.begin("local_write_file");
        let _b = g.begin("local_write_file");
        match g.decide() {
            QuitDecision::ConfirmNeeded { count, message } => {
                assert_eq!(count, 2);
                assert!(message.contains("2 个"), "{message}");
                assert!(message.contains("备份"), "要告诉用户有后路: {message}");
            }
            d => panic!("应需要确认: {d:?}"),
        }
    }
}
