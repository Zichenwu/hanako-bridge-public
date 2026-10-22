// src-tauri/src/daemon/command_approval.rs
//! 本机命令确认（docs: openhanako ADR 0013 / spec 05）。
//!
//! 与写文件确认（`approval.rs`）是**两条独立链**：
//! - 命令确认**永不经过网页确认装饰器**（`WebFirstApprover`）——ADR 0013 决策 1，地位等同删除；
//!   结构上靠「命令确认器单独注入，不与写文件共用 approver」保证，而不是靠运行时判断。
//! - 请求形状不同：命令原文 + 工作目录 + 来源，而不是路径 + diff。
//!
//! 生产实现（原生窗口）在票 02 接入；本模块先给出 trait 与测试替身，供端到端测试注入。

use serde::{Deserialize, Serialize};

/// 一条命令确认请求（展示给电脑主人）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRequest {
    /// 服务端任务 id（同一时刻只弹一个，排队用）
    pub task_id: String,
    /// 命令原文（展示前已脱敏）
    pub command: String,
    /// 规范化后的工作目录
    pub cwd: String,
    /// 工作目录所在授权目录是否只读（确认窗醒目提示）
    pub read_only_root: bool,
    /// 发起的执行体 / 会话（展示「来自哪个助手和会话」）
    pub agent_id: String,
    pub session_id: String,
    /// 模型给的理由（可空）
    pub reason: Option<String>,
}

/// 电脑主人对一条命令的决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandDecision {
    /// 仅此一次
    Once,
    /// 本会话内逐字相同的命令 + 目录不再问
    SessionPass,
    /// 拒绝（含超时：调用方把超时也当拒绝，对外不可区分）
    Rejected,
}

/// 命令确认器。实现方负责「在被操作的那台电脑上」征得同意。
#[async_trait::async_trait]
pub trait CommandApprover: Send + Sync {
    async fn ask(&self, req: &CommandRequest) -> CommandDecision;
}

/// 测试替身：固定回答，并记录收到的请求。`None` = 永不回答（模拟人不在电脑前，由调用方超时）。
pub struct FixedCommandApprover {
    answer: Option<CommandDecision>,
    seen: std::sync::Mutex<Vec<CommandRequest>>,
}

impl FixedCommandApprover {
    pub fn new(answer: Option<CommandDecision>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { answer, seen: std::sync::Mutex::new(Vec::new()) })
    }
    /// 迄今收到的请求（按到达顺序）。
    pub fn seen(&self) -> Vec<CommandRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl CommandApprover for FixedCommandApprover {
    async fn ask(&self, req: &CommandRequest) -> CommandDecision {
        self.seen.lock().unwrap().push(req.clone());
        match self.answer {
            Some(d) => d,
            None => std::future::pending().await,
        }
    }
}

/// 无窗口时的默认实现：一律拒绝（fail-closed）。票 02 换成原生窗口实现。
pub struct DenyAllCommandApprover;

#[async_trait::async_trait]
impl CommandApprover for DenyAllCommandApprover {
    async fn ask(&self, _req: &CommandRequest) -> CommandDecision {
        CommandDecision::Rejected
    }
}

// ────────────────────────────────────────────────────────────────
// 本会话免问（Session Pass）
// ────────────────────────────────────────────────────────────────

/// 本会话免问记录：键 = (会话, 命令原文, 规范化 cwd)，**逐字**比较，不做模糊匹配。
/// 只存内存：Bridge 重启即清空。撤销授权由执行器每次用现读策略复核目录（目录被撤即不命中），
/// 暂停由 [`SessionPasses::clear`] 清空。
#[derive(Default)]
pub struct SessionPasses {
    set: std::sync::Mutex<std::collections::HashSet<(String, String, String)>>,
}

/// 设置窗展示用的一条记录。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PassView {
    pub session_id: String,
    pub command: String,
    pub cwd: String,
}

impl SessionPasses {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }
    pub fn grant(&self, session: &str, command: &str, cwd: &str) {
        if session.is_empty() {
            return; // 没有会话归属的命令不记免问
        }
        self.set.lock().unwrap().insert((session.into(), command.into(), cwd.into()));
    }
    pub fn hit(&self, session: &str, command: &str, cwd: &str) -> bool {
        !session.is_empty() && self.set.lock().unwrap().contains(&(session.into(), command.into(), cwd.into()))
    }
    /// 撤销某一条（设置窗逐条删）。
    pub fn revoke(&self, session: &str, command: &str, cwd: &str) -> bool {
        self.set.lock().unwrap().remove(&(session.into(), command.into(), cwd.into()))
    }
    pub fn clear(&self) {
        self.set.lock().unwrap().clear();
    }
    /// 按设置窗展示值（命令已脱敏）撤销：脱敏后相同的条目一并删。
    pub fn revoke_shown(&self, session: &str, shown_command: &str, cwd: &str) {
        self.set.lock().unwrap().retain(|(s, c, d)| {
            !(s == session && d == cwd && crate::daemon::command_guard::redact(c).0 == shown_command)
        });
    }
    /// 设置窗列表（命令已脱敏）。
    pub fn list(&self) -> Vec<PassView> {
        let mut v: Vec<PassView> = self
            .set
            .lock()
            .unwrap()
            .iter()
            .map(|(s, c, d)| PassView {
                session_id: s.clone(),
                command: crate::daemon::command_guard::redact(c).0,
                cwd: d.clone(),
            })
            .collect();
        v.sort_by(|a, b| (&a.session_id, &a.command).cmp(&(&b.session_id, &b.command)));
        v
    }
}

// ────────────────────────────────────────────────────────────────
// 原生窗口确认桥（生产实现）
// ────────────────────────────────────────────────────────────────

/// 排队上限：同时只展示 1 个，再排 3 个；更多直接拒（spec 05「确认串行」）。
pub const MAX_QUEUED: usize = 3;

struct Pending {
    req: CommandRequest,
    tx: tokio::sync::oneshot::Sender<CommandDecision>,
    /// 轮到展示时通知等待方开始计时
    shown: Option<tokio::sync::oneshot::Sender<()>>,
}

#[derive(Default)]
struct Inner {
    visible: Option<Pending>,
    queue: std::collections::VecDeque<Pending>,
}

/// 命令确认桥：**排队、不互顶**（写文件的 approval 窗新请求会顶掉旧请求，命令不能沿用）。
/// 确认计时从「轮到它展示」起算（排队期间不计时，由 [`MAX_QUEUED`] 限制排队长度），超时 = 拒绝。
/// 没有窗口实现（headless）一律拒。
pub struct CommandBridge {
    inner: std::sync::Mutex<Inner>,
    show: std::sync::Mutex<Option<std::sync::Arc<dyn Fn(&CommandRequest) -> bool + Send + Sync>>>,
    timeout: std::time::Duration,
}

impl CommandBridge {
    pub fn new() -> std::sync::Arc<Self> {
        Self::with_timeout(crate::daemon::tools::command::CONFIRM_TIMEOUT)
    }

    pub fn with_timeout(timeout: std::time::Duration) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { inner: Default::default(), show: Default::default(), timeout })
    }

    /// GUI setup 后注入「打开确认窗」的实现。返回 false = 打不开（按拒绝）。
    pub fn set_presenter(&self, f: std::sync::Arc<dyn Fn(&CommandRequest) -> bool + Send + Sync>) {
        *self.show.lock().unwrap() = Some(f);
    }

    /// 窗口取当前展示的请求。
    pub fn peek(&self) -> Option<CommandRequest> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).visible.as_ref().map(|p| p.req.clone())
    }

    pub fn queued(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).queue.len()
    }

    /// 窗口提交。迟到 / 不匹配的 task_id 一律 Err。
    pub fn respond(&self, task_id: &str, d: CommandDecision) -> Result<(), String> {
        let next = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            match g.visible.take() {
                Some(p) if p.req.task_id == task_id => {
                    let _ = p.tx.send(d);
                    g.promote()
                }
                other => {
                    g.visible = other;
                    return Err(format!("命令确认不存在或已超时: {task_id}"));
                }
            }
        };
        self.present(next);
        Ok(())
    }

    /// 某请求结束（超时 / 被取消）时摘掉自己并提上队首。
    fn forget(&self, task_id: &str) {
        let next = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.queue.retain(|p| p.req.task_id != task_id);
            if g.visible.as_ref().map(|p| p.req.task_id == task_id).unwrap_or(false) {
                g.visible = None;
                g.promote()
            } else {
                None
            }
        };
        self.present(next);
    }

    fn present(&self, mut next: Option<CommandRequest>) {
        while let Some(req) = next {
            let f = self.show.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if f.map(|f| f(&req)).unwrap_or(false) {
                return;
            }
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.visible = None; // tx drop → 该次得到拒绝
            next = g.promote();
        }
    }
}

impl Inner {
    fn promote(&mut self) -> Option<CommandRequest> {
        if self.visible.is_some() {
            return None;
        }
        let mut p = self.queue.pop_front()?;
        if let Some(s) = p.shown.take() {
            let _ = s.send(());
        }
        let req = p.req.clone();
        self.visible = Some(p);
        Some(req)
    }
}

/// 摘除守卫：`ask` 的 future 被丢弃（超时 / task_cancel）时也把自己从桥里清掉，不卡住队列。
struct Forget<'a>(&'a CommandBridge, String);
impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.0.forget(&self.1);
    }
}

#[async_trait::async_trait]
impl CommandApprover for CommandBridge {
    async fn ask(&self, req: &CommandRequest) -> CommandDecision {
        if self.show.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
            log::warn!("[command] 没有确认窗实现（headless），拒绝");
            return CommandDecision::Rejected;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (shown_tx, shown_rx) = tokio::sync::oneshot::channel();
        let show_now = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.visible.is_none() {
                g.visible = Some(Pending { req: req.clone(), tx, shown: None });
                true
            } else if g.queue.len() < MAX_QUEUED {
                g.queue.push_back(Pending { req: req.clone(), tx, shown: Some(shown_tx) });
                false
            } else {
                log::warn!("[command] 确认排队已满（{MAX_QUEUED}），拒绝 {}", req.task_id);
                return CommandDecision::Rejected;
            }
        };
        let _forget = Forget(self, req.task_id.clone());
        if show_now {
            self.present(Some(req.clone()));
        } else if shown_rx.await.is_err() {
            // 排队中被摘掉（窗口打不开等）
            return CommandDecision::Rejected;
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(d)) => d,
            _ => CommandDecision::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> CommandRequest {
        CommandRequest {
            task_id: "t1".into(),
            command: "git status".into(),
            cwd: "/w".into(),
            read_only_root: false,
            agent_id: "a".into(),
            session_id: "s".into(),
            reason: None,
        }
    }

    #[tokio::test]
    async fn 替身按固定答案回答并记录请求() {
        let a = FixedCommandApprover::new(Some(CommandDecision::SessionPass));
        assert_eq!(a.ask(&req()).await, CommandDecision::SessionPass);
        assert_eq!(a.seen(), vec![req()]);
    }

    #[tokio::test]
    async fn 替身无答案时永不返回() {
        let a = FixedCommandApprover::new(None);
        let r = tokio::time::timeout(std::time::Duration::from_millis(50), a.ask(&req())).await;
        assert!(r.is_err());
    }

    fn req_id(id: &str) -> CommandRequest {
        CommandRequest { task_id: id.into(), ..req() }
    }

    #[tokio::test]
    async fn 桥_无窗口实现一律拒() {
        let b = CommandBridge::new();
        assert_eq!(b.ask(&req()).await, CommandDecision::Rejected);
    }

    #[tokio::test]
    async fn 桥_三条并发依次展示_无一被顶掉() {
        let b = CommandBridge::new();
        let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let s2 = shown.clone();
        b.set_presenter(std::sync::Arc::new(move |r| { s2.lock().unwrap().push(r.task_id.clone()); true }));
        let hs: Vec<_> = ["a", "b", "c"].iter().map(|id| {
            let b = b.clone();
            let id = id.to_string();
            tokio::spawn(async move { b.ask(&req_id(&id)).await })
        }).collect();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(shown.lock().unwrap().len(), 1, "同一时刻只展示一个");
        for _ in 0..3 {
            let cur = b.peek().expect("应有展示中的请求").task_id;
            b.respond(&cur, CommandDecision::Once).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for h in hs {
            assert_eq!(h.await.unwrap(), CommandDecision::Once);
        }
        assert_eq!(shown.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn 桥_排队超过上限直接拒() {
        let b = CommandBridge::new();
        b.set_presenter(std::sync::Arc::new(|_| true));
        let mut hs = Vec::new();
        for i in 0..(1 + MAX_QUEUED) {
            let b = b.clone();
            hs.push(tokio::spawn(async move { b.ask(&req_id(&format!("q{i}"))).await }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(b.ask(&req_id("over")).await, CommandDecision::Rejected);
        assert_eq!(b.queued(), MAX_QUEUED);
        for h in hs { h.abort(); }
    }

    #[tokio::test]
    async fn 桥_展示中的请求超时被丢弃后_队首顶上() {
        let b = CommandBridge::new();
        b.set_presenter(std::sync::Arc::new(|_| true));
        let b1 = b.clone();
        let first = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_millis(100), b1.ask(&req_id("first"))).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let b2 = b.clone();
        let second = tokio::spawn(async move { b2.ask(&req_id("second")).await });
        assert!(first.await.unwrap().is_err(), "first 应超时");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(b.peek().unwrap().task_id, "second");
        b.respond("second", CommandDecision::SessionPass).unwrap();
        assert_eq!(second.await.unwrap(), CommandDecision::SessionPass);
    }

    #[tokio::test]
    async fn 桥_计时从展示起算_排队期间不计() {
        let b = CommandBridge::with_timeout(std::time::Duration::from_millis(300));
        b.set_presenter(std::sync::Arc::new(|_| true));
        let b1 = b.clone();
        let first = tokio::spawn(async move { b1.ask(&req_id("first")).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let b2 = b.clone();
        let second = tokio::spawn(async move { b2.ask(&req_id("second")).await });
        // first 展示 250ms 后才答（second 已排队 250ms，若排队也计时则 second 只剩 50ms）
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        b.respond("first", CommandDecision::Once).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        b.respond("second", CommandDecision::Once).expect("second 不应已超时");
        assert_eq!(first.await.unwrap(), CommandDecision::Once);
        assert_eq!(second.await.unwrap(), CommandDecision::Once);
    }

    #[tokio::test]
    async fn 桥_展示后无人点按超时拒绝() {
        let b = CommandBridge::with_timeout(std::time::Duration::from_millis(100));
        b.set_presenter(std::sync::Arc::new(|_| true));
        assert_eq!(b.ask(&req_id("x")).await, CommandDecision::Rejected);
        assert!(b.peek().is_none(), "超时后应从展示位摘掉");
    }

    #[tokio::test]
    async fn 桥_迟到提交无效() {
        let b = CommandBridge::new();
        b.set_presenter(std::sync::Arc::new(|_| true));
        assert!(b.respond("ghost", CommandDecision::Once).is_err());
    }

    #[test]
    fn 免问_逐字匹配三元组() {
        let p = SessionPasses::new();
        p.grant("s1", "git status", "/w");
        assert!(p.hit("s1", "git status", "/w"));
        assert!(!p.hit("s1", "git status ", "/w"), "多一个空格也要问");
        assert!(!p.hit("s1", "git status", "/w/sub"), "换目录要问");
        assert!(!p.hit("s2", "git status", "/w"), "换会话要问");
        p.grant("", "x", "/w");
        assert!(!p.hit("", "x", "/w"), "无会话归属不记免问");
        assert!(p.revoke("s1", "git status", "/w"));
        p.grant("s1", "git status", "/w");
        p.revoke_shown("s1", &p.list()[0].command.clone(), "/w");
        assert!(!p.hit("s1", "git status", "/w"), "按展示值撤销");
        assert!(!p.hit("s1", "git status", "/w"));
        p.clear();
        assert!(p.list().is_empty());
    }

    #[tokio::test]
    async fn 默认实现一律拒绝() {
        assert_eq!(DenyAllCommandApprover.ask(&req()).await, CommandDecision::Rejected);
    }
}
