// src-tauri/src/daemon/approval_native.rs
//! 写文件 / 删除确认的原生窗口桥（Task 6 起；2026-10-29 改为排队 + 批量删除合并）。
//!
//! # 为什么重写（2026-10-29 真机事故）
//! 旧实现每来一个请求就「关掉 approval 窗口 → 立即用同一个 label 新建」。`close()` 是异步的，
//! 同一个主线程回调里旧窗口还没销毁，新建同名窗口失败 → 代码把失败当作**拒绝**立即返回。
//! 一次并发 13 个删除时用户看到「弹一下就闪走」，模型拿到 `user rejected` 说「你拒绝了 3 个」，
//! 而用户一个都没点；被顶掉的请求留在 pending 里没人能点，45 秒后超时。
//!
//! # 现在的模型
//! - **只有一个可见项**，其余排队（不互顶、不丢）；窗口复用，不再「关旧建新」。
//! - **删除合并**：可见项是删除、且它的「助手 + 会话」与队列里的其它删除相同 → 同一个窗口里
//!   列出全部，用户一次点「全部允许 / 全部拒绝」。写 / 改永远单独确认（要看路径、diff）。
//! - **计时从「轮到它展示」起算**（排队期间不计时，否则排在后面的请求还没露面就超时）；
//!   合并展示的一组共享同一个起点。排队长度有上限 [`MAX_QUEUED`]，超出直接拒（服务端另有并发上限）。
//! - **窗口打不开**单独报 [`Decision::Unavailable`]（不是「用户拒绝」），模型据此如实说明。
//!
//! # 线程模型
//! daemon 在自己的 tokio runtime 里 `ask()`；窗口命令在 Tauri 主线程 `respond()`。
//! 两边只通过 `Mutex<Inner>` + oneshot 协调。展示窗口用注入的 presenter（lib.rs 在 setup 里装），
//! 测试里注入假 presenter，不依赖 AppHandle。

use super::approval::{Approver, Decision, WriteRequest};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 排队上限：同时展示 1 组，再排 [`MAX_QUEUED`] 个；超出直接拒。
/// 服务端单节点并发上限 4（同一时刻最多 4 个在途任务），这里留足余量，正常不会触顶。
pub const MAX_QUEUED: usize = 32;

/// 一组合并展示的删除最多列多少条（再多就分批，防止窗口变成长卷轴、用户看不完就点允许）。
pub const MAX_BATCH: usize = 20;

/// 从展示起算的确认时限（与 `approval::WRITE_CONFIRM_TIMEOUT` 一致：45 秒无人响应 = 拒绝）。
pub const CONFIRM_TIMEOUT: Duration = super::approval::WRITE_CONFIRM_TIMEOUT;

/// 窗口里展示的单条。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApprovalItem {
    pub task_id: String,
    /// "write" | "edit" | "delete"
    pub op: String,
    pub path: String,
    pub diff_preview: Option<String>,
    pub backup_path: Option<String>,
}

/// 传给 approval 窗口前端的当前一组（单条写 / 改，或同来源的一批删除）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApprovalPayload {
    /// 本组 id（= 首条 task_id）。提交时回传，迟到 / 不匹配的一律拒绝。
    pub group_id: String,
    /// 发起的执行体（{team}--{user}；缺省 "agent"）
    pub agent_id: String,
    pub op: String,
    pub items: Vec<ApprovalItem>,
    /// 排在这组后面、还要确认的条数（窗口提示「之后还有 N 个」）
    pub queued_after: usize,
    /// 本组剩余秒数（窗口倒计时展示用；真正的超时在 Rust 侧）
    pub remaining_sec: u64,
    // ── 兼容旧前端的单条字段（取首条）──
    pub task_id: String,
    pub path: String,
    pub diff_preview: Option<String>,
    pub backup_path: Option<String>,
}

/// 展示窗口的实现：返回 false = 打不开（本组按「无法弹出确认窗」结束）。
pub type Presenter = Arc<dyn Fn() -> bool + Send + Sync>;
/// 本组结束后收起窗口（队列空时调用）。
pub type Hider = Arc<dyn Fn() + Send + Sync>;

struct Pending {
    item: ApprovalItem,
    agent_id: String,
    session: Option<String>,
    tx: tokio::sync::oneshot::Sender<Decision>,
    /// 轮到展示时通知等待方开始计时（随展示时刻一起发出）
    shown: Option<tokio::sync::oneshot::Sender<std::time::Instant>>,
    /// 开始展示的时刻（各条自己的计时起点：被提上来 / 并入正在展示的组那一刻）
    visible_at: Option<std::time::Instant>,
}

#[derive(Default)]
struct Inner {
    /// 当前展示的一组（非空 = 窗口上有东西）
    visible: Vec<Pending>,
    queue: VecDeque<Pending>,
    seq: u64,
    /// 页面最近一次拉到的条目（窗口上用户看得到的）。点关闭按钮时只把这些记为拒绝。
    last_seen: Vec<String>,
}

impl Inner {
    /// 可见组为空时，从队首拉起下一组（删除按来源合并）。返回是否拉起了新组。
    fn promote(&mut self) -> bool {
        if !self.visible.is_empty() {
            return false;
        }
        let Some(first) = self.queue.pop_front() else {
            return false;
        };
        let mut group = vec![first];
        if group[0].item.op == "delete" {
            let (agent, session) = (group[0].agent_id.clone(), group[0].session.clone());
            let mut rest = VecDeque::new();
            while let Some(p) = self.queue.pop_front() {
                if group.len() < MAX_BATCH && p.item.op == "delete" && p.agent_id == agent && p.session == session {
                    group.push(p);
                } else {
                    rest.push_back(p);
                }
            }
            self.queue = rest;
        }
        let now = std::time::Instant::now();
        for p in group.iter_mut() {
            p.visible_at = Some(now);
            if let Some(s) = p.shown.take() {
                let _ = s.send(now);
            }
        }
        self.visible = group;
        self.last_seen.clear(); // 新组：页面还没拉到它
        true
    }

    /// 可见组仍在展示时，把新到的同来源删除并进来（用户还没点，窗口刷新一下就能看到）。
    /// 并入的那条从并入时刻起算自己的 45 秒，不吃前面那些条已经用掉的时间。
    fn try_join_visible(&mut self, mut p: Pending) -> Result<std::time::Instant, Pending> {
        let can = match self.visible.first() {
            Some(head) => {
                head.item.op == "delete"
                    && p.item.op == "delete"
                    && head.agent_id == p.agent_id
                    && head.session == p.session
                    && self.visible.len() < MAX_BATCH
            }
            None => false,
        };
        if can {
            let now = std::time::Instant::now();
            p.visible_at = Some(now);
            p.shown = None;
            self.visible.push(p);
            Ok(now)
        } else {
            Err(p)
        }
    }

    fn payload(&self) -> Option<ApprovalPayload> {
        let head = self.visible.first()?;
        // 倒计时展示最急的那条（它到点会从列表里消失，列表随之刷新）
        let elapsed = self.visible.iter().filter_map(|p| p.visible_at).map(|t| t.elapsed()).max().unwrap_or_default();
        Some(ApprovalPayload {
            group_id: head.item.task_id.clone(),
            agent_id: head.agent_id.clone(),
            op: head.item.op.clone(),
            items: self.visible.iter().map(|p| p.item.clone()).collect(),
            queued_after: self.queue.len(),
            remaining_sec: CONFIRM_TIMEOUT.saturating_sub(elapsed).as_secs(),
            task_id: head.item.task_id.clone(),
            path: head.item.path.clone(),
            diff_preview: head.item.diff_preview.clone(),
            backup_path: head.item.backup_path.clone(),
        })
    }
}

/// daemon 与 GUI 共享的确认桥（lib.rs 构造，Arc 分给 daemon / setup / 窗口命令）。
pub struct ApprovalBridge {
    inner: Mutex<Inner>,
    presenter: Mutex<Option<Presenter>>,
    hider: Mutex<Option<Hider>>,
    timeout: Duration,
}

impl ApprovalBridge {
    pub fn new() -> Arc<Self> {
        Self::with_timeout(CONFIRM_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Arc<Self> {
        Arc::new(Self { inner: Default::default(), presenter: Default::default(), hider: Default::default(), timeout })
    }

    /// GUI setup 后注入「展示 / 收起窗口」实现。之前到达的请求按 headless 拒绝（不会自动批准）。
    pub fn set_presenter(&self, show: Presenter, hide: Hider) {
        *self.presenter.lock().unwrap_or_else(|e| e.into_inner()) = Some(show);
        *self.hider.lock().unwrap_or_else(|e| e.into_inner()) = Some(hide);
        log::info!("[approval-bridge] 原生确认窗口就绪");
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 窗口取当前展示的一组（同时记下「用户看得到哪些」，点关闭按钮时据此结算）。
    pub fn peek_pending(&self) -> Option<ApprovalPayload> {
        let mut g = self.lock();
        let p = g.payload();
        g.last_seen = p.as_ref().map(|p| p.items.iter().map(|i| i.task_id.clone()).collect()).unwrap_or_default();
        p
    }

    /// 当前是否没有要展示的（hider 在主线程里收起前再核一次，避免「先 show 后 hide」把新请求藏起来）。
    pub fn is_idle(&self) -> bool {
        self.lock().visible.is_empty()
    }

    /// 排队中的条数（不含当前展示的一组）。
    pub fn queued(&self) -> usize {
        self.lock().queue.len()
    }

    /// 用户对当前一组作出决定。
    ///
    /// - `group_id` 必须是当前展示组的 id；迟到 / 不匹配 → `Err`（窗口提示「已超时」，不会误批别的请求）
    /// - `decision_str`："approved" | "rejected"（其它一律按拒绝）
    /// - `task_ids`：窗口提交时**看到的**那些条。组在展示期间可能并入了新的删除、也可能有条目超时掉出，
    ///   只对「看到的且仍在组里」的条目生效，其余留在窗口里继续确认——绝不替用户批他没看到的文件。
    ///   缺省（旧页面）= 只对组首条生效。
    pub fn respond(&self, group_id: &str, decision_str: &str, task_ids: Option<Vec<String>>) -> Result<(), String> {
        let decision = match decision_str {
            "approved" => Decision::Approved,
            "rejected" => Decision::Rejected,
            other => {
                log::warn!("[approval-bridge] 未知 decision: {other}，视为拒绝");
                Decision::Rejected
            }
        };
        let reshow = {
            let mut g = self.lock();
            if g.visible.first().map(|p| p.item.task_id.as_str()) != Some(group_id) {
                return Err(format!("确认不存在或已超时: {group_id}"));
            }
            let seen: Vec<String> = task_ids.unwrap_or_else(|| vec![group_id.to_string()]);
            let (done, keep): (Vec<Pending>, Vec<Pending>) =
                g.visible.drain(..).partition(|p| seen.iter().any(|id| id == &p.item.task_id));
            g.visible = keep;
            for p in done {
                let _ = p.tx.send(decision.clone());
            }
            if g.visible.is_empty() {
                g.promote()
            } else {
                true // 剩下的是用户没看到的：留在窗口里刷新展示
            }
        };
        self.after_change(reshow);
        Ok(())
    }

    /// 某条结束（超时 / 任务被取消 / future 被丢弃）时摘掉它，必要时拉起下一组。
    /// 已经被结算过的（正常路径：respond 时已移出）什么都不做——不重复收起窗口。
    fn forget(&self, task_id: &str) {
        let reshow = {
            let mut g = self.lock();
            let (q0, v0) = (g.queue.len(), g.visible.len());
            g.queue.retain(|p| p.item.task_id != task_id);
            g.visible.retain(|p| p.item.task_id != task_id);
            if v0 != g.visible.len() {
                // 可见组里少了一条：还有剩的就刷新，空了就拉下一组（没有下一组 → 收起）
                if g.visible.is_empty() { g.promote() } else { true }
            } else if q0 != g.queue.len() {
                // 只是排队中的被摘掉：窗口照旧，刷新一下「之后还有 N 个」
                !g.visible.is_empty()
            } else {
                return;
            }
        };
        self.after_change(reshow);
    }

    /// 窗口实现异步发现「没能打开」（lib.rs 新建窗口失败）：当前组按 Unavailable 结束，再试下一组。
    pub fn window_failed(&self) {
        log::error!("[approval] 确认窗口打不开，本组按「无法弹出确认」结束");
        let next = {
            let mut g = self.lock();
            for p in g.visible.drain(..) {
                let _ = p.tx.send(Decision::Unavailable);
            }
            g.promote()
        };
        self.after_change(next);
    }

    /// 用户点了窗口右上角关闭：把**页面上看得到的**那些按拒绝结算（与点「拒绝」同一口径）。
    /// 展示期间刚并入、页面还没拉到的条目留在窗口里继续确认——不替用户把没看到的记成「你拒绝了」。
    pub fn dismiss_current(&self) {
        let next = {
            let mut g = self.lock();
            if g.visible.is_empty() {
                return;
            }
            // 页面还没拉到当前组（刚提上来就点了关闭）：至少有组首条一直在窗口标题位，按它结算
            let mut seen = std::mem::take(&mut g.last_seen);
            if seen.is_empty() {
                seen.push(g.visible[0].item.task_id.clone());
            }
            let (done, keep): (Vec<Pending>, Vec<Pending>) = g.visible.drain(..).partition(|p| seen.iter().any(|id| id == &p.item.task_id));
            g.visible = keep;
            for p in done {
                let _ = p.tx.send(Decision::Rejected);
            }
            if g.visible.is_empty() { g.promote() } else { true }
        };
        self.after_change(next);
    }

    /// 状态变化后的窗口动作：有东西要展示 → 展示（打不开则整组按 Unavailable 结束）；空了 → 收起。
    fn after_change(&self, show: bool) {
        if show {
            self.present();
        } else if self.lock().visible.is_empty() {
            if let Some(h) = self.hider.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                h();
            }
        }
    }

    fn present(&self) {
        loop {
            let f = self.presenter.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if f.map(|f| f()).unwrap_or(false) {
                return;
            }
            log::error!("[approval] 无法打开确认窗口，本组按「无法弹出确认」结束");
            let mut g = self.lock();
            for p in g.visible.drain(..) {
                let _ = p.tx.send(Decision::Unavailable);
            }
            if !g.promote() {
                return;
            }
        }
    }

    /// 入队并等待决定（[`NativeWindowApprover::ask`] 的实现）。
    async fn ask(&self, req: &WriteRequest, agent_id: String, session: Option<String>) -> Decision {
        if self.presenter.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
            log::warn!("[approval] 确认窗口未就绪（GUI 未启动 / headless），拒绝 op={} path={}", req.op, req.path);
            return Decision::Unavailable;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (shown_tx, shown_rx) = tokio::sync::oneshot::channel();
        let task_id = {
            let mut g = self.lock();
            g.seq += 1;
            format!("approval_{}_{:x}", g.seq, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos())
        };
        let item = ApprovalItem {
            task_id: task_id.clone(),
            op: req.op.clone(),
            path: req.path.clone(),
            diff_preview: req.diff_preview.clone(),
            backup_path: req.backup_path.clone(),
        };
        let p = Pending { item, agent_id, session, tx, shown: Some(shown_tx), visible_at: None };

        enum Placed {
            /// 自己成了可见组（需要展示窗口）
            Head(std::time::Instant),
            /// 并进了正在展示的删除组（刷新窗口；计时沿用该组起点）
            Joined(std::time::Instant),
            Queued,
        }
        let placed = {
            let mut g = self.lock();
            if g.visible.is_empty() && g.queue.is_empty() {
                g.queue.push_back(p);
                g.promote();
                Placed::Head(g.visible.first().and_then(|p| p.visible_at).unwrap_or_else(std::time::Instant::now))
            } else {
                match g.try_join_visible(p) {
                    Ok(at) => Placed::Joined(at),
                    Err(p) if g.queue.len() < MAX_QUEUED => {
                        g.queue.push_back(p);
                        Placed::Queued
                    }
                    Err(_) => {
                        log::warn!("[approval] 确认排队已满（{MAX_QUEUED}），拒绝 {}", req.path);
                        return Decision::Busy;
                    }
                }
            }
        };
        // 从这里起无论怎么结束（含 future 被丢弃）都把自己摘掉，不卡住队列
        let _forget = Forget(self, task_id.clone());

        let started = match placed {
            Placed::Head(at) => {
                self.present();
                at
            }
            Placed::Joined(at) => {
                self.present(); // 刷新窗口内容
                at
            }
            Placed::Queued => match shown_rx.await {
                Ok(at) => at,
                Err(_) => return Decision::Unavailable, // 排队中被摘掉（窗口打不开）
            },
        };
        let left = self.timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(left, rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => Decision::Unavailable,
            Err(_) => Decision::TimedOut,
        }
    }
}

/// 摘除守卫：`ask` 的 future 被丢弃（服务端 task_cancel / 超时）时也把自己清掉。
struct Forget<'a>(&'a ApprovalBridge, String);
impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.0.forget(&self.1);
    }
}

/// 原生窗口确认器：`Approver` 实现，委托给共享的 [`ApprovalBridge`]。
pub struct NativeWindowApprover {
    bridge: Arc<ApprovalBridge>,
}

impl NativeWindowApprover {
    pub fn new(bridge: Arc<ApprovalBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait::async_trait]
impl Approver for NativeWindowApprover {
    async fn ask(&self, req: &WriteRequest) -> Decision {
        // 会话 / 执行体从任务局部上下文取（client 在执行任务前设置）；删除按它们合并
        let ctx = super::web_confirm::CURRENT_TASK.try_with(|c| c.clone()).ok().unwrap_or_default();
        let agent = ctx.agent_id.unwrap_or_else(|| "agent".to_string());
        self.bridge.ask(req, agent, ctx.session_path).await
    }
    /// 桥自己计时（从轮到展示起算），外层别从入队就掐
    fn self_timed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn wreq(op: &str, path: &str) -> WriteRequest {
        WriteRequest { op: op.into(), path: path.into(), diff_preview: None, backup_path: None }
    }

    /// 装一个计数的假窗口；返回 (桥, 展示次数, 收起次数)。
    fn bridge_with_window(ok: bool, timeout: Duration) -> (Arc<ApprovalBridge>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let b = ApprovalBridge::with_timeout(timeout);
        let shows = Arc::new(AtomicUsize::new(0));
        let hides = Arc::new(AtomicUsize::new(0));
        let (s, h) = (shows.clone(), hides.clone());
        b.set_presenter(
            Arc::new(move || {
                s.fetch_add(1, Ordering::SeqCst);
                ok
            }),
            Arc::new(move || {
                h.fetch_add(1, Ordering::SeqCst);
            }),
        );
        (b, shows, hides)
    }

    fn all_ids(p: &ApprovalPayload) -> Option<Vec<String>> {
        Some(p.items.iter().map(|i| i.task_id.clone()).collect())
    }

    #[tokio::test]
    async fn 旧页面不带条目列表_只对组首条生效_不替用户批其余() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "delete", "a", "s1");
        let t2 = spawn_ask(&b, "delete", "b", "s1");
        settle().await;
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 2);
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Approved);
        let p = b.peek_pending().expect("b 仍在等");
        assert_eq!(p.items[0].path, "b");
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Rejected);
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn spawn_ask(b: &Arc<ApprovalBridge>, op: &str, path: &str, session: &str) -> tokio::task::JoinHandle<Decision> {
        let b = b.clone();
        let r = wreq(op, path);
        let s = session.to_string();
        tokio::spawn(async move { b.ask(&r, "team--alice".into(), Some(s)).await })
    }

    #[tokio::test]
    async fn headless_无窗口实现_返回无法弹出而不是用户拒绝() {
        let b = ApprovalBridge::new();
        let d = b.ask(&wreq("write", "a.txt"), "a".into(), None).await;
        assert_eq!(d, Decision::Unavailable);
    }

    #[tokio::test]
    async fn 并发写请求排队_互不顶掉_逐个确认() {
        let (b, _shows, hides) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "write", "a.txt", "s1");
        settle().await;
        let t2 = spawn_ask(&b, "write", "b.txt", "s1");
        let t3 = spawn_ask(&b, "edit", "c.txt", "s1");
        settle().await;
        // 只展示第一个，后两个排队；第一个没有被顶掉
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 1, "写 / 改不合并");
        assert_eq!(p.path, "a.txt");
        assert_eq!(p.queued_after, 2);
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Approved);
        let p = b.peek_pending().unwrap();
        assert_eq!(p.path, "b.txt", "按到达顺序提上来");
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Rejected);
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t3.await.unwrap(), Decision::Approved);
        assert!(b.peek_pending().is_none());
        assert_eq!(hides.load(Ordering::SeqCst), 1, "全部确认完才收起窗口");
    }

    #[tokio::test]
    async fn 同来源连续删除合并成一个窗口_一次允许全部生效() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let ts: Vec<_> = (0..5).map(|i| spawn_ask(&b, "delete", &format!("~$f{i}.xlsx"), "s1")).collect();
        settle().await;
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 5, "同一助手同一会话的删除合并展示");
        assert_eq!(p.op, "delete");
        b.respond(&p.group_id, "approved", Some(p.items.iter().map(|i| i.task_id.clone()).collect())).unwrap();
        for t in ts {
            assert_eq!(t.await.unwrap(), Decision::Approved);
        }
        assert!(b.peek_pending().is_none());
    }

    #[tokio::test]
    async fn 不同会话的删除不合并() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "delete", "a", "s1");
        settle().await;
        let t2 = spawn_ask(&b, "delete", "b", "s2");
        settle().await;
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.queued_after, 1);
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Rejected);
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items[0].path, "b");
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Approved);
    }

    #[tokio::test]
    async fn 删除合并_不把夹在中间的写请求吞进去_写请求顺序保留() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let w0 = spawn_ask(&b, "write", "head.txt", "s1"); // 先占住可见位，后面的都排队
        settle().await;
        let d1 = spawn_ask(&b, "delete", "d1", "s1");
        settle().await;
        let w1 = spawn_ask(&b, "write", "w1", "s1");
        settle().await;
        let d2 = spawn_ask(&b, "delete", "d2", "s1");
        settle().await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(w0.await.unwrap(), Decision::Approved);
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.iter().map(|i| i.path.as_str()).collect::<Vec<_>>(), vec!["d1", "d2"]);
        b.respond(&p.group_id, "approved", all_ids(&p)).unwrap();
        assert_eq!(d1.await.unwrap(), Decision::Approved);
        assert_eq!(d2.await.unwrap(), Decision::Approved);
        let p = b.peek_pending().unwrap();
        assert_eq!(p.path, "w1", "写请求不被删除组吞掉，单独确认");
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(w1.await.unwrap(), Decision::Rejected);
    }

    #[tokio::test]
    async fn 展示期间并入的新删除_用户按旧条数提交时不替他批没看到的() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "delete", "a", "s1");
        settle().await;
        let seen = b.peek_pending().unwrap(); // 用户看到 1 条
        let t2 = spawn_ask(&b, "delete", "b", "s1"); // 展示期间又来一条，并进同组
        settle().await;
        assert_eq!(b.peek_pending().unwrap().items.len(), 2);
        b.respond(&seen.group_id, "approved", Some(seen.items.iter().map(|i| i.task_id.clone()).collect())).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Approved);
        // b 仍在窗口里等用户
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].path, "b");
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Rejected);
    }

    #[tokio::test]
    async fn 窗口打不开_报无法弹出_不是用户拒绝_且不卡队列() {
        let (b, shows, _h) = bridge_with_window(false, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "write", "a", "s1");
        let t2 = spawn_ask(&b, "write", "b", "s1");
        assert_eq!(t1.await.unwrap(), Decision::Unavailable);
        assert_eq!(t2.await.unwrap(), Decision::Unavailable);
        assert!(shows.load(Ordering::SeqCst) >= 2);
        assert!(b.peek_pending().is_none());
    }

    #[tokio::test]
    async fn 超时报超时_排队期间不计时() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_millis(200));
        let t1 = spawn_ask(&b, "write", "a", "s1");
        settle().await;
        let t2 = spawn_ask(&b, "write", "b", "s1");
        // 第一个展示 150ms 后才答；第二个已排队 150ms，若排队也计时则只剩 50ms
        tokio::time::sleep(Duration::from_millis(150)).await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Approved);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let p = b.peek_pending().expect("第二个仍在等，没被排队时间吃掉");
        assert_eq!(p.path, "b");
        assert_eq!(t2.await.unwrap(), Decision::TimedOut);
        assert!(b.peek_pending().is_none(), "超时后摘掉自己");
    }

    #[tokio::test]
    async fn 迟到的提交_不会误批下一组() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "write", "a", "s1");
        settle().await;
        let t2 = spawn_ask(&b, "write", "b", "s1");
        settle().await;
        let first = b.peek_pending().unwrap();
        b.respond(&first.group_id, "rejected", None).unwrap();
        assert_eq!(t1.await.unwrap(), Decision::Rejected);
        // 用户在旧窗口连点了一下允许：组 id 已变，必须报错，不能批 b
        assert!(b.respond(&first.group_id, "approved", None).is_err());
        let p = b.peek_pending().unwrap();
        assert_eq!(p.path, "b");
        b.respond(&p.group_id, "rejected", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Rejected);
    }

    #[tokio::test]
    async fn 任务被取消_future丢弃时摘掉自己_下一个顶上() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t1 = spawn_ask(&b, "write", "a", "s1");
        settle().await;
        let t2 = spawn_ask(&b, "write", "b", "s1");
        settle().await;
        t1.abort();
        let _ = t1.await;
        settle().await;
        let p = b.peek_pending().unwrap();
        assert_eq!(p.path, "b");
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(t2.await.unwrap(), Decision::Approved);
    }

    #[tokio::test]
    async fn 合并组有上限_超出分批() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let w = spawn_ask(&b, "write", "head", "s1");
        settle().await;
        let ts: Vec<_> = (0..MAX_BATCH + 3).map(|i| spawn_ask(&b, "delete", &format!("d{i}"), "s1")).collect();
        settle().await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(w.await.unwrap(), Decision::Approved);
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), MAX_BATCH);
        assert_eq!(p.queued_after, 3);
        b.respond(&p.group_id, "approved", all_ids(&p)).unwrap();
        let p = b.peek_pending().unwrap();
        assert_eq!(p.items.len(), 3);
        b.respond(&p.group_id, "approved", all_ids(&p)).unwrap();
        for t in ts {
            assert_eq!(t.await.unwrap(), Decision::Approved);
        }
    }

    /// 审查 P1：外层 ApprovalManager 的 45s 不得从入队就掐——排在后面的请求露面后要有完整的确认时间。
    /// 用 Manager 的测试超时 200ms 模拟 45s：a 展示 150ms 才答，b 露面后仍须能在 150ms 后被批准。
    #[tokio::test]
    async fn 串上_manager_排队请求露面后仍有完整时限() {
        use super::super::approval::{ApprovalManager, ApprovalMode};
        let b = ApprovalBridge::with_timeout(Duration::from_millis(200));
        b.set_presenter(Arc::new(|| true), Arc::new(|| {}));
        let mgr = Arc::new(
            ApprovalManager::new(ApprovalMode::Strict, Box::new(NativeWindowApprover::new(b.clone())) as Box<dyn Approver>)
                .with_timeout(Duration::from_millis(200)),
        );
        let m1 = mgr.clone();
        let t1 = tokio::spawn(async move { m1.check(&wreq("write", "a")).await });
        settle().await;
        let m2 = mgr.clone();
        let t2 = tokio::spawn(async move { m2.check(&wreq("write", "b")).await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap();
        assert!(t1.await.unwrap().is_ok());
        tokio::time::sleep(Duration::from_millis(150)).await; // b 已入队 300ms > 200ms，但只展示了 150ms
        let p = b.peek_pending().expect("b 不应被外层超时掐掉");
        assert_eq!(p.path, "b");
        b.respond(&p.group_id, "approved", None).unwrap();
        assert!(t2.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn 点关闭只拒绝页面上看得到的_刚并入的留着() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let tx = spawn_ask(&b, "delete", "x", "s1");
        settle().await;
        let _ = b.peek_pending(); // 页面拉到 x
        let ty = spawn_ask(&b, "delete", "y", "s1"); // 并入，页面还没拉到
        settle().await;
        b.dismiss_current();
        assert_eq!(tx.await.unwrap(), Decision::Rejected);
        let p = b.peek_pending().expect("y 留在窗口里");
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].path, "y");
        b.respond(&p.group_id, "approved", None).unwrap();
        assert_eq!(ty.await.unwrap(), Decision::Approved);
    }

    #[tokio::test]
    async fn 新组刚提上来_页面没拉就点关闭_至少拒组首条_不会关不掉() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let ta = spawn_ask(&b, "write", "a", "s1");
        settle().await;
        let tb = spawn_ask(&b, "write", "b", "s1");
        settle().await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "approved", None).unwrap(); // b 被提上来，页面还没拉
        assert_eq!(ta.await.unwrap(), Decision::Approved);
        b.dismiss_current();
        assert_eq!(tb.await.unwrap(), Decision::Rejected);
        assert!(b.peek_pending().is_none());
    }

    #[tokio::test]
    async fn 排队满_报积压而不是没弹出() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let head = spawn_ask(&b, "write", "head", "s1");
        settle().await;
        let qs: Vec<_> = (0..MAX_QUEUED).map(|i| spawn_ask(&b, "write", &format!("w{i}"), "s1")).collect();
        settle().await;
        let d = b.ask(&wreq("write", "over"), "a".into(), Some("s1".into())).await;
        assert_eq!(d, Decision::Busy);
        head.abort();
        for q in qs {
            q.abort();
        }
    }

    #[tokio::test]
    async fn 未知决定按拒绝() {
        let (b, _s, _h) = bridge_with_window(true, Duration::from_secs(5));
        let t = spawn_ask(&b, "write", "a", "s1");
        settle().await;
        let p = b.peek_pending().unwrap();
        b.respond(&p.group_id, "trust_session", None).unwrap();
        assert_eq!(t.await.unwrap(), Decision::Rejected);
    }
}
