// src-tauri/src/daemon/web_confirm.rs
//! 跨机网页确认（票 17，spec 故事 43，服务端对端见 openhanako 票 16）。
//!
//! 场景：人在 B 电脑的网页里让 agent 改 A 电脑的文件，A 上的原生确认窗没人点 → 45s 超时被拒。
//! 可选解法：A 的用户**在本机设置里**开了「不在电脑前时网页确认」，且 A 空闲 >2 分钟，
//! 则把这次确认转给发起任务的网页，用户在网页点「仅此一次 / 拒绝」。
//!
//! ## 本模块是 `Approver` 的装饰器
//! 包住原来的 `NativeWindowApprover`：条件满足时先走网页，否则（或网页侧明确“办不到”时）走本机窗口。
//!
//! ## 回落规则（最容易写错的地方）
//! | 网页侧结果 | 行为 | 理由 |
//! |---|---|---|
//! | `once` | 批准（仅此一次） | 用户在网页点了 |
//! | 用户点拒绝 / 超时（`by=web|timeout`） | **拒绝，不回落本机窗口** | 用户不在电脑前，再弹本机窗只会空等 45s 再拒，且会把窗口堆在无人的屏幕上 |
//! | 服务端“办不到”（`by=server`：无发起连接 / 删除 / 批量超限 / 未启用） | **回落本机窗口** | 网页根本没弹卡，不回落就等于凭空拒绝 |
//! | 发送失败 / 等待超时未收到任何回执 | 回落本机窗口 | 通道故障，不能把用户锁死 |
//!
//! ## 不可绕过的红线
//! - 永不批准 `TrustSession`：网页侧只有「仅此一次」，放宽只能本机做；
//! - 删除、批量 >5 **本机侧先判**，不发请求（服务端会二次判定，但不依赖它）；
//! - 开关关 / 空闲取不到 / 空闲 ≤2min → 不走网页（fail-closed）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::approval::{Approver, Decision, WriteRequest};
use super::idle::IdleSource;
use super::tray_state::should_route_to_web;

/// 等待网页回执的上限。略小于本机写确认的 45s，留出回落本机窗口的余量。
pub const WEB_WAIT: Duration = Duration::from_secs(40);

/// 服务端回传的网页决定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebDecision {
    /// 用户在网页点了「仅此一次」
    Once,
    /// 用户在网页点了拒绝，或网页卡超时（不回落）
    Rejected,
    /// 服务端办不到（回落本机窗口）
    Unavailable,
}

/// 解析服务端 `web_confirm_decision` 帧 → (节点侧 confirmId, 决定)。非该帧返回 None。
pub fn parse_decision(v: &serde_json::Value) -> Option<(String, WebDecision)> {
    if v.get("type")?.as_str()? != "web_confirm_decision" {
        return None;
    }
    let id = v.get("confirmId")?.as_str()?.to_string();
    let action = v.get("action").and_then(|a| a.as_str()).unwrap_or("reject");
    let by = v.get("by").and_then(|b| b.as_str()).unwrap_or("");
    let d = match (action, by) {
        ("once", _) => WebDecision::Once,
        // 服务端自己拒（没有发起连接 / 删除 / 批量 / 未启用）：网页从未弹卡 → 回落本机
        (_, "server") => WebDecision::Unavailable,
        _ => WebDecision::Rejected,
    };
    Some((id, d))
}

/// 等待中的网页确认登记表：节点侧 confirmId → 唤醒通道。
#[derive(Default)]
pub struct WebConfirmWaiters {
    map: Mutex<HashMap<String, oneshot::Sender<WebDecision>>>,
}

impl WebConfirmWaiters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn register(&self, id: &str) -> oneshot::Receiver<WebDecision> {
        let (tx, rx) = oneshot::channel();
        self.map.lock().unwrap().insert(id.to_string(), tx);
        rx
    }

    fn forget(&self, id: &str) {
        self.map.lock().unwrap().remove(id);
    }

    /// client 主循环收到服务端回执时调用。未知 id（已超时清理 / 伪造）静默忽略。
    pub fn deliver(&self, id: &str, d: WebDecision) -> bool {
        match self.map.lock().unwrap().remove(id) {
            Some(tx) => tx.send(d).is_ok(),
            None => false,
        }
    }

    pub fn pending(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

/// 当前任务的上下文（会话 ID 等），由 client 在执行任务前设置到任务局部。
#[derive(Debug, Clone, Default)]
pub struct TaskCtx {
    pub session_path: Option<String>,
}

tokio::task_local! {
    /// 任务局部上下文：Approver::ask 只拿到 WriteRequest，拿不到会话；用 task-local 传递，避免改 trait 签名波及所有实现。
    pub static CURRENT_TASK: TaskCtx;
}

/// 装饰器。
pub struct WebFirstApprover<A: Approver> {
    inner: A,
    /// 本机设置里的开关（每次询问时现读，用户改设置立即生效）
    switch: Arc<dyn Fn() -> bool + Send + Sync>,
    idle: Arc<dyn IdleSource>,
    waiters: Arc<WebConfirmWaiters>,
    /// 向服务端发帧的出口（client 主循环的 ws 发送队列）
    out: mpsc::Sender<String>,
    wait: Duration,
}

impl<A: Approver> WebFirstApprover<A> {
    pub fn new(
        inner: A,
        switch: Arc<dyn Fn() -> bool + Send + Sync>,
        idle: Arc<dyn IdleSource>,
        waiters: Arc<WebConfirmWaiters>,
        out: mpsc::Sender<String>,
    ) -> Self {
        Self { inner, switch, idle, waiters, out, wait: WEB_WAIT }
    }

    #[cfg(test)]
    fn with_wait(mut self, w: Duration) -> Self {
        self.wait = w;
        self
    }
}

#[async_trait::async_trait]
impl<A: Approver> Approver for WebFirstApprover<A> {
    async fn ask(&self, req: &WriteRequest) -> Decision {
        // 本机侧先判：开关 / 空闲 / 删除 / 批量。任一不满足直接走本机窗口，不发请求。
        // 批量：WriteRequest 是单文件粒度，file_count 恒为 1（批量红线②在 approval.rs 中，接线后此处同步传入）。
        let route = should_route_to_web(
            (self.switch)(),
            self.idle.idle(),
            &req.op,
            1,
        );
        if !route {
            return self.inner.ask(req).await;
        }
        let session = CURRENT_TASK.try_with(|c| c.session_path.clone()).ok().flatten();
        let Some(session) = session else {
            // 没有会话标识 = 服务端无从找发起连接，必然被拒；不如直接本机窗口
            return self.inner.ask(req).await;
        };

        let id = format!("wc_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        let rx = self.waiters.register(&id);
        let frame = serde_json::json!({
            "type": "web_confirm_request",
            "confirmId": id,
            "sessionPath": session,
            "op": req.op,
            "fileCount": 1,
            // 只带文件名，不带绝对路径（路径只在本机，与 roots 不外发同一原则）
            "summary": std::path::Path::new(&req.path).file_name().map(|n| n.to_string_lossy().to_string()),
        });
        if self.out.send(frame.to_string()).await.is_err() {
            self.waiters.forget(&id);
            return self.inner.ask(req).await; // 通道故障：回落
        }

        match tokio::time::timeout(self.wait, rx).await {
            Ok(Ok(WebDecision::Once)) => Decision::Approved, // 只有「仅此一次」，绝不 TrustSession
            Ok(Ok(WebDecision::Rejected)) => Decision::Rejected, // 用户拒绝 / 网页超时：不回落
            Ok(Ok(WebDecision::Unavailable)) | Ok(Err(_)) => self.inner.ask(req).await,
            Err(_elapsed) => {
                self.waiters.forget(&id);
                // 迟到的回执会被 deliver 忽略；回落本机窗口，不把用户锁死
                self.inner.ask(req).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Fixed(Option<Duration>);
    impl IdleSource for Fixed {
        fn idle(&self) -> Option<Duration> {
            self.0
        }
    }

    /// 记录本机窗口被问了几次，并返回固定决定。
    struct Local {
        asked: Arc<AtomicU32>,
        answer: Decision,
    }
    #[async_trait::async_trait]
    impl Approver for Local {
        async fn ask(&self, _r: &WriteRequest) -> Decision {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    fn req(op: &str) -> WriteRequest {
        WriteRequest { op: op.into(), path: "/Users/a/财务/预算.xlsx".into(), diff_preview: None, backup_path: None }
    }

    struct H {
        approver: WebFirstApprover<Local>,
        asked: Arc<AtomicU32>,
        waiters: Arc<WebConfirmWaiters>,
        rx: mpsc::Receiver<String>,
    }
    fn harness(switch: bool, idle: Option<Duration>, local: Decision) -> H {
        let asked = Arc::new(AtomicU32::new(0));
        let waiters = WebConfirmWaiters::new();
        let (tx, rx) = mpsc::channel(8);
        let approver = WebFirstApprover::new(
            Local { asked: asked.clone(), answer: local },
            Arc::new(move || switch),
            Arc::new(Fixed(idle)),
            waiters.clone(),
            tx,
        )
        .with_wait(Duration::from_millis(300));
        H { approver, asked, waiters, rx }
    }
    const AWAY: Option<Duration> = Some(Duration::from_secs(300));

    async fn run<F: std::future::Future>(f: F) -> F::Output {
        CURRENT_TASK.scope(TaskCtx { session_path: Some("/s/1.jsonl".into()) }, f).await
    }


    /// 构造请求并在 task-local 会话上下文中询问（请求在函数体内持有，避免临时值借用问题）。
    async fn ask_with(a: &WebFirstApprover<Local>, op: &str) -> Decision {
        let r = req(op);
        run(a.ask(&r)).await
    }

    // ── 不走网页的所有情形（fail-closed）──────────────────────────
    #[tokio::test]
    async fn 开关关闭_直接本机窗口_不发请求() {
        let mut h = harness(false, AWAY, Decision::Approved);
        let d = ask_with(&h.approver, "write").await;
        assert_eq!(d, Decision::Approved);
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
        assert!(h.rx.try_recv().is_err(), "开关关闭时一个字节都不该发");
    }

    #[tokio::test]
    async fn 人在电脑前或空闲取不到_不走网页() {
        for idle in [Some(Duration::from_secs(10)), Some(Duration::from_secs(120)), None] {
            let mut h = harness(true, idle, Decision::Rejected);
            ask_with(&h.approver, "write").await;
            assert_eq!(h.asked.load(Ordering::SeqCst), 1, "idle={idle:?}");
            assert!(h.rx.try_recv().is_err(), "idle={idle:?} 不应发请求");
        }
    }

    #[tokio::test]
    async fn 删除永远不走网页() {
        let mut h = harness(true, AWAY, Decision::Rejected);
        ask_with(&h.approver, "delete").await;
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
        assert!(h.rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn 没有会话标识_直接本机窗口() {
        let mut h = harness(true, AWAY, Decision::Approved);
        let r = req("write");
        let d = h.approver.ask(&r).await; // 不在 CURRENT_TASK scope 内
        assert_eq!(d, Decision::Approved);
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
        assert!(h.rx.try_recv().is_err());
    }

    // ── 走网页的结果 ───────────────────────────────────────────────
    #[tokio::test]
    async fn 网页仅此一次_批准且不问本机窗口() {
        let mut h = harness(true, AWAY, Decision::Rejected);
        let (d, _) = tokio::join!(ask_with(&h.approver, "edit"), reply_ref(&mut h.rx, &h.waiters, WebDecision::Once));
        assert_eq!(d, Decision::Approved);
        assert_eq!(h.asked.load(Ordering::SeqCst), 0, "网页批准后不应再弹本机窗口");
    }

    /// 借用版 reply（join! 里不能同时可变借整个 H）。
    async fn reply_ref(rx: &mut mpsc::Receiver<String>, w: &Arc<WebConfirmWaiters>, d: WebDecision) {
        let raw = rx.recv().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        w.deliver(v["confirmId"].as_str().unwrap(), d);
    }

    #[tokio::test]
    async fn 批准永远是仅此一次_不会产生_trust_session() {
        let mut h = harness(true, AWAY, Decision::Rejected);
        let (d, _) = tokio::join!(ask_with(&h.approver, "write"), reply_ref(&mut h.rx, &h.waiters, WebDecision::Once));
        assert!(matches!(d, Decision::Approved), "网页只能产出 Approved，不能是 TrustSession: {d:?}");
    }

    #[tokio::test]
    async fn 网页拒绝或网页超时_拒绝且不回落本机窗口() {
        let mut h = harness(true, AWAY, Decision::Approved);
        let (d, _) = tokio::join!(ask_with(&h.approver, "write"), reply_ref(&mut h.rx, &h.waiters, WebDecision::Rejected));
        assert_eq!(d, Decision::Rejected);
        assert_eq!(h.asked.load(Ordering::SeqCst), 0, "用户不在电脑前，回落只会让窗口空等");
    }

    #[tokio::test]
    async fn 服务端办不到_回落本机窗口() {
        let mut h = harness(true, AWAY, Decision::Approved);
        let (d, _) = tokio::join!(ask_with(&h.approver, "write"), reply_ref(&mut h.rx, &h.waiters, WebDecision::Unavailable));
        assert_eq!(d, Decision::Approved, "本机窗口的答案");
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn 一直没回执_等待超时后回落本机窗口_且登记被清理() {
        let h = harness(true, AWAY, Decision::Rejected);
        let d = ask_with(&h.approver, "write").await;
        assert_eq!(d, Decision::Rejected);
        assert_eq!(h.asked.load(Ordering::SeqCst), 1, "通道静默时不能把用户锁死");
        assert_eq!(h.waiters.pending(), 0, "超时后必须清理登记，否则泄漏");
    }

    #[tokio::test]
    async fn 发送通道关闭_回落本机窗口() {
        let mut h = harness(true, AWAY, Decision::Approved);
        h.rx.close();
        let d = ask_with(&h.approver, "write").await;
        assert_eq!(d, Decision::Approved);
        assert_eq!(h.asked.load(Ordering::SeqCst), 1);
        assert_eq!(h.waiters.pending(), 0);
    }

    #[tokio::test]
    async fn 请求帧不含绝对路径() {
        let mut h = harness(true, AWAY, Decision::Rejected);
        let (_, raw) = tokio::join!(ask_with(&h.approver, "write"), async {
            let raw = h.rx.recv().await.unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            h.waiters.deliver(v["confirmId"].as_str().unwrap(), WebDecision::Rejected);
            raw
        });
        assert!(raw.contains("预算.xlsx"), "只给文件名: {raw}");
        assert!(!raw.contains("/Users/a"), "绝对路径只在本机，不外发: {raw}");
        assert!(!raw.contains("财务"), "目录名同样不外发: {raw}");
    }

    // ── 回执解析 / 登记表 ──────────────────────────────────────────
    #[test]
    fn 回执解析_once_用户拒绝_服务端办不到() {
        let p = |j: serde_json::Value| parse_decision(&j).map(|x| x.1);
        assert_eq!(p(serde_json::json!({"type":"web_confirm_decision","confirmId":"a","action":"once","by":"web"})), Some(WebDecision::Once));
        assert_eq!(p(serde_json::json!({"type":"web_confirm_decision","confirmId":"a","action":"reject","by":"web"})), Some(WebDecision::Rejected));
        assert_eq!(p(serde_json::json!({"type":"web_confirm_decision","confirmId":"a","action":"reject","by":"timeout"})), Some(WebDecision::Rejected));
        assert_eq!(p(serde_json::json!({"type":"web_confirm_decision","confirmId":"a","action":"reject","by":"server","reason":"no_initiator"})), Some(WebDecision::Unavailable));
        assert_eq!(p(serde_json::json!({"type":"heartbeat_ack"})), None);
        assert_eq!(p(serde_json::json!({"type":"web_confirm_decision"})), None, "缺 confirmId 丢弃");
    }

    #[test]
    fn 服务端若伪装成_once_也只能是仅此一次() {
        // 协议里根本没有 allow_session 这个取值；未知 action 一律按拒绝
        let p = parse_decision(&serde_json::json!({"type":"web_confirm_decision","confirmId":"a","action":"allow_session","by":"web"})).unwrap();
        assert_eq!(p.1, WebDecision::Rejected);
    }

    #[test]
    fn 未知_id_的回执被忽略() {
        let w = WebConfirmWaiters::new();
        assert!(!w.deliver("nope", WebDecision::Once));
        assert_eq!(w.pending(), 0);
    }
}
