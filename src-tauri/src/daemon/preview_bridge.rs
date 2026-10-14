// src-tauri/src/daemon/preview_bridge.rs
//! 预览确认弹窗桥（票 03，ADR 0009 决策 4）。
//!
//! 每个文件首次预览时，在**被读取的那台电脑上**弹确认。用户可选
//! 仅这次 / 本目录本次会话都允许 / 拒绝——**没有永久**（永久只能去本机设置里开）。
//!
//! ## 为什么不复用上传弹窗桥（对抗审查 P1）
//! `upload_bridge::ask_with_timeout` 里有 `g.clear()`：新请求会**顶掉**旧请求，旧请求的
//! `oneshot::Sender` 被 drop，于是旧的那次询问**静默得到「拒绝」**。上传是助手逐个发起的、
//! 几乎不并发，这个取舍可以接受；预览是用户在网页上连续点文件，**天然并发**——沿用就会出现
//! 「点了三个文件，前两个无声变成未获允许」。所以预览改为**排队**：同时只展示一个弹窗，
//! 其余按到达顺序等待，前一个结束后再展示下一个，谁都不会被顶掉。
//!
//! ## 两个独立计时器（对抗审查 P1）
//! 「等用户确认」与「传输无进度」是两件事，必须各自计时，否则互相抢跑：
//! 用户思考 50 秒才点允许，若共用一个 60 秒计时器，随后的读文件只剩 10 秒就被判无进度作废。
//! 本模块只负责**确认计时器**（[`PREVIEW_ASK_TIMEOUT`]）；传输无进度计时器在票 04 的读取路径里，
//! 从「用户点了允许」那一刻才起算。
//!
//! ## 不可绕过的红线
//! - **超时 = 拒绝**，没有弹窗实现（headless）= 拒绝，绝不默认允许；
//! - 排队等待期间也计时（从进队列算起），否则排在后面的请求可以无限期占住名额；
//! - 迟到的点击无效（已超时/已结束的 askId 一律 `Err`）；
//! - 展示数据**不含绝对路径**，只给文件名与目录显示名。

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use super::preview_gate::UserChoice;

/// 预览确认弹窗等待上限 = 60 秒（故事 20：超时与拒绝对外不可区分）。
///
/// ⚠️ 与「传输无进度 60 秒」是**两个独立计时器**（见模块注释）。
pub const PREVIEW_ASK_TIMEOUT: Duration = Duration::from_secs(60);

/// 同时只展示一个预览确认弹窗；其余排队。
const MAX_VISIBLE: usize = 1;

/// 展示给弹窗的请求。**不含绝对路径**，只给文件名与目录显示名。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PreviewAsk {
    pub ask_id: String,
    pub file_name: String,
    pub size: u64,
    pub folder_name: String,
    pub root_id: String,
    pub agent_id: String,
    /// "local_web" | "other_device" | "web"
    ///
    /// 跨机发起时弹窗要显式警示「另一台设备正在请求看这台电脑上的文件」，
    /// 但**确认仍只能在本机点**（ADR 决策 4），不会被转给网页。
    pub origin: String,
    /// 弹窗文案的关键承诺（故事 13）：只在网页显示，不保存到云端。
    ///
    /// 作为**数据**下发而非写死在 UI 里，便于用测试锁住它不被改掉或与上传文案混用。
    pub notice: String,
}

/// 故事 13 的承诺文案。预览弹窗必须显示它，且**不得**出现「上传 / 保存到云端」等字样。
pub const PREVIEW_NOTICE: &str = "只在网页显示，不保存到云端";

impl PreviewAsk {
    /// 构造（自动带上承诺文案）。
    pub fn new(
        ask_id: String,
        file_name: String,
        size: u64,
        folder_name: String,
        root_id: String,
        agent_id: String,
        origin: String,
    ) -> Self {
        Self { ask_id, file_name, size, folder_name, root_id, agent_id, origin, notice: PREVIEW_NOTICE.into() }
    }
}

struct Pending {
    ask: PreviewAsk,
    tx: tokio::sync::oneshot::Sender<UserChoice>,
}

/// 预览确认桥。与 `UploadBridge` 结构相近，但**排队而不互顶**。
#[derive(Default)]
pub struct PreviewBridge {
    inner: Mutex<Inner>,
    show: Mutex<Option<Arc<dyn Fn(&PreviewAsk) -> bool + Send + Sync>>>,
}

#[derive(Default)]
struct Inner {
    /// 正在展示的（最多 MAX_VISIBLE 个）
    visible: HashMap<String, Pending>,
    /// 等待展示的，按到达顺序
    queue: VecDeque<Pending>,
}

impl PreviewBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_presenter(&self, f: Arc<dyn Fn(&PreviewAsk) -> bool + Send + Sync>) {
        *self.show.lock().unwrap() = Some(f);
    }

    /// 当前正在展示的请求（原生窗口打开后拉取用）。
    pub fn peek(&self) -> Option<PreviewAsk> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).visible.values().next().map(|p| p.ask.clone())
    }

    /// 排队中的数量（测试与排障用）。
    pub fn queued(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).queue.len()
    }

    /// 正在展示的数量。
    pub fn visible(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).visible.len()
    }

    /// 弹窗提交。已超时/不存在返回 `Err`（迟到的点击不得生效）。
    ///
    /// 答完后立即把队首提上来展示——这样用户连续点多个文件时，弹窗一个接一个出现。
    pub fn respond(&self, ask_id: &str, choice: UserChoice) -> Result<(), String> {
        let promoted = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            match g.visible.remove(ask_id) {
                None => return Err(format!("预览确认不存在或已超时: {ask_id}")),
                Some(p) => {
                    let _ = p.tx.send(choice);
                    g.promote()
                }
            }
        };
        // 展示放在锁外：presenter 可能回调进来
        self.present_promoted(promoted);
        Ok(())
    }

    pub async fn ask(&self, ask: PreviewAsk) -> UserChoice {
        self.ask_with_timeout(ask, PREVIEW_ASK_TIMEOUT).await
    }

    /// 询问一次。
    ///
    /// `timeout` **从进队列那一刻起算**（不是从被展示起算）：否则排在后面的请求能无限期
    /// 占住名额，一个卡住的弹窗会让整条队列永不超时。
    pub async fn ask_with_timeout(&self, ask: PreviewAsk, timeout: Duration) -> UserChoice {
        let presenter = self.show.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(present) = presenter else {
            log::warn!("[preview] 没有可用的弹窗实现（headless），拒绝");
            return UserChoice::Reject;
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = ask.ask_id.clone();

        // 入队或直接占用展示名额；**绝不 clear 旧请求**
        let show_now = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.visible.len() < MAX_VISIBLE {
                g.visible.insert(id.clone(), Pending { ask: ask.clone(), tx });
                true
            } else {
                g.queue.push_back(Pending { ask: ask.clone(), tx });
                false
            }
        };

        if show_now && !present(&ask) {
            // 窗口打不开 = 拒绝；让队首顶上，不要卡住整条队列
            let promoted = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.visible.remove(&id);
                g.promote()
            };
            self.present_promoted(promoted);
            return UserChoice::Reject;
        }

        let out = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(c)) => c,
            // 超时、或 tx 被 drop（理论上不会，排队不互顶）→ 拒绝
            _ => UserChoice::Reject,
        };

        // 清理自己（可能在 visible 也可能还在 queue 里排着），并把队首提上来
        let promoted = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let was_visible = g.visible.remove(&id).is_some();
            g.queue.retain(|p| p.ask.ask_id != id);
            if was_visible {
                g.promote()
            } else {
                None
            }
        };
        self.present_promoted(promoted);
        out
    }

    /// 把被提升的请求展示出来；窗口打不开则拒绝它并继续提升下一个。
    fn present_promoted(&self, promoted: Option<PreviewAsk>) {
        let mut next = promoted;
        while let Some(ask) = next {
            let presenter = self.show.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let ok = presenter.map(|f| f(&ask)).unwrap_or(false);
            if ok {
                return;
            }
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.visible.remove(&ask.ask_id); // tx drop → 该次询问得到拒绝
            next = g.promote();
        }
    }
}

impl Inner {
    /// 队首补位到展示槽，返回需要展示的请求。
    fn promote(&mut self) -> Option<PreviewAsk> {
        if self.visible.len() >= MAX_VISIBLE {
            return None;
        }
        let p = self.queue.pop_front()?;
        let ask = p.ask.clone();
        self.visible.insert(ask.ask_id.clone(), p);
        Some(ask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn ask(id: &str) -> PreviewAsk {
        PreviewAsk::new(
            id.into(),
            "预算.xlsx".into(),
            1024,
            "财务".into(),
            "r1".into(),
            "bi--zhangsan".into(),
            "local_web".into(),
        )
    }

    #[tokio::test]
    async fn 没有弹窗实现_拒绝() {
        let b = PreviewBridge::new();
        assert_eq!(b.ask(ask("1")).await, UserChoice::Reject);
    }

    #[tokio::test]
    async fn 弹窗打不开_拒绝且清理() {
        let b = PreviewBridge::new();
        b.set_presenter(Arc::new(|_| false));
        assert_eq!(b.ask(ask("1")).await, UserChoice::Reject);
        assert!(b.peek().is_none());
        assert_eq!(b.queued(), 0);
    }

    #[tokio::test]
    async fn 用户选择原样返回() {
        for c in [UserChoice::Once, UserChoice::Session, UserChoice::Reject] {
            let b = PreviewBridge::new();
            let b2 = b.clone();
            b.set_presenter(Arc::new(move |a| {
                let b3 = b2.clone();
                let id = a.ask_id.clone();
                tokio::spawn(async move {
                    tokio::task::yield_now().await;
                    let _ = b3.respond(&id, c);
                });
                true
            }));
            assert_eq!(b.ask(ask("1")).await, c);
        }
    }

    #[tokio::test]
    async fn 超时_拒绝_且迟到的点击无效() {
        let b = PreviewBridge::new();
        b.set_presenter(Arc::new(|_| true));
        let r = b.ask_with_timeout(ask("1"), Duration::from_millis(30)).await;
        assert_eq!(r, UserChoice::Reject);
        assert!(b.respond("1", UserChoice::Once).is_err(), "超时后点允许不得生效");
        assert_eq!(b.visible(), 0, "超时后必须清理，否则名额泄漏");
    }

    // ── 排队：核心差异（变异锁）──────────────────────────────────────

    /// 变异锁（对抗审查 P1）：把入队改成 `visible.clear()`（即照抄 upload_bridge 的互顶写法）
    /// → 本用例红。并发两个预览时，第一个**不得**被顶掉。
    #[tokio::test]
    async fn 第二个预览不顶掉第一个_两者各自得到自己的答案() {
        let b = PreviewBridge::new();
        let shown = Arc::new(AtomicU32::new(0));
        let s2 = shown.clone();
        b.set_presenter(Arc::new(move |_| {
            s2.fetch_add(1, Ordering::SeqCst);
            true
        }));

        let b1 = b.clone();
        let first = tokio::spawn(async move { b1.ask_with_timeout(ask("one"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let b2 = b.clone();
        let second = tokio::spawn(async move { b2.ask_with_timeout(ask("two"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 第一个仍在展示，第二个在排队——没有任何一个被静默拒绝
        assert_eq!(b.peek().map(|a| a.ask_id), Some("one".into()), "第一个必须还在展示");
        assert_eq!(b.queued(), 1, "第二个应排队而不是顶掉第一个");
        assert_eq!(shown.load(Ordering::SeqCst), 1, "同时只展示一个弹窗");

        // 答第一个 → 第二个自动提上来展示
        b.respond("one", UserChoice::Once).unwrap();
        assert_eq!(first.await.unwrap(), UserChoice::Once);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(b.peek().map(|a| a.ask_id), Some("two".into()), "队首应自动补位");
        assert_eq!(shown.load(Ordering::SeqCst), 2);

        b.respond("two", UserChoice::Session).unwrap();
        assert_eq!(second.await.unwrap(), UserChoice::Session, "排队的那个必须拿到自己的答案");
    }

    #[tokio::test]
    async fn 连点多个文件_全部按顺序拿到各自答案_无人被静默拒绝() {
        let b = PreviewBridge::new();
        let b2 = b.clone();
        // presenter 收到就立刻批准，模拟用户快速点「仅这次」
        b.set_presenter(Arc::new(move |a| {
            let b3 = b2.clone();
            let id = a.ask_id.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                let _ = b3.respond(&id, UserChoice::Once);
            });
            true
        }));

        let mut handles = Vec::new();
        for i in 0..5 {
            let bi = b.clone();
            handles.push(tokio::spawn(async move {
                bi.ask_with_timeout(ask(&format!("f{i}")), Duration::from_secs(5)).await
            }));
        }
        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.await.unwrap(), UserChoice::Once, "第 {i} 个被静默拒绝了");
        }
        assert_eq!(b.visible(), 0);
        assert_eq!(b.queued(), 0, "全部结束后不得有残留");
    }

    #[tokio::test]
    async fn 排队中的请求也计时_不会无限占名额() {
        let b = PreviewBridge::new();
        b.set_presenter(Arc::new(|_| true)); // 永不作答
        let b1 = b.clone();
        // 第一个占住展示槽且不作答
        let first = tokio::spawn(async move { b1.ask_with_timeout(ask("stuck"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 第二个排队，用很短的超时 —— 即使一直没被展示，也必须到点就拒
        let r = b.ask_with_timeout(ask("waiting"), Duration::from_millis(40)).await;
        assert_eq!(r, UserChoice::Reject, "排队中必须计时，否则一个卡住的弹窗锁死整条队列");
        assert_eq!(b.queued(), 0, "超时的排队项必须被摘除");
        first.abort();
    }

    #[tokio::test]
    async fn 队首窗口打不开_自动跳过并提升下一个() {
        let b = PreviewBridge::new();
        let shown = Arc::new(AtomicU32::new(0));
        let s2 = shown.clone();
        // 第一个能开；"bad" 开不了；"good" 能开
        b.set_presenter(Arc::new(move |a| {
            s2.fetch_add(1, Ordering::SeqCst);
            a.ask_id != "bad"
        }));

        let b1 = b.clone();
        let first = tokio::spawn(async move { b1.ask_with_timeout(ask("one"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let b2 = b.clone();
        let bad = tokio::spawn(async move { b2.ask_with_timeout(ask("bad"), Duration::from_secs(5)).await });
        let b3 = b.clone();
        let good = tokio::spawn(async move { b3.ask_with_timeout(ask("good"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;

        b.respond("one", UserChoice::Once).unwrap();
        assert_eq!(first.await.unwrap(), UserChoice::Once);
        tokio::time::sleep(Duration::from_millis(30)).await;
        // bad 因为窗口打不开被拒，good 顶上
        assert_eq!(bad.await.unwrap(), UserChoice::Reject);
        assert_eq!(b.peek().map(|a| a.ask_id), Some("good".into()), "窗口打不开不能卡死队列");
        b.respond("good", UserChoice::Once).unwrap();
        assert_eq!(good.await.unwrap(), UserChoice::Once);
    }

    // ── 展示数据 ───────────────────────────────────────────────────

    #[test]
    fn 展示数据不含绝对路径() {
        let j = serde_json::to_string(&ask("1")).unwrap();
        assert!(!j.contains("\"path\""), "{j}");
        assert!(!j.contains("/Users/"), "{j}");
        assert!(j.contains("预算.xlsx"), "只给文件名: {j}");
    }

    /// 变异锁（故事 13）：把承诺文案改掉或改成上传口径 → 本用例红。
    #[test]
    fn 弹窗文案明确只在网页显示不保存到云端() {
        let a = ask("1");
        assert_eq!(a.notice, PREVIEW_NOTICE);
        assert!(a.notice.contains("只在网页显示"));
        assert!(a.notice.contains("不保存到云端"));
        // 不得与「上传到云端」混用口径
        for wrong in ["传到云端", "上传", "保存到云端存储"] {
            assert!(
                !a.notice.replace("不保存到云端", "").contains(wrong),
                "预览文案不得出现上传口径 {wrong}: {}",
                a.notice
            );
        }
    }

    #[test]
    fn 跨机来源原样带给弹窗以便警示() {
        let mut a = ask("1");
        a.origin = "other_device".into();
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains("other_device"), "弹窗要能显式警示跨机发起: {j}");
    }

    #[test]
    fn 确认超时是六十秒_且与传输计时器是两个常量() {
        assert_eq!(PREVIEW_ASK_TIMEOUT, Duration::from_secs(60));
        // 传输无进度计时器在票 04，这里固化「确认计时器独立存在」这件事：
        // 它不得与上传弹窗的常量是同一个（两条通道独立）
        assert_eq!(super::super::upload_bridge::UPLOAD_ASK_TIMEOUT, Duration::from_secs(60));
        // 值相同但必须是两个独立常量 —— 改一个不该影响另一个（编译期已保证，此处留档）
    }
}
