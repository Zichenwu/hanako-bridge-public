// src-tauri/src/daemon/tray_hub.rs
//! 托盘状态中枢：把 `tray_state` 的纯逻辑接到真实世界（时钟、系统通知、托盘文案）。
//!
//! 职责边界：
//! - `tray_state.rs`：纯逻辑，无副作用，可确定性测试；
//! - 本模块：持有状态机 + 注入的「通知发送器 / 托盘更新器 / 时钟」，把事件喂进去并执行副作用。
//!   发送器与更新器都是 trait，测试里换成记录器，不碰系统通知与 Tauri。
//!
//! 线程模型：client.rs 跑在独立 tokio runtime，托盘/通知在 Tauri 主线程。
//! 这里所有状态在一把 `Mutex` 后，副作用通过 trait 对象回调（lib.rs 的实现负责切回主线程）。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::tray_state::{
    DisconnectReason, Event, Notice, RemoteUseNotifier, TrayMachine, TrayState,
};

/// 系统通知发送器。
pub trait Notifier: Send + Sync {
    fn send(&self, title: &str, body: &str);
}

/// 托盘展示更新器（图标 tooltip / 菜单首行）。
pub trait TrayView: Send + Sync {
    fn update(&self, state: TrayState);
}

/// 时钟抽象：单调时间（状态机用）+ 当地日期键（跨天提醒用）。
pub trait Clock: Send + Sync {
    fn mono(&self) -> Duration;
    fn day_key(&self) -> u32;
}

pub struct SystemClock {
    start: Instant,
}
impl SystemClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}
impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock for SystemClock {
    fn mono(&self) -> Duration {
        self.start.elapsed()
    }
    fn day_key(&self) -> u32 {
        use chrono::Datelike;
        let d = chrono::Local::now();
        (d.year() as u32) * 10_000 + d.month() * 100 + d.day()
    }
}

struct Inner {
    machine: TrayMachine,
    remote: RemoteUseNotifier,
    last_state: Option<TrayState>,
}

pub struct TrayHub {
    inner: Mutex<Inner>,
    active: std::sync::atomic::AtomicU32,
    notifier: Arc<dyn Notifier>,
    view: Arc<dyn TrayView>,
    clock: Arc<dyn Clock>,
}

impl TrayHub {
    pub fn new(notifier: Arc<dyn Notifier>, view: Arc<dyn TrayView>, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            active: std::sync::atomic::AtomicU32::new(0),
            inner: Mutex::new(Inner {
                machine: TrayMachine::new(),
                remote: RemoteUseNotifier::new(),
                last_state: None,
            }),
            notifier,
            view,
            clock,
        })
    }

    /// 喂入连接事件：执行通知 + 刷新托盘。
    pub fn on_event(&self, ev: Event) {
        let now = self.clock.mono();
        let (notices, state) = {
            let mut g = self.inner.lock().unwrap();
            let n = g.machine.on_event(ev, now);
            let s = g.machine.state(now);
            (n, s)
        };
        self.apply(notices, state);
    }

    /// 定时 tick（建议每 5–10s 一次）：推进「>5min 离线」判定并刷新托盘。
    pub fn tick(&self) {
        let now = self.clock.mono();
        let (notices, state) = {
            let mut g = self.inner.lock().unwrap();
            let n = g.machine.tick(now);
            let s = g.machine.state(now);
            (n, s)
        };
        self.apply(notices, state);
    }

    /// 进行中任务数变化。
    pub fn set_active_tasks(&self, n: u32) {
        let now = self.clock.mono();
        let state = {
            let mut g = self.inner.lock().unwrap();
            g.machine.set_active_tasks(n);
            g.machine.state(now)
        };
        self.apply(Vec::new(), state);
    }

    /// 任务开始 / 结束：维护进行中计数（托盘「活动中」态）。计数用饱和减，防止重复 finished 下溢。
    pub fn task_started(&self) {
        let n = self.active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.set_active_tasks(n);
    }
    pub fn task_finished(&self) {
        let prev = self
            .active
            .fetch_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |v| Some(v.saturating_sub(1)))
            .unwrap_or(0);
        self.set_active_tasks(prev.saturating_sub(1));
    }

    /// 一个任务到达（带服务端标注的来源）：跨机使用提醒去重后发通知。
    pub fn on_task(&self, origin: &str, session: Option<&str>) {
        let day = self.clock.day_key();
        let notice = {
            let mut g = self.inner.lock().unwrap();
            g.remote.on_task(origin, session, day)
        };
        if let Some(n) = notice {
            self.apply(vec![n], self.current());
        }
    }

    pub fn current(&self) -> TrayState {
        let now = self.clock.mono();
        self.inner.lock().unwrap().machine.state(now)
    }

    fn apply(&self, notices: Vec<Notice>, state: TrayState) {
        for n in notices {
            let (title, body) = notice_text(&n);
            self.notifier.send(title, &body);
        }
        let changed = {
            let mut g = self.inner.lock().unwrap();
            let changed = g.last_state != Some(state);
            g.last_state = Some(state);
            changed
        };
        if changed {
            self.view.update(state);
        }
    }
}

/// 通知文案。标题统一「Hanako」，正文短且含原因（spec 故事 59）。
pub fn notice_text(n: &Notice) -> (&'static str, String) {
    match n {
        Notice::Disconnected(r) => ("Hanako Bridge", format!("本机连接已断开（{}）", r.text())),
        Notice::Recovered => ("Hanako Bridge", "本机连接已恢复".to_string()),
        Notice::DispatchWhileDown => ("Hanako Bridge", "有任务在等这台电脑，正在重连…".to_string()),
        Notice::RemoteUse { first_of_day } => (
            "Hanako Bridge",
            if *first_of_day {
                "今天第一次有另一台设备在使用这台电脑".to_string()
            } else {
                "有另一台设备正在使用这台电脑".to_string()
            },
        ),
    }
}

/// 把断开原因映射成托盘可读的一行（菜单首行用，比 `TrayState::label` 更具体）。
pub fn reason_hint(r: DisconnectReason) -> &'static str {
    r.text()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Rec {
        sent: Mutex<Vec<String>>,
    }
    impl Notifier for Rec {
        fn send(&self, _t: &str, b: &str) {
            self.sent.lock().unwrap().push(b.to_string());
        }
    }
    #[derive(Default)]
    struct View {
        seen: Mutex<Vec<TrayState>>,
    }
    impl TrayView for View {
        fn update(&self, s: TrayState) {
            self.seen.lock().unwrap().push(s);
        }
    }
    struct FakeClock {
        t: AtomicU64,
        day: AtomicU64,
    }
    impl Clock for FakeClock {
        fn mono(&self) -> Duration {
            Duration::from_secs(self.t.load(Ordering::SeqCst))
        }
        fn day_key(&self) -> u32 {
            self.day.load(Ordering::SeqCst) as u32
        }
    }

    fn setup() -> (Arc<TrayHub>, Arc<Rec>, Arc<View>, Arc<FakeClock>) {
        let rec = Arc::new(Rec::default());
        let view = Arc::new(View::default());
        let clock = Arc::new(FakeClock { t: AtomicU64::new(0), day: AtomicU64::new(20261006) });
        let hub = TrayHub::new(rec.clone(), view.clone(), clock.clone());
        (hub, rec, view, clock)
    }
    fn at(c: &FakeClock, s: u64) {
        c.t.store(s, Ordering::SeqCst);
    }

    #[test]
    fn 完整断线场景_通知次数与文案() {
        let (hub, rec, view, clk) = setup();
        hub.on_event(Event::Connected);
        at(&clk, 100);
        hub.on_event(Event::Lost);
        at(&clk, 110); // 抖动期
        hub.tick();
        assert!(rec.sent.lock().unwrap().is_empty(), "抖动期零通知");
        at(&clk, 200); // 重连中，无派活
        hub.tick();
        assert!(rec.sent.lock().unwrap().is_empty(), "重连窗口无派活不通知");
        at(&clk, 500); // >5min
        hub.tick();
        hub.tick();
        hub.tick();
        assert_eq!(rec.sent.lock().unwrap().as_slice(), ["本机连接已断开（网络中断）"], "恰一次且含原因");
        at(&clk, 600);
        hub.on_event(Event::Connected);
        assert_eq!(rec.sent.lock().unwrap().last().unwrap(), "本机连接已恢复");
        assert_eq!(rec.sent.lock().unwrap().len(), 2);
        // 托盘态序列去重：只在变化时更新
        let seen = view.seen.lock().unwrap();
        assert!(seen.windows(2).all(|w| w[0] != w[1]), "托盘态不应重复推送相同状态: {seen:?}");
    }

    #[test]
    fn 跨机提醒走通知器_本机网页不提醒() {
        let (hub, rec, _v, _c) = setup();
        hub.on_event(Event::Connected);
        hub.on_task("local_web", Some("s1"));
        hub.on_task("web", Some("s1"));
        assert!(rec.sent.lock().unwrap().is_empty());
        hub.on_task("other_device", Some("s1"));
        hub.on_task("other_device", Some("s1"));
        assert_eq!(rec.sent.lock().unwrap().as_slice(), ["今天第一次有另一台设备在使用这台电脑"]);
    }

    #[test]
    fn 被顶下线_立即一次通知_托盘变态() {
        let (hub, rec, view, _c) = setup();
        hub.on_event(Event::Connected);
        hub.on_event(Event::Displaced);
        hub.on_event(Event::Displaced);
        assert_eq!(rec.sent.lock().unwrap().as_slice(), ["本机连接已断开（已在另一台电脑上线）"]);
        assert_eq!(view.seen.lock().unwrap().last(), Some(&TrayState::Displaced));
    }

    #[test]
    fn 活动中态随任务数切换() {
        let (hub, _r, view, _c) = setup();
        hub.on_event(Event::Connected);
        hub.set_active_tasks(1);
        assert_eq!(hub.current(), TrayState::Active);
        hub.set_active_tasks(0);
        assert_eq!(hub.current(), TrayState::Connected);
        let seen = view.seen.lock().unwrap();
        assert_eq!(seen.as_slice(), [TrayState::Connected, TrayState::Active, TrayState::Connected]);
    }

    #[test]
    fn 任务计数_饱和减_重复结束不下溢() {
        let (hub, _r, _v, _c) = setup();
        hub.on_event(Event::Connected);
        hub.task_started();
        hub.task_started();
        hub.task_finished();
        assert_eq!(hub.current(), TrayState::Active, "还有 1 个在跑");
        hub.task_finished();
        hub.task_finished(); // 多余的 finished
        hub.task_finished();
        assert_eq!(hub.current(), TrayState::Connected);
        hub.task_started();
        assert_eq!(hub.current(), TrayState::Active, "下溢会让计数变成 u32::MAX 永远活动中；这里必须回到 1");
    }

    #[test]
    fn 通知文案不含路径与凭据() {
        for n in [
            Notice::Disconnected(DisconnectReason::Network),
            Notice::Disconnected(DisconnectReason::CredentialInvalid),
            Notice::Recovered,
            Notice::DispatchWhileDown,
            Notice::RemoteUse { first_of_day: true },
        ] {
            let (_, body) = notice_text(&n);
            assert!(!body.contains('/') && !body.contains('\\') && !body.to_lowercase().contains("token"), "{body}");
            assert!(body.chars().count() <= 30, "通知正文要短: {body}");
        }
    }
}
