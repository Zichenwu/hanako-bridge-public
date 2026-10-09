// src-tauri/src/daemon/tray_state.rs
//! 托盘状态机与通知决策（本机模式票 17，决策文档 §6.2 / spec 故事 41、58–62）。
//!
//! 全部是**纯逻辑 + 可注入时钟**：不碰系统通知、不碰托盘、不碰 tokio。
//! 这样「断开 <30s 零通知 / 30s–5min 仅有派活才通知 / >5min 恰一次 / 只有发过断开才发恢复」
//! 这类最容易写错、也最容易把人烦死的规则，能用确定性单测锁死，并做变异验证。
//!
//! ## 状态优先级（同时满足多个时取最高）
//! 需升级 > 凭据失效 > 被顶下线 > 已暂停 > 离线 > 重连中 > 活动中 > 已连接
//! 原因：前几项是「需要用户动手才能恢复」，必须压过「会自己好」的重连中。
//!
//! ## 通知规则（spec 58–62）
//! | 断开时长 | 行为 |
//! |---|---|
//! | < 30s | 零通知（网络抖动） |
//! | 30s – 5min | 仅在期间**有派活**时通知一次；否则静默 |
//! | > 5min | 恰一次「已断开」，含原因；之后不再重复 |
//! | 恢复 | **仅当之前发过断开通知**才发「已恢复」 |
//! 「凭据失效」「被顶下线」是不会自愈的终态：立即恰发一次，不等 5 分钟。

use std::time::Duration;

/// 断开 <30s 视为抖动。
pub const JITTER_MAX: Duration = Duration::from_secs(30);
/// 断开 >5min 进入「离线」。
pub const RECONNECTING_MAX: Duration = Duration::from_secs(5 * 60);
/// 用户在电脑前的判据：键鼠空闲低于此值视为「在电脑前」（跨机确认门槛，spec 故事 43）。
pub const AWAY_IDLE_THRESHOLD: Duration = Duration::from_secs(120);

/// 托盘状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrayState {
    Connected,
    Active,
    Reconnecting,
    Offline,
    Paused,
    Displaced,
    CredentialInvalid,
    NeedUpgrade,
}

impl TrayState {
    /// 优先级（越大越优先显示）。
    fn rank(self) -> u8 {
        match self {
            TrayState::NeedUpgrade => 7,
            TrayState::CredentialInvalid => 6,
            TrayState::Displaced => 5,
            TrayState::Paused => 4,
            TrayState::Offline => 3,
            TrayState::Reconnecting => 2,
            TrayState::Active => 1,
            TrayState::Connected => 0,
        }
    }

    /// 托盘菜单首行文案（≤ 一行）。
    pub fn label(self) -> &'static str {
        match self {
            TrayState::Connected => "已连接",
            TrayState::Active => "活动中",
            TrayState::Reconnecting => "重连中…",
            TrayState::Offline => "已离线",
            TrayState::Paused => "已暂停",
            TrayState::Displaced => "已在另一台电脑上线",
            TrayState::CredentialInvalid => "需要重新授权",
            TrayState::NeedUpgrade => "需要升级",
        }
    }

    /// 是否需要用户动手才能恢复（这类状态的托盘要带「去处理」入口）。
    pub fn needs_action(self) -> bool {
        matches!(
            self,
            TrayState::Displaced | TrayState::CredentialInvalid | TrayState::NeedUpgrade
        )
    }
}

/// 断开原因（通知文案用，决策文档 §6.2：网络 / 凭据失效 / 被顶下线 / 被远程断开）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    Network,
    CredentialInvalid,
    Displaced,
    RemoteDisconnect,
}

impl DisconnectReason {
    pub fn text(self) -> &'static str {
        match self {
            DisconnectReason::Network => "网络中断",
            DisconnectReason::CredentialInvalid => "授权已失效",
            DisconnectReason::Displaced => "已在另一台电脑上线",
            DisconnectReason::RemoteDisconnect => "已从网页断开",
        }
    }
}

/// 该发哪条系统通知。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// 「Hanako Bridge连接已断开」+ 原因
    Disconnected(DisconnectReason),
    /// 「Hanako Bridge连接已恢复」
    Recovered,
    /// 断开期间有派活（30s–5min）：告诉用户「有任务在等这台电脑」
    DispatchWhileDown,
    /// 跨机使用提醒（每会话首次执行 / 当天首次远程使用）
    RemoteUse { first_of_day: bool },
}

/// 连接事件（由 client.rs / 命令层喂入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// 收到 registered
    Connected,
    /// 连接掉了（网络类，会自动重连）
    Lost,
    /// 握手 403
    CredentialInvalid,
    /// 被顶（displaced 帧或关闭码 4001）
    Displaced,
    /// 网页断开（disconnect{reason:"user_remote"} / 吊销）
    RemoteDisconnect,
    /// 收到协议版本过低的拒绝
    NeedUpgrade,
    /// 本机或网页暂停状态变化
    Paused(bool),
    /// 断开期间服务端尝试派活（重连后由服务端补发的任务，或本机观察到的排队）
    DispatchWhileDown,
}

/// 状态机。所有时间由调用方传入（`now`），便于确定性测试。
#[derive(Debug)]
pub struct TrayMachine {
    /// 当前「连接类」状态（不含 Paused / Active 叠加）
    conn: ConnPhase,
    paused: bool,
    /// 进行中任务数 >0 时叠加 Active
    active_tasks: u32,
    /// 本次断开已经发过「已断开」通知 → 恢复时才允许发「已恢复」
    disconnect_notified: bool,
    /// 本次断开期间是否已发过「有派活」通知（30s–5min 内最多一次）
    dispatch_notified: bool,
    /// 断开起点（相对单调时钟的 Duration）
    down_since: Option<Duration>,
    /// 曾经成功连接过（区分「从未连上」与「断开」）
    ever_connected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnPhase {
    Up,
    /// 掉线中（含抖动 / 重连中 / 离线三段，由时长决定）
    Down,
    Displaced,
    CredentialInvalid,
    NeedUpgrade,
    RemoteDisconnected,
}

impl Default for TrayMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrayMachine {
    pub fn new() -> Self {
        Self {
            conn: ConnPhase::Down,
            paused: false,
            active_tasks: 0,
            disconnect_notified: false,
            dispatch_notified: false,
            down_since: None,
            ever_connected: false,
        }
    }

    /// 进行中任务数变化（任务开始 +1 / 结束 -1 由调用方维护，这里只取总数）。
    pub fn set_active_tasks(&mut self, n: u32) {
        self.active_tasks = n;
    }

    /// 喂入一个事件，返回需要发出的通知（可能为空）。
    pub fn on_event(&mut self, ev: Event, now: Duration) -> Vec<Notice> {
        let mut out = Vec::new();
        match ev {
            Event::Connected => {
                let was_notified = self.disconnect_notified;
                self.conn = ConnPhase::Up;
                self.down_since = None;
                self.disconnect_notified = false;
                self.dispatch_notified = false;
                self.ever_connected = true;
                // 只有之前发过「已断开」才发「已恢复」——抖动恢复不打扰
                if was_notified {
                    out.push(Notice::Recovered);
                }
            }
            Event::Lost => {
                // 终态（被顶 / 凭据失效 / 网页断开 / 需升级）不会因为一次 Lost 退回「网络掉线」
                if matches!(self.conn, ConnPhase::Up) || self.down_since.is_none() {
                    if self.down_since.is_none() {
                        self.down_since = Some(now);
                    }
                    if matches!(self.conn, ConnPhase::Up) {
                        self.conn = ConnPhase::Down;
                    }
                }
            }
            Event::CredentialInvalid => {
                out.extend(self.enter_terminal(ConnPhase::CredentialInvalid, DisconnectReason::CredentialInvalid, now));
            }
            Event::Displaced => {
                out.extend(self.enter_terminal(ConnPhase::Displaced, DisconnectReason::Displaced, now));
            }
            Event::RemoteDisconnect => {
                out.extend(self.enter_terminal(ConnPhase::RemoteDisconnected, DisconnectReason::RemoteDisconnect, now));
            }
            Event::NeedUpgrade => {
                // 需升级：不是「断开」，不发断开通知（托盘态足够，升级入口在菜单）
                self.conn = ConnPhase::NeedUpgrade;
                self.down_since.get_or_insert(now);
            }
            Event::Paused(p) => {
                self.paused = p;
            }
            Event::DispatchWhileDown => {
                // 仅在「重连中」区间（30s–5min）且本次断开还没发过派活通知时发一次
                if self.phase_at(now) == Phase::Reconnecting && !self.dispatch_notified && !self.disconnect_notified {
                    self.dispatch_notified = true;
                    out.push(Notice::DispatchWhileDown);
                }
            }
        }
        out
    }

    /// 时间推进（定时 tick 调用）：到达 >5min 时恰发一次「已断开」。
    pub fn tick(&mut self, now: Duration) -> Vec<Notice> {
        let mut out = Vec::new();
        if matches!(self.conn, ConnPhase::Down)
            && self.ever_connected
            && self.phase_at(now) == Phase::Offline
            && !self.disconnect_notified
        {
            self.disconnect_notified = true;
            out.push(Notice::Disconnected(DisconnectReason::Network));
        }
        out
    }

    /// 当前应显示的托盘状态。
    pub fn state(&self, now: Duration) -> TrayState {
        let mut best = match self.conn {
            ConnPhase::Up => TrayState::Connected,
            ConnPhase::Down => match self.phase_at(now) {
                Phase::Jitter => TrayState::Connected, // 抖动期托盘不变（spec：不变）
                Phase::Reconnecting => TrayState::Reconnecting,
                Phase::Offline => TrayState::Offline,
                Phase::None => TrayState::Offline, // 从未连上
            },
            ConnPhase::Displaced => TrayState::Displaced,
            ConnPhase::CredentialInvalid => TrayState::CredentialInvalid,
            ConnPhase::NeedUpgrade => TrayState::NeedUpgrade,
            ConnPhase::RemoteDisconnected => TrayState::Offline,
        };
        if self.paused && TrayState::Paused.rank() > best.rank() {
            best = TrayState::Paused;
        }
        // 活动中只叠加在「已连接」之上（断线时还显示活动中会误导）
        if self.active_tasks > 0 && matches!(self.conn, ConnPhase::Up) && TrayState::Active.rank() > best.rank() {
            best = TrayState::Active;
        }
        best
    }

    fn enter_terminal(&mut self, phase: ConnPhase, reason: DisconnectReason, now: Duration) -> Vec<Notice> {
        let mut out = Vec::new();
        self.conn = phase;
        self.down_since.get_or_insert(now);
        // 不会自愈的终态：立即恰发一次，不等 5 分钟；已发过则不重复
        if self.ever_connected && !self.disconnect_notified {
            self.disconnect_notified = true;
            out.push(Notice::Disconnected(reason));
        }
        out
    }

    fn phase_at(&self, now: Duration) -> Phase {
        let Some(since) = self.down_since else { return Phase::None };
        let d = now.saturating_sub(since);
        if d < JITTER_MAX {
            Phase::Jitter
        } else if d <= RECONNECTING_MAX {
            Phase::Reconnecting
        } else {
            Phase::Offline
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    None,
    Jitter,
    Reconnecting,
    Offline,
}

// ────────────────────────────────────────────────────────────────
// 跨机使用提醒（spec 故事 41：每会话首次执行 + 当天首次远程使用发通知，其余只改托盘态）
// ────────────────────────────────────────────────────────────────

/// 远程使用提醒去重。来源由服务端在任务帧里标注（票 16 的 origin）：`other_device` 才算远程。
#[derive(Debug, Default)]
pub struct RemoteUseNotifier {
    seen_sessions: std::collections::HashSet<String>,
    /// 当天首次远程使用的日期键（YYYYMMDD）；跨天自动重置
    last_day: Option<u32>,
}

impl RemoteUseNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// 一个任务到达。`origin` 不是 `other_device` 一律不提醒（本机网页 / 信号不足 = 用户自己在用）。
    /// `day` 为当地日期键（如 20261006），由调用方传入。
    pub fn on_task(&mut self, origin: &str, session: Option<&str>, day: u32) -> Option<Notice> {
        if origin != "other_device" {
            return None;
        }
        let first_of_day = self.last_day != Some(day);
        if first_of_day {
            self.last_day = Some(day);
            // 跨天：会话集合也重置，否则昨天的会话今天继续用永远不再提醒
            self.seen_sessions.clear();
        }
        let first_of_session = match session {
            Some(s) if !s.is_empty() => self.seen_sessions.insert(s.to_string()),
            _ => false, // 没有会话标识无法去重，宁可只在当天首次提醒一次
        };
        if first_of_day || first_of_session {
            Some(Notice::RemoteUse { first_of_day })
        } else {
            None
        }
    }
}

// ────────────────────────────────────────────────────────────────
// 跨机网页确认开关（spec 故事 43）
// ────────────────────────────────────────────────────────────────

/// 本机确认写操作时，是否应把确认转给发起的网页。
///
/// 全部条件缺一不可（fail-closed）：
/// 1. 用户在本机设置里**开启**了开关（默认关）；
/// 2. 取得到键鼠空闲秒，且 **> 2 分钟**（人确实不在电脑前）。取不到（Wayland 等）= 不转；
/// 3. 不是删除；
/// 4. 批量不超过阈值（与 approval.rs 红线② 一致）。
pub fn should_route_to_web(switch_on: bool, idle: Option<Duration>, op: &str, file_count: usize) -> bool {
    if !switch_on {
        return false;
    }
    let Some(idle) = idle else { return false };
    if idle <= AWAY_IDLE_THRESHOLD {
        return false;
    }
    if op == "delete" {
        return false;
    }
    file_count <= 5
}

/// 开关是否允许被打开：**只能在本机设置**。网页 / 服务端来源一律不行。
pub fn web_confirm_switch_allowed(source_is_local_ui: bool) -> bool {
    source_is_local_ui
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    fn up_machine() -> TrayMachine {
        let mut m = TrayMachine::new();
        m.on_event(Event::Connected, S(0));
        m
    }

    // ── 通知规则（变异锁 T1–T8）──────────────────────────────────

    #[test]
    fn 断开不足30秒_零通知且托盘不变() {
        let mut m = up_machine();
        assert!(m.on_event(Event::Lost, S(100)).is_empty());
        for t in [100, 110, 129] {
            assert!(m.tick(S(t)).is_empty(), "t={t}");
            assert_eq!(m.state(S(t)), TrayState::Connected, "抖动期托盘不变 t={t}");
        }
        // 30s 内恢复：不发「已恢复」（因为从没发过「已断开」）
        assert!(m.on_event(Event::Connected, S(125)).is_empty());
    }

    #[test]
    fn 三十秒到五分钟_仅有派活才通知_且只一次() {
        let mut m = up_machine();
        m.on_event(Event::Lost, S(100));
        // 没有派活：静默
        assert!(m.tick(S(200)).is_empty());
        assert_eq!(m.state(S(200)), TrayState::Reconnecting);
        // 抖动期内的派活不算（<30s）
        let mut m2 = up_machine();
        m2.on_event(Event::Lost, S(100));
        assert!(m2.on_event(Event::DispatchWhileDown, S(110)).is_empty(), "<30s 的派活不通知");
        // 重连窗口内第一次派活通知，第二次不再
        assert_eq!(m.on_event(Event::DispatchWhileDown, S(200)), vec![Notice::DispatchWhileDown]);
        assert!(m.on_event(Event::DispatchWhileDown, S(210)).is_empty(), "同一次断开只通知一次");
    }

    #[test]
    fn 超过五分钟_恰一次已断开且含原因() {
        let mut m = up_machine();
        m.on_event(Event::Lost, S(100));
        assert!(m.tick(S(100 + 300)).is_empty(), "恰 5min 仍是重连中");
        let first = m.tick(S(100 + 301));
        assert_eq!(first, vec![Notice::Disconnected(DisconnectReason::Network)]);
        for t in [500, 700, 10_000] {
            assert!(m.tick(S(t)).is_empty(), "之后不再重复 t={t}");
        }
        assert_eq!(m.state(S(10_000)), TrayState::Offline);
    }

    #[test]
    fn 仅在发过断开通知后才发已恢复() {
        // 发过断开 → 恢复时发
        let mut m = up_machine();
        m.on_event(Event::Lost, S(0));
        m.tick(S(400));
        assert_eq!(m.on_event(Event::Connected, S(500)), vec![Notice::Recovered]);
        // 再断再恢复（这次没过 5 分钟）→ 不发
        m.on_event(Event::Lost, S(600));
        assert!(m.on_event(Event::Connected, S(700)).is_empty());
        // 只收到过派活通知（没到 5min）→ 恢复也不发「已恢复」
        let mut m2 = up_machine();
        m2.on_event(Event::Lost, S(0));
        m2.on_event(Event::DispatchWhileDown, S(100));
        assert!(m2.on_event(Event::Connected, S(200)).is_empty());
    }

    #[test]
    fn 从未连上过_不发断开通知() {
        let mut m = TrayMachine::new();
        m.on_event(Event::Lost, S(0));
        assert!(m.tick(S(1000)).is_empty());
        assert_eq!(m.state(S(1000)), TrayState::Offline);
    }

    #[test]
    fn 终态立即恰发一次_不等五分钟() {
        for (ev, reason, st) in [
            (Event::CredentialInvalid, DisconnectReason::CredentialInvalid, TrayState::CredentialInvalid),
            (Event::Displaced, DisconnectReason::Displaced, TrayState::Displaced),
            (Event::RemoteDisconnect, DisconnectReason::RemoteDisconnect, TrayState::Offline),
        ] {
            let mut m = up_machine();
            assert_eq!(m.on_event(ev.clone(), S(10)), vec![Notice::Disconnected(reason)]);
            assert!(m.on_event(ev, S(11)).is_empty(), "重复事件不重复通知");
            assert!(m.tick(S(10_000)).is_empty(), "终态不被 tick 当成网络断开再发一次");
            assert_eq!(m.state(S(10)), st);
        }
    }

    #[test]
    fn 终态不被后续网络掉线覆盖() {
        let mut m = up_machine();
        m.on_event(Event::Displaced, S(10));
        m.on_event(Event::Lost, S(20));
        assert_eq!(m.state(S(1000)), TrayState::Displaced);
        assert!(m.tick(S(1000)).is_empty());
    }

    #[test]
    fn 需升级不发断开通知但压过重连中() {
        let mut m = up_machine();
        assert!(m.on_event(Event::NeedUpgrade, S(5)).is_empty());
        assert_eq!(m.state(S(5)), TrayState::NeedUpgrade);
        assert!(m.state(S(5)).needs_action());
    }

    // ── 状态优先级 ────────────────────────────────────────────────

    #[test]
    fn 暂停压过已连接与活动中_但不压过需用户处理的状态() {
        let mut m = up_machine();
        m.set_active_tasks(2);
        assert_eq!(m.state(S(1)), TrayState::Active);
        m.on_event(Event::Paused(true), S(2));
        assert_eq!(m.state(S(2)), TrayState::Paused, "暂停压过活动中");
        m.on_event(Event::CredentialInvalid, S(3));
        assert_eq!(m.state(S(3)), TrayState::CredentialInvalid, "凭据失效压过暂停");
        m.on_event(Event::Paused(false), S(4));
        assert_eq!(m.state(S(4)), TrayState::CredentialInvalid);
    }

    #[test]
    fn 活动中只在已连接时叠加_断线时不显示活动中() {
        let mut m = up_machine();
        m.set_active_tasks(1);
        m.on_event(Event::Lost, S(10));
        assert_eq!(m.state(S(100)), TrayState::Reconnecting);
    }

    #[test]
    fn 八种状态都可达且标签互不相同() {
        let all = [
            TrayState::Connected, TrayState::Active, TrayState::Reconnecting, TrayState::Offline,
            TrayState::Paused, TrayState::Displaced, TrayState::CredentialInvalid, TrayState::NeedUpgrade,
        ];
        let labels: std::collections::HashSet<_> = all.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), all.len());
        let ranks: std::collections::HashSet<_> = all.iter().map(|s| s.rank()).collect();
        assert_eq!(ranks.len(), all.len(), "优先级必须全序，否则同时满足两个状态时显示不确定");
    }

    // ── 跨机提醒 ──────────────────────────────────────────────────

    #[test]
    fn 跨机提醒_当天首次与每会话首次_其余静默() {
        let mut n = RemoteUseNotifier::new();
        assert_eq!(n.on_task("other_device", Some("s1"), 20261006), Some(Notice::RemoteUse { first_of_day: true }));
        assert_eq!(n.on_task("other_device", Some("s1"), 20261006), None, "同会话第二次静默");
        assert_eq!(n.on_task("other_device", Some("s2"), 20261006), Some(Notice::RemoteUse { first_of_day: false }), "新会话首次");
        assert_eq!(n.on_task("other_device", Some("s2"), 20261006), None);
    }

    #[test]
    fn 跨机提醒_本机网页与信号不足不提醒() {
        let mut n = RemoteUseNotifier::new();
        for o in ["local_web", "web", "", "whatever"] {
            assert_eq!(n.on_task(o, Some("s1"), 20261006), None, "origin={o}");
        }
        // 本机使用不应消耗「当天首次」名额
        assert_eq!(n.on_task("other_device", Some("s1"), 20261006), Some(Notice::RemoteUse { first_of_day: true }));
    }

    #[test]
    fn 跨机提醒_跨天重置() {
        let mut n = RemoteUseNotifier::new();
        n.on_task("other_device", Some("s1"), 20261006);
        assert_eq!(n.on_task("other_device", Some("s1"), 20261007), Some(Notice::RemoteUse { first_of_day: true }), "次日同会话再提醒");
    }

    #[test]
    fn 跨机提醒_无会话标识只在当天首次提醒() {
        let mut n = RemoteUseNotifier::new();
        assert!(n.on_task("other_device", None, 20261006).is_some());
        assert_eq!(n.on_task("other_device", None, 20261006), None);
        assert_eq!(n.on_task("other_device", Some(""), 20261006), None);
    }

    // ── 网页确认开关 ──────────────────────────────────────────────

    #[test]
    fn 网页确认_全部条件缺一不可() {
        let away = Some(S(121));
        assert!(should_route_to_web(true, away, "write", 1));
        assert!(!should_route_to_web(false, away, "write", 1), "开关默认关");
        assert!(!should_route_to_web(true, Some(S(120)), "write", 1), "恰 2 分钟不算 >2 分钟");
        assert!(!should_route_to_web(true, Some(S(30)), "write", 1), "人在电脑前");
        assert!(!should_route_to_web(true, None, "write", 1), "取不到空闲 = fail-closed");
        assert!(!should_route_to_web(true, away, "delete", 1), "删除不转网页");
        assert!(!should_route_to_web(true, away, "write", 6), "批量超阈值不转网页");
        assert!(should_route_to_web(true, away, "edit", 5), "恰 5 个可以");
    }

    #[test]
    fn 网页确认开关只能本机打开() {
        assert!(web_confirm_switch_allowed(true));
        assert!(!web_confirm_switch_allowed(false));
    }
}
