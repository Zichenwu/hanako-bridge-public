// src-tauri/src/daemon/pause.rs
//! 本机暂停（票 17，spec 故事 53 / 决策文档 §6.3）。
//!
//! 语义：
//! - 暂停期间本机**拒绝一切派活**（返回 `LOCAL_NODE_PAUSED`），连接保持，托盘显示「已暂停」；
//! - 默认 30 分钟（防忘记恢复），最长 24 小时；到期自动恢复；
//! - 本机来源的暂停优先级最高：网页恢复不了（服务端票 06 已实现，这里只负责上报 `pause_state`）。
//!
//! 时间全部用**墙上时钟毫秒**（Unix epoch），因为要原样作为 `pause_state.until` 发给服务端；
//! 服务端以同一口径判定到期。时钟由调用方注入，便于确定性测试。
//!
//! ## 为什么暂停状态要在任务入口而不是只靠服务端
//! 服务端票 06 已经在派活前拒绝 `LOCAL_NODE_PAUSED`，但：①断线重连的空档、②旧服务端、③网页侧
//! 暂停状态和本机不同步时，任务仍可能到达本机。**本机是真源**（闸的一贯原则），所以这里再拒一次。

use std::sync::Mutex;

/// 默认暂停时长（毫秒）：30 分钟。
pub const DEFAULT_PAUSE_MS: u64 = 30 * 60_000;
/// 最长暂停（毫秒）：24 小时。
pub const MAX_PAUSE_MS: u64 = 24 * 3_600_000;
/// 本机派活被暂停的机读错误码（与服务端 `LOCAL_NODE_ERR.PAUSED` 一致）。
pub const ERR_PAUSED: &str = "LOCAL_NODE_PAUSED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PauseInfo {
    /// 到期的 Unix 毫秒时间戳
    pub until_ms: u64,
}

/// 线程安全的暂停状态。
#[derive(Debug, Default)]
pub struct PauseState {
    inner: Mutex<Option<PauseInfo>>,
}

impl PauseState {
    pub fn new() -> Self {
        Self::default()
    }

    /// 暂停。`duration_ms = None` → 默认 30 分钟；超过上限截断；0 视为默认（避免「暂停 0 秒」等于没暂停的歧义）。
    /// 返回到期时间戳（供上报 `pause_state`）。
    pub fn pause(&self, duration_ms: Option<u64>, now_ms: u64) -> PauseInfo {
        let d = match duration_ms {
            Some(d) if d > 0 => d.min(MAX_PAUSE_MS),
            _ => DEFAULT_PAUSE_MS,
        };
        let info = PauseInfo { until_ms: now_ms.saturating_add(d) };
        *self.inner.lock().unwrap() = Some(info);
        info
    }

    /// 恢复。
    pub fn resume(&self) {
        *self.inner.lock().unwrap() = None;
    }

    /// 当前是否处于暂停（到期即视为未暂停并惰性清除）。
    pub fn active(&self, now_ms: u64) -> Option<PauseInfo> {
        let mut g = self.inner.lock().unwrap();
        match *g {
            Some(p) if now_ms < p.until_ms => Some(p),
            Some(_) => {
                *g = None;
                None
            }
            None => None,
        }
    }

    pub fn is_paused(&self, now_ms: u64) -> bool {
        self.active(now_ms).is_some()
    }

    /// 任务入口闸：暂停中返回机读错误码文案，否则 None。
    pub fn gate(&self, now_ms: u64) -> Option<String> {
        self.active(now_ms).map(|p| {
            let left_min = (p.until_ms - now_ms).div_ceil(60_000);
            format!("{ERR_PAUSED}: 本机已暂停，约 {left_min} 分钟后自动恢复")
        })
    }
}

/// `pause_state` 上报帧。恢复时不带 `until`。
pub fn pause_frame(info: Option<PauseInfo>) -> serde_json::Value {
    match info {
        Some(p) => serde_json::json!({ "type": "pause_state", "paused": true, "until": p.until_ms }),
        None => serde_json::json!({ "type": "pause_state", "paused": false }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000_000;

    #[test]
    fn 默认暂停三十分钟() {
        let p = PauseState::new();
        let info = p.pause(None, T0);
        assert_eq!(info.until_ms, T0 + 30 * 60_000);
        assert!(p.is_paused(T0 + 30 * 60_000 - 1));
        assert!(!p.is_paused(T0 + 30 * 60_000), "恰到期即恢复");
    }

    #[test]
    fn 时长上限二十四小时_零与缺省按默认() {
        let p = PauseState::new();
        assert_eq!(p.pause(Some(10 * 86_400_000), T0).until_ms, T0 + MAX_PAUSE_MS, "超长截断到 24h");
        assert_eq!(p.pause(Some(0), T0).until_ms, T0 + DEFAULT_PAUSE_MS, "0 不能变成「没暂停」");
        assert_eq!(p.pause(Some(5 * 60_000), T0).until_ms, T0 + 5 * 60_000);
    }

    #[test]
    fn 到期自动恢复且惰性清除() {
        let p = PauseState::new();
        p.pause(Some(60_000), T0);
        assert!(p.active(T0 + 59_999).is_some());
        assert!(p.active(T0 + 60_000).is_none());
        assert!(p.active(T0 + 1).is_none(), "已被清除，时钟回拨也不会复活");
    }

    #[test]
    fn 任务入口闸_暂停中拒绝并带机读码() {
        let p = PauseState::new();
        assert!(p.gate(T0).is_none(), "未暂停放行");
        p.pause(Some(10 * 60_000), T0);
        let msg = p.gate(T0 + 1).unwrap();
        assert!(msg.starts_with(ERR_PAUSED), "{msg}");
        assert!(msg.contains("10 分钟"), "向上取整到分钟: {msg}");
        p.resume();
        assert!(p.gate(T0 + 2).is_none());
    }

    #[test]
    fn 上报帧_暂停带到期时间_恢复不带() {
        let f = pause_frame(Some(PauseInfo { until_ms: 123 }));
        assert_eq!(f["type"], "pause_state");
        assert_eq!(f["paused"], true);
        assert_eq!(f["until"], 123);
        let g = pause_frame(None);
        assert_eq!(g["paused"], false);
        assert!(g.get("until").is_none());
    }

    #[test]
    fn 再次暂停覆盖旧的到期时间() {
        let p = PauseState::new();
        p.pause(Some(60 * 60_000), T0);
        let b = p.pause(Some(60_000), T0 + 10);
        assert_eq!(b.until_ms, T0 + 10 + 60_000);
        assert!(!p.is_paused(T0 + 70_000), "后一次覆盖前一次，不取最大值");
    }
}
