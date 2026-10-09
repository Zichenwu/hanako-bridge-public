// src-tauri/src/daemon/idle.rs
//! 本机键鼠空闲秒数采集（票 17）。
//!
//! 用途：①心跳上报 `idleSeconds` → 服务端做「本机网页 / 另一台设备」来源判别（票 16）；
//!       ②跨机网页确认门槛「空闲 >2 分钟」。
//!
//! ## fail-closed 约定
//! 取不到就返回 `None`，**绝不**用 0 或默认值糊弄：
//! - 上报侧：`None` → 心跳不带 `idleSeconds` 字段 → 服务端视为「信号不足」；
//! - 使用侧：`None` → `should_route_to_web` 返回 false（不转网页确认）。
//! Linux 不启用后端（见 Cargo.toml 注释），恒返回 `None`。

use std::time::Duration;

/// 空闲来源抽象，便于测试注入。
pub trait IdleSource: Send + Sync {
    fn idle(&self) -> Option<Duration>;
}

/// 系统真实空闲（Windows / macOS）。
pub struct SystemIdle;

impl IdleSource for SystemIdle {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn idle(&self) -> Option<Duration> {
        user_idle::UserIdle::get_time().ok().map(|t| t.duration())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn idle(&self) -> Option<Duration> {
        None
    }
}

/// 心跳附带字段：有值才带 `idleSeconds`。整数秒，向下取整。
pub fn heartbeat_frame(idle: Option<Duration>) -> serde_json::Value {
    heartbeat_frame_full(idle, None)
}

/// 心跳完整构造（票 19）：除 idleSeconds 外，可带当日计数 `today:{read,write,preview}`。
/// 计数是审计日志的派生（只报计数、不报内容），供网页「本机」页展示。
///
/// 票 05：`preview` 是**新增的第三个桶**，与 read/write 并列。旧服务端收到多出来的键
/// 会忽略（`reportToday` 只取它认识的字段），不会因此拒绝心跳。
pub fn heartbeat_frame_full(idle: Option<Duration>, today: Option<super::audit::TodayCounts>) -> serde_json::Value {
    let mut v = serde_json::json!({ "type": "heartbeat" });
    if let Some(d) = idle {
        v["idleSeconds"] = serde_json::json!(d.as_secs());
    }
    if let Some(c) = today {
        v["today"] = serde_json::json!({ "read": c.read, "write": c.write, "preview": c.preview });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Option<Duration>);
    impl IdleSource for Fixed {
        fn idle(&self) -> Option<Duration> {
            self.0
        }
    }

    #[test]
    fn 有空闲值才带字段_取不到不带() {
        let f = heartbeat_frame(Fixed(Some(Duration::from_millis(5_900))).idle());
        assert_eq!(f["type"], "heartbeat");
        assert_eq!(f["idleSeconds"], 5, "向下取整到整数秒");
        let g = heartbeat_frame(Fixed(None).idle());
        assert!(g.get("idleSeconds").is_none(), "取不到绝不能上报成 0，否则服务端会当成「刚有键鼠活动」");
    }

    #[test]
    fn 零秒是合法值_不等于取不到() {
        let f = heartbeat_frame(Some(Duration::ZERO));
        assert_eq!(f["idleSeconds"], 0);
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn linux_不启用后端_恒为_none() {
        assert!(SystemIdle.idle().is_none());
    }

    // ── 票 05：心跳带三桶计数 ────────────────────────────────

    /// 变异锁：心跳帧漏掉 `preview` 键 → 本用例红（网页侧永远拿不到预览数）。
    #[test]
    fn 心跳带三桶计数() {
        let c = super::super::audit::TodayCounts { read: 4, write: 1, preview: 7 };
        let f = heartbeat_frame_full(Some(Duration::from_secs(3)), Some(c));
        assert_eq!(f["today"]["read"], 4);
        assert_eq!(f["today"]["write"], 1);
        assert_eq!(f["today"]["preview"], 7, "预览桶必须单独上报，不能并进 read");
        // 三个数互相独立，不是同一个值的副本
        assert_ne!(f["today"]["read"], f["today"]["preview"]);
    }

    #[test]
    fn 无计数时不带_today_字段() {
        let f = heartbeat_frame_full(Some(Duration::from_secs(1)), None);
        assert!(f.get("today").is_none(), "拿不到计数就不带字段，不编造 0");
    }
}
