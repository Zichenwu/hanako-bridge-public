// src-tauri/src/daemon/heartbeat.rs
//! 心跳与断线重连退避策略。

use std::time::Duration;

/// 心跳间隔（spec §7.4：每 30s ping/pong）。
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// 本机策略快照比对周期。
///
/// 移除授权目录是收紧权限的操作，云端快照滞后期间网页仍会认为该目录可用；
/// 用独立于心跳的短周期把滞后压到秒级（真正的拦截不依赖它：本机每个任务现读策略）。
pub const POLICY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 退避上限（spec §7.4：上限 60s）。
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// 指数退避（1s → 2s → 4s → … → 上限 60s）+ 确定性抖动。
///
/// `attempt` 从 0 开始（第 0 次重连等约 1s）。
/// 抖动用 attempt 派生的确定性值（±25%），避免多节点同时重连的雪崩，
/// 同时保证测试可断言（不用真随机）。
pub fn backoff_delay(attempt: u32) -> Duration {
    // 1,2,4,8,16,32,64 —— checked_shl 防止大 attempt 溢出
    let base_secs = 1u64.checked_shl(attempt.min(6)).unwrap_or(64);
    let capped = base_secs.min(BACKOFF_MAX.as_secs());
    // 确定性抖动：按 attempt 奇偶 ±25%
    let jitter = if attempt % 2 == 0 {
        capped + capped / 4
    } else {
        capped.saturating_sub(capped / 4)
    };
    Duration::from_secs(jitter.min(BACKOFF_MAX.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 退避从零次约一秒起() {
        let d = backoff_delay(0);
        assert!(
            d >= Duration::from_millis(750) && d <= Duration::from_millis(1250),
            "attempt=0 应约 1s，实际 {:?}",
            d
        );
    }

    #[test]
    fn 退避指数增长趋势() {
        // 偶数次无负抖动，便于比较增长趋势
        assert!(backoff_delay(2) > backoff_delay(0));
        assert!(backoff_delay(4) > backoff_delay(2));
    }

    #[test]
    fn 退避有上限() {
        for a in [10u32, 20, 50, 100] {
            assert!(backoff_delay(a) <= BACKOFF_MAX, "attempt={a} 超上限");
        }
    }

    #[test]
    fn 退避不降到零() {
        for a in 0..12 {
            assert!(backoff_delay(a) >= Duration::from_millis(500), "attempt={a} 过小");
        }
    }

    #[test]
    fn 心跳间隔_30s() {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(30));
    }
}
