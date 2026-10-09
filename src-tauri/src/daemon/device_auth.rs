// src-tauri/src/daemon/device_auth.rs
//! 浏览器授权码登录 + 续期的客户端（票 14）。
//!
//! # 契约（hub 侧尚未实现，本模块对着假 hub 测试；hub 端点是下一棒）
//!
//! 全部路径相对 `hubUrl`（如 `https://…/hapi`），**不是** hanako serverUrl。
//!
//! ```text
//! POST /api/node-login/start
//!   body : { machineName, appVersion, agentId? }           ← agentId = 发起时正在用的执行体（US5）
//!   200  : { deviceCode, userCode, verificationUrl, expiresIn, interval }
//!          deviceCode  本机私有的高熵轮询凭证，只在本机与 hub 之间走，**不进浏览器 URL**
//!          userCode    给人核对的短码（如 `WXYZ-2345`），网页确认页显示同一个
//!          interval    建议轮询间隔秒数
//!
//! POST /api/node-login/poll
//!   body : { deviceCode }
//!   200  : { status: "pending" }
//!        | { status: "denied" }                            ← 用户点了「拒绝」
//!        | { status: "expired" }                           ← 码过期
//!        | { status: "approved", serverUrl, agentId, nodeName,
//!            credentialSecret, credentialId, expiresAt }   ← 只会被成功领取一次
//!   429  : 轮询过快，客户端须把间隔翻倍（slow_down）
//!
//! POST /api/node-login/renew          Authorization: Bearer <当前节点凭据>
//!   200  : { credentialSecret, credentialId, expiresAt }   ← 旧凭据同时作废
//!   401/403 : 凭据已失效，必须重新走授权码
//! ```
//!
//! # 设计要点
//! - 轮询遇 `expired/denied` 立即终止，不自动再发起（避免用户没在看时反复弹浏览器）
//! - 轮询网络错误**不终止**（笔记本合盖/切网很常见），按退避继续，直到码过期
//! - `slow_down`(429) 把间隔翻倍，封顶 30s，防把 hub 打挂
//! - 续期 401/403 = 凭据彻底失效 → `RenewOutcome::NeedReauth`（托盘变黄）；
//!   网络错误/5xx = `RenewOutcome::Retry`（不等于失效，别吓用户）
//! - token / deviceCode 一律不进日志

use serde::Deserialize;
use std::time::Duration;

/// 轮询间隔封顶（slow_down 翻倍时）。
pub const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// 轮询间隔下限：服务端若给 0 或过小，按此兜底，避免空转打满 hub。
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 到期前多久开始续期（决策 §6.1：24h）。
pub const RENEW_BEFORE_EXPIRY: chrono::Duration = chrono::Duration::hours(24);

/// `node-login/start` 的响应。
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    #[serde(default)]
    pub interval: u64,
}

/// 领取成功后得到的节点凭据（不实现 Debug 的明文输出，见下方手写 Debug）。
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrantedCredential {
    pub server_url: String,
    pub agent_id: String,
    pub node_name: Option<String>,
    pub credential_secret: String,
    pub credential_id: Option<String>,
    pub expires_at: String,
}

// 手写 Debug：防止 `{:?}` / unwrap panic 信息把明文 secret 打进日志
impl std::fmt::Debug for GrantedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantedCredential")
            .field("server_url", &self.server_url)
            .field("agent_id", &self.agent_id)
            .field("node_name", &self.node_name)
            .field("credential_secret", &"<redacted>")
            .field("credential_id", &self.credential_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// 一次轮询的归一化结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    Pending,
    Denied,
    Expired,
    Approved(GrantedCredential),
    /// 服务端要求放慢（HTTP 429）
    SlowDown,
}

/// 续期的归一化结果。
#[derive(Clone, PartialEq, Eq)]
pub enum RenewOutcome {
    Renewed { secret: String, credential_id: Option<String>, expires_at: String },
    /// 凭据已失效（401/403）：只能重新授权
    NeedReauth,
    /// 暂时性失败（网络/5xx）：稍后重试，不代表凭据失效
    Retry(String),
}

impl std::fmt::Debug for RenewOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Renewed { credential_id, expires_at, .. } => f
                .debug_struct("Renewed")
                .field("secret", &"<redacted>")
                .field("credential_id", credential_id)
                .field("expires_at", expires_at)
                .finish(),
            Self::NeedReauth => write!(f, "NeedReauth"),
            Self::Retry(m) => write!(f, "Retry({m})"),
        }
    }
}

/// 把 `poll` 的 (HTTP 状态码, body) 归一化为 [`PollOutcome`]。纯函数，便于穷举测试。
pub fn parse_poll(status: u16, body: &str) -> Result<PollOutcome, String> {
    if status == 429 {
        return Ok(PollOutcome::SlowDown);
    }
    if !(200..300).contains(&status) {
        return Err(format!("poll HTTP {status}"));
    }
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("poll 响应非 JSON: {e}"))?;
    match v.get("status").and_then(|s| s.as_str()) {
        Some("pending") => Ok(PollOutcome::Pending),
        Some("denied") => Ok(PollOutcome::Denied),
        Some("expired") => Ok(PollOutcome::Expired),
        Some("approved") => {
            let g: GrantedCredential =
                serde_json::from_value(v).map_err(|e| format!("approved 响应字段不全: {e}"))?;
            if g.credential_secret.is_empty() || g.agent_id.is_empty() {
                return Err("approved 响应缺少凭据或执行体".into());
            }
            Ok(PollOutcome::Approved(g))
        }
        other => Err(format!("poll 未知 status: {other:?}")),
    }
}

/// 把 `renew` 的 (HTTP 状态码, body) 归一化为 [`RenewOutcome`]。
pub fn parse_renew(status: u16, body: &str) -> RenewOutcome {
    match status {
        200..=299 => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct R {
                credential_secret: String,
                credential_id: Option<String>,
                expires_at: String,
            }
            match serde_json::from_str::<R>(body) {
                Ok(r) if !r.credential_secret.is_empty() => RenewOutcome::Renewed {
                    secret: r.credential_secret,
                    credential_id: r.credential_id,
                    expires_at: r.expires_at,
                },
                // 2xx 但内容不对：不能当成功（会把空 secret 写进钥匙串），也不能当失效
                _ => RenewOutcome::Retry("续期响应格式异常".into()),
            }
        }
        401 | 403 => RenewOutcome::NeedReauth,
        _ => RenewOutcome::Retry(format!("续期 HTTP {status}")),
    }
}

/// 轮询下一次等待多久。
///
/// - `server_interval`：服务端建议值（秒）；过小按 [`MIN_POLL_INTERVAL`] 兜底
/// - `slowed`：已收到几次 slow_down，每次翻倍，封顶 [`MAX_POLL_INTERVAL`]
pub fn next_poll_delay(server_interval_secs: u64, slowed: u32) -> Duration {
    let base = Duration::from_secs(server_interval_secs).max(MIN_POLL_INTERVAL);
    let factor = 1u32.checked_shl(slowed.min(6)).unwrap_or(64);
    (base * factor).min(MAX_POLL_INTERVAL)
}

/// 凭据是否该续期：距到期不足 [`RENEW_BEFORE_EXPIRY`]（含已过期）。
///
/// 到期时间无法解析时返回 `true`——宁可多续一次，也不要带着未知到期时间的凭据一路用到 403。
pub fn should_renew(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(exp) => exp.with_timezone(&chrono::Utc) - now <= RENEW_BEFORE_EXPIRY,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn approved_body() -> String {
        serde_json::json!({
            "status": "approved",
            "serverUrl": "https://x.example.com/hapi/hanako",
            "agentId": "team--alice",
            "nodeName": "alice-laptop",
            "credentialSecret": "SECRET-xyz",
            "credentialId": "cred_1",
            "expiresAt": "2026-10-12T00:00:00Z"
        })
        .to_string()
    }

    // ── parse_poll ──────────────────────────────────────────
    #[test]
    fn poll_各状态归一化() {
        assert_eq!(parse_poll(200, r#"{"status":"pending"}"#).unwrap(), PollOutcome::Pending);
        assert_eq!(parse_poll(200, r#"{"status":"denied"}"#).unwrap(), PollOutcome::Denied);
        assert_eq!(parse_poll(200, r#"{"status":"expired"}"#).unwrap(), PollOutcome::Expired);
        assert_eq!(parse_poll(429, "").unwrap(), PollOutcome::SlowDown);
    }

    #[test]
    fn poll_approved_取出凭据() {
        match parse_poll(200, &approved_body()).unwrap() {
            PollOutcome::Approved(g) => {
                assert_eq!(g.credential_secret, "SECRET-xyz");
                assert_eq!(g.agent_id, "team--alice");
                assert_eq!(g.node_name.as_deref(), Some("alice-laptop"));
            }
            o => panic!("应为 Approved，实际 {o:?}"),
        }
    }

    #[test]
    fn poll_approved_缺凭据_报错而非放行() {
        let body = serde_json::json!({"status":"approved","serverUrl":"https://x","agentId":"a--b",
            "credentialSecret":"","expiresAt":"2026-10-12T00:00:00Z"}).to_string();
        assert!(parse_poll(200, &body).is_err());
        let body = serde_json::json!({"status":"approved","serverUrl":"https://x"}).to_string();
        assert!(parse_poll(200, &body).is_err());
    }

    #[test]
    fn poll_异常响应_报错() {
        assert!(parse_poll(500, "").is_err());
        assert!(parse_poll(200, "not json").is_err());
        assert!(parse_poll(200, r#"{"status":"weird"}"#).is_err());
        assert!(parse_poll(200, r#"{}"#).is_err());
    }

    #[test]
    fn 凭据_debug_不泄漏明文() {
        let g = match parse_poll(200, &approved_body()).unwrap() {
            PollOutcome::Approved(g) => g,
            _ => unreachable!(),
        };
        let dbg = format!("{g:?} {:?}", PollOutcome::Approved(g.clone()));
        assert!(!dbg.contains("SECRET-xyz"), "Debug 输出泄漏了 secret: {dbg}");
        let r = RenewOutcome::Renewed { secret: "SECRET-abc".into(), credential_id: None, expires_at: "x".into() };
        assert!(!format!("{r:?}").contains("SECRET-abc"));
    }

    // ── parse_renew ─────────────────────────────────────────
    #[test]
    fn renew_成功() {
        let b = r#"{"credentialSecret":"NEW","credentialId":"c2","expiresAt":"2026-10-19T00:00:00Z"}"#;
        assert_eq!(
            parse_renew(200, b),
            RenewOutcome::Renewed { secret: "NEW".into(), credential_id: Some("c2".into()), expires_at: "2026-10-19T00:00:00Z".into() }
        );
    }

    #[test]
    fn renew_401_403_需重新授权() {
        assert_eq!(parse_renew(401, ""), RenewOutcome::NeedReauth);
        assert_eq!(parse_renew(403, "{}"), RenewOutcome::NeedReauth);
    }

    #[test]
    fn renew_暂时性失败_不等于失效() {
        assert!(matches!(parse_renew(500, ""), RenewOutcome::Retry(_)));
        assert!(matches!(parse_renew(502, ""), RenewOutcome::Retry(_)));
        assert!(matches!(parse_renew(429, ""), RenewOutcome::Retry(_)));
    }

    #[test]
    fn renew_2xx_但内容异常_不写入空凭据() {
        assert!(matches!(parse_renew(200, "not json"), RenewOutcome::Retry(_)));
        assert!(matches!(parse_renew(200, r#"{"credentialSecret":"","expiresAt":"x"}"#), RenewOutcome::Retry(_)));
        assert!(matches!(parse_renew(200, r#"{}"#), RenewOutcome::Retry(_)));
    }

    // ── 轮询间隔 ────────────────────────────────────────────
    #[test]
    fn 轮询间隔_下限兜底() {
        assert_eq!(next_poll_delay(0, 0), MIN_POLL_INTERVAL);
        assert_eq!(next_poll_delay(1, 0), MIN_POLL_INTERVAL);
        assert_eq!(next_poll_delay(5, 0), Duration::from_secs(5));
    }

    #[test]
    fn 轮询间隔_slow_down_翻倍且封顶() {
        assert_eq!(next_poll_delay(5, 1), Duration::from_secs(10));
        assert_eq!(next_poll_delay(5, 2), Duration::from_secs(20));
        assert_eq!(next_poll_delay(5, 3), MAX_POLL_INTERVAL);
        assert_eq!(next_poll_delay(5, 100), MAX_POLL_INTERVAL);
    }

    // ── 续期阈值（票 14 变异点：阈值判断写反 → 续期用例红）─────
    fn at(s: &str) -> chrono::DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn 续期_剩余超过24h_不续() {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
        assert!(!should_renew("2026-10-07T00:00:01Z", now)); // 剩 48h
        assert!(!should_renew("2026-10-06T00:00:01Z", now)); // 剩 24h+1s
    }

    #[test]
    fn 续期_剩余不足24h_续() {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
        assert!(should_renew("2026-10-06T00:00:00Z", now)); // 恰好 24h：边界算续
        assert!(should_renew("2026-10-05T12:00:00Z", now));
        assert!(should_renew("2026-10-04T00:00:00Z", now)); // 已过期
    }

    #[test]
    fn 续期_到期时间无法解析_保守续() {
        let now = at("2026-10-05T00:00:00Z");
        assert!(should_renew("not-a-date", now));
        assert!(should_renew("", now));
    }
}
