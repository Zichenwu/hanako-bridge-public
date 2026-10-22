// src-tauri/src/daemon/hk_profile.rs
//! 读取 `hk login` 落盘的节点凭据（`~/.hk/profile.json`）。
//!
//! 决策文档 §1.1 P15：凭据**不能手填**。浏览器授权码登录（票 14）上线前，
//! 本机沿用 hk 已签发的 `execution.node` 窄 scope 凭据（Q15 兼容一个版本）。
//!
//! # 只取 nodeCredentialSecret
//! profile 里还有 `credentialSecret`（chat 等宽 scope）与 `agentToken`。
//! **绝不回退使用它们**：P2 要求必须是独立 scope `execution.node`，
//! 宽 scope 凭据打节点端点既会被服务端拒绝，也违反最小权限。
//!
//! # 安全
//! token 不写入日志；过期判断只报到期时间，不回显 secret。

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::PathBuf;

use super::config::{default_node_id_pub, DaemonConfig};

/// profile.json 中本模块关心的字段（其余字段一律忽略，不反序列化 secret 以外的凭据）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFile {
    server_url: Option<String>,
    agent_id: Option<String>,
    node_credential_secret: Option<String>,
    node_credential_expires_at: Option<String>,
}

/// profile 不可用的原因（供日志与测试断言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// JSON 解析失败
    Malformed,
    /// 没有 nodeCredentialSecret（旧版 hk login 未签发节点凭据）
    MissingNodeCredential,
    /// 缺 serverUrl 或格式非法
    InvalidServerUrl,
    /// 节点凭据已过期（携带到期时间，便于提示用户重新登录）
    Expired(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "profile.json 格式错误"),
            Self::MissingNodeCredential => {
                write!(f, "profile.json 没有节点凭据（nodeCredentialSecret），请升级 hk 后重新 hk login")
            }
            Self::InvalidServerUrl => write!(f, "profile.json 的 serverUrl 缺失或不是 http(s)://"),
            Self::Expired(at) => write!(f, "hk 节点凭据已于 {at} 过期，请重新 hk login"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// `~/.hk/profile.json` 的路径。
pub fn hk_profile_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(".hk").join("profile.json"))
}

/// 由 profile.json 原文构造 daemon 配置（纯函数，`now` 注入以便测试过期边界）。
pub fn config_from_profile_json(raw: &str, now: DateTime<Utc>) -> Result<DaemonConfig, ProfileError> {
    let p: ProfileFile = serde_json::from_str(raw).map_err(|_| ProfileError::Malformed)?;

    let token = p
        .node_credential_secret
        .filter(|s| !s.is_empty())
        .ok_or(ProfileError::MissingNodeCredential)?;

    let base_url = p
        .server_url
        .map(|u| u.trim_end_matches('/').to_string())
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .ok_or(ProfileError::InvalidServerUrl)?;

    // 到期判断：缺省或无法解析 = 不拦（由服务端握手裁决）；明确已到期才拦，避免 403 重连风暴
    if let Some(at) = p.node_credential_expires_at.as_deref() {
        if let Ok(expires) = DateTime::parse_from_rfc3339(at) {
            if expires.with_timezone(&Utc) <= now {
                return Err(ProfileError::Expired(at.to_string()));
            }
        }
    }

    Ok(DaemonConfig {
        base_url,
        token,
        node_id: default_node_id_pub(),
        agent_id: p.agent_id.filter(|s| !s.is_empty()),
    })
}

/// 读取真实 `~/.hk/profile.json`。文件不存在静默返回 None；存在但不可用时打一条警告。
pub fn load_from_hk_profile() -> Option<DaemonConfig> {
    let path = hk_profile_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    match config_from_profile_json(&raw, Utc::now()) {
        Ok(cfg) => {
            log::info!("[config] 使用 hk login 节点凭据 base_url={}", cfg.base_url);
            Some(cfg)
        }
        Err(e) => {
            log::warn!("[config] {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-05T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    fn profile(expires: Option<&str>) -> String {
        let mut v = serde_json::json!({
            "schemaVersion": 1,
            "serverUrl": "https://x.example.com/hapi/hanako/",
            "agentId": "team--alice",
            "credentialSecret": "WIDE-SCOPE-MUST-NOT-BE-USED",
            "agentToken": "AGENT-TOKEN-MUST-NOT-BE-USED",
            "nodeCredentialSecret": "node-secret-1",
        });
        if let Some(e) = expires {
            v["nodeCredentialExpiresAt"] = serde_json::json!(e);
        }
        v.to_string()
    }

    #[test]
    fn 合法_profile_取节点凭据与执行体() {
        let c = config_from_profile_json(&profile(Some("2026-10-20T00:00:00Z")), now()).unwrap();
        assert_eq!(c.token, "node-secret-1");
        assert_eq!(c.base_url, "https://x.example.com/hapi/hanako");
        assert_eq!(c.agent_id.as_deref(), Some("team--alice"));
        assert!(!c.node_id.is_empty());
    }

    #[test]
    fn 绝不回退宽_scope_凭据() {
        let raw = serde_json::json!({
            "serverUrl": "https://x.example.com",
            "credentialSecret": "WIDE",
            "agentToken": "AGENT",
        })
        .to_string();
        assert_eq!(
            config_from_profile_json(&raw, now()).unwrap_err(),
            ProfileError::MissingNodeCredential
        );
    }

    #[test]
    fn 已过期_报错并带到期时间() {
        let err = config_from_profile_json(&profile(Some("2026-08-28T09:28:38.381Z")), now()).unwrap_err();
        assert_eq!(err, ProfileError::Expired("2026-08-28T09:28:38.381Z".into()));
    }

    #[test]
    fn 恰好到期时刻_视为已过期() {
        let err = config_from_profile_json(&profile(Some("2026-10-05T12:00:00Z")), now()).unwrap_err();
        assert!(matches!(err, ProfileError::Expired(_)));
    }

    #[test]
    fn 缺到期时间_不拦() {
        assert!(config_from_profile_json(&profile(None), now()).is_ok());
    }

    #[test]
    fn 到期时间无法解析_不拦() {
        assert!(config_from_profile_json(&profile(Some("not-a-date")), now()).is_ok());
    }

    #[test]
    fn server_url_非法_报错() {
        let raw = serde_json::json!({"serverUrl":"ftp://x","nodeCredentialSecret":"s"}).to_string();
        assert_eq!(config_from_profile_json(&raw, now()).unwrap_err(), ProfileError::InvalidServerUrl);
        let raw = serde_json::json!({"nodeCredentialSecret":"s"}).to_string();
        assert_eq!(config_from_profile_json(&raw, now()).unwrap_err(), ProfileError::InvalidServerUrl);
    }

    #[test]
    fn 非法_json_报格式错() {
        assert_eq!(config_from_profile_json("{ nope", now()).unwrap_err(), ProfileError::Malformed);
    }
}
