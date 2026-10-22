// src-tauri/src/daemon/credential_store.rs
//! 节点凭据存储：系统钥匙串（票 14，US9：别的程序不能直接读文件拿走凭据）。
//!
//! 业务逻辑只依赖 [`CredentialStore`] trait：测试用 [`MemoryStore`]，生产用 [`KeyringStore`]。
//!
//! # 存什么
//! 整个 [`StoredCredential`] 序列化成一条 JSON 存进钥匙串的一个条目
//! （service=`com.palmpay.hanako`，account=`node-credential`）。secret 与 expires_at
//! 必须**同条目原子读写**：分两条存，崩在中间就会出现「新 secret + 旧到期时间」，续期判断全错。
//!
//! # 已知陷阱（keyring 3.x）
//! 不开平台 feature 时 keyring 退化为**内存 mock**：set 成功、重启后 get 读不到，且不报错。
//! Cargo.toml 已按平台显式开后端；[`KeyringStore::probe`] 在启动时做一次写-读-删往返，
//! 读不回来就判定钥匙串不可用，调用方据此降级并明确告知，而不是静默丢凭据。

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const KEYRING_SERVICE: &str = "com.palmpay.hanako";
pub const KEYRING_ACCOUNT: &str = "node-credential";

/// 落钥匙串的凭据快照。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCredential {
    pub server_url: String,
    pub agent_id: String,
    pub secret: String,
    pub credential_id: Option<String>,
    pub expires_at: String,
    /// 节点名（机器名），展示用；可缺省
    #[serde(default)]
    pub node_name: Option<String>,
}

impl std::fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredential")
            .field("server_url", &self.server_url)
            .field("agent_id", &self.agent_id)
            .field("secret", &"<redacted>")
            .field("credential_id", &self.credential_id)
            .field("expires_at", &self.expires_at)
            .field("node_name", &self.node_name)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// 钥匙串后端不可用（Linux 无 secret-service、用户拒绝解锁等）
    Unavailable(String),
    /// 条目存在但内容损坏（手工改过/版本不兼容）
    Corrupt(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) => write!(f, "系统钥匙串不可用: {m}"),
            Self::Corrupt(m) => write!(f, "钥匙串中的凭据已损坏: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub trait CredentialStore: Send + Sync {
    /// 读取；条目不存在返回 `Ok(None)`（这是正常的首次启动状态，不是错误）。
    fn load(&self) -> Result<Option<StoredCredential>, StoreError>;
    fn save(&self, cred: &StoredCredential) -> Result<(), StoreError>;
    /// 删除；条目本来就不存在也视为成功（幂等，登出/重新授权路径不该因此失败）。
    fn clear(&self) -> Result<(), StoreError>;
}

// ────────────────────────────────────────────────────────────────
// 内存实现（测试 + 钥匙串不可用时的会话内降级）
// ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MemoryStore {
    slot: Mutex<Option<String>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// 测试用：直接塞入原始字符串，模拟损坏条目。
    #[cfg(test)]
    pub fn put_raw(&self, raw: &str) {
        *self.slot.lock().unwrap() = Some(raw.to_string());
    }
}

impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredCredential>, StoreError> {
        decode(self.slot.lock().unwrap().as_deref())
    }
    fn save(&self, cred: &StoredCredential) -> Result<(), StoreError> {
        *self.slot.lock().unwrap() = Some(encode(cred)?);
        Ok(())
    }
    fn clear(&self) -> Result<(), StoreError> {
        *self.slot.lock().unwrap() = None;
        Ok(())
    }
}

fn encode(cred: &StoredCredential) -> Result<String, StoreError> {
    serde_json::to_string(cred).map_err(|e| StoreError::Corrupt(format!("序列化失败: {e}")))
}

fn decode(raw: Option<&str>) -> Result<Option<StoredCredential>, StoreError> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let c: StoredCredential =
                serde_json::from_str(s).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            // 空 secret 等同没有凭据：绝不把它当「已登录」返回，否则会带着空 token 去握手
            if c.secret.is_empty() {
                return Err(StoreError::Corrupt("secret 为空".into()));
            }
            Ok(Some(c))
        }
    }
}

// ────────────────────────────────────────────────────────────────
// 系统钥匙串实现
// ────────────────────────────────────────────────────────────────

pub struct KeyringStore {
    service: String,
    account: String,
}

impl KeyringStore {
    pub fn new() -> Self {
        Self { service: KEYRING_SERVICE.into(), account: KEYRING_ACCOUNT.into() }
    }

    /// 自定义条目名（探针/测试用，避免碰真实凭据条目）。
    pub fn with_entry(service: &str, account: &str) -> Self {
        Self { service: service.into(), account: account.into() }
    }

    fn entry(&self) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, &self.account).map_err(|e| StoreError::Unavailable(e.to_string()))
    }

    /// 启动自检：在**独立的探针条目**上写 → 读 → 删。读不回来 = 后端是 mock 或被锁，判不可用。
    /// 不碰真实凭据条目，所以不会误删用户已存的凭据。
    pub fn probe() -> Result<(), StoreError> {
        let probe = Self::with_entry(KEYRING_SERVICE, "probe-roundtrip");
        let e = probe.entry()?;
        let token = format!("probe-{}", std::process::id());
        e.set_password(&token).map_err(|err| StoreError::Unavailable(err.to_string()))?;
        let got = e.get_password();
        let _ = e.delete_credential();
        match got {
            Ok(v) if v == token => Ok(()),
            Ok(_) => Err(StoreError::Unavailable("写入后读回内容不一致".into())),
            Err(err) => Err(StoreError::Unavailable(format!("写入后读不回来（可能是 mock 后端）: {err}"))),
        }
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for KeyringStore {
    fn load(&self) -> Result<Option<StoredCredential>, StoreError> {
        match self.entry()?.get_password() {
            Ok(raw) => decode(Some(&raw)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Unavailable(e.to_string())),
        }
    }
    fn save(&self, cred: &StoredCredential) -> Result<(), StoreError> {
        let raw = encode(cred)?;
        self.entry()?.set_password(&raw).map_err(|e| StoreError::Unavailable(e.to_string()))
    }
    fn clear(&self) -> Result<(), StoreError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Unavailable(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(secret: &str) -> StoredCredential {
        StoredCredential {
            server_url: "https://x.example.com/hapi/hanako".into(),
            agent_id: "team--alice".into(),
            secret: secret.into(),
            credential_id: Some("cred_1".into()),
            expires_at: "2026-10-12T00:00:00Z".into(),
            node_name: Some("laptop".into()),
        }
    }

    #[test]
    fn 首次启动读到_none_不是错误() {
        assert_eq!(MemoryStore::new().load().unwrap(), None);
    }

    #[test]
    fn 存取往返() {
        let s = MemoryStore::new();
        s.save(&cred("S1")).unwrap();
        assert_eq!(s.load().unwrap(), Some(cred("S1")));
    }

    #[test]
    fn 覆盖写入_secret_与到期时间同步更新() {
        let s = MemoryStore::new();
        s.save(&cred("OLD")).unwrap();
        let mut n = cred("NEW");
        n.expires_at = "2026-10-19T00:00:00Z".into();
        s.save(&n).unwrap();
        let got = s.load().unwrap().unwrap();
        assert_eq!(got.secret, "NEW");
        assert_eq!(got.expires_at, "2026-10-19T00:00:00Z", "secret 与到期时间必须同条目原子更新");
    }

    #[test]
    fn 清除后读到_none_且重复清除幂等() {
        let s = MemoryStore::new();
        s.save(&cred("S")).unwrap();
        s.clear().unwrap();
        assert_eq!(s.load().unwrap(), None);
        s.clear().unwrap();
    }

    #[test]
    fn 损坏条目_报_corrupt_而非当作已登录() {
        let s = MemoryStore::new();
        s.put_raw("{ not json");
        assert!(matches!(s.load(), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn 空_secret_条目_视为损坏() {
        let s = MemoryStore::new();
        s.put_raw(&serde_json::to_string(&cred("")).unwrap());
        assert!(matches!(s.load(), Err(StoreError::Corrupt(_))), "空 secret 不能被当成有效登录态");
    }

    #[test]
    fn debug_不泄漏_secret() {
        assert!(!format!("{:?}", cred("TOP-SECRET")).contains("TOP-SECRET"));
    }

    /// 真实钥匙串往返。本机（无头 Linux）没有 secret-service 时会判不可用并**跳过**——
    /// 这条只在 Mac/Windows 实机或带 gnome-keyring 的 Linux 上才有意义，CI 不依赖它。
    #[test]
    fn 真实钥匙串往返_环境不支持则跳过() {
        if let Err(e) = KeyringStore::probe() {
            eprintln!("[skip] 本机钥匙串后端不可用，跳过真实往返: {e}");
            return;
        }
        let s = KeyringStore::with_entry(KEYRING_SERVICE, &format!("test-{}", std::process::id()));
        s.save(&cred("REAL")).unwrap();
        assert_eq!(s.load().unwrap(), Some(cred("REAL")));
        eprintln!("[real] 钥匙串写入并读回成功");
        s.clear().unwrap();
        assert_eq!(s.load().unwrap(), None);
        eprintln!("[real] 清除后读到 None");
    }
}
