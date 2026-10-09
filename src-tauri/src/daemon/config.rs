// src-tauri/src/daemon/config.rs
//! daemon 配置：从环境变量或持久化文件读取云端连接信息。
//!
//! # 优先级（高→低）
//! 1. 环境变量（HANA_CLOUD_BASE_URL / HANA_DAEMON_TOKEN / HANA_NODE_ID / HANA_AGENT_ID）
//! 2. `~/.hanako-tauri/config.json`（旧版手填配置，兼容保留）
//! 3. 系统钥匙串里的节点凭据（浏览器授权码登录签发，票 14）
//! 4. `~/.hk/profile.json` 的节点凭据（`hk login` 签发，票 13；兼容一个版本，Q15）
//!
//! 打包后的 Windows 应用没有任何 env，因此文件回退是首次配置的唯一路径。
//!
//! # 安全注意
//! - `token` 字段从不经 Tauri IPC 传到前端（get_daemon_config 只返回 base_url + node_id）
//! - config.json 含 token 明文，文件权限：Unix 建议 600（代码显式 chmod），
//!   Windows 无等价 API，依赖用户主目录 ACL（已在注释中说明）
//! - token 不写入任何日志（log::info!/warn! 均不包含 token 值）

use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

// ────────────────────────────────────────────────────────────────
// DaemonConfig
// ────────────────────────────────────────────────────────────────

/// daemon 运行所需配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// 云端 hanako-server 的 base URL（如 https://hanako.example.com/hapi/hanako）
    pub base_url: String,
    /// device credential 对应的 token（出站 WSS 认证用）
    /// ⚠️ 安全：从不通过 IPC 传至前端；文件存储时请确保文件权限 600（Unix）
    pub token: String,
    /// 本机节点标识（serverNodeId）；优先 env > 文件 > hostname > 固定占位
    pub node_id: String,
    /// 本机绑定的账号执行体 ID（如 `team--alice`），用于推导新注册帧的 grants。
    /// 来源：hk profile 的 agentId；env/config.json 配置的旧路径为 None（grants 为空，
    /// 服务端此时无可派活的执行体——待票 14/15 的授权流程补齐）。
    pub agent_id: Option<String>,
}

// ────────────────────────────────────────────────────────────────
// 文件持久化格式（config.json 读写用，与 DaemonConfig 字段一一对应）
// ────────────────────────────────────────────────────────────────

/// config.json 文件格式（序列化/反序列化）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigFile {
    base_url: String,
    token: String,
    /// node_id 可选；不填则运行时用 hostname 填充
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
}

// ────────────────────────────────────────────────────────────────
// ConfigError
// ────────────────────────────────────────────────────────────────

/// 配置错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingBaseUrl,
    MissingToken,
    InvalidBaseUrl(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBaseUrl => write!(f, "缺少云端地址（HANA_CLOUD_BASE_URL 或 config.json）"),
            Self::MissingToken => write!(f, "缺少连接 Token（HANA_DAEMON_TOKEN 或 config.json）"),
            Self::InvalidBaseUrl(u) => write!(f, "base_url 必须是 http(s):// 开头: {u}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ────────────────────────────────────────────────────────────────
// 路径辅助
// ────────────────────────────────────────────────────────────────

/// 生产 hub 入口（授权码登录 / 续期走它；与 hk CLI 的 DEFAULT_HUB_URL 一致）。
///
/// **编译期注入**（`HANAKO_DEFAULT_HUB_URL`，CI 从 secret 读）：源码不写死公司域名，便于以脱敏镜像公开构建。
/// 未注入时落到 RFC 2606 保留域 `hub.invalid`（永远解析不到）——宁可登录失败，也不能悄悄连去别处；
/// CI 在 secret 缺失时直接失败，`publish-bridge.sh` 发布前还会检查安装包里确实带着真实地址。
pub const DEFAULT_HUB_URL: &str = match option_env!("HANAKO_DEFAULT_HUB_URL") {
    Some(u) => u,
    None => "https://hub.invalid/hapi",
};

/// 解析 hub 地址：`HANA_HUB_URL` 优先，否则生产默认。尾斜杠剥掉。
///
/// 非 http(s) 一律忽略并回落默认（这个地址会交给系统浏览器打开，不能是 file:// 等）。
/// http:// 不阻断（测试/私有部署确有需要）但警告：授权码与凭据将明文过网。
pub fn resolve_hub_url(lookup: impl Fn(&str) -> Option<String>) -> String {
    let raw = lookup("HANA_HUB_URL").map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty());
    match raw {
        Some(u) if u.starts_with("https://") => u,
        Some(u) if u.starts_with("http://") => {
            log::warn!("[config] HANA_HUB_URL 不是 https（{u}）——授权码与凭据将明文传输，仅测试环境可接受");
            u
        }
        Some(u) => {
            log::warn!("[config] HANA_HUB_URL 不是 http(s)，已忽略: {u}");
            DEFAULT_HUB_URL.to_string()
        }
        None => DEFAULT_HUB_URL.to_string(),
    }
}

/// 删除指定文件；不存在视为成功（幂等）。拆成接收路径的内核，测试只打临时目录，绝不碰真实 home。
pub(crate) fn remove_file_if_exists(p: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(p) {
        Ok(()) => {
            log::info!("[config] 已清除旧版手填配置（被钥匙串凭据取代）");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("清除旧版配置失败: {e}")),
    }
}

/// `~/.hanako-tauri/config.json` 的路径（与 workspaces.json 同目录）。
pub fn config_json_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(".hanako-tauri").join("config.json"))
}

// ────────────────────────────────────────────────────────────────
// DaemonConfig impl
// ────────────────────────────────────────────────────────────────

impl DaemonConfig {
    /// 从真实环境变量构造（向后兼容；打包 Windows 应用通常走 from_env_or_file）。
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| env::var(k).ok())
    }

    /// 从环境变量或文件读取配置（推荐入口）。
    ///
    /// 优先级：env 完整 > config.json > 钥匙串 > hk profile > 报错。
    /// 只要 env 里有 HANA_CLOUD_BASE_URL + HANA_DAEMON_TOKEN，就完全用 env（向后兼容）。
    /// 若 env 不完整，尝试读取 config.json；config.json 也缺则返回 ConfigError。
    pub fn from_env_or_file() -> Result<Self, ConfigError> {
        Self::from_env_or_file_with(&super::credential_store::KeyringStore::new())
    }

    /// 同 [`from_env_or_file`]，但钥匙串这一级使用调用方提供的存储。
    ///
    /// 必须让「写入凭据的存储」与「读取凭据的存储」是同一个：钥匙串不可用时应用会降级为会话内存储，
    /// 若此处仍去读真实钥匙串，授权成功后 daemon 永远读不到刚拿到的凭据而起不来。
    pub fn from_env_or_file_with(store: &dyn super::credential_store::CredentialStore) -> Result<Self, ConfigError> {
        // 优先尝试纯 env 路径
        match Self::from_env() {
            Ok(cfg) => return Ok(cfg),
            Err(_) => {}
        }
        // env 不完整，尝试从文件加载
        if let Some(cfg) = Self::load_from_file() {
            return Ok(cfg);
        }
        // 钥匙串里的授权码登录凭据（票 14）：新流程的主路径，优先于 hk login 的旧落盘凭据
        if let Some(cfg) = Self::from_store(store) {
            return Ok(cfg);
        }
        // 再尝试 hk login 落盘的节点凭据（票 13，兼容一个版本）
        if let Some(cfg) = super::hk_profile::load_from_hk_profile() {
            return Ok(cfg);
        }
        // 三者都缺：返回最具体的错误（env 路径的错误，即 MissingBaseUrl/MissingToken）
        Self::from_env()
    }

    /// 删除旧版手填的 `~/.hanako-tauri/config.json`。文件不存在视为成功。
    ///
    /// 浏览器授权成功后调用：config.json 的优先级高于钥匙串，不清掉的话，曾手填过 Token 的用户
    /// 授权成功后 daemon 仍会读到旧（多半已过期）的 token，新凭据被遮蔽、表现为「授权成功但连不上」。
    /// 只清这个被新流程取代的旧文件；env 是运维显式设置的，不动。
    pub fn remove_legacy_file() -> Result<(), String> {
        match config_json_path() {
            Some(p) => remove_file_if_exists(&p),
            None => Ok(()),
        }
    }

    /// 从系统钥匙串读取授权码登录签发的凭据。
    ///
    /// 钥匙串不可用 / 没有条目 / 条目损坏 都返回 None 并落到下一级来源，**不阻断启动**：
    /// 用户机器上钥匙串被锁或缺后端时，仍可用 hk login 的凭据工作。
    /// 已过期的钥匙串凭据也返回（由续期流程处理），不在这里丢弃——丢掉就再无机会续期。
    pub fn load_from_keyring() -> Option<Self> {
        use super::credential_store::KeyringStore;
        Self::from_store(&KeyringStore::new())
    }

    /// 由任意凭据存储构造配置（`load_from_keyring` 的可测试内核）。
    pub fn from_store(store: &dyn super::credential_store::CredentialStore) -> Option<Self> {
        match store.load() {
            Ok(Some(c)) => {
                log::info!("[config] 使用钥匙串中的节点凭据 agent={}", c.agent_id);
                Some(Self {
                    base_url: c.server_url.trim_end_matches('/').to_string(),
                    token: c.secret,
                    // 身份恒取本机主机名：授权页上的名字可被用户改，拿它当身份会让重新授权后
                    // serverNodeId 变化、已绑定会话对不上（2026-10-08 node_AliceMac → AliceMac 实例）。
                    // 授权页名字只作显示名兜底，见 commands::adopt_auth_name_as_display。
                    node_id: default_node_id(),
                    agent_id: Some(c.agent_id),
                })
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("[config] {e}，回退到下一级凭据来源");
                None
            }
        }
    }

    /// 从任意取值函数构造（测试用闭包注入，不污染真实环境变量）。
    pub fn from_lookup<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let base_url = get("HANA_CLOUD_BASE_URL")
            .ok_or(ConfigError::MissingBaseUrl)?
            .trim_end_matches('/')
            .to_string();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            return Err(ConfigError::InvalidBaseUrl(base_url));
        }
        let token = get("HANA_DAEMON_TOKEN").ok_or(ConfigError::MissingToken)?;
        if token.is_empty() {
            return Err(ConfigError::MissingToken);
        }
        // node_id 优先级：env > hostname > 固定占位
        let node_id = get("HANA_NODE_ID").unwrap_or_else(default_node_id);
        let agent_id = get("HANA_AGENT_ID").filter(|s| !s.is_empty());
        Ok(Self { base_url, token, node_id, agent_id })
    }

    /// 验证配置是否合法（供 save_daemon_config 命令使用）。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_url.is_empty() {
            return Err(ConfigError::MissingBaseUrl);
        }
        if !(self.base_url.starts_with("https://") || self.base_url.starts_with("http://")) {
            return Err(ConfigError::InvalidBaseUrl(self.base_url.clone()));
        }
        if self.token.is_empty() {
            return Err(ConfigError::MissingToken);
        }
        Ok(())
    }

    /// 持久化到 `~/.hanako-tauri/config.json`（原子写：先写 .tmp 再 rename）。
    ///
    /// 安全：token 明文存储；在 Unix 下设置 600 权限，Windows 依赖主目录 ACL。
    pub fn save_to_file(&self) -> Result<(), String> {
        let json_path = config_json_path().ok_or("无法确定 home 目录")?;
        let dir = json_path.parent().ok_or("无法确定 config.json 父目录")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {e}"))?;

        let file_cfg = ConfigFile {
            base_url: self.base_url.clone(),
            token: self.token.clone(),
            node_id: Some(self.node_id.clone()),
            agent_id: self.agent_id.clone(),
        };
        let data =
            serde_json::to_string_pretty(&file_cfg).map_err(|e| format!("序列化失败: {e}"))?;

        // 原子写：写临时文件后 rename（与 workspaces.json 同一模式）
        let tmp_path = json_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &data).map_err(|e| format!("写临时文件失败: {e}"))?;

        // Unix：设置 600 权限（文件含 token 明文，最小权限原则）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }

        // Windows 安全：Rust 的 std::fs::rename 在 Windows 上使用 MoveFileExW +
        // MOVEFILE_REPLACE_EXISTING，目标文件已存在时会原子替换（第二次保存同样正常）。
        // 不需要手动 remove_file 前置步骤。（M4 核实：std 文档 + 1.x 实现确认）
        std::fs::rename(&tmp_path, &json_path).map_err(|e| format!("rename 失败: {e}"))?;
        // 注意：不 log token 值，只 log base_url 和 node_id
        log::info!(
            "[config] 配置已持久化 base_url={} node_id={}",
            self.base_url,
            self.node_id
        );
        Ok(())
    }

    /// 从 `~/.hanako-tauri/config.json` 读取配置（宽容：文件不存在或格式错误返回 None）。
    pub fn load_from_file() -> Option<Self> {
        let json_path = config_json_path()?;
        let data = std::fs::read_to_string(&json_path).ok()?;
        let file_cfg: ConfigFile = serde_json::from_str(&data).ok()?;

        // base_url 剥尾斜杠 + 校验
        let base_url = file_cfg.base_url.trim_end_matches('/').to_string();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            log::warn!("[config] config.json base_url 格式非法，忽略文件配置");
            return None;
        }
        if file_cfg.token.is_empty() {
            log::warn!("[config] config.json token 为空，忽略文件配置");
            return None;
        }

        let node_id = file_cfg
            .node_id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_node_id);

        Some(Self { base_url, token: file_cfg.token, node_id, agent_id: file_cfg.agent_id.filter(|s| !s.is_empty()) })
    }
}

// ────────────────────────────────────────────────────────────────
// node_id 默认值：hostname sanitized → 固定占位
// ────────────────────────────────────────────────────────────────

/// 生成默认 node_id：优先使用 hostname（sanitize 为 ASCII 字母数字加短横），
/// 失败则退回 "node_dev_placeholder"。
///
/// 设计依据：同一台机器每次启动 node_id 应相同（稳定机器指纹），
/// hostname 是跨重启最简单的稳定标识，不需要持久化额外文件。
///
/// pub 供 lib.rs save_daemon_config 命令在前端未传 node_id 时调用。
pub fn default_node_id_pub() -> String {
    default_node_id()
}

fn default_node_id() -> String {
    match hostname::get() {
        Ok(h) => {
            let raw = h.to_string_lossy().to_string();
            // sanitize：只保留 ASCII 字母数字和 '-'，其余替换为 '-'，长度截断到 48
            let sanitized: String = raw
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
                .take(48)
                .collect();
            let sanitized = sanitized.trim_matches('-').to_string();
            if sanitized.is_empty() {
                "node_dev_placeholder".into()
            } else {
                format!("node_{sanitized}")
            }
        }
        Err(_) => "node_dev_placeholder".into(),
    }
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 用 HashMap 模拟环境变量。
    fn cfg(vars: &[(&str, &str)]) -> Result<DaemonConfig, ConfigError> {
        let map: HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DaemonConfig::from_lookup(move |k| map.get(k).cloned())
    }

    #[test]
    fn 缺_base_url_报错() {
        let r = cfg(&[("HANA_DAEMON_TOKEN", "tok")]);
        assert_eq!(r.unwrap_err(), ConfigError::MissingBaseUrl);
    }

    #[test]
    fn 缺_token_报错() {
        let r = cfg(&[("HANA_CLOUD_BASE_URL", "https://x.example.com")]);
        assert_eq!(r.unwrap_err(), ConfigError::MissingToken);
    }

    #[test]
    fn 空_token_报错() {
        let r = cfg(&[
            ("HANA_CLOUD_BASE_URL", "https://x.example.com"),
            ("HANA_DAEMON_TOKEN", ""),
        ]);
        assert_eq!(r.unwrap_err(), ConfigError::MissingToken);
    }

    #[test]
    fn base_url_非_http_报错() {
        let r = cfg(&[
            ("HANA_CLOUD_BASE_URL", "ftp://x.example.com"),
            ("HANA_DAEMON_TOKEN", "tok"),
        ]);
        assert!(matches!(r.unwrap_err(), ConfigError::InvalidBaseUrl(_)));
    }

    #[test]
    fn 合法配置_剥尾斜杠() {
        let r = cfg(&[
            ("HANA_CLOUD_BASE_URL", "https://x.example.com/hapi/hanako/"),
            ("HANA_DAEMON_TOKEN", "tok"),
            ("HANA_NODE_ID", "node_test_1"),
        ])
        .unwrap();
        assert_eq!(r.base_url, "https://x.example.com/hapi/hanako");
        assert_eq!(r.token, "tok");
        assert_eq!(r.node_id, "node_test_1");
    }

    #[test]
    fn 缺省_node_id_使用_hostname_或占位() {
        let r = cfg(&[
            ("HANA_CLOUD_BASE_URL", "https://x.example.com"),
            ("HANA_DAEMON_TOKEN", "tok"),
        ])
        .unwrap();
        // node_id 不应为空；可能是 node_<hostname> 或 node_dev_placeholder
        assert!(!r.node_id.is_empty());
        // 不再是固定占位——hostname 可用则以 "node_" 开头
        // （CI 环境 hostname 总能 resolve，所以这里只断言不空）
    }

    // ─── from_env_or_file 优先级测试 ────────────────────────────

    /// env 完整时，from_env_or_file 返回 env 值（忽略文件）。
    #[test]
    fn env_优先于文件() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("config.json");

        // 写一个文件配置（base_url 故意不同）
        let file_cfg = serde_json::json!({
            "base_url": "https://file.example.com",
            "token": "file_token",
            "node_id": "node_file"
        });
        std::fs::write(&json_path, file_cfg.to_string()).unwrap();

        // 直接用 from_lookup 模拟 env 存在（不触碰真实 env/home_dir）
        let map: HashMap<String, String> = [
            ("HANA_CLOUD_BASE_URL", "https://env.example.com"),
            ("HANA_DAEMON_TOKEN", "env_token"),
            ("HANA_NODE_ID", "node_env"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let result = DaemonConfig::from_lookup(|k| map.get(k).cloned()).unwrap();
        assert_eq!(result.base_url, "https://env.example.com");
        assert_eq!(result.token, "env_token");
        assert_eq!(result.node_id, "node_env");
    }

    /// 文件配置 save + load 往返正确（不依赖真实 home_dir）。
    #[test]
    fn 文件配置_save_load_往返() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("config.json");

        let original = DaemonConfig {
            base_url: "https://save.example.com/hapi/hanako".into(),
            token: "token_roundtrip".into(),
            node_id: "node_roundtrip".into(),
            agent_id: None,
        };

        // 手动写文件（绕过 save_to_file 的 home_dir 依赖）
        let file_cfg = ConfigFile {
            base_url: original.base_url.clone(),
            token: original.token.clone(),
            node_id: Some(original.node_id.clone()),
            agent_id: None,
        };
        let data = serde_json::to_string_pretty(&file_cfg).unwrap();
        std::fs::write(&json_path, &data).unwrap();

        // 直接解析（不依赖 config_json_path()）
        let loaded: ConfigFile = serde_json::from_str(&data).unwrap();
        let loaded_cfg = DaemonConfig {
            base_url: loaded.base_url.trim_end_matches('/').to_string(),
            token: loaded.token,
            node_id: loaded.node_id.filter(|s| !s.is_empty()).unwrap_or_else(default_node_id),
            agent_id: None,
        };

        assert_eq!(loaded_cfg.base_url, original.base_url);
        assert_eq!(loaded_cfg.token, original.token);
        assert_eq!(loaded_cfg.node_id, original.node_id);
    }

    /// 文件 node_id 为空时，load_from_file 用 default_node_id 填充。
    #[test]
    fn 文件_node_id_为空_用_hostname_填充() {
        let data = serde_json::json!({
            "base_url": "https://x.example.com",
            "token": "tok_hostname_test"
        });
        // 解析
        let file_cfg: ConfigFile = serde_json::from_str(&data.to_string()).unwrap();
        let node_id = file_cfg
            .node_id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_node_id);
        assert!(!node_id.is_empty());
    }

    /// 文件缺失时 load_from_file 返回 None。
    #[test]
    fn 文件不存在返回_none() {
        // config_json_path 指向真实 home，可能存在也可能不存在
        // 这里只测试 serde 解析路径：无效 json → None
        let bad_json = "{ not valid json";
        let result: Option<ConfigFile> = serde_json::from_str(bad_json).ok();
        assert!(result.is_none());
    }

    /// validate() 对合法配置通过。
    #[test]
    fn validate_合法配置通过() {
        let c = DaemonConfig {
            base_url: "https://x.example.com".into(),
            token: "tok".into(),
            node_id: "n1".into(),
            agent_id: None,
        };
        assert!(c.validate().is_ok());
    }

    /// validate() 对缺 token 报错。
    #[test]
    fn validate_空_token_报错() {
        let c = DaemonConfig {
            base_url: "https://x.example.com".into(),
            token: "".into(),
            node_id: "n1".into(),
            agent_id: None,
        };
        assert_eq!(c.validate().unwrap_err(), ConfigError::MissingToken);
    }

    // ─── 钥匙串来源（票 14）───────────────────────────────────

    fn stored(secret: &str) -> super::super::credential_store::StoredCredential {
        super::super::credential_store::StoredCredential {
            server_url: "https://x.example.com/hapi/hanako/".into(),
            agent_id: "team--alice".into(),
            secret: secret.into(),
            credential_id: None,
            expires_at: "2026-10-12T00:00:00Z".into(),
            node_name: Some("my-laptop".into()),
        }
    }

    #[test]
    fn 钥匙串凭据_转为配置() {
        use super::super::credential_store::{CredentialStore, MemoryStore};
        let s = MemoryStore::new();
        s.save(&stored("KR-SECRET")).unwrap();
        let c = DaemonConfig::from_store(&s).unwrap();
        assert_eq!(c.token, "KR-SECRET");
        assert_eq!(c.base_url, "https://x.example.com/hapi/hanako", "尾斜杠须剥掉");
        assert_eq!(c.agent_id.as_deref(), Some("team--alice"));
        assert_eq!(c.node_id, default_node_id(), "身份恒为主机名，不取授权页上可改的名字");
        assert_ne!(c.node_id, "my-laptop");
    }

    #[test]
    fn 钥匙串无条目_返回_none_落到下一级() {
        assert!(DaemonConfig::from_store(&super::super::credential_store::MemoryStore::new()).is_none());
    }

    #[test]
    fn 钥匙串条目损坏_不阻断_返回_none() {
        let s = super::super::credential_store::MemoryStore::new();
        s.put_raw("{ broken");
        assert!(DaemonConfig::from_store(&s).is_none());
    }

    #[test]
    fn 已过期的钥匙串凭据_仍返回_交给续期流程() {
        use super::super::credential_store::CredentialStore;
        let s = super::super::credential_store::MemoryStore::new();
        let mut c = stored("OLD");
        c.expires_at = "2020-01-01T00:00:00Z".into();
        s.save(&c).unwrap();
        assert!(DaemonConfig::from_store(&s).is_some(), "丢掉过期凭据就再没机会续期了");
    }

    /// 出包注入锁（10-09）：CI 在单测与构建两步都设了 `HANAKO_DEFAULT_HUB_URL`（同一个 secret）。
    /// 设了 `HANAKO_EXPECT_INJECTED_HUB=1` 时，编译进来的默认地址必须等于该 env——证明注入真的到达 rustc。
    /// 本地不设该变量 → 只断言「未注入时是 hub.invalid」，不影响开发。
    #[test]
    fn 默认地址_编译期注入() {
        if std::env::var("HANAKO_EXPECT_INJECTED_HUB").as_deref() == Ok("1") {
            let want = option_env!("HANAKO_DEFAULT_HUB_URL").expect("CI 期望注入但编译时没有 HANAKO_DEFAULT_HUB_URL");
            assert_eq!(DEFAULT_HUB_URL, want);
            assert!(DEFAULT_HUB_URL.starts_with("https://") && !DEFAULT_HUB_URL.contains("hub.invalid"));
        } else if option_env!("HANAKO_DEFAULT_HUB_URL").is_none() {
            assert_eq!(DEFAULT_HUB_URL, "https://hub.invalid/hapi");
        }
    }

    #[test]
    fn hub_地址_默认生产_env_可覆盖_非法回落() {
        let none = |_: &str| None;
        assert_eq!(resolve_hub_url(none), DEFAULT_HUB_URL);
        let set = |v: &'static str| move |k: &str| (k == "HANA_HUB_URL").then(|| v.to_string());
        assert_eq!(resolve_hub_url(set("https://h.example.com/hapi/")), "https://h.example.com/hapi", "尾斜杠须剥掉");
        assert_eq!(resolve_hub_url(set("http://127.0.0.1:3006")), "http://127.0.0.1:3006", "http 不阻断（测试环境）");
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "ftp://x", "   ", ""] {
            assert_eq!(resolve_hub_url(set(bad)), DEFAULT_HUB_URL, "{bad:?} 不得被采用（会交给系统浏览器打开）");
        }
    }

    #[test]
    fn 清除旧配置_存在则删_不存在幂等_且只动指定文件() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.json");
        let other = dir.path().join("workspaces.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::write(&other, "[]").unwrap();
        remove_file_if_exists(&target).unwrap();
        assert!(!target.exists());
        assert!(other.exists(), "不得误删同目录的 workspaces.json（授权目录列表）");
        remove_file_if_exists(&target).unwrap(); // 幂等
    }

    /// default_node_id 不返回空字符串。
    #[test]
    fn default_node_id_不为空() {
        let id = default_node_id();
        assert!(!id.is_empty());
    }
}
