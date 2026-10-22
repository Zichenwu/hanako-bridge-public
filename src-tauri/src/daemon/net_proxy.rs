// src-tauri/src/daemon/net_proxy.rs
//! 「直连优先、失败才退代理」的出网兜底。
//!
//! 背景（2026-10-07 Windows 真机）：用户机器 `ProxyEnable=0`，只靠 PAC 把流量指到本机
//! 代理 `127.0.0.1:1001`；浏览器能上网，客户端直连出不去，登录按钮点了没反应。
//!
//! 原则：**默认行为不变**。绝大多数用户直连就通，这里只在直连失败时才尝试代理：
//! 1. `HTTPS_PROXY` / `ALL_PROXY` 环境变量（显式配置，最高优先）
//! 2. Windows 注册表 `Internet Settings\ProxyServer`（不看 ProxyEnable——
//!    PAC 场景下开关是 0，但 ProxyServer 仍指向同一个本机代理）
//! 3. macOS `scutil --proxy` 里**已启用**的 HTTPS / HTTP 代理（GUI 启动的 App 不继承 shell 环境变量）
//!
//! 刻意不做 PAC 解析（要跑 JS，复杂度与收益不匹配）。

/// 候选代理地址（`http://host:port` 形式），按优先级去重。没有则为空。
pub fn fallback_proxies() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(v) = std::env::var(k) {
            push_unique(&mut out, normalize(&v));
        }
    }
    if let Some(v) = registry_proxy_server() {
        push_unique(&mut out, parse_proxy_server(&v));
    }
    if let Some(v) = macos_scutil_proxy() {
        for p in parse_scutil(&v) {
            push_unique(&mut out, Some(p));
        }
    }
    out
}

/// 解析 `scutil --proxy` 输出，按 HTTPS → HTTP 取**已启用**的代理。
pub(crate) fn parse_scutil(text: &str) -> Vec<String> {
    let mut kv = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(" : ") {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let mut out = Vec::new();
    for pre in ["HTTPS", "HTTP"] {
        if kv.get(&format!("{pre}Enable")).map(String::as_str) != Some("1") {
            continue;
        }
        if let (Some(h), Some(p)) = (kv.get(&format!("{pre}Proxy")), kv.get(&format!("{pre}Port"))) {
            let v = format!("http://{h}:{p}");
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn macos_scutil_proxy() -> Option<String> {
    let o = std::process::Command::new("/usr/sbin/scutil").arg("--proxy").output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn macos_scutil_proxy() -> Option<String> {
    None
}

fn push_unique(out: &mut Vec<String>, v: Option<String>) {
    if let Some(v) = v {
        if !out.contains(&v) {
            out.push(v);
        }
    }
}

/// 规范化单个代理地址：补 `http://`，只接受 http 代理（ureq 与手写 CONNECT 都只支持它）。
fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('/');
    if s.is_empty() {
        return None;
    }
    if s.starts_with("http://") {
        return Some(s.to_string());
    }
    if s.contains("://") {
        return None; // socks5:// https:// 等：不支持，宁可不用也别用错
    }
    Some(format!("http://{s}"))
}

/// 解析注册表 ProxyServer：可能是 `host:port`、`http://host:port`，
/// 或分协议形式 `http=h:p;https=h:p;socks=h:p`（取 https，退 http）。
pub(crate) fn parse_proxy_server(v: &str) -> Option<String> {
    let v = v.trim();
    if !v.contains('=') {
        return normalize(v);
    }
    let mut http = None;
    for part in v.split(';') {
        if let Some((k, val)) = part.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "https" => return normalize(val),
                "http" => http = normalize(val),
                _ => {}
            }
        }
    }
    http
}

#[cfg(windows)]
fn registry_proxy_server() -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    let key = winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .ok()?;
    key.get_value::<String, _>("ProxyServer").ok().filter(|s| !s.trim().is_empty())
}

#[cfg(not(windows))]
fn registry_proxy_server() -> Option<String> {
    None
}

/// 从 `http://host:port` 取出 `host:port`（CONNECT 隧道用）。
pub(crate) fn host_port(proxy: &str) -> Option<String> {
    let rest = proxy.strip_prefix("http://")?;
    let hp = rest.rsplit('@').next()?.trim_end_matches('/');
    if hp.is_empty() {
        None
    } else if hp.contains(':') {
        Some(hp.to_string())
    } else {
        Some(format!("{hp}:80"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_per_scheme_forms() {
        assert_eq!(parse_proxy_server("127.0.0.1:1001").as_deref(), Some("http://127.0.0.1:1001"));
        assert_eq!(parse_proxy_server("http://127.0.0.1:1001").as_deref(), Some("http://127.0.0.1:1001"));
        assert_eq!(
            parse_proxy_server("http=1.1.1.1:80;https=2.2.2.2:443;socks=3.3.3.3:1080").as_deref(),
            Some("http://2.2.2.2:443")
        );
        assert_eq!(parse_proxy_server("http=1.1.1.1:80;socks=3.3.3.3:1080").as_deref(), Some("http://1.1.1.1:80"));
        assert_eq!(parse_proxy_server("socks=3.3.3.3:1080"), None);
        assert_eq!(parse_proxy_server(""), None);
    }

    #[test]
    fn rejects_non_http_proxy_schemes() {
        assert_eq!(normalize("socks5://127.0.0.1:1080"), None);
        assert_eq!(normalize("https://p:8443"), None);
    }

    #[test]
    fn scutil_takes_enabled_https_then_http() {
        let out = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  HTTPEnable : 1\n  HTTPPort : 7890\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 7891\n  HTTPSProxy : 127.0.0.1\n  ProxyAutoConfigEnable : 0\n  SOCKSEnable : 1\n  SOCKSPort : 7892\n  SOCKSProxy : 127.0.0.1\n}\n";
        assert_eq!(parse_scutil(out), vec!["http://127.0.0.1:7891", "http://127.0.0.1:7890"]);
        // 未启用的不取；只有 PAC 时为空（不解析 PAC）
        let off = "<dictionary> {\n  HTTPSEnable : 0\n  HTTPSPort : 1\n  HTTPSProxy : 1.1.1.1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://x/pac\n}\n";
        assert!(parse_scutil(off).is_empty());
        assert!(parse_scutil("<dictionary> {\n}\n").is_empty());
    }

    #[test]
    fn host_port_extracts_authority() {
        assert_eq!(host_port("http://127.0.0.1:1001").as_deref(), Some("127.0.0.1:1001"));
        assert_eq!(host_port("http://u:p@proxy.local:8080").as_deref(), Some("proxy.local:8080"));
        assert_eq!(host_port("http://proxy.local").as_deref(), Some("proxy.local:80"));
        assert_eq!(host_port("socks5://x:1"), None);
    }
}
