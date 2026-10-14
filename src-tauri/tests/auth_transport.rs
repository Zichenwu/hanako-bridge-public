// tests/auth_transport.rs
//! 票 14：用本地 HTTP 服务端验证**生产传输层** UreqTransport 的行为。
//!
//! auth_flow 的单测用脚本化假传输，覆盖不到真 HTTP 客户端的默认行为。ureq 默认把 4xx/5xx
//! 当作 Err 抛出——如果没显式关掉，429(slow_down)/401/403(续期失效) 会全部变成「网络错误」，
//! 轮询不会放慢、续期失效被误判为暂时失败而永远重试。这里锁死这些状态码的透传。

use hanako_tauri_lib::daemon::auth_flow::{AuthTransport, UreqTransport};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// 起一个只服务一次请求的假 HTTP 服务端，返回 (base_url, 收到的原始请求)。
fn serve_once(status: u16, body: &'static str) -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // 头与 body 可能分多个 TCP 包到达：读到头结束后，再按 Content-Length 补读 body
        let mut raw: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).unwrap();
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..pos]).to_lowercase();
                let want = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))
                    .unwrap_or(0);
                if raw.len() >= pos + 4 + want {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        *seen2.lock().unwrap() = String::from_utf8_lossy(&raw).to_string();
        let reason = match status { 200 => "OK", 401 => "Unauthorized", 403 => "Forbidden", 429 => "Too Many Requests", _ => "X" };
        let resp = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        s.write_all(resp.as_bytes()).unwrap();
    });
    (format!("http://127.0.0.1:{port}"), seen)
}

#[test]
fn 状态码_4xx_不被当作网络错误() {
    for (code, body) in [(429u16, ""), (401, r#"{"error":"x"}"#), (403, r#"{"error":"y"}"#)] {
        let (base, _) = serve_once(code, body);
        let r = UreqTransport.post(&format!("{base}/p"), None, &serde_json::json!({}));
        assert_eq!(r.map(|(s, _)| s), Ok(code), "{code} 必须作为状态码透传，不能变成 Err");
    }
}

#[test]
fn 成功响应_body_完整返回() {
    let (base, _) = serve_once(200, r#"{"status":"pending"}"#);
    let (s, b) = UreqTransport.post(&format!("{base}/p"), None, &serde_json::json!({})).unwrap();
    assert_eq!((s, b.as_str()), (200, r#"{"status":"pending"}"#));
}

#[test]
fn bearer_与_json_体真的发出去了() {
    let (base, seen) = serve_once(200, "{}");
    UreqTransport.post(&format!("{base}/renew"), Some("TOK-123"), &serde_json::json!({"deviceCode":"DEV"})).unwrap();
    let raw = seen.lock().unwrap().to_lowercase();
    assert!(raw.contains("post /renew"), "{raw}");
    assert!(raw.contains("authorization: bearer tok-123"), "Bearer 头没发出: {raw}");
    assert!(raw.contains("content-type: application/json"), "{raw}");
    // 不比字符串（ureq 发的是带缩进的 JSON）：取 body 部分解析后比较内容
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("body 不是合法 JSON({e}): {raw}"));
    assert_eq!(v["devicecode"], "dev", "JSON 体内容不对: {raw}");
}

#[test]
fn 无_bearer_时不带授权头() {
    let (base, seen) = serve_once(200, "{}");
    UreqTransport.post(&format!("{base}/start"), None, &serde_json::json!({})).unwrap();
    assert!(!seen.lock().unwrap().to_lowercase().contains("authorization"), "start/poll 不应带 Authorization");
}

#[test]
fn 连接被拒_是_err() {
    // 端口 1 几乎不会有监听；连接失败必须是 Err，供轮询层当作「暂时网络错误」处理
    assert!(UreqTransport.post("http://127.0.0.1:1/p", None, &serde_json::json!({})).is_err());
}
