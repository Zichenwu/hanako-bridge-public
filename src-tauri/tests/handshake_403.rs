// 票 17：握手 403 的真实错误串必须被识别为「凭据失效」。
//
// 为什么要真连：client.rs 的 `is_handshake_forbidden` 靠匹配 tungstenite 的错误文本，
// 单测里手写的字符串可能和真实格式不一致（升级 tungstenite 后更可能悄悄变）。
// 这里起一个只回 403 的本地 TCP 服务，用和 client.rs 完全相同的调用（connect_async + 同样的 map_err 格式）
// 拿到真实错误，再喂给生产函数。

use hanako_tauri_lib::daemon::client::is_handshake_forbidden;
use std::io::{Read, Write};
use std::net::TcpListener;

fn serve_once(status_line: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

/// 与 client.rs connect_once 完全一致的错误格式化。
async fn handshake_err(port: u16) -> String {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!("ws://127.0.0.1:{port}/api/execution-node/ws");
    let req = url.into_client_request().unwrap();
    match tokio_tungstenite::connect_async(req).await {
        Ok(_) => panic!("不该握手成功"),
        Err(e) => format!("握手失败: {e}"),
    }
}

#[tokio::test]
async fn 真实握手_403_被识别为凭据失效() {
    let port = serve_once("HTTP/1.1 403 Forbidden");
    let err = handshake_err(port).await;
    println!("真实错误串: {err}");
    assert!(is_handshake_forbidden(&err), "真实 403 错误串未被识别: {err}");
}

#[tokio::test]
async fn 真实握手_非403_不被误判() {
    for line in ["HTTP/1.1 502 Bad Gateway", "HTTP/1.1 429 Too Many Requests", "HTTP/1.1 404 Not Found"] {
        let port = serve_once(line);
        let err = handshake_err(port).await;
        assert!(!is_handshake_forbidden(&err), "{line} 被误判为凭据失效: {err}");
    }
}

#[tokio::test]
async fn 真实连接被拒_不判凭据失效() {
    // 绑定后立即释放端口 → 连接被拒
    let port = { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    let err = handshake_err(port).await;
    assert!(!is_handshake_forbidden(&err), "连接被拒不是凭据失效: {err}");
}
