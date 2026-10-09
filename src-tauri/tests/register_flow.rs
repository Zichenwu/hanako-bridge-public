// tests/register_flow.rs
//! 票 13 集成测试：用本地假 WS 服务端验证 daemon 的「注册帧内容」与「被顶/被拒后不重连」。
//!
//! 为什么必须端到端：`is_displaced()` 等纯函数单测只证明判定对，证明不了
//! 「主循环真的收到帧后 return、而不是继续 backoff 重连」。被顶后仍重连 = 两台电脑无限互顶。
//!
//! 假服务端行为由 `Script` 决定；每次有连接进来就计数，测试断言连接次数。

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

/// 收到 register 后服务端的反应。
#[derive(Clone, Copy)]
enum Script {
    /// 回 registered，之后保持连接
    Accept,
    /// 回 displaced 帧，然后以 4001 关闭
    DisplaceWithFrame,
    /// 只回 displaced 帧，不关连接（模拟关闭码丢失；此时唯一的终止依据是帧本身）
    DisplaceFrameOnly,
    /// 只以 4001 关闭（模拟 displaced 帧丢失）
    DisplaceCloseOnly,
    /// 回 register_failed
    RejectFrame,
    /// 不回任何东西直接以 1000 关闭（普通断线，应重连）
    PlainClose,
}

struct Fake {
    port: u16,
    connections: Arc<AtomicUsize>,
    /// 每次连接收到的首个 register 帧
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
}

async fn spawn_fake(script: Script) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let (c2, f2) = (connections.clone(), frames.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let (c3, f3) = (c2.clone(), f2.clone());
            tokio::spawn(async move {
                let ws = match tokio_tungstenite::accept_async(stream).await {
                    Ok(w) => w,
                    Err(_) => return,
                };
                c3.fetch_add(1, Ordering::SeqCst);
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    let Message::Text(t) = msg else { continue };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else { continue };
                    if v.get("type").and_then(|x| x.as_str()) != Some("register") {
                        continue;
                    }
                    f3.lock().unwrap().push(v);
                    match script {
                        Script::Accept => {
                            let _ = tx.send(Message::Text(r#"{"type":"registered","protocolVersion":1,"legacyFrame":false}"#.into())).await;
                        }
                        Script::DisplaceWithFrame => {
                            let _ = tx.send(Message::Text(r#"{"type":"displaced","reason":"replaced_by_newer_node","by":"other"}"#.into())).await;
                            let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::from(4001), reason: "displaced".into() }))).await;
                            return;
                        }
                        Script::DisplaceFrameOnly => {
                            let _ = tx.send(Message::Text(r#"{"type":"displaced","reason":"replaced_by_newer_node","by":"other"}"#.into())).await;
                            // 不关闭、不 return：保持连接，让客户端只能靠帧本身决定是否停止
                        }
                        Script::DisplaceCloseOnly => {
                            let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::from(4001), reason: "displaced".into() }))).await;
                            return;
                        }
                        Script::RejectFrame => {
                            let _ = tx.send(Message::Text(r#"{"type":"register_failed","error":"protocol version 0 below minimum 1"}"#.into())).await;
                            let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::Policy, reason: "register_failed".into() }))).await;
                            return;
                        }
                        Script::PlainClose => {
                            let _ = tx.send(Message::Close(Some(CloseFrame { code: CloseCode::Normal, reason: "bye".into() }))).await;
                            return;
                        }
                    }
                }
            });
        }
    });
    Fake { port, connections, frames }
}

fn client_for(port: u16, agent: Option<&str>) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    let cfg = DaemonConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        token: "tok".into(),
        node_id: "node_laptop".into(),
        agent_id: agent.map(str::to_string),
    };
    let link = NodeLink::new(&cfg);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let c = DaemonClient::new(cfg, link, ApprovalBridge::new(), stop_rx, Arc::new(AtomicBool::new(false)));
    (c, stop_tx)
}

/// 等到 run() 结束或超时，返回是否自行结束。
async fn finished_within(handle: tokio::task::JoinHandle<()>, dur: Duration) -> bool {
    tokio::time::timeout(dur, handle).await.is_ok()
}

#[tokio::test]
async fn 注册帧是新协议帧且不含绝对路径() {
    let fake = spawn_fake(Script::Accept).await;
    let (client, stop) = client_for(fake.port, Some("team--alice"));
    let h = tokio::spawn(client.run());
    tokio::time::sleep(Duration::from_millis(600)).await;
    let _ = stop.send(true);
    let _ = finished_within(h, Duration::from_secs(3)).await;

    let frames = fake.frames.lock().unwrap();
    assert_eq!(frames.len(), 1, "应恰好注册一次");
    let f = &frames[0];
    assert_eq!(f["type"], "register");
    assert!(f["protocolVersion"].as_u64().is_some(), "缺 protocolVersion = 服务端当旧帧，互顶失效");
    assert!(f["appVersion"].is_string());
    assert!(f["roots"].is_array());
    assert!(f["grants"].is_object());
    assert_eq!(f["link"]["serverNodeId"], "node_laptop");
    // roots 里任何字段都不该是路径
    let wire = f["roots"].to_string();
    assert!(!wire.contains('/') && !wire.contains('\\'), "roots 不得含路径: {wire}");
}

#[tokio::test]
async fn 收到被顶帧后不重连() {
    let fake = spawn_fake(Script::DisplaceWithFrame).await;
    let (client, _stop) = client_for(fake.port, None);
    let h = tokio::spawn(client.run());
    // 首次重连退避约 1.25s；等 2.5s 若仍在重连，连接数会 ≥2
    let ended = finished_within(h, Duration::from_millis(2500)).await;
    assert!(ended, "被顶后 run() 应自行结束");
    assert_eq!(fake.connections.load(Ordering::SeqCst), 1, "被顶后不得重连");
}

#[tokio::test]
async fn 只有被顶帧_关闭码丢失_也停止() {
    let fake = spawn_fake(Script::DisplaceFrameOnly).await;
    let (client, _stop) = client_for(fake.port, None);
    let h = tokio::spawn(client.run());
    let ended = finished_within(h, Duration::from_millis(2500)).await;
    assert!(ended, "仅收到 displaced 帧（连接仍开着）时 run() 也应自行结束");
    assert_eq!(fake.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn 只有关闭码4001_帧丢失_也不重连() {
    let fake = spawn_fake(Script::DisplaceCloseOnly).await;
    let (client, _stop) = client_for(fake.port, None);
    let h = tokio::spawn(client.run());
    let ended = finished_within(h, Duration::from_millis(2500)).await;
    assert!(ended, "仅关闭码 4001 时 run() 也应自行结束");
    assert_eq!(fake.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn 注册被拒后不重连() {
    let fake = spawn_fake(Script::RejectFrame).await;
    let (client, _stop) = client_for(fake.port, None);
    let h = tokio::spawn(client.run());
    let ended = finished_within(h, Duration::from_millis(2500)).await;
    assert!(ended, "register_failed 后 run() 应自行结束");
    assert_eq!(fake.connections.load(Ordering::SeqCst), 1);
}

/// 对照组：普通断线必须重连，否则上面三条「不重连」可能只是客户端根本没在重连。
#[tokio::test]
async fn 普通断线会重连_对照组() {
    let fake = spawn_fake(Script::PlainClose).await;
    let (client, stop) = client_for(fake.port, None);
    let h = tokio::spawn(client.run());
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let n = fake.connections.load(Ordering::SeqCst);
    let _ = stop.send(true);
    let _ = finished_within(h, Duration::from_secs(3)).await;
    assert!(n >= 2, "普通断线应触发重连，实际连接数 {n}");
}
