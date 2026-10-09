// tests/policy_push.rs
//! 票 15 集成测试：真 DaemonClient + 假 WS 服务端，验证
//! 「运行中授权目录 / 读写 / 执行体授权变化 → 本机推送 roots_changed / grants_changed」
//! 以及「任务帧按本机当下策略复核（不信任注册时的快照）」。
//!
//! 单测只能证明比对函数对；证明不了主循环里真的会发帧，也证明不了 task 分支真的读了最新策略。
//! 本文件是独立 test binary，用自己的 HOME（不碰真实 ~/.hanako-tauri）。

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hanako_tauri_lib::daemon::auth_request::{AuthDecision, AuthRequestBridge};
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const AGENT: &str = "bi--zhangsan";

/// HOME 是进程级全局，两个测试都改它，必须串行。
static HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 假服务端：回 registered；记录收到的所有帧；收到 `send_task` 通道里的任务就下发并等结果。
struct Fake {
    port: u16,
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
    task_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
}

async fn spawn_fake() -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let f2 = frames.clone();
    let (task_tx, task_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let task_rx = Arc::new(tokio::sync::Mutex::new(task_rx));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let f3 = f2.clone();
            let task_rx = task_rx.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
                let (mut tx, mut rx) = ws.split();
                loop {
                    tokio::select! {
                        Some(task) = async { task_rx.lock().await.recv().await } => {
                            let _ = tx.send(Message::Text(task.to_string())).await;
                        }
                        msg = rx.next() => {
                            let Some(Ok(Message::Text(t))) = msg else { if msg.is_none() { return } else { continue } };
                            let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else { continue };
                            let is_register = v["type"] == "register";
                            f3.lock().unwrap().push(v);
                            if is_register {
                                let _ = tx.send(Message::Text(r#"{"type":"registered","protocolVersion":1,"legacyFrame":false}"#.into())).await;
                            }
                        }
                    }
                }
            });
        }
    });
    Fake { port, frames, task_tx }
}

fn client_for(port: u16) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    let cfg = DaemonConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        token: "tok".into(),
        node_id: "node_laptop".into(),
        agent_id: Some(AGENT.into()),
    };
    let link = NodeLink::new(&cfg);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let c = DaemonClient::new(cfg, link, ApprovalBridge::new(), stop_rx, Arc::new(AtomicBool::new(false)));
    (c, stop_tx)
}

fn client_with_bridge(port: u16, bridge: Arc<AuthRequestBridge>) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    let (c, stop) = client_for(port);
    (c.with_auth_requests(bridge), stop)
}

fn kinds(fake: &Fake) -> Vec<String> {
    fake.frames.lock().unwrap().iter().map(|f| f["type"].as_str().unwrap_or("").to_string()).collect()
}

fn find(fake: &Fake, kind: &str) -> Vec<serde_json::Value> {
    fake.frames.lock().unwrap().iter().filter(|f| f["type"] == kind).cloned().collect()
}

async fn wait_for(fake: &Fake, kind: &str, n: usize, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if find(fake, kind).len() >= n {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn rid(p: &std::path::Path) -> String {
    hanako_tauri_lib::daemon::register::root_id_for(p)
}

/// 单个 #[tokio::test] 串行完成全部场景：HOME 是进程级全局，拆成多个并行测试会互相覆盖。
#[tokio::test]
async fn 运行中策略变化_推送并按最新策略复核任务() {
    let _g = HOME_LOCK.lock().await;
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    std::env::remove_var("HANA_LOCAL_WORKSPACES");
    let cfg_dir = home.path().join(".hanako-tauri");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    // Windows 上 home_dir 走 KNOWNFOLDER 不读 HOME，策略/工作区/审计路径用显式覆盖隔离
    std::env::set_var("HANAKO_POLICY_PATH", cfg_dir.join("policy.json"));
    std::env::set_var("HANAKO_WORKSPACES_PATH", cfg_dir.join("workspaces.json"));
    std::env::set_var("HANAKO_DATA_DIR", &cfg_dir);

    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let r1 = d1.path().canonicalize().unwrap();
    let r2 = d2.path().canonicalize().unwrap();
    std::fs::write(r1.join("hello.txt"), "HELLO-FROM-R1").unwrap();
    let write_ws = |paths: &[&std::path::Path]| {
        let v: Vec<String> = paths.iter().map(|p| p.to_string_lossy().to_string()).collect();
        std::fs::write(cfg_dir.join("workspaces.json"), serde_json::to_string(&v).unwrap()).unwrap();
    };
    write_ws(&[&r1]);

    let fake = spawn_fake().await;
    let (client, stop) = client_for(fake.port);
    let h = tokio::spawn(client.run());

    // ① 注册帧：只有 r1，grants 为凭据执行体独占
    assert!(wait_for(&fake, "register", 1, 5).await, "应收到注册帧");
    let reg = find(&fake, "register").remove(0);
    assert_eq!(reg["roots"].as_array().unwrap().len(), 1);
    assert_eq!(reg["grants"][AGENT][0], rid(&r1));
    assert!(find(&fake, "roots_changed").is_empty(), "策略没变不应推送");

    // ② 新增目录 r2 → roots_changed + grants_changed（无需重连）
    write_ws(&[&r1, &r2]);
    assert!(wait_for(&fake, "roots_changed", 1, 6).await, "新增目录后应推 roots_changed，实际帧: {:?}", kinds(&fake));
    assert!(wait_for(&fake, "grants_changed", 1, 6).await);
    let rc = &find(&fake, "roots_changed")[0];
    assert_eq!(rc["roots"].as_array().unwrap().len(), 2);
    assert!(!rc.to_string().contains(r1.to_str().unwrap()), "推送帧不得含绝对路径");
    assert_eq!(find(&fake, "register").len(), 1, "推送不应触发重连/重新注册");

    // ③ 设置 r1 只读 → roots_changed 带 mode=ro
    let policy_json = serde_json::json!({ "modes": { rid(&r1): "ro" } });
    std::fs::write(cfg_dir.join("policy.json"), policy_json.to_string()).unwrap();
    assert!(wait_for(&fake, "roots_changed", 2, 6).await, "改只读应推 roots_changed");
    let latest = find(&fake, "roots_changed").pop().unwrap();
    let r1_view = latest["roots"].as_array().unwrap().iter().find(|r| r["rootId"] == rid(&r1)).unwrap().clone();
    assert_eq!(r1_view["mode"], "ro");

    // ④ 任务帧按本机当下策略复核：读 r1 的文件（只读根可读）成功
    fake.task_tx.send(serde_json::json!({
        "type": "task", "taskId": "t1", "tool": "local_read_file",
        "params": { "path": "hello.txt", "_agent_id": AGENT, "_root_id": rid(&r1) }
    })).unwrap();
    assert!(wait_for(&fake, "task_result", 1, 5).await);
    let t1 = find(&fake, "task_result").remove(0);
    assert_eq!(t1["ok"], true, "{t1}");
    assert!(t1["result"].as_str().unwrap().contains("HELLO-FROM-R1"));

    // ⑤ 撤销：把 r1 从目录列表移除。云端快照此刻可能还没更新，但本机复核必须立刻生效。
    write_ws(&[&r2]);
    fake.task_tx.send(serde_json::json!({
        "type": "task", "taskId": "t2", "tool": "local_read_file",
        "params": { "path": "hello.txt", "_agent_id": AGENT, "_root_id": rid(&r1) }
    })).unwrap();
    assert!(wait_for(&fake, "task_result", 2, 5).await);
    let t2 = find(&fake, "task_result").remove(1);
    assert_eq!(t2["ok"], false);
    assert!(t2["error"].as_str().unwrap().starts_with("LOCAL_ROOT_REVOKED"), "{t2}");

    // ⑥ 撤销后 grants_changed 里不再含 r1
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut gone = false;
    while tokio::time::Instant::now() < deadline {
        if let Some(g) = find(&fake, "grants_changed").last() {
            let ids = g["grants"][AGENT].as_array().cloned().unwrap_or_default();
            if ids.len() == 1 && ids[0] == rid(&r2) {
                gone = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "撤销 r1 后 grants_changed 应只剩 r2");

    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
}


/// 网页「请求使用这台电脑」端到端：服务端下发 auth_request → 本机弹窗（假 presenter 代替真窗口）
/// → 用户勾选并允许 → policy.json 落盘 → 2s 内 grants_changed 推回云端。
/// 另一助手（wallet--zhangsan）此前不在 grants 里，这是它进入授权的唯一路径。
#[tokio::test]
async fn 授权请求_允许后写盘并推送_拒绝和畸形帧无副作用() {
    let _g = HOME_LOCK.lock().await;
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    std::env::remove_var("HANA_LOCAL_WORKSPACES");
    let cfg_dir = home.path().join(".hanako-tauri");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    // Windows 上 home_dir 走 KNOWNFOLDER 不读 HOME，策略/工作区/审计路径用显式覆盖隔离
    std::env::set_var("HANAKO_POLICY_PATH", cfg_dir.join("policy.json"));
    std::env::set_var("HANAKO_WORKSPACES_PATH", cfg_dir.join("workspaces.json"));
    std::env::set_var("HANAKO_DATA_DIR", &cfg_dir);
    let d1 = tempfile::tempdir().unwrap();
    let r1 = d1.path().canonicalize().unwrap();
    std::fs::write(cfg_dir.join("workspaces.json"), serde_json::to_string(&vec![r1.to_string_lossy()]).unwrap()).unwrap();

    // 假弹窗：收到请求就按脚本自动响应
    let bridge = AuthRequestBridge::new();
    let script: Arc<Mutex<Vec<AuthDecision>>> = Arc::new(Mutex::new(vec![
        AuthDecision::Reject,
        AuthDecision::Allow(vec![rid(&r1)]),
    ]));
    let shown = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let (b2, script, shown) = (bridge.clone(), script.clone(), shown.clone());
        bridge.set_presenter(Arc::new(move |req| {
            shown.lock().unwrap().push(req.agent_id.clone());
            let d = script.lock().unwrap().remove(0);
            let (b3, id) = (b2.clone(), req.request_id.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(80)).await;
                let _ = b3.respond(&id, d);
            });
            true
        }));
    }

    let fake = spawn_fake().await;
    let (client, stop) = client_with_bridge(fake.port, bridge);
    let h = tokio::spawn(client.run());
    assert!(wait_for(&fake, "register", 1, 5).await);

    let other = "wallet--zhangsan";
    let send_req = |id: &str, agent: serde_json::Value| {
        fake.task_tx.send(serde_json::json!({"type":"auth_request","requestId":id,"agentId":agent,"origin":"web"})).unwrap();
    };

    // ① 畸形帧（agentId 缺失）→ 不弹窗、不写盘
    send_req("bad", serde_json::Value::Null);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(shown.lock().unwrap().is_empty(), "畸形帧不得弹窗");
    assert!(!cfg_dir.join("policy.json").exists());

    // ② 用户拒绝 → 不写盘，也不推 grants_changed
    send_req("req1", serde_json::json!(other));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(shown.lock().unwrap().len(), 1);
    assert!(!cfg_dir.join("policy.json").exists(), "拒绝后不得落盘");
    assert!(find(&fake, "grants_changed").is_empty());

    // ③ 用户允许 → policy.json 含 wallet 授权，grants_changed 推回云端
    send_req("req2", serde_json::json!(other));
    assert!(wait_for(&fake, "grants_changed", 1, 8).await, "允许后应推 grants_changed，实际: {:?}", kinds(&fake));
    let g = find(&fake, "grants_changed").pop().unwrap();
    assert_eq!(g["grants"][other][0], rid(&r1));
    assert_eq!(g["grants"][AGENT][0], rid(&r1), "原有助手 A 不受影响");
    let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(cfg_dir.join("policy.json")).unwrap()).unwrap();
    assert!(saved["agents"].as_array().unwrap().iter().any(|a| a == other), "进入候选助手集合");

    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
}
