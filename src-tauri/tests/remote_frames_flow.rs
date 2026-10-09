//! 审核 C-F6 端到端：主循环真的处理 task_cancel / trust_revoke（此前两帧落到「收到:」日志分支被忽略）。
//!
//! 用假 WS 服务端派一个上传任务，本机上传弹窗挂起（presenter 返回 true 但永不回答）；
//! 服务端随即发 task_cancel → 期望本机立刻回 task_result ok=false + CANCELLED，且**不带 upload 字节**。
//! trust_revoke：policy 里该目录为 always，收到帧后应变回 ask（键被删）。
//! 共享 HOME / HANA_LOCAL_WORKSPACES 环境变量，用例串行。

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

static LOCK: Mutex<()> = Mutex::new(());
const AGENT: &str = "bi--zhangsan";

/// 假服务端：注册后依次下发 `frames`，把收到的 task_result 交给 `results`。
async fn fake(frames: Vec<String>) -> (u16, tokio::sync::mpsc::Receiver<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut out, mut inp) = ws.split();
        while let Some(Ok(msg)) = inp.next().await {
            let Message::Text(t) = msg else { continue };
            let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
            match v["type"].as_str() {
                Some("register") => {
                    out.send(Message::Text(r#"{"type":"registered","protocolVersion":1,"legacyFrame":false}"#.into())).await.unwrap();
                    for f in &frames {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        out.send(Message::Text(f.clone().into())).await.unwrap();
                    }
                }
                Some("task_result") => { let _ = tx.send(v).await; }
                _ => {}
            }
        }
    });
    (port, rx)
}

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    root: std::path::PathBuf,
    root_id: String,
    policy_path: std::path::PathBuf,
}

fn env(upload_always: bool) -> Env {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    let ws = tempfile::tempdir().unwrap();
    let root = ws.path().canonicalize().unwrap();
    std::fs::write(root.join("a.xlsx"), b"PK-FAKE").unwrap();
    std::env::set_var("HANA_LOCAL_WORKSPACES", root.to_str().unwrap());
    let root_id = hanako_tauri_lib::daemon::register::root_id_for(&root);
    let dir = home.path().join(".hanako-tauri");
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.json");
    // Windows 上 home_dir 走 KNOWNFOLDER 不读 HOME/USERPROFILE，策略/工作区/审计路径用显式覆盖隔离
    std::env::set_var("HANAKO_POLICY_PATH", &policy_path);
    std::env::set_var("HANAKO_WORKSPACES_PATH", dir.join("workspaces.json"));
    std::env::set_var("HANAKO_DATA_DIR", &dir);
    let upload = if upload_always { format!(r#","upload":{{"{root_id}":"always"}}"#) } else { String::new() };
    std::fs::write(&policy_path, format!(r#"{{"grants":{{"{AGENT}":["{root_id}"]}}{upload}}}"#)).unwrap();
    Env { _home: home, _ws: ws, root, root_id, policy_path }
}

fn client(port: u16) -> (DaemonClient, tokio::sync::watch::Sender<bool>, Arc<hanako_tauri_lib::daemon::upload_bridge::UploadBridge>) {
    let cfg = DaemonConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        token: "tok".into(),
        node_id: "node_laptop".into(),
        agent_id: Some(AGENT.into()),
    };
    let link = NodeLink::new(&cfg);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uploads = hanako_tauri_lib::daemon::upload_bridge::UploadBridge::new();
    // 弹窗「打开成功」但用户永远不回答 → 任务挂在等弹窗的 await 上
    uploads.set_presenter(Arc::new(|_| true));
    let c = DaemonClient::new(cfg, link, ApprovalBridge::new(), stop_rx, Arc::new(AtomicBool::new(false)))
        .with_uploads(uploads.clone());
    (c, stop_tx, uploads)
}

fn upload_task(task_id: &str) -> String {
    serde_json::json!({
        "type": "task", "taskId": task_id, "tool": "local_upload_to_workspace", "origin": "web",
        "params": { "path": "a.xlsx", "_agent_id": AGENT, "_session_id": "s1" },
        "lease": {
            "schemaVersion": 1, "leaseId": "l1", "targetServerNodeId": "node_laptop", "commandClass": "write_files",
            "backupPolicy": "snapshot_before_write", "expiresAt": "2099-01-01T00:00:00Z", "agentId": AGENT, "resourceIds": []
        }
    }).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn task_cancel_打断挂起的上传弹窗_不带字节() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _e = env(false);
    let frames = vec![upload_task("t-cancel"), r#"{"type":"task_cancel","taskId":"t-cancel"}"#.to_string()];
    let (port, mut results) = fake(frames).await;
    let (c, stop, uploads) = client(port);
    let h = tokio::spawn(c.run());
    let r = tokio::time::timeout(Duration::from_secs(10), results.recv()).await
        .expect("10s 内没收到 task_result——task_cancel 没生效（弹窗默认 60s 才超时）").unwrap();
    assert_eq!(r["taskId"], "t-cancel");
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().contains("LOCAL_TASK_CANCELLED"), "{r}");
    assert!(r.get("upload").is_none(), "取消的任务不得带字节: {r}");
    let _ = uploads;
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_revoke_把永久上传收回成每次问() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true);
    let frames = vec![format!(r#"{{"type":"trust_revoke","trustId":"{}"}}"#, e.root_id)];
    let (port, _results) = fake(frames).await;
    let (c, stop, _u) = client(port);
    let h = tokio::spawn(c.run());
    let mut ok = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s = std::fs::read_to_string(&e.policy_path).unwrap();
        if !s.contains("always") { ok = true; break; }
    }
    assert!(ok, "trust_revoke 后 policy 仍含 always: {}", std::fs::read_to_string(&e.policy_path).unwrap());
    assert!(e.root.exists());
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}
