// src-tauri/tests/preview_chunked_flow.rs
//! 本地文件预览 票 07 · 端到端：真 DaemonClient + 假 WS 服务端，走完整条拉取链。
//!
//! 这是 `client.rs` 里「内联接线」（pull 路由 / abort 注销 / 分片失败不重复发 abort）唯一能被测到的地方：
//! 单测只覆盖 `preview_stream` 模块自身，抓不到「模块齐、单测绿、生产没接上」——这是 10-08 连续
//! 三处缺陷（注册帧漏报 / 身份取错 / 弹窗桥没装）的同一个病根。
//!
//! 共享 HOME / 环境变量，用例串行。

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hanako_tauri_lib::daemon::preview_bridge::PreviewBridge;
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

static LOCK: Mutex<()> = Mutex::new(());
const AGENT: &str = "bi--zhangsan";
const MB: usize = 1024 * 1024;
const CHUNK: usize = 4 * MB;

/// 假服务端的行为：收到 Bridge 的每一帧都转交测试；`auto_pull` 决定它怎么「要下一片」。
#[derive(Clone, Copy, PartialEq)]
enum Pull {
    /// 像真服务端：meta 后批 3 片，每收一片再多批一片
    Window,
    /// 完全不发 pull（验证没批准就不发）
    Never,
}

struct Fake {
    port: u16,
    frames: mpsc::Receiver<serde_json::Value>,
    /// 测试向 Bridge 额外下发的帧
    inject: mpsc::Sender<String>,
}

async fn fake(request: String, pull: Pull) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel(512);
    let (inj_tx, mut inj_rx) = mpsc::channel::<String>(16);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut out, mut inp) = ws.split();
        let mut total_chunks: u64 = 0;
        let mut granted: u64 = 0;
        let mut received: u64 = 0;
        let mut pid = String::new();
        loop {
            tokio::select! {
                Some(extra) = inj_rx.recv() => { let _ = out.send(Message::Text(extra.into())).await; }
                msg = inp.next() => {
                    let Some(Ok(Message::Text(t))) = msg else { if msg.is_none() { break } else { continue } };
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
                    match v["type"].as_str() {
                        Some("register") => {
                            out.send(Message::Text(r#"{"type":"registered","protocolVersion":1,"legacyFrame":false}"#.into())).await.unwrap();
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            let rq: serde_json::Value = serde_json::from_str(&request).unwrap();
                            pid = rq["previewId"].as_str().unwrap().to_string();
                            out.send(Message::Text(request.clone().into())).await.unwrap();
                        }
                        Some("preview_meta") => {
                            let size = v["size"].as_u64().unwrap_or(0);
                            total_chunks = size.div_ceil(CHUNK as u64);
                            if pull == Pull::Window && total_chunks > 0 {
                                granted = total_chunks.min(3);
                                let f = serde_json::json!({"type":"preview_pull","previewId":pid,"upTo":granted});
                                out.send(Message::Text(f.to_string().into())).await.unwrap();
                            }
                        }
                        Some("preview_chunk") => {
                            received += 1;
                            if pull == Pull::Window {
                                let up = total_chunks.min(received + 3);
                                if up > granted {
                                    granted = up;
                                    let f = serde_json::json!({"type":"preview_pull","previewId":pid,"upTo":up});
                                    out.send(Message::Text(f.to_string().into())).await.unwrap();
                                }
                            }
                        }
                        _ => {}
                    }
                    let _ = tx.send(v).await;
                }
            }
        }
    });
    Fake { port, frames: rx, inject: inj_tx }
}

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    root: std::path::PathBuf,
    data_dir: std::path::PathBuf,
}

fn env() -> Env {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    let ws = tempfile::tempdir().unwrap();
    let root = ws.path().canonicalize().unwrap();
    std::env::set_var("HANA_LOCAL_WORKSPACES", root.to_str().unwrap());
    let root_id = hanako_tauri_lib::daemon::register::root_id_for(&root);
    let dir = home.path().join(".hanako-tauri");
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.json");
    std::env::set_var("HANAKO_POLICY_PATH", &policy_path);
    std::env::set_var("HANAKO_WORKSPACES_PATH", dir.join("workspaces.json"));
    std::env::set_var("HANAKO_DATA_DIR", &dir);
    // 预览永久允许（不弹窗）：本测试关心的是传输，不是确认闸
    std::fs::write(&policy_path, format!(r#"{{"grants":{{"{AGENT}":["{root_id}"]}},"preview":{{"{root_id}":"always"}}}}"#)).unwrap();
    Env { _home: home, _ws: ws, root, data_dir: dir }
}

fn client(port: u16) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    let cfg = DaemonConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        token: "tok".into(),
        node_id: "node_laptop".into(),
        agent_id: Some(AGENT.into()),
    };
    let link = NodeLink::new(&cfg);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let previews = PreviewBridge::new();
    previews.set_presenter(Arc::new(|_| true));
    let c = DaemonClient::new(cfg, link, ApprovalBridge::new(), stop_rx, Arc::new(AtomicBool::new(false)))
        .with_previews(previews);
    (c, stop_tx)
}

fn request(path: &str, chunked: bool) -> String {
    let mut v = serde_json::json!({
        "type": "preview_request", "previewId": "pv_e2e", "path": path,
        "agentId": AGENT, "origin": "local_web", "sessionId": "s1",
    });
    if chunked {
        v["transfer"] = "chunked".into();
    }
    v.to_string()
}

/// 收集到 `stop_at` 类型的帧（含）为止；超时 panic。
async fn collect_until(f: &mut Fake, stop_at: &[&str], secs: u64) -> Vec<serde_json::Value> {
    let mut got = vec![];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Some(v)) = tokio::time::timeout(left, f.frames.recv()).await else {
            let seen: Vec<serde_json::Value> = got.iter().map(|x: &serde_json::Value| x["type"].clone()).collect();
            panic!("超时，已收: {seen:?}")
        };
        let ty = v["type"].as_str().unwrap_or("").to_string();
        if ty == "preview_meta" || ty == "preview_chunk" || ty == "preview_end" || ty == "preview_abort" {
            got.push(v);
            if stop_at.contains(&ty.as_str()) {
                return got;
            }
        }
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// 变异：client.rs 的 `preview_streams.on_pull(..)` 不路由 → 本用例卡在等 pull，超时红。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_分片请求_按服务端pull逐片发送_拼回逐字节一致() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    // 9MB + 123 字节 = 3 片（4MB, 4MB, 1MB+123），pdf
    let body = pattern(CHUNK * 2 + MB + 123);
    std::fs::write(e.root.join("big.pdf"), &body).unwrap();
    let mut f = fake(request("big.pdf", true), Pull::Window).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());

    let got = collect_until(&mut f, &["preview_end", "preview_abort"], 20).await;
    assert_eq!(got.first().unwrap()["type"], "preview_meta");
    assert_eq!(got.first().unwrap()["size"], body.len());
    assert_eq!(got.last().unwrap()["type"], "preview_end", "必须以 end 收尾: {:?}", got.last());

    use base64::Engine as _;
    let mut joined = vec![];
    let chunks: Vec<_> = got.iter().filter(|x| x["type"] == "preview_chunk").collect();
    assert_eq!(chunks.len(), 3);
    for (i, c) in chunks.iter().enumerate() {
        assert_eq!(c["seq"], i as u64, "序号必须从 0 严格递增");
        joined.extend(base64::engine::general_purpose::STANDARD.decode(c["data"].as_str().unwrap()).unwrap());
    }
    assert_eq!(joined, body, "拼回来必须与磁盘逐字节一致");

    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// 变异：去掉 client.rs 里的「等批准」→ 本用例红（没有 pull 也会发出分片）。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_服务端不发pull_Bridge只发meta_不发任何分片() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    std::fs::write(e.root.join("a.pdf"), pattern(CHUNK * 2)).unwrap();
    let mut f = fake(request("a.pdf", true), Pull::Never).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());

    let got = collect_until(&mut f, &["preview_meta"], 10).await;
    assert_eq!(got[0]["type"], "preview_meta");
    // 再等一会儿：没有 pull，不得出现任何 chunk / end
    let more = tokio::time::timeout(Duration::from_millis(800), f.frames.recv()).await;
    if let Ok(Some(v)) = more {
        assert!(
            v["type"] != "preview_chunk" && v["type"] != "preview_end",
            "没收到 pull 就发了 {}: 拉取式背压失效",
            v["type"]
        );
    }
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// 变异：client.rs 收到服务端 preview_abort 不注销登记项 → 本用例红（Bridge 继续发或久久不停）。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_服务端中途preview_abort_Bridge立即停手_不再发分片() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    std::fs::write(e.root.join("a.pdf"), pattern(CHUNK * 8)).unwrap();
    // Never：只发 meta，Bridge 卡在等第 1 片的批准
    let mut f = fake(request("a.pdf", true), Pull::Never).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());
    let _ = collect_until(&mut f, &["preview_meta"], 10).await;

    // 服务端叫停，然后补发一个 pull——已被叫停的预览不得再因这个 pull 发出分片
    f.inject.send(serde_json::json!({"type":"preview_abort","previewId":"pv_e2e","code":"LOCAL_PREVIEW_STALLED"}).to_string()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    f.inject.send(serde_json::json!({"type":"preview_pull","previewId":"pv_e2e","upTo":8}).to_string()).await.unwrap();
    let more = tokio::time::timeout(Duration::from_millis(800), f.frames.recv()).await;
    if let Ok(Some(v)) = more {
        assert!(v["type"] != "preview_chunk", "被叫停后收到迟到的 pull 仍发了分片");
    }
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// 变异：client.rs 分片失败后仍重复发 abort（去掉 `if !streamed`）→ 本用例红。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_传输中文件被改_恰好一个abort_不以end收尾() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    let p = e.root.join("a.pdf");
    std::fs::write(&p, pattern(CHUNK * 3)).unwrap();
    // 服务端先收到 meta 才发 pull；这里在 meta 到达后、第一次 pull 前改文件
    let mut f = fake(request("a.pdf", true), Pull::Never).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());
    let _ = collect_until(&mut f, &["preview_meta"], 10).await;
    std::fs::write(&p, pattern(CHUNK * 3 + 17)).unwrap(); // 改大
    f.inject.send(serde_json::json!({"type":"preview_pull","previewId":"pv_e2e","upTo":3}).to_string()).await.unwrap();

    let got = collect_until(&mut f, &["preview_abort", "preview_end"], 15).await;
    assert_eq!(got.last().unwrap()["type"], "preview_abort", "被改的传输必须以 abort 收尾: {:?}", got.last());
    assert_eq!(got.last().unwrap()["code"], "LOCAL_PREVIEW_RETRY");
    // 之后不得再有第二个 abort（stream_file 已发过一次）
    let mut extra = 0;
    while let Ok(Some(v)) = tokio::time::timeout(Duration::from_millis(600), f.frames.recv()).await {
        if v["type"] == "preview_abort" {
            extra += 1;
        }
    }
    assert_eq!(extra, 0, "同一预览不得发两个 abort");
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// 变异：把 `transfer` 无条件当 chunked（或不读它）→ 本用例红。步一的行为必须逐字节不变。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_不带transfer的请求_仍走步一单帧_不依赖pull() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    std::fs::write(e.root.join("a.txt"), "hello world").unwrap();
    let mut f = fake(request("a.txt", false), Pull::Never).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());
    let got = collect_until(&mut f, &["preview_end", "preview_abort"], 10).await;
    let types: Vec<_> = got.iter().map(|x| x["type"].as_str().unwrap().to_string()).collect();
    assert_eq!(types, ["preview_meta", "preview_chunk", "preview_end"], "步一帧序: meta → chunk → end（没有 pull 也能完成）");
    assert!(got[1].get("seq").is_none(), "步一的 chunk 不带 seq（旧服务端不认）");
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// 读本机审计里 local_preview_file 条目的 decision。
fn preview_decisions(data_dir: &std::path::Path) -> Vec<String> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(data_dir.join("audit")) else { return out };
    for e in rd.flatten() {
        let Ok(t) = std::fs::read_to_string(e.path()) else { continue };
        for line in t.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if v["tool"] == "local_preview_file" {
                out.push(v["decision"].as_str().unwrap_or("").to_string());
            }
        }
    }
    out
}

/// 审核 F5 变异：client.rs 收到 Stopped 不改写结论 → 本用例红（服务端叫停的预览被记成 approved）。
#[tokio::test(flavor = "multi_thread")]
async fn 端到端_服务端叫停的预览_本机审计不记成已允许() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    std::fs::write(e.root.join("a.pdf"), pattern(CHUNK * 4)).unwrap();
    let mut f = fake(request("a.pdf", true), Pull::Never).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());
    let _ = collect_until(&mut f, &["preview_meta"], 10).await;
    f.inject.send(serde_json::json!({"type":"preview_abort","previewId":"pv_e2e","code":"LOCAL_PREVIEW_STALLED"}).to_string()).await.unwrap();
    let mut decisions = vec![];
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        decisions = preview_decisions(&e.data_dir);
        if !decisions.is_empty() { break; }
    }
    assert_eq!(decisions.len(), 1, "应恰好一条预览审计: {decisions:?}");
    assert_ne!(decisions[0], "approved", "没传完的预览不得记成已允许");
    assert!(decisions[0].starts_with("rejected:"), "{decisions:?}");
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn 端到端_传完的预览_本机审计记已允许_对照组() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env();
    std::fs::write(e.root.join("ok.pdf"), pattern(CHUNK + 5)).unwrap();
    let mut f = fake(request("ok.pdf", true), Pull::Window).await;
    let (c, stop) = client(f.port);
    let h = tokio::spawn(c.run());
    let _ = collect_until(&mut f, &["preview_end", "preview_abort"], 15).await;
    let mut decisions = vec![];
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        decisions = preview_decisions(&e.data_dir);
        if !decisions.is_empty() { break; }
    }
    assert_eq!(decisions, vec!["approved".to_string()]);
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

