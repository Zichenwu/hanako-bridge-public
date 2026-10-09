// tests/hub_contract.rs
//! 票 14 契约核对：hub 真实路由产出的响应（由 hub 侧测试落盘到 /tmp/t14-contract.json）
//! 喂给 Tauri 侧真实的解析函数。两边各自的单测都是自己写自己的假数据，字段名对不上
//! （camelCase vs snake_case、expiresIn vs expires_in）时双方都绿——只有这类交叉核对能抓到。
//!
//! 快照入库于 tests/fixtures/hub_node_login.json，CI 直接可跑；hub 响应字段变更时重新生成并更新快照。

use hanako_tauri_lib::daemon::device_auth::{parse_poll, parse_renew, PollOutcome, RenewOutcome, StartResponse};

fn load() -> Option<serde_json::Value> {
    // 入库的快照；设 HUB_CONTRACT=/path 可临时指向刚生成的新快照做漂移核对
    let path = std::env::var("HUB_CONTRACT").unwrap_or_else(|_| format!("{}/tests/fixtures/hub_node_login.json", env!("CARGO_MANIFEST_DIR")));
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    Some(v.get("responses").cloned().unwrap_or(v))
}
fn pick(d: &serde_json::Value, k: &str) -> (u16, String) {
    (d[k]["status"].as_u64().unwrap() as u16, d[k]["body"].as_str().unwrap().to_string())
}

#[test]
fn start_响应能被_start_response_解析() {
    let Some(d) = load() else { panic!("契约快照缺失或无法解析") };
    let (st, body) = pick(&d, "start");
    assert_eq!(st, 200);
    let r: StartResponse = serde_json::from_str(&body).expect("hub 的 start 响应与 StartResponse 字段不匹配");
    assert!(!r.device_code.is_empty() && !r.user_code.is_empty());
    assert!(r.verification_url.starts_with("https://"));
    assert!(r.expires_in > 0, "expiresIn 必须解析出正数，否则轮询预算为 0 立即放弃");
    assert!(r.interval > 0);
    assert!(!r.verification_url.contains(&r.device_code), "deviceCode 不得出现在浏览器 URL");
}

#[test]
fn poll_各状态与解析器一致() {
    let Some(d) = load() else { panic!("契约快照缺失或无法解析") };
    let (s, b) = pick(&d, "poll_pending");  assert_eq!(parse_poll(s, &b).unwrap(), PollOutcome::Pending);
    let (s, b) = pick(&d, "poll_slow");     assert_eq!(parse_poll(s, &b).unwrap(), PollOutcome::SlowDown);
    let (s, b) = pick(&d, "poll_expired");  assert_eq!(parse_poll(s, &b).unwrap(), PollOutcome::Expired);
    let (s, b) = pick(&d, "poll_denied");   assert_eq!(parse_poll(s, &b).unwrap(), PollOutcome::Denied);
}

#[test]
fn poll_approved_字段完整可用() {
    let Some(d) = load() else { panic!("契约快照缺失或无法解析") };
    let (s, b) = pick(&d, "poll_approved");
    match parse_poll(s, &b).expect("hub 的 approved 响应被解析器拒绝") {
        PollOutcome::Approved(g) => {
            assert_eq!(g.credential_secret, "hana_dev_NODE");
            assert_eq!(g.agent_id, "team--alice");
            assert_eq!(g.node_name.as_deref(), Some("laptop"));
            assert!(g.server_url.ends_with("/hanako"));
            assert!(chrono::DateTime::parse_from_rfc3339(&g.expires_at).is_ok(), "expiresAt 必须是 RFC3339，续期判断依赖它");
        }
        o => panic!("应为 Approved，实际 {o:?}"),
    }
}

#[test]
fn renew_成功与失效() {
    let Some(d) = load() else { panic!("契约快照缺失或无法解析") };
    let (s, b) = pick(&d, "renew_ok");
    match parse_renew(s, &b) {
        RenewOutcome::Renewed { expires_at, credential_id, .. } => {
            assert_eq!(credential_id.as_deref(), Some("cred_r"));
            assert!(chrono::DateTime::parse_from_rfc3339(&expires_at).is_ok());
        }
        o => panic!("应为 Renewed，实际 {o:?}"),
    }
    let (s, b) = pick(&d, "renew_401");
    assert_eq!(parse_renew(s, &b), RenewOutcome::NeedReauth, "hub 的 401 必须被识别为需重新授权");
}

/// 请求路径契约：Tauri 发出去的路径必须与 hub 实际挂载的路径一致。
/// 曾出现 Tauri 写 /api/hanako/node-login/*、hub 挂 /api/node-login/*，上线即全部 404，
/// 而两侧单测和响应体快照都查不出来——所以这里用真实的 UreqTransport 打一个记录路径的本地服务。
#[test]
fn 请求路径与_hub_挂载一致() {
    use hanako_tauri_lib::daemon::auth_flow::{maybe_renew, poll_until_done, start_login, LoginRequest, UreqTransport};
    use hanako_tauri_lib::daemon::credential_store::{CredentialStore, MemoryStore, StoredCredential};
    use hanako_tauri_lib::daemon::device_auth::StartResponse;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let paths = Arc::new(Mutex::new(Vec::<String>::new()));
    let p2 = paths.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = match stream { Ok(s) => s, Err(_) => return };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let line = head.lines().next().unwrap_or("").to_string(); // POST /path HTTP/1.1
            p2.lock().unwrap().push(line.split_whitespace().nth(1).unwrap_or("").to_string());
            let body = r#"{"status":"pending","deviceCode":"d","userCode":"U","verificationUrl":"https://x","expiresIn":600,"interval":5}"#;
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });

    let base = format!("http://127.0.0.1:{port}/hapi");
    let t = UreqTransport;
    let _ = start_login(&t, &LoginRequest { hub_url: base.clone(), machine_name: "m".into(), app_version: "v".into(), agent_id: None });
    let st = StartResponse { device_code: "D".repeat(20), user_code: "U".into(), verification_url: "https://x".into(), expires_in: 1, interval: 1 };
    let _ = poll_until_done(&t, &base, &st, &|_| {}, || {});
    let store = MemoryStore::new();
    store.save(&StoredCredential { server_url: "s".into(), agent_id: "a--b".into(), secret: "S".into(), credential_id: None, expires_at: "2020-01-01T00:00:00Z".into(), node_name: None }).unwrap();
    let _ = maybe_renew(&t, &store, &base, chrono::Utc::now());

    let got = paths.lock().unwrap().clone();
    // hub 侧 server.ts：公开组 app.route('/api', createNodeLoginPublicRoutes(...))，路由内 '/node-login/{start,poll,renew}'
    assert!(got.contains(&"/hapi/api/node-login/start".to_string()), "start 路径不对: {got:?}");
    assert!(got.contains(&"/hapi/api/node-login/poll".to_string()), "poll 路径不对: {got:?}");
    assert!(got.contains(&"/hapi/api/node-login/renew".to_string()), "renew 路径不对: {got:?}");
}
