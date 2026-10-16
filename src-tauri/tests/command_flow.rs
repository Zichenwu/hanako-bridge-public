//! 本机命令（ADR 0013）端到端：假 WS 服务端 + 真 daemon 主循环 + 替身确认器 + 真子进程。
//! 共享 HOME / HANA_LOCAL_WORKSPACES 等环境变量，用例串行。

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hanako_tauri_lib::daemon::command_approval::{CommandApprover, CommandDecision, FixedCommandApprover};
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

static LOCK: Mutex<()> = Mutex::new(());
const AGENT: &str = "merchant--zhangsan";
const DENIED: &str = "LOCAL_COMMAND_NOT_APPROVED: 用户未批准这条命令";

/// 假服务端：注册后依次下发 `frames`；收到的 register 帧与 task_result 都交出去。
async fn fake(frames: Vec<String>) -> (u16, tokio::sync::mpsc::Receiver<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut out, mut inp) = ws.split();
        while let Some(Ok(msg)) = inp.next().await {
            let Message::Text(t) = msg else { continue };
            let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
            match v["type"].as_str() {
                Some("register") => {
                    let _ = tx.send(v.clone()).await;
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
    data_dir: std::path::PathBuf,
}

/// `allow` = 本机总开关；`read_only` = 授权目录只读
fn env(allow: bool, read_only: bool) -> Env {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    let ws = tempfile::tempdir().unwrap();
    let root = ws.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::env::set_var("HANA_LOCAL_WORKSPACES", root.to_str().unwrap());
    let root_id = hanako_tauri_lib::daemon::register::root_id_for(&root);
    let dir = home.path().join(".hanako-tauri");
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.json");
    std::env::set_var("HANAKO_POLICY_PATH", &policy_path);
    std::env::set_var("HANAKO_WORKSPACES_PATH", dir.join("workspaces.json"));
    std::env::set_var("HANAKO_DATA_DIR", &dir);
    let modes = if read_only { format!(r#","modes":{{"{root_id}":"ro"}}"#) } else { String::new() };
    std::fs::write(
        &policy_path,
        format!(r#"{{"grants":{{"{AGENT}":["{root_id}"]}},"allowCommands":{allow}{modes}}}"#),
    )
    .unwrap();
    Env { _home: home, _ws: ws, root, root_id, data_dir: dir }
}

fn client(port: u16, approver: Arc<dyn CommandApprover>) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    client_with(port, approver, hanako_tauri_lib::daemon::command_approval::SessionPasses::new())
}

fn client_with(
    port: u16,
    approver: Arc<dyn CommandApprover>,
    passes: Arc<hanako_tauri_lib::daemon::command_approval::SessionPasses>,
) -> (DaemonClient, tokio::sync::watch::Sender<bool>) {
    let cfg = DaemonConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        token: "tok".into(),
        node_id: "node_laptop".into(),
        agent_id: Some(AGENT.into()),
    };
    let link = NodeLink::new(&cfg);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let c = DaemonClient::new(cfg, link, ApprovalBridge::new(), stop_rx, Arc::new(AtomicBool::new(false)))
        .with_command_approver(approver)
        .with_command_passes(passes);
    (c, stop_tx)
}

fn lease(class: &str, root_id: &str) -> serde_json::Value {
    // backupPolicy 用服务端真实签发值（write_files 必须带备份，否则 write_files 用例会被备份规则而非类别规则拦下）
    serde_json::json!({
        "schemaVersion": 1, "leaseId": format!("l-{}", rand_id()), "targetServerNodeId": "node_laptop", "commandClass": class,
        "backupPolicy": "snapshot_before_write", "expiresAt": "2099-01-01T00:00:00Z", "agentId": AGENT, "resourceIds": [root_id]
    })
}

fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn task(id: &str, e: &Env, command: &str, cwd: &str, lease: Option<serde_json::Value>) -> String {
    task_in("/s/a.jsonl", id, e, command, cwd, lease)
}

fn task_in(session: &str, id: &str, e: &Env, command: &str, cwd: &str, lease: Option<serde_json::Value>) -> String {
    let mut v = serde_json::json!({
        "type": "task", "taskId": id, "tool": "local_run_command", "origin": "web",
        "params": { "command": command, "cwd": cwd, "_agent_id": AGENT, "_session_id": session, "_root_id": e.root_id },
    });
    if let Some(l) = lease { v["lease"] = l; }
    v.to_string()
}

/// 跑一组帧，收齐 n 个 task_result（附带 register 帧）。
async fn drive(frames: Vec<String>, n: usize, approver: Arc<dyn CommandApprover>) -> (serde_json::Value, Vec<serde_json::Value>) {
    drive_with(frames, n, approver, hanako_tauri_lib::daemon::command_approval::SessionPasses::new()).await
}

async fn drive_with(
    frames: Vec<String>,
    n: usize,
    approver: Arc<dyn CommandApprover>,
    passes: Arc<hanako_tauri_lib::daemon::command_approval::SessionPasses>,
) -> (serde_json::Value, Vec<serde_json::Value>) {
    let (port, mut rx) = fake(frames).await;
    let (c, stop) = client_with(port, approver, passes);
    let h = tokio::spawn(c.run());
    let register = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("没收到注册帧").unwrap();
    let mut results = Vec::new();
    while results.len() < n {
        let r = tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("等 task_result 超时").unwrap();
        results.push(r);
    }
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    (register, results)
}

fn audit_lines(e: &Env) -> Vec<serde_json::Value> {
    let dir = e.data_dir.join("audit");
    let mut out = Vec::new();
    for f in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        for l in std::fs::read_to_string(f.path()).unwrap_or_default().lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
                if v["tool"] == "local_run_command" { out.push(v); }
            }
        }
    }
    out
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 确认后执行_回退出码与输出_审计不记输出() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let t = task("t1", &e, "echo SECRET_OUTPUT_xyz; pwd; exit 2", "sub", Some(lease("run_script", &e.root_id)));
    let (reg, r) = drive(vec![t], 1, a.clone()).await;
    assert_eq!(reg["shellCapability"]["enabled"], true, "{reg}");
    assert_eq!(r[0]["ok"], true, "{}", r[0]);
    let text = r[0]["result"].as_str().unwrap();
    assert!(text.starts_with("exit_code: 2\n"), "{text}");
    assert!(text.contains("SECRET_OUTPUT_xyz"));
    assert!(text.contains("/sub"), "cwd 应为授权目录下的 sub: {text}");
    // 确认窗看到的是规范化后的绝对 cwd、非只读
    let seen = a.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].cwd, e.root.join("sub").to_string_lossy());
    assert!(!seen[0].read_only_root);
    // 审计：归命令、记决定与命令，不记输出
    let au = audit_lines(&e);
    assert_eq!(au.len(), 1, "{au:?}");
    assert_eq!(au[0]["decision"], "once");
    assert!(au[0]["path"].as_str().unwrap().contains("echo SECRET_OUTPUT_xyz"));
    assert!(!au[0].to_string().contains("SECRET_OUTPUT_xyz\\n") && !au[0]["error"].to_string().contains("SECRET_OUTPUT"), "审计不得记输出: {}", au[0]);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 所有拒绝分支对外逐字相同_且命令未执行() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // 每个分支：(总开关, 确认答案, cwd, lease 类别 / None)
    let cases: Vec<(&str, bool, Option<CommandDecision>, &str, Option<&str>)> = vec![
        ("总开关关", false, Some(CommandDecision::Once), ".", Some("run_script")),
        ("用户拒绝", true, Some(CommandDecision::Rejected), ".", Some("run_script")),
        ("缺 lease", true, Some(CommandDecision::Once), ".", None),
        ("lease 类别不对", true, Some(CommandDecision::Once), ".", Some("write_files")),
        ("cwd 越界", true, Some(CommandDecision::Once), "../..", Some("run_script")),
        ("cwd 不存在", true, Some(CommandDecision::Once), "nope", Some("run_script")),
    ];
    for (name, allow, ans, cwd, class) in cases {
        let e = env(allow, false);
        let marker = e.root.join("ran");
        let cmd = format!("touch {}", marker.display());
        let a = FixedCommandApprover::new(ans);
        let t = task("t", &e, &cmd, cwd, class.map(|c| lease(c, &e.root_id)));
        let (_reg, r) = drive(vec![t], 1, a).await;
        assert_eq!(r[0]["ok"], false, "{name}: {}", r[0]);
        assert_eq!(r[0]["error"], DENIED, "{name}: 对外文案必须逐字相同");
        assert!(!marker.exists(), "{name}: 命令不应执行");
        let au = audit_lines(&e);
        assert_eq!(au.len(), 1, "{name}: 每个拒绝都要审计 {au:?}");
        assert_eq!(au[0]["ok"], false);
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 总开关关时注册帧报_enabled_false() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _e = env(false, false);
    let (port, mut rx) = fake(vec![]).await;
    let (c, stop) = client(port, FixedCommandApprover::new(Some(CommandDecision::Once)));
    let h = tokio::spawn(c.run());
    let reg = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
    assert_eq!(reg["shellCapability"]["enabled"], false);
    assert_eq!(reg["shellCapability"]["version"], 1);
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 只读授权目录也可执行_确认请求带只读标记() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, true);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let t = task("t", &e, "echo ok", ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a.clone()).await;
    assert_eq!(r[0]["ok"], true, "{}", r[0]);
    assert!(a.seen()[0].read_only_root);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 无人确认时_task_cancel_回统一文案() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = FixedCommandApprover::new(None); // 永不回答
    let frames = vec![
        task("t-c", &e, "echo hi", ".", Some(lease("run_script", &e.root_id))),
        r#"{"type":"task_cancel","taskId":"t-c"}"#.to_string(),
    ];
    let (_reg, r) = drive(frames, 1, a).await;
    assert_eq!(r[0]["taskId"], "t-c");
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 执行中_task_cancel_杀掉整棵进程树() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let pidfile = e.root.join("pid");
    let cmd = format!("sh -c 'sleep 60 & echo $! > {}; wait'", pidfile.display());
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    // 1.5s 后再发 cancel（fake 每帧间隔 150ms，这里多塞几个无关帧拉开时间）
    let mut frames = vec![task("t-k", &e, &cmd, ".", Some(lease("run_script", &e.root_id)))];
    for _ in 0..8 { frames.push(r#"{"type":"noop"}"#.to_string()); }
    frames.push(r#"{"type":"task_cancel","taskId":"t-k"}"#.to_string());
    let (_reg, r) = drive(frames, 1, a).await;
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
    let pid: i32 = std::fs::read_to_string(&pidfile).expect("命令应已启动").trim().parse().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // SAFETY: 只探测进程是否存在（信号 0）
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "取消后孙进程 {pid} 仍存活");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 网页确认开且空闲_命令仍走本机确认器() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    // 打开「不在电脑前时网页确认」
    let p = std::env::var("HANAKO_POLICY_PATH").unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    v["webConfirm"] = serde_json::json!(true);
    std::fs::write(&p, v.to_string()).unwrap();
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let t = task("t", &e, "echo ok", ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a.clone()).await;
    assert_eq!(r[0]["ok"], true, "{}", r[0]);
    assert_eq!(a.seen().len(), 1, "命令确认必须落到本机确认器，不经网页确认装饰器");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 确认超时按拒绝_命令不执行() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    std::env::set_var("HANAKO_COMMAND_CONFIRM_TIMEOUT_MS", "300");
    let marker = e.root.join("ran");
    let a = FixedCommandApprover::new(None); // 人不在电脑前
    let t = task("t", &e, &format!("touch {}", marker.display()), ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a).await;
    std::env::remove_var("HANAKO_COMMAND_CONFIRM_TIMEOUT_MS");
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
    assert!(!marker.exists());
    assert_eq!(audit_lines(&e)[0]["decision"], "timeout");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 拒绝名单命中_不弹确认_对外同一句_审计记类别() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let frames = vec![
        task("t1", &e, "sudo id", ".", Some(lease("run_script", &e.root_id))),
        task("t2", &e, "cat ~/.ssh/id_rsa", ".", Some(lease("run_script", &e.root_id))),
    ];
    let (_reg, r) = drive(frames, 2, a.clone()).await;
    for x in &r {
        assert_eq!(x["error"], DENIED, "{x}");
    }
    assert!(a.seen().is_empty(), "命中拒绝名单不应弹确认");
    let au = audit_lines(&e);
    assert_eq!(au.len(), 2);
    assert!(au.iter().all(|x| x["decision"] == "denylist"));
    assert!(au.iter().any(|x| x["error"] == "denylist:privilege"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 输出与审计与确认窗里的密钥都已打码() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    // 假密钥运行时拼出（源码里不出现完整形态，过公开镜像扫描闸）
    let secret = format!("{}{}", "ghp_", "1234567890abcdefghijklmnopqrstuvwxyzAB");
    let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let cmd = format!("echo token={secret}; echo {aws} >&2; GH={secret} true");
    let t = task("t", &e, &cmd, ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a.clone()).await;
    let text = r[0]["result"].as_str().unwrap();
    assert!(!text.contains(&secret) && !text.contains(&aws), "{text}");
    assert!(text.contains("redacted: true"), "{text}");
    assert!(!a.seen()[0].command.contains(&secret), "确认窗显示的命令应脱敏");
    let au = audit_lines(&e);
    assert!(!au[0].to_string().contains(&secret), "审计里的命令应脱敏: {}", au[0]);
}

/// 第一次答「本会话不再问」，之后的回答都是「拒绝」：只有真命中免问的才会执行。
struct FirstPassThenReject(std::sync::atomic::AtomicU32, Mutex<Vec<String>>);

#[async_trait::async_trait]
impl CommandApprover for FirstPassThenReject {
    async fn ask(&self, req: &hanako_tauri_lib::daemon::command_approval::CommandRequest) -> CommandDecision {
        self.1.lock().unwrap().push(req.task_id.clone());
        if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 { CommandDecision::SessionPass } else { CommandDecision::Rejected }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 本会话免问_逐字相同才免_换字符换目录换会话仍问() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = Arc::new(FirstPassThenReject(Default::default(), Mutex::new(vec![])));
    let l = || Some(lease("run_script", &e.root_id));
    let frames = vec![
        task("t1", &e, "echo hi", ".", l()),               // 弹 → 本会话不再问
        task("t2", &e, "echo hi", ".", l()),               // 命中，不弹，执行
        task("t3", &e, "echo hi ", ".", l()),              // 多一个空格 → 弹 → 拒
        task("t4", &e, "echo hi", "sub", l()),             // 换目录 → 弹 → 拒
        task_in("/s/b.jsonl", "t5", &e, "echo hi", ".", l()), // 换会话 → 弹 → 拒
    ];
    let (_reg, r) = drive(frames, 5, a.clone()).await;
    let by = |id: &str| r.iter().find(|x| x["taskId"] == id).unwrap().clone();
    assert_eq!(by("t1")["ok"], true);
    assert_eq!(by("t2")["ok"], true, "免问应命中");
    for id in ["t3", "t4", "t5"] {
        assert_eq!(by(id)["error"], DENIED, "{id} 应重新问并被拒");
    }
    let asked = a.1.lock().unwrap().clone();
    assert!(!asked.contains(&"t2".to_string()), "命中免问不应弹确认: {asked:?}");
    assert_eq!(asked.len(), 4);
    let au = audit_lines(&e);
    assert!(au.iter().any(|x| x["decision"] == "session_pass_hit"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 本会话免问_目录被撤销授权后不再生效() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let passes = hanako_tauri_lib::daemon::command_approval::SessionPasses::new();
    passes.grant("/s/a.jsonl", "echo hi", &e.root.to_string_lossy());
    // 撤销：该执行体不再被授权这个目录
    let p = std::env::var("HANAKO_POLICY_PATH").unwrap();
    std::fs::write(&p, r#"{"grants":{},"allowCommands":true}"#).unwrap();
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let t = task("t", &e, "echo hi", ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive_with(vec![t], 1, a.clone(), passes).await;
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
    assert!(a.seen().is_empty(), "目录已撤销，应在复核处就被拒");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 命令拿不到bridge连接token_经真实任务帧() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    // 对抗审核 B 路 P1-3：echo $HANA_DAEMON_TOKEN / env | base64 能绕过一切事后脱敏
    let sentinel = format!("{}{}", "BRIDGE_TOKEN_", "SENTINEL_9f3a");
    std::env::set_var("HANA_DAEMON_TOKEN", &sentinel);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let frames = vec![
        task("t1", &e, "echo [$HANA_DAEMON_TOKEN]", ".", Some(lease("run_script", &e.root_id))),
        task("t2", &e, "env | base64 | tr -d '\\n'", ".", Some(lease("run_script", &e.root_id))),
    ];
    let (_reg, r) = drive(frames, 2, a).await;
    std::env::remove_var("HANA_DAEMON_TOKEN");
    let by = |id: &str| r.iter().find(|x| x["taskId"] == id).unwrap()["result"].as_str().unwrap_or("").to_string();
    assert!(by("t1").contains("[]"), "token 变量应为空: {}", by("t1"));
    // base64 解出来也不能含哨兵
    let b64 = by("t2");
    let body = b64.split("--- stdout ---\n").nth(1).unwrap_or("").split("\n--- stderr").next().unwrap_or("").trim().to_string();
    let decoded = String::from_utf8_lossy(&base64_decode(&body)).to_string();
    assert!(!decoded.contains(&sentinel), "env 全量里不应有 Bridge token");
    assert!(!decoded.contains("HANA_DAEMON_TOKEN"), "连变量名都不该出现");
}

fn base64_decode(s: &str) -> Vec<u8> {
    let t: Vec<u8> = s.bytes().filter_map(|c| match c {
        b'A'..=b'Z' => Some(c - b'A'), b'a'..=b'z' => Some(c - b'a' + 26), b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62), b'/' => Some(63), _ => None,
    }).collect();
    let mut out = Vec::new();
    for ch in t.chunks(4) {
        let n = ch.len();
        let v = ch.iter().enumerate().fold(0u32, |a, (i, b)| a | ((*b as u32) << (18 - 6 * i as u32)));
        out.push((v >> 16) as u8);
        if n > 2 { out.push((v >> 8) as u8); }
        if n > 3 { out.push(v as u8); }
    }
    out
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn setsid后台进程不拖住任务_经真实任务帧() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let t0 = std::time::Instant::now();
    let t = task("t", &e, "setsid -f sleep 40; echo started", ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a).await;
    assert!(t0.elapsed() < Duration::from_secs(12), "被后台孙进程拖住了: {:?}", t0.elapsed());
    assert_eq!(r[0]["ok"], true, "{}", r[0]);
    assert!(r[0]["result"].as_str().unwrap().contains("started"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 换行后的sudo被拒_命令不执行() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let marker = e.root.join("MARK");
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let cmd = format!("echo a\nsudo -n true\ntouch {}", marker.display());
    let t = task("t", &e, &cmd, ".", Some(lease("run_script", &e.root_id)));
    let (_reg, r) = drive(vec![t], 1, a.clone()).await;
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
    assert!(!marker.exists(), "命中拒绝名单后不得执行任何一行");
    assert!(a.seen().is_empty(), "不应弹确认");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn 过期字符串畸形的lease被拒() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = env(true, false);
    let marker = e.root.join("RAN");
    let a = FixedCommandApprover::new(Some(CommandDecision::Once));
    let mut l = lease("run_script", &e.root_id);
    l["expiresAt"] = serde_json::json!("zzz");
    let t = task("t", &e, &format!("touch {}", marker.display()), ".", Some(l));
    let (_reg, r) = drive(vec![t], 1, a).await;
    assert_eq!(r[0]["error"], DENIED, "{}", r[0]);
    assert!(!marker.exists());
}
