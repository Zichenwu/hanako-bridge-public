// 联调 example（票 14）：用与 lib.rs 相同的 AuthManager + DaemonSupervisor 装配，
// 把「托盘点击『用浏览器登录』」换成直接调用，用于对着真实 hub 路由做端到端验证。
//
// 不往生产二进制里加任何自动登录入口——那会变成后门。
//
// 用法（需先起 hub 联调服务）：
//   HANA_HUB_URL=http://127.0.0.1:39020/hapi E2E_APPROVE_URL=http://127.0.0.1:39020/__approve \
//   HOME=/tmp/e2e-home cargo run --example auth_e2e
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hanako_tauri_lib::daemon::auth_flow::{AuthState, UreqTransport};
use hanako_tauri_lib::daemon::auth_manager::{AuthDeps, AuthManager, LoginOutcome};
use hanako_tauri_lib::daemon::credential_store::{CredentialStore, MemoryStore};
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonConfig, DaemonSupervisor};

fn main() {
    hanako_tauri_lib::init_logger_for_tools();
    let hub = hanako_tauri_lib::daemon::config::resolve_hub_url(|k| std::env::var(k).ok());
    let approve_url = std::env::var("E2E_APPROVE_URL").expect("需要 E2E_APPROVE_URL");

    let supervisor = DaemonSupervisor::new(ApprovalBridge::new());
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let reloads = Arc::new(Mutex::new(0u32));

    let sup = supervisor.clone();
    let store_for_reload = store.clone();
    let r2 = reloads.clone();
    let approve = approve_url.clone();
    let deps = AuthDeps {
        transport: Arc::new(UreqTransport),
        store: store.clone(),
        // “浏览器”：从确认页 URL 里取 code，然后让联调服务替用户点「允许」
        open_url: Arc::new(move |u| {
            let code = u.split("code=").nth(1).unwrap_or("");
            println!("E2E 打开确认页: {u}");
            let a = format!("{approve}?code={code}");
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(600));
                match ureq::get(&a).call() {
                    Ok(mut r) => println!("E2E 模拟用户点允许 → {}", r.body_mut().read_to_string().unwrap_or_default()),
                    Err(e) => println!("E2E 模拟点允许失败: {e}"),
                }
            });
            Ok(())
        }),
        sleep: Arc::new(std::thread::sleep),
        now: Arc::new(chrono::Utc::now),
        on_credential: Arc::new(move || {
            *r2.lock().unwrap() += 1;
            let _ = DaemonConfig::remove_legacy_file();
            sup.reload_credentials(store_for_reload.as_ref());
        }),
        on_state: Arc::new(|s| match s {
            AuthState::SignedIn { agent_id, expires_at } => println!("E2E 状态 → 已登录 {agent_id} 到期 {expires_at}"),
            other => println!("E2E 状态 → {other:?}"),
        }),
    };
    let mgr = AuthManager::new(deps, hub, "e2e-box".into(), "0.1.0".into());

    println!("E2E 起始状态: {:?}", mgr.state());
    let outcome = mgr.login(Some("team--alice".into()));
    println!("E2E 登录结果: {outcome:?}");
    assert_eq!(outcome, LoginOutcome::SignedIn, "登录应成功");

    let cred = store.load().unwrap().expect("钥匙串应已有凭据");
    println!("E2E 钥匙串凭据: agent={} secret_prefix={}", cred.agent_id, &cred.secret[..12.min(cred.secret.len())]);
    println!("E2E on_credential 触发次��: {}", reloads.lock().unwrap());
    std::thread::sleep(Duration::from_millis(2500));
    println!("E2E daemon 状态: {:?}", supervisor.status());

    // 续期：把钥匙串凭据改成「1 小时后到期」以落入 24h 窗口
    let mut near = cred.clone();
    near.expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    store.save(&near).unwrap();
    let step = mgr.tick_renew();
    println!("E2E 续期结果: {step:?}");
    std::thread::sleep(Duration::from_millis(2500));
    println!("E2E 续期后 daemon 状态: {:?}", supervisor.status());
    let after = store.load().unwrap().unwrap();
    println!("E2E 续期后 secret_prefix={} (应为 hana_dev_ROT)", &after.secret[..12.min(after.secret.len())]);
    println!("E2E on_credential 触发次数: {}", reloads.lock().unwrap());

    // 被吊销的凭据续期 → 需重新授权
    let mut revoked = after.clone();
    revoked.secret = "hana_dev_REVOKED".into();
    revoked.expires_at = near.expires_at.clone();
    store.save(&revoked).unwrap();
    let step = mgr.tick_renew();
    println!("E2E 吊销凭据续期: {step:?}");
    println!("E2E 最终状态: {:?}", mgr.state());
}
