// src-tauri/src/lib.rs
//! Hanako Tauri 壳装配入口。
//!
//! 安全红线（spec §3.1）：
//! - remote.urls 一条都不配（capabilities/default.json 空 remote）
//! - approval/settings 窗口加载本地文件（WebviewUrl::App），禁 iframe 承载远程内容
//! - 票 13 起**没有主窗口**：不再加载任何云端 URL，webview 只有 approval/settings 两个本地页；
//!   进程仅靠托盘存活，daemon 只主动出站连云端
//!
//! # daemon↔GUI 审批桥设计（Task 6）
//!
//! 问题：daemon 在 tauri::Builder::default().run() 之前 spawn，此时无 AppHandle。
//!
//! 解决：在 run() 里先构造 Arc<ApprovalBridge>，分别传给：
//!   1. DaemonSupervisor（持有 bridge，负责 daemon 生命周期管理）
//!   2. .setup(|app| bridge.set_app_handle(app.handle().clone())) —— GUI 启动后注入 AppHandle
//!   3. .manage(bridge.clone()) / .manage(supervisor) —— 注册为 Tauri 状态，供命令读写
//!
//! # daemon 热重启设计（P3.5）
//!
//! DaemonSupervisor::restart(cfg) 发送 stop 信号给旧 DaemonClient，旧 client 退出后
//! supervisor 用新配置重新 spawn 线程+runtime+DaemonClient。ApprovalBridge 跨 restart 不变。
//!
//! # 安全：token 不经 IPC 传前端
//!
//! get_daemon_config 只返回 base_url + node_id，从不返回 token。
//! save_daemon_config 接收前端提交的 token；若前端提交空字符串，
//! 则保留文件/env 中已存储的 token（用户可只改 base_url 而无需重新输入 token）。

pub mod daemon;

use daemon::auth_request::{AuthDecision, AuthRequest};
use daemon::commands::{self as store, Paths};
use daemon::auth_flow::{AuthState, UreqTransport};
use daemon::auth_manager::{AuthDeps, AuthManager, LoginOutcome, RENEW_CHECK_INTERVAL};
use daemon::credential_store::{CredentialStore, KeyringStore, MemoryStore};
use daemon::{ApprovalBridge, DaemonConfig, DaemonSupervisor};
use std::sync::Arc;
use tauri::Manager;

// ────────────────────────────────────────────────────────────────
// 应用入口
// ────────────────────────────────────────────────────────────────

/// 启动 Tauri 应用。
pub fn run() {
    logger_init();

    // Task 6：构造 daemon↔GUI 审批桥（Arc，两端共享）
    let bridge = ApprovalBridge::new();

    // P3.5：构造 daemon 生命周期管理器（持有 bridge 的 Arc，与 GUI 解耦）
    let supervisor = DaemonSupervisor::new(bridge.clone());

    // daemon 先于 GUI spawn：独立于 webkit 初始化，避免被 GUI 卡住
    // supervisor.start_if_configured() 在内部处理"未配置则仅壳运行"逻辑
    supervisor.start_if_configured();

    let auth = build_auth_manager(&supervisor);
    start_renew_scheduler(auth.clone());

    tauri::Builder::default()
        // 注册 tauri-plugin-dialog（pick_workspace_dir 依赖）
        .plugin(tauri_plugin_dialog::init())
        // 系统通知（票 17）：断开 / 恢复 / 跨机使用提醒
        .plugin(tauri_plugin_notification::init())
        // 注册共享审批桥为 Tauri 状态（供 approval 相关命令访问）
        .manage(bridge.clone())
        // 注册 daemon supervisor 为 Tauri 状态（供 save_daemon_config 等命令访问）
        .manage(supervisor.clone())
        // 授权管理器（票 14）：浏览器授权码登录 + 钥匙串 + 到期前 24h 续期
        .manage(auth.clone())
        .setup(move |app| {
            // 注入 AppHandle 到审批桥：之后 ask() 可真正弹窗
            bridge.set_app_handle(app.handle().clone());

            // 托盘菜单（Task 6 B7）
            setup_tray(app)?;

            // 票 17：托盘状态中枢。通知器 / 托盘视图回调都在 daemon 线程被调用，内部自行切回主线程
            if let Some(sup) = app.try_state::<Arc<DaemonSupervisor>>() {
                let hub = build_tray_hub(app.handle());
                sup.set_hub(hub.clone());
                // supervisor 在 setup 之前已 start_if_configured，首个 client 没拿到 hub；
                // reload 让它以带 hub 的 client 重新起一次（内容不变，仅注入观察者）
                sup.restart_with_current_hub();
            }

            // 票 15b：授权请求弹窗实现（daemon 收到 auth_request 帧时调用）
            if let Some(sup) = app.try_state::<Arc<DaemonSupervisor>>() {
                let handle = app.handle().clone();
                sup.auth_requests().set_presenter(Arc::new(move |req: &AuthRequest| {
                    present_auth_request(&handle, req)
                }));
            }

            // 票 18：上传偏好弹窗实现（daemon 执行 local_upload_to_workspace 时调用）
            if let Some(sup) = app.try_state::<Arc<DaemonSupervisor>>() {
                let handle = app.handle().clone();
                sup.uploads().set_presenter(Arc::new(move |_ask| {
                    if let Some(w) = handle.get_webview_window(WindowKind::UploadAsk.label()) {
                        let _ = w.close(); // 新请求顶掉旧弹窗
                    }
                    open_window(&handle, WindowKind::UploadAsk)
                }));
            }

            // 本地文件预览确认弹窗（票 03 只做了桥、从未接 UI → 没有 presenter 时桥立即拒绝，
            // 网页表现为「未获允许」且电脑上什么都不弹，2026-10-08 验收发现）。
            // 桥同一时刻只展示一个：被提上来的请求出现时旧请求已答完，直接关旧开新。
            if let Some(sup) = app.try_state::<Arc<DaemonSupervisor>>() {
                let handle = app.handle().clone();
                sup.previews().set_presenter(Arc::new(move |_ask| {
                    if let Some(w) = handle.get_webview_window(WindowKind::PreviewAsk.label()) {
                        let _ = w.close();
                    }
                    open_window(&handle, WindowKind::PreviewAsk)
                }));
            }

            // 票 15b：首次启动（既没登录也没有授权目录）自动弹出引导；之后不再自动弹
            if should_show_onboarding(app.handle()) {
                open_window(app.handle(), WindowKind::Onboarding);
            }

            log::info!("[shell] Tauri 应用启动，AppHandle 已注入审批桥");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 票 15b：引导 / 设置窗 / 授权请求弹窗
            ui_overview,
            ui_pick_folder,
            ui_remove_folder,
            ui_set_mode,
            ui_set_agent,
            ui_set_upload,
            ui_set_preview,
            ui_set_preview_limit,
            ui_set_web_confirm,
            ui_set_display_name,
            ui_open_backup_dir,
            ui_open_url,
            ui_open_web,
            ui_open_window,
            ui_close_window,
            get_pending_auth_request,
            respond_auth_request,
            get_pending_upload_ask,
            respond_upload_ask,
            get_pending_preview_ask,
            respond_preview_ask,
            get_pending_approval,
            respond_approval,
            // P3.5 新增：daemon 配置查询与热重启
            get_daemon_config,
            save_daemon_config,
            daemon_status,
            // 票 14：授权码登录
            auth_state,
            auth_login,
            auth_logout,
        ])
        .build(tauri::generate_context!())
        .expect("构建 Tauri 应用失败")
        .run(|_app, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if should_prevent_exit(code) {
                    api.prevent_exit();
                }
            }
        });
}

/// 退出请求是否应被拦截。
///
/// `code == None` 是「最后一个窗口关闭」引发的隐式退出——托盘应用必须拦下；
/// `Some(_)` 是代码显式 `app.exit(code)`，放行。托盘「退出」菜单直接
/// `std::process::exit(0)`，不经 ExitRequested，所以不受此函数影响。
pub(crate) fn should_prevent_exit(code: Option<i32>) -> bool {
    code.is_none()
}

// ────────────────────────────────────────────────────────────────
// 托盘菜单（Task 6 B7）
// ────────────────────────────────────────────────────────────────

/// 构建系统托盘菜单：状态 / 设置 / 退出。
fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let status_item =
        MenuItem::with_id(app, "status", "状态: 运行中", false, None::<&str>)?;
    // 暂停 / 恢复合并为一个菜单项：暂停中显示「恢复」，否则显示「暂停 30 分钟」（文案由 TrayView 随状态切换）
    let pause_item = MenuItem::with_id(app, "pause", "暂停 30 分钟", true, None::<&str>)?;
    let login_item = MenuItem::with_id(app, "login", "用浏览器登录…", true, None::<&str>)?;
    let settings_item = MenuItem::with_id(app, "settings", "设置", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&status_item, &pause_item, &login_item, &settings_item, &quit_item])?;
    app.manage(StatusMenuItem(status_item.clone()));
    app.manage(PauseMenuItem(pause_item.clone()));

    // 使用应用默认窗口图标作为托盘图标（从 bundle.icon 嵌入）
    // macOS 上 icon_as_template(false) 保留彩色，避免被渲染成纯黑模板图标
    let tray_icon = app
        .default_window_icon()
        .cloned()
        .ok_or("托盘图标缺失：bundle.icon 未配置或图标文件不存在")?;

    TrayIconBuilder::with_id("main")
        .icon(tray_icon)
        .icon_as_template(false)
        .menu(&menu)
        .tooltip("Hanako Bridge")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "settings" => { open_window(app, WindowKind::Settings); }
            "login" => {
                // 托盘回调在 UI 线程：授权要阻塞轮询数分钟，必须甩到独立线程
                if let Some(auth) = app.try_state::<Arc<AuthManager>>() {
                    let auth = auth.inner().clone();
                    std::thread::spawn(move || {
                        let r = auth.login(None);
                        log::info!("[auth] 托盘发起登录结果: {r:?}");
                    });
                }
            }
            "pause" => toggle_pause(app),
            "quit" => request_quit(app),
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// 托盘菜单首行（状态行）的句柄，TrayView 实现用它改文案。
struct StatusMenuItem(tauri::menu::MenuItem<tauri::Wry>);

/// 「暂停/恢复」菜单项句柄。
struct PauseMenuItem(tauri::menu::MenuItem<tauri::Wry>);

/// 暂停 ↔ 恢复。暂停默认 30 分钟；切换后立即上报 `pause_state` 并刷新托盘。
/// 托盘回调在 UI 线程，这里只做内存操作与状态推送，不阻塞。
fn toggle_pause(app: &tauri::AppHandle) {
    let Some(sup) = app.try_state::<Arc<DaemonSupervisor>>() else { return };
    let pause = sup.pause_state();
    let now = unix_ms();
    let paused_now = pause.is_paused(now);
    if paused_now {
        pause.resume();
    } else {
        pause.pause(None, now);
    }
    let is_paused = !paused_now;
    if let Some(hub) = sup.hub() {
        hub.on_event(daemon::tray_state::Event::Paused(is_paused));
    }
    if let Some(item) = app.try_state::<PauseMenuItem>() {
        let _ = item.0.set_text(if is_paused { "恢复" } else { "暂停 30 分钟" });
    }
    // 把本机暂停上报服务端（来源 local，网页恢复不了）
    sup.send_pause_state(pause.active(unix_ms()));
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 退出：有进行中的写操作先原生确认，否则直接退。
/// 托盘回调在 UI 线程；原生对话框阻塞等待用户，放到独立线程避免卡住托盘。
fn request_quit(app: &tauri::AppHandle) {
    use daemon::quit_guard::QuitDecision;
    let decision = app
        .try_state::<Arc<DaemonSupervisor>>()
        .map(|s| s.quit_guard().decide())
        .unwrap_or(QuitDecision::Proceed);
    match decision {
        QuitDecision::Proceed => std::process::exit(0),
        QuitDecision::ConfirmNeeded { message, .. } => {
            let app = app.clone();
            std::thread::spawn(move || {
                use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
                let quit = app
                    .dialog()
                    .message(message)
                    .title("Hanako Bridge")
                    .buttons(MessageDialogButtons::OkCancelCustom("仍要退出".into(), "取消".into()))
                    .blocking_show();
                if quit {
                    std::process::exit(0);
                }
            });
        }
    }
}

/// 真实系统通知器：失败（用户关了通知权限等）只记日志，绝不影响 daemon。
struct SystemNotifier {
    app: tauri::AppHandle,
}
impl daemon::tray_hub::Notifier for SystemNotifier {
    fn send(&self, title: &str, body: &str) {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = self.app.notification().builder().title(title).body(body).show() {
            log::warn!("[tray] 系统通知发送失败（不影响运行）: {e}");
        }
    }
}

/// 真实托盘视图：更新状态行文案与 tooltip。回调发生在 daemon 线程，菜单操作切回主线程。
struct SystemTrayView {
    app: tauri::AppHandle,
}
impl daemon::tray_hub::TrayView for SystemTrayView {
    fn update(&self, state: daemon::tray_state::TrayState) {
        let app = self.app.clone();
        let label = format!("状态: {}", state.label());
        let tip = format!("Hanako Bridge · {}", state.label());
        let _ = self.app.run_on_main_thread(move || {
            if let Some(item) = app.try_state::<StatusMenuItem>() {
                let _ = item.0.set_text(&label);
            }
            if let Some(tray) = app.tray_by_id("main") {
                let _ = tray.set_tooltip(Some(&tip));
            }
        });
    }
}

/// 构造托盘状态中枢（真实通知器 + 托盘视图 + 系统时钟）。
fn build_tray_hub(app: &tauri::AppHandle) -> Arc<daemon::tray_hub::TrayHub> {
    daemon::tray_hub::TrayHub::new(
        Arc::new(SystemNotifier { app: app.clone() }),
        Arc::new(SystemTrayView { app: app.clone() }),
        Arc::new(daemon::tray_hub::SystemClock::new()),
    )
}

// ────────────────────────────────────────────────────────────────
// Tauri 命令（Task 6 B6）
// ────────────────────────────────────────────────────────────────

/// 窗口种类。尺寸、标题、是否置顶都在这里集中定义（tauri.conf.json 里的静态声明必须与此一致）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WindowKind {
    Onboarding,
    Settings,
    AuthRequest,
    UploadAsk,
    PreviewAsk,
}

impl WindowKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            WindowKind::Onboarding => "onboarding",
            WindowKind::Settings => "settings",
            WindowKind::AuthRequest => "auth-request",
            WindowKind::UploadAsk => "upload-ask",
            WindowKind::PreviewAsk => "preview-ask",
        }
    }
    pub(crate) fn url(self) -> &'static str {
        match self {
            WindowKind::Onboarding => "onboarding.html",
            WindowKind::Settings => "settings.html",
            WindowKind::AuthRequest => "auth-request.html",
            WindowKind::UploadAsk => "upload-ask.html",
            WindowKind::PreviewAsk => "preview-ask.html",
        }
    }
    pub(crate) fn title(self) -> &'static str {
        match self {
            WindowKind::Onboarding => "Hanako Bridge",
            WindowKind::Settings => "Hanako Bridge · 设置",
            WindowKind::AuthRequest => "请求使用这台电脑",
            WindowKind::UploadAsk => "把文件传到云端",
            WindowKind::PreviewAsk => "在网页上预览文件",
        }
    }
    /// (宽, 高)：设置窗 480×680 与 tauri.conf.json 一致；引导 460 宽；弹窗 440 宽。
    pub(crate) fn size(self) -> (f64, f64) {
        match self {
            WindowKind::Onboarding => (460.0, 540.0),
            WindowKind::Settings => (480.0, 680.0),
            WindowKind::AuthRequest => (440.0, 470.0),
            WindowKind::UploadAsk => (460.0, 470.0),
            WindowKind::PreviewAsk => (440.0, 400.0),
        }
    }
    /// 授权请求弹窗：置顶但不抢焦点（用户可能正在打字，误触一个"允许"是真实风险）。
    pub(crate) fn steals_focus(self) -> bool {
        !matches!(self, WindowKind::AuthRequest | WindowKind::UploadAsk | WindowKind::PreviewAsk)
    }
    pub(crate) fn always_on_top(self) -> bool {
        matches!(self, WindowKind::AuthRequest | WindowKind::UploadAsk | WindowKind::PreviewAsk)
    }
}

/// 打开或聚焦一个窗口。可从任意线程调用（内部派发到主线程）。
pub(crate) fn open_window(app: &tauri::AppHandle, kind: WindowKind) -> bool {
    let app2 = app.clone();
    let r = app.run_on_main_thread(move || {
        if let Some(w) = app2.get_webview_window(kind.label()) {
            let _ = w.show();
            if kind.steals_focus() {
                let _ = w.set_focus();
            }
            return;
        }
        let (w, h) = kind.size();
        let mut b = tauri::WebviewWindowBuilder::new(&app2, kind.label(), tauri::WebviewUrl::App(kind.url().into()))
            .title(kind.title())
            .inner_size(w, h)
            .resizable(kind == WindowKind::Settings)
            .always_on_top(kind.always_on_top())
            .focused(kind.steals_focus());
        if kind == WindowKind::Settings {
            b = b.min_inner_size(480.0, 580.0); // 与 tauri.conf.json settings.minHeight 一致
        }
        if let Err(e) = b.build() {
            log::error!("[window] 打开 {} 失败: {e}", kind.label());
        }
    });
    r.is_ok()
}

/// 授权请求弹窗实现：返回 false = 窗口没能打开（桥据此立即拒绝，不等 60 秒）。
fn present_auth_request(app: &tauri::AppHandle, _req: &AuthRequest) -> bool {
    // 已有弹窗时先关掉：新请求顶掉旧请求（桥里旧请求已按拒绝处理）
    if let Some(w) = app.get_webview_window(WindowKind::AuthRequest.label()) {
        let _ = w.close();
    }
    open_window(app, WindowKind::AuthRequest)
}

/// 首次运行：没有任何凭据登录痕迹且没有授权目录 → 弹引导。
/// 用"是否已有授权目录 或 已登录"判断，避免老用户升级后被引导打扰。
fn should_show_onboarding(app: &tauri::AppHandle) -> bool {
    if std::env::var("HANAKO_NO_ONBOARDING").is_ok() {
        return false;
    }
    let Ok(paths) = Paths::real() else { return false };
    let has_dirs = !store::read_dirs(&paths, true).is_empty();
    let signed_in = app
        .try_state::<Arc<AuthManager>>()
        .map(|a| matches!(a.state(), AuthState::SignedIn { .. }))
        .unwrap_or(false);
    let configured = app
        .try_state::<Arc<DaemonSupervisor>>()
        .map(|s| s.status().configured)
        .unwrap_or(false);
    !(has_dirs || signed_in || configured)
}

/// 三个窗口共用的概览：连接状态 + 登录状态 + 策略视图。token 从不出现在这里。
#[tauri::command]
fn ui_overview(
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
    auth: tauri::State<'_, Arc<AuthManager>>,
) -> Result<serde_json::Value, String> {
    let paths = Paths::real()?;
    let status = supervisor.status();
    // 候选助手里的"默认助手"：daemon 在跑用它的凭据执行体，否则取登录状态里的
    let signed_agent = match auth.state() {
        AuthState::SignedIn { agent_id, .. } => Some(agent_id),
        _ => None,
    };
    let default_agent = status.agent_id.clone().or(signed_agent.clone());
    let view = store::get_view(&paths, default_agent.as_deref(), true);
    let (view_json, view_err) = match view {
        Ok(v) => (serde_json::to_value(&v).map_err(|e| e.to_string())?, None),
        Err(e) => (serde_json::json!({"folders": [], "agents": [], "web_confirm": false}), Some(e)),
    };
    Ok(serde_json::json!({
        "connection": status,
        "auth": auth_state_json(&auth.state()),
        "auth_error": auth.last_error(),
        "machine": daemon::config::default_node_id_pub(),
        // 给人看的名字：自定义 > 机器名去 node_ 前缀（与网页端回退口径一致）
        "display_name": store::display_name(&paths),
        "display_default": daemon::config::default_node_id_pub().trim_start_matches("node_").to_string(),
        "policy": view_json,
        "policy_error": view_err,
        "backup_size": store::human_size(store::backup_size(&paths, true)),
    }))
}

fn auth_state_json(st: &AuthState) -> serde_json::Value {
    match st {
        AuthState::SignedOut => serde_json::json!({"state": "signed_out"}),
        AuthState::AwaitingApproval { user_code, verification_url } => {
            serde_json::json!({"state": "awaiting", "user_code": user_code, "verification_url": verification_url})
        }
        AuthState::SignedIn { agent_id, expires_at } => {
            serde_json::json!({"state": "signed_in", "agent_id": agent_id, "expires_at": expires_at})
        }
        AuthState::NeedReauth { reason } => serde_json::json!({"state": "need_reauth", "reason": format!("{reason:?}")}),
    }
}

/// 原生文件夹选择器 + 落盘。`grant_to` = 初始授权的助手（引导默认只给登录时的助手）。
/// 返回新目录的 rootId；取消选择返回 null。
#[tauri::command]
fn ui_pick_folder(
    grant_to: Option<String>,
    app: tauri::AppHandle,
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(picked) = app.dialog().file().blocking_pick_folder() else { return Ok(None) };
    let dir = picked.into_path().map_err(|e| e.to_string())?;
    let paths = Paths::real()?;
    let default_agent = supervisor.current_agent();
    let id = store::add_folder(&paths, &dir, default_agent.as_deref(), grant_to.as_deref().or(default_agent.as_deref()), true)?;
    log::info!("[workspace] 新增授权目录 {id}");
    Ok(Some(id))
}

#[tauri::command]
fn ui_remove_folder(root_id: String, supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<(), String> {
    store::remove_folder(&Paths::real()?, &root_id, supervisor.current_agent().as_deref(), true)
}

#[tauri::command]
fn ui_set_mode(root_id: String, mode: String) -> Result<(), String> {
    store::set_mode(&Paths::real()?, &root_id, &mode, true)
}

#[tauri::command]
fn ui_set_agent(
    root_id: String,
    agent: String,
    allowed: bool,
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<(), String> {
    store::set_agent_access(&Paths::real()?, &root_id, &agent, allowed, supervisor.current_agent().as_deref(), true)
}

#[tauri::command]
fn ui_set_upload(root_id: String, pref: String) -> Result<(), String> {
    store::set_upload(&Paths::real()?, &root_id, &pref, true)
}

/// 设置某目录的**网页预览**偏好。放宽（always）只能从本机设置窗走到这里。
#[tauri::command]
fn ui_set_preview(root_id: String, pref: String) -> Result<(), String> {
    store::set_preview(&Paths::real()?, &root_id, &pref, true)
}

/// 设置预览大小上限档位（MB，只认 50/100/200）。全局一个值，不按目录。
#[tauri::command]
fn ui_set_preview_limit(mb: u64) -> Result<(), String> {
    store::set_preview_limit(&Paths::real()?, mb)
}

/// 改电脑显示名：落盘后重连一次，让云端几秒内看到新名字（身份 serverNodeId 不变，已绑定会话不受影响）。
#[tauri::command]
fn ui_set_display_name(name: String, supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<Option<String>, String> {
    let saved = store::set_display_name(&Paths::real()?, &name)?;
    supervisor.restart_with_current_hub();
    Ok(saved)
}

#[tauri::command]
fn ui_set_web_confirm(on: bool) -> Result<(), String> {
    store::set_web_confirm(&Paths::real()?, on)
}

/// 打开第一个授权目录下的备份文件夹（没有备份目录则打开授权目录本身）。
#[tauri::command]
fn ui_open_backup_dir() -> Result<(), String> {
    let paths = Paths::real()?;
    let dirs = store::read_dirs(&paths, true);
    let target = dirs
        .iter()
        .map(|d| d.join(".hanako-backup"))
        .find(|p| p.is_dir())
        .or_else(|| dirs.first().cloned())
        .ok_or("还没有授权目录")?;
    webbrowser::open(&target.to_string_lossy()).map_err(|e| e.to_string())
}

/// 用系统浏览器打开 URL。只放行 http(s)——窗口里的 JS 不该能让系统去打开 file:// 或自定义协议。
fn open_http_url(url: &str) -> Result<(), String> {
    let lower = url.trim().to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("只允许打开 http(s) 地址".into());
    }
    webbrowser::open(url.trim()).map_err(|e| e.to_string())
}

#[tauri::command]
fn ui_open_url(url: String) -> Result<(), String> {
    open_http_url(&url)
}

/// 打开 Hanako 网页（引导完成页的「打开 Hanako」）。地址取自 hub 配置，不接收前端传入。
#[tauri::command]
fn ui_open_web() -> Result<(), String> {
    let hub = daemon::config::resolve_hub_url(|k| std::env::var(k).ok());
    open_http_url(&hub)
}

/// 从一个窗口打开另一个窗口（引导完成页的「打开 Hanako」走网页，这里只给窗口互跳用）。
#[tauri::command]
fn ui_open_window(kind: String, app: tauri::AppHandle) -> Result<(), String> {
    let k = match kind.as_str() {
        "settings" => WindowKind::Settings,
        "onboarding" => WindowKind::Onboarding,
        other => return Err(format!("未知窗口: {other}")),
    };
    open_window(&app, k);
    Ok(())
}

#[tauri::command]
fn ui_close_window(label: String, app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window(&label) {
        let _ = w.close();
    }
}

/// 授权请求弹窗取数据：请求 + 可勾选的目录（含读写模式）+ 助手 Team。
#[tauri::command]
fn get_pending_auth_request(supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<Option<serde_json::Value>, String> {
    let Some(req) = supervisor.auth_requests().peek() else { return Ok(None) };
    let paths = Paths::real()?;
    let view = store::get_view(&paths, supervisor.current_agent().as_deref(), true)?;
    Ok(Some(serde_json::json!({ "request": req, "folders": view.folders })))
}

/// 弹窗提交：`picked` 为空数组表示拒绝。只有非空才会被当作允许（并由 daemon 侧写盘）。
#[tauri::command]
fn respond_auth_request(
    request_id: String,
    allow: bool,
    picked: Vec<String>,
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<(), String> {
    let decision = if allow && !picked.is_empty() { AuthDecision::Allow(picked) } else { AuthDecision::Reject };
    supervisor.auth_requests().respond(&request_id, decision)
}

/// 上传偏好弹窗取数据。
#[tauri::command]
fn get_pending_upload_ask(supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<Option<serde_json::Value>, String> {
    Ok(supervisor.uploads().peek().map(|a| serde_json::to_value(a).unwrap_or(serde_json::Value::Null)))
}

/// 上传偏好弹窗提交。`choice` 只接受 once / session / reject，其它一律按拒绝——
/// 没有「永久」：永久信任只能在设置里开。
#[tauri::command]
fn respond_upload_ask(ask_id: String, choice: String, supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<(), String> {
    use daemon::upload_gate::UserChoice;
    let c = match choice.as_str() {
        "once" => UserChoice::Once,
        "session" => UserChoice::Session,
        _ => UserChoice::Reject,
    };
    supervisor.uploads().respond(&ask_id, c)
}

/// 预览确认弹窗取数据（不含绝对路径，见 `PreviewAsk`）。
#[tauri::command]
fn get_pending_preview_ask(supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<Option<serde_json::Value>, String> {
    Ok(supervisor.previews().peek().map(|a| serde_json::to_value(a).unwrap_or(serde_json::Value::Null)))
}

/// 预览确认弹窗提交。只认 once / session，其余一律按拒绝——没有「永久」（只能在设置里开）。
#[tauri::command]
fn respond_preview_ask(ask_id: String, choice: String, supervisor: tauri::State<'_, Arc<DaemonSupervisor>>) -> Result<(), String> {
    supervisor.previews().respond(&ask_id, parse_preview_choice(&choice))
}

pub(crate) fn parse_preview_choice(choice: &str) -> daemon::preview_gate::UserChoice {
    use daemon::preview_gate::UserChoice;
    match choice {
        "once" => UserChoice::Once,
        "session" => UserChoice::Session,
        _ => UserChoice::Reject,
    }
}

/// 返回当前待确认的审批请求（供 approval.html 前端调用）。
#[tauri::command]
fn get_pending_approval(
    state: tauri::State<'_, Arc<ApprovalBridge>>,
) -> Result<Option<serde_json::Value>, String> {
    match state.peek_pending() {
        Some(payload) => {
            let v = serde_json::to_value(&payload).map_err(|e| e.to_string())?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// 用户在 approval 窗口点击按钮后调用，回传决策给 daemon 的 ask()。
#[tauri::command]
fn respond_approval(
    task_id: String,
    decision: String,
    trust_path: Option<String>,
    state: tauri::State<'_, Arc<ApprovalBridge>>,
) -> Result<(), String> {
    let trust = trust_path.map(std::path::PathBuf::from);
    state
        .respond(&task_id, &decision, trust)
        .map_err(|e| e.to_string())
}

// ────────────────────────────────────────────────────────────────
// P3.5 新增命令：daemon 配置查询与热重启
// ────────────────────────────────────────────────────────────────

/// 返回当前 daemon 配置供设置窗口展示（base_url + node_id）。
///
/// **安全约束**：token 从不返回给前端。
/// 若尚未配置返回 null（前端 JS 可用 null 判断"未配置"并显示提示）。
#[tauri::command]
fn get_daemon_config(
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<Option<serde_json::Value>, String> {
    match supervisor.current_config_display() {
        Some(d) => {
            let v = serde_json::to_value(&d).map_err(|e| e.to_string())?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// 保存 daemon 配置并触发热重启。
///
/// # 参数
/// - `base_url`：云端地址（必须 http(s)://）
/// - `token`：连接 Token；若前端传入空字符串，则**保留已存储的 token**（用户只改地址时无需重新输 token）
/// - `node_id`：节点标识；空字符串则自动用 hostname 填充
///
/// # 安全约束
/// - token 不写入日志
/// - 调用 save_to_file() 后再 restart()，重启前持久化完成（保证 crash 后下次仍能启动）
#[tauri::command]
fn save_daemon_config(
    base_url: String,
    token: String,
    node_id: Option<String>,
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<(), String> {
    // 若 token 为空，保留已存储的 token（用户只改 base_url 时不需要重新输）
    let effective_token = if token.is_empty() {
        // 优先读已有的文件配置 token；若文件不存在也没有 env，则报错（必须提供 token）
        let existing = DaemonConfig::load_from_file()
            .map(|c| c.token)
            .or_else(|| std::env::var("HANA_DAEMON_TOKEN").ok())
            .filter(|t| !t.is_empty());
        match existing {
            Some(t) => t,
            None => return Err("请输入连接 Token（首次配置必填）".into()),
        }
    } else {
        token
    };

    // node_id：空则 hostname 填充（DaemonConfig::from_lookup 的相同逻辑）
    let effective_node_id = node_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| daemon::config::default_node_id_pub());

    let cfg = DaemonConfig {
        base_url: base_url.trim_end_matches('/').to_string(),
        token: effective_token,
        node_id: effective_node_id,
        // 手填路径不带执行体；grants 为空（待票 14/15 授权流程）
        agent_id: None,
    };

    // 验证
    cfg.validate().map_err(|e| e.to_string())?;

    // 持久化（原子写，先落盘再重启，保证 crash 后下次仍能启动）
    cfg.save_to_file()?;

    // 热重启 daemon
    supervisor.restart(cfg);

    log::info!("[config] 配置已保存，daemon 热重启中");
    Ok(())
}

/// 返回 daemon 当前状态（供设置窗口轮询）。
///
/// 返回 JSON 对象：`{configured: bool, connected: bool, node_id: string | null}`
#[tauri::command]
fn daemon_status(
    supervisor: tauri::State<'_, Arc<DaemonSupervisor>>,
) -> Result<serde_json::Value, String> {
    let status = supervisor.status();
    serde_json::to_value(&status).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{open_http_url, should_prevent_exit};

    /// tauri.conf.json 的静态窗口声明必须与 WindowKind 一致：两处尺寸漂移会让
    /// "托盘打开"和"自动弹出"得到不同大小的窗口（接力文档点名的坑）。
    #[test]
    fn 窗口尺寸_conf与代码一致() {
        use super::WindowKind::*;
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let wins = conf["app"]["windows"].as_array().unwrap();
        for k in [Onboarding, Settings, AuthRequest] {
            let w = wins.iter().find(|w| w["label"] == k.label()).unwrap_or_else(|| panic!("conf 缺窗口 {}", k.label()));
            let (cw, ch) = k.size();
            assert_eq!(w["width"].as_f64().unwrap(), cw, "{} 宽", k.label());
            assert_eq!(w["height"].as_f64().unwrap(), ch, "{} 高", k.label());
            assert_eq!(w["url"], k.url(), "{} url", k.label());
            assert_eq!(w["alwaysOnTop"].as_bool().unwrap_or(false), k.always_on_top(), "{} 置顶", k.label());
        }
    }

    /// 授权请求弹窗：置顶但不抢焦点；其余窗口正常抢焦点。
    #[test]
    fn 授权请求弹窗_置顶不抢焦点() {
        use super::WindowKind::*;
        assert!(AuthRequest.always_on_top() && !AuthRequest.steals_focus());
        assert!(!Settings.always_on_top() && Settings.steals_focus());
        assert!(!Onboarding.always_on_top() && Onboarding.steals_focus());
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let w = conf["app"]["windows"].as_array().unwrap().iter().find(|w| w["label"] == "auth-request").unwrap();
        assert_eq!(w["focus"], false, "conf 里也必须不抢焦点");
    }

    /// 窗口页面全部用 `window.__TAURI__.core.invoke`，这要求 `app.withGlobalTauri=true`。
    /// 缺了它脚本第一行就抛错、窗口整片空白——而 mock 的 Playwright 验收发现不了（真机才暴露）。
    #[test]
    fn 开启全局_tauri_对象() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["app"]["withGlobalTauri"], true);
    }

    /// capabilities 必须覆盖所有窗口，否则窗口里的 invoke 会被拒（白屏式故障，只有真机才能发现）。
    #[test]
    fn capabilities_覆盖全部窗口() {
        let cap: serde_json::Value = serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let listed: Vec<&str> = cap["windows"].as_array().unwrap().iter().filter_map(|w| w.as_str()).collect();
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        for w in conf["app"]["windows"].as_array().unwrap() {
            let l = w["label"].as_str().unwrap();
            assert!(listed.contains(&l), "capabilities 缺窗口 {l}");
        }
        assert!(cap.get("remote").is_none(), "不得配置 remote（spec §3.1 红线）");
    }

    #[test]
    fn ui_页面无内联事件与内联脚本_csp_下按钮才有效() {
        // 审核 R2-N1：CSP 的 script-src 回落到 default-src 'self'（无 unsafe-inline），内联 onclick=
        // 被 webview 静默拦截，写确认窗三个按钮全部失效（每次写都 45s 超时被拒）。
        // 守住：只要 CSP 不放行内联脚本，ui/*.html 就不得出现 on*= 与无 src 的 <script>。
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let csp = conf["app"]["security"]["csp"].as_str().unwrap();
        let script_allows_inline = csp.split(';').map(str::trim).any(|d| {
            (d.starts_with("script-src") || d.starts_with("default-src")) && d.contains("'unsafe-inline'")
        });
        assert!(!script_allows_inline, "CSP 不应为脚本放行 unsafe-inline: {csp}");
        let on_attr = regex::Regex::new(r#"(?i)<[^>]*\son[a-z]+\s*="#).unwrap();
        let script_tag = regex::Regex::new(r#"(?i)<script\b[^>]*>"#).unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
        let mut n = 0;
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("html") {
                continue;
            }
            let html = std::fs::read_to_string(&p).unwrap();
            assert!(!on_attr.is_match(&html), "{} 含内联事件处理器", p.display());
            for m in script_tag.find_iter(&html) {
                assert!(m.as_str().contains("src="), "{} 含内联 <script>: {}", p.display(), m.as_str());
            }
            n += 1;
        }
        assert!(n >= 5, "应扫到全部 ui 页面，实际 {n}");
    }

    #[test]
    fn 只允许打开_http_地址() {
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "ftp://x", "hanako://x", "", "  /usr/bin/x", "data:text/html,x"] {
            assert!(open_http_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn 无窗口隐式退出被拦() {
        assert!(should_prevent_exit(None));
    }

    #[test]
    fn 显式退出放行() {
        assert!(!should_prevent_exit(Some(0)));
        assert!(!should_prevent_exit(Some(1)));
    }
}

// ────────────────────────────────────────────────────────────────
// 票 14：授权码登录
// ────────────────────────────────────────────────────────────────

/// 构造授权管理器，把「凭据变化 → 清旧配置 + 重启 daemon」接到 supervisor 上。
///
/// 钥匙串不可用（无头 Linux / 用户拒绝解锁）时先探测，降级为会话内内存存储并明确告警，
/// 而不是静默丢凭据：此时登录仍可用，但重启应用后需重新授权。
fn build_auth_manager(supervisor: &Arc<DaemonSupervisor>) -> Arc<AuthManager> {
    let store: Arc<dyn CredentialStore> = match KeyringStore::probe() {
        Ok(()) => Arc::new(KeyringStore::new()),
        Err(e) => {
            log::warn!("[auth] {e}；降级为会话内存储，重启应用后需重新授权");
            Arc::new(MemoryStore::new())
        }
    };
    let sup = supervisor.clone();
    let sup_for_logout = supervisor.clone();
    // 授权写入与 daemon 重载必须用同一个存储（见 DaemonConfig::from_env_or_file_with）
    let store_for_reload = store.clone();
    let deps = AuthDeps {
        transport: Arc::new(UreqTransport),
        store,
        open_url: Arc::new(|u| webbrowser::open(u).map_err(|e| e.to_string())),
        sleep: Arc::new(std::thread::sleep),
        now: Arc::new(chrono::Utc::now),
        on_credential: Arc::new(move || {
            // 旧版手填配置优先级高于钥匙串，不清掉会遮蔽刚拿到的新凭据
            if let Err(e) = DaemonConfig::remove_legacy_file() {
                log::warn!("[auth] {e}");
            }
            // 确认页上的名字只当显示名兜底（身份恒为主机名）；须在 reload 之前写，重连注册帧才带上
            if let Ok(Some(c)) = store_for_reload.load() {
                let machine = daemon::config::default_node_id_pub();
                match Paths::real().and_then(|p| daemon::commands::adopt_auth_name_as_display(&p, c.node_name.as_deref(), &machine)) {
                    Ok(true) => log::info!("[auth] 授权页名字已作为显示名"),
                    Ok(false) => {}
                    Err(e) => log::warn!("[auth] 写显示名失败（不影响登录）: {e}"),
                }
            }
            sup.reload_credentials(store_for_reload.as_ref());
        }),
        on_state: Arc::new(|st| log::info!("[auth] 状态 → {}", describe_state(st))),
        on_signed_out: Arc::new(move || {
            // 旧版手填配置也要清：否则下次启动 daemon 会从 config.json 读到 token 自己连回去
            if let Err(e) = DaemonConfig::remove_legacy_file() {
                log::warn!("[auth] {e}");
            }
            sup_for_logout.stop();
        }),
    };
    let hub = daemon::config::resolve_hub_url(|k| std::env::var(k).ok());
    let machine = daemon::config::default_node_id_pub();
    AuthManager::new(deps, hub, machine, env!("CARGO_PKG_VERSION").to_string())
}

/// 状态的日志描述（不含任何 secret / 完整确认页地址里的码以外的内容）。
fn describe_state(st: &AuthState) -> String {
    match st {
        AuthState::SignedOut => "未登录".into(),
        AuthState::AwaitingApproval { user_code, .. } => format!("等待网页确认（码 {user_code}）"),
        AuthState::SignedIn { agent_id, expires_at } => format!("已登录 agent={agent_id} 到期={expires_at}"),
        AuthState::NeedReauth { reason } => format!("需要重新授权（{reason:?}）"),
    }
}

/// 后台续期调度：独立线程，每 [`RENEW_CHECK_INTERVAL`] 检查一次，真正续期只在到期前 24h 内发生。
///
/// 启动后先等一个周期再查第一次：应用刚启动时网络/钥匙串可能还没就绪，
/// 且用户刚登录完不该立刻又打一次 hub。
fn start_renew_scheduler(auth: Arc<AuthManager>) {
    std::thread::Builder::new()
        .name("hanako-renew".into())
        .spawn(move || loop {
            std::thread::sleep(RENEW_CHECK_INTERVAL);
            let step = auth.tick_renew();
            log::debug!("[auth] 续期检查: {step:?}");
        })
        .expect("启动续期调度线程失败");
}

/// 当前登录状态（设置窗 / 托盘轮询）。不含 secret。
#[tauri::command]
fn auth_state(auth: tauri::State<'_, Arc<AuthManager>>) -> serde_json::Value {
    match auth.state() {
        AuthState::SignedOut => serde_json::json!({"state": "signed_out"}),
        AuthState::AwaitingApproval { user_code, verification_url } => {
            serde_json::json!({"state": "awaiting", "user_code": user_code, "verification_url": verification_url})
        }
        AuthState::SignedIn { agent_id, expires_at } => {
            serde_json::json!({"state": "signed_in", "agent_id": agent_id, "expires_at": expires_at})
        }
        AuthState::NeedReauth { reason } => serde_json::json!({"state": "need_reauth", "reason": format!("{reason:?}")}),
    }
}

/// 发起浏览器授权码登录。阻塞轮询，故放到 blocking 线程，命令本身立即返回「已发起」。
#[tauri::command]
fn auth_login(agent_id: Option<String>, auth: tauri::State<'_, Arc<AuthManager>>) -> Result<(), String> {
    let auth = auth.inner().clone();
    std::thread::spawn(move || {
        let r = auth.login(agent_id);
        if !matches!(r, LoginOutcome::SignedIn | LoginOutcome::AlreadyRunning) {
            log::warn!("[auth] 登录未成功: {r:?}");
        }
    });
    Ok(())
}

/// 登出：通知服务端吊销 → 清钥匙串 → 停 daemon。含网络请求，放 blocking 线程避免卡住 UI 线程。
#[tauri::command]
async fn auth_logout(auth: tauri::State<'_, Arc<AuthManager>>) -> Result<(), String> {
    let auth = auth.inner().clone();
    tauri::async_runtime::spawn_blocking(move || auth.logout())
        .await
        .map_err(|e| e.to_string())?
}

// ────────────────────────────────────────────────────────────────
// 日志
// ────────────────────────────────────────────────────────────────

/// 初始化日志（简易 stderr logger，RUST_LOG 控制级别）。
fn logger_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        log::set_logger(&StderrLogger)
            .map(|_| log::set_max_level(log::LevelFilter::Info))
            .ok();
    });
}

/// 供 examples / 联调工具复用同一 logger（避免为探针多引一个日志依赖）。
pub fn init_logger_for_tools() {
    logger_init();
}

/// 简易 stderr logger（占位）。
struct StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("[{}] {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}
