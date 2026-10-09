// src-tauri/src/daemon/supervisor.rs
//! DaemonSupervisor：管理 daemon 生命周期，支持配置变更后热重启。
//!
//! # 设计决策：tokio::sync::watch 而非 CancellationToken
//!
//! 选择 `tokio::sync::watch::Receiver<bool>` 作为停止信号，原因：
//! 1. tokio 已是依赖，无需新增 tokio-util；
//! 2. watch channel 天然支持多接收端 clone（select! 中 `changed().await` 即可）；
//! 3. CancellationToken 功能更强，但本场景只需二值停止信号，watch 足够且轻量。
//!
//! # 已连接状态追踪（I2 修复：每次 start_with_cfg 分配独立 flag）
//!
//! 每次 `start_with_cfg()` 都分配一个**新的** `Arc<AtomicBool>` 并存储在
//! `RunningDaemon.connected` 中，同时传给新建的 `DaemonClient`。
//!
//! 修复前：supervisor 持有单一共享 `Arc<AtomicBool> connected`，旧 client 退出时
//! 写 false 会覆盖新 client 刚写下的 true，造成状态闪烁（竞态）。
//!
//! 修复后：`status()` 从当前 `RunningDaemon` 读 flag，旧 client 的写操作
//! 打到已孤立的旧 flag，对新 flag 完全无影响。`stop_current()` 将旧 flag 置 false
//! 的逻辑保留（无害，因为旧快照立即被 take() 丢弃）。
//!
//! # 线程安全
//!
//! - supervisor 本身可通过 `Arc<DaemonSupervisor>` 在 Tauri 状态中共享；
//! - 内部所有可变状态均受 `Mutex` 或原子量保护。

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use super::approval_native::ApprovalBridge;
use super::client::DaemonClient;
use super::config::DaemonConfig;
use super::register::NodeLink;

// ────────────────────────────────────────────────────────────────
// DaemonSupervisor（pub，通过 Arc 共享为 Tauri 状态）
// ────────────────────────────────────────────────────────────────

/// daemon 生命周期管理器，支持热重启。
///
/// 由 `lib.rs::run()` 构造，以 `Arc<DaemonSupervisor>` 注册为 Tauri 状态，
/// 供 `save_daemon_config` 命令调用 `restart(cfg)` 触发热重启。
pub struct DaemonSupervisor {
    /// daemon↔GUI 审批桥（跨 restart 保持同一个 Arc）
    bridge: Arc<ApprovalBridge>,

    /// 当前运行中的 daemon 状态（受 Mutex 保护，restart 时替换）
    running: Mutex<Option<RunningDaemon>>,

    /// 授权请求桥（跨 restart 保持同一个 Arc；弹窗命令与 daemon 共用）
    auth_requests: Arc<super::auth_request::AuthRequestBridge>,

    /// 最近一次成功连上的时间（HH:MM，本地时区），设置窗「未连接 · 正在重试（上次 15:02）」用。
    /// 跨 restart 保留——重启期间用户看到的仍是真实的上次连上时间。
    last_connected: Mutex<Option<String>>,

    /// 托盘状态中枢（票 17）：lib.rs setup 阶段注入；None = 不接托盘/通知（测试 / headless）
    hub: Mutex<Option<Arc<super::tray_hub::TrayHub>>>,

    /// 本机暂停状态（票 17）：跨 restart 共享，热重启不会偷偷解除暂停
    pause: Arc<super::pause::PauseState>,
    /// 退出保护（票 17）：进行中写操作计数
    quit_guard: Arc<super::quit_guard::QuitGuard>,

    /// 上传偏好弹窗桥（票 18）：跨 restart 共享；lib.rs 注入弹窗实现
    uploads: Arc<super::upload_bridge::UploadBridge>,
    /// 预览确认弹窗桥（本地文件预览 票 03）。跨 restart 共享同一实例——
    /// 与上传桥**各自独立**（预览排队不互顶，上传互顶）。
    previews: Arc<super::preview_bridge::PreviewBridge>,

    /// 当前连接的出站队列（client 每次连上登记，断开清空）：托盘「暂停」要主动推 `pause_state`
    outbound: Mutex<Option<tokio::sync::mpsc::Sender<String>>>,
}

/// 一次运行中的 daemon 快照。
struct RunningDaemon {
    /// 当前使用的配置（用于 get_daemon_config 返回 node_id / base_url）
    cfg: DaemonConfig,
    /// 停止信号发送端；drop 或发送 true 即停止对应的 client 任务
    stop_tx: tokio::sync::watch::Sender<bool>,
    /// 本次运行的连接状态标志（每次 start_with_cfg 分配新实例）。
    ///
    /// status() 从此处读取，确保读到的是【当前】client 的状态，
    /// 而非旧 client 在退出时写下的 false（I2 竞态修复）。
    connected: Arc<AtomicBool>,
}

impl DaemonSupervisor {
    /// 构造空 supervisor（尚未启动 daemon）。
    pub fn new(bridge: Arc<ApprovalBridge>) -> Arc<Self> {
        Arc::new(Self {
            bridge,
            running: Mutex::new(None),
            auth_requests: super::auth_request::AuthRequestBridge::new(),
            last_connected: Mutex::new(None),
            hub: Mutex::new(None),
            pause: Arc::new(super::pause::PauseState::new()),
            quit_guard: super::quit_guard::QuitGuard::new(),
            outbound: Mutex::new(None),
            uploads: super::upload_bridge::UploadBridge::new(),
            previews: super::preview_bridge::PreviewBridge::new(),
        })
    }

    /// 注入托盘状态中枢。必须在 `start_if_configured` 之前或之后均可：之后注入的只影响下次（重）启动的 client。
    pub fn set_hub(&self, hub: Arc<super::tray_hub::TrayHub>) {
        *self.hub.lock().unwrap() = Some(hub);
    }

    /// 若配置可用（env 或文件），启动 daemon。等同于应用启动时的首次启动。
    pub fn start_if_configured(self: &Arc<Self>) {
        match DaemonConfig::from_env_or_file() {
            Ok(cfg) => self.start_with_cfg(cfg),
            Err(e) => {
                log::warn!("[supervisor] 未配置（{e}），daemon 不启动，仅壳运行（云端模式）");
            }
        }
    }

    /// 使用新配置重启 daemon（停止旧 daemon → 启动新 daemon）。
    ///
    /// 调用方：`save_daemon_config` Tauri 命令（配置持久化后调用）。
    ///
    /// # 新旧 client 共存窗口（fire-and-forget 重启）
    ///
    /// `restart()` 向旧 client 发送 stop 信号后**立即** spawn 新 client 线程，
    /// 不等待旧线程退出（fire-and-forget）。旧 client 的短暂共存无害，原因：
    ///
    /// 1. **独立 link_id**：新 `NodeLink` 在 `start_with_cfg` 里重新生成，
    ///    服务端以 link_id 区分节点连接，旧连接被孤立后服务端会在下次心跳超时时驱逐。
    /// 2. **共存上界有界**：旧 client 在 WS 循环或 backoff sleep 的下一个
    ///    `select!` tick 检测到 stop 信号即退出；最坏情况等待一个最大退避（上界约 60s）。
    /// 3. **新 flag 隔离**：每次 `start_with_cfg` 为新 client 分配独立的
    ///    `Arc<AtomicBool>`；旧 client 退出时的 `store(false)` 打到已孤立的旧 flag，
    ///    `status()` 只读当前 `RunningDaemon` 的 flag，不受旧 client 干扰（I2 修复）。
    pub fn restart(self: &Arc<Self>, cfg: DaemonConfig) {
        log::info!(
            "[supervisor] 热重启 daemon base_url={} node_id={}",
            cfg.base_url,
            cfg.node_id
        );
        self.stop_current();
        self.start_with_cfg(cfg);
    }

    /// 重新按优先级加载配置并重启 daemon（授权成功 / 续期成功后调用，让 daemon 换用新凭据）。
    ///
    /// 为什么必须重启：续期时 hanako 会**吊销旧凭据**，而运行中的 daemon 握手用的还是旧 token，
    /// 下次断线重连必 403。授权成功同理（之前可能根本没有 daemon 在跑）。
    /// 加载失败（钥匙串刚写入却读不出等）只记日志、不停掉现有 daemon——宁可继续用旧连接也不要把人踢下线。
    pub fn reload_credentials(self: &Arc<Self>, store: &dyn super::credential_store::CredentialStore) {
        match DaemonConfig::from_env_or_file_with(store) {
            Ok(cfg) => self.restart(cfg),
            Err(e) => log::warn!("[supervisor] 凭据已变更但重新加载配置失败（保持现状）: {e}"),
        }
    }

    pub fn hub(&self) -> Option<Arc<super::tray_hub::TrayHub>> {
        self.hub.lock().unwrap().clone()
    }

    /// 退出登录后停掉 daemon（不重启）。之后 status() 为未配置，直到下次登录 reload_credentials。
    pub fn stop(&self) {
        log::info!("[supervisor] 已退出登录，停止 daemon");
        self.stop_current();
    }

    /// 向服务端上报本机暂停状态（`pause_state` 帧）。连接不在线时无操作——
    /// 重连后由 client 在注册成功时补发（见 client.rs，暂停状态随本机走，不依赖服务端记忆）。
    pub fn send_pause_state(&self, info: Option<super::pause::PauseInfo>) {
        if let Some(tx) = self.outbound.lock().unwrap().as_ref() {
            let _ = tx.try_send(super::pause::pause_frame(info).to_string());
        }
    }

    /// client 建立连接后登记出站队列，供 supervisor 侧（托盘回调）主动推帧。
    pub fn set_outbound(&self, tx: Option<tokio::sync::mpsc::Sender<String>>) {
        *self.outbound.lock().unwrap() = tx;
    }

    pub fn uploads(&self) -> Arc<super::upload_bridge::UploadBridge> {
        self.uploads.clone()
    }

    pub fn previews(&self) -> Arc<super::preview_bridge::PreviewBridge> {
        self.previews.clone()
    }

    pub fn pause_state(&self) -> Arc<super::pause::PauseState> {
        self.pause.clone()
    }

    pub fn quit_guard(&self) -> Arc<super::quit_guard::QuitGuard> {
        self.quit_guard.clone()
    }

    /// 用当前运行配置原地重启一次，使新注入的 hub 生效。未运行（未配置）则无操作。
    /// 仅在 setup 阶段调用一次：首个 client 在 hub 注入前已启动，不重启就永远拿不到状态事件。
    pub fn restart_with_current_hub(self: &Arc<Self>) {
        let cfg = self.running.lock().unwrap().as_ref().map(|r| r.cfg.clone());
        if let Some(cfg) = cfg {
            self.restart(cfg);
        }
    }

    /// 授权请求桥（lib.rs 注入弹窗实现、弹窗命令读写都走它）。
    pub fn auth_requests(&self) -> Arc<super::auth_request::AuthRequestBridge> {
        self.auth_requests.clone()
    }

    /// 当前 daemon 使用的凭据绑定的执行体（登录时正在用的助手）。
    pub fn current_agent(&self) -> Option<String> {
        self.running.lock().unwrap().as_ref().and_then(|r| r.cfg.agent_id.clone())
    }

    /// 最近一次连上的时间（HH:MM）。
    pub fn last_connected(&self) -> Option<String> {
        self.last_connected.lock().unwrap().clone()
    }

    /// daemon 当前状态（供 daemon_status 命令）。
    pub fn status(&self) -> DaemonStatus {
        let running_guard = self.running.lock().unwrap();
        match running_guard.as_ref() {
            None => DaemonStatus {
                configured: false,
                connected: false,
                node_id: None,
                agent_id: None,
                last_connected: self.last_connected.lock().unwrap().clone(),
            },
            Some(r) => {
                // 读当前 RunningDaemon 自己的 flag，不受旧 client 写操作影响（I2 修复）
                let connected = r.connected.load(Ordering::Relaxed);
                if connected {
                    // 由被轮询驱动：设置窗/托盘每次查状态时顺带刷新「最近连上」
                    *self.last_connected.lock().unwrap() =
                        Some(chrono::Local::now().format("%H:%M").to_string());
                }
                DaemonStatus {
                    configured: true,
                    connected,
                    node_id: Some(r.cfg.node_id.clone()),
                    agent_id: r.cfg.agent_id.clone(),
                    last_connected: self.last_connected.lock().unwrap().clone(),
                }
            }
        }
    }

    /// 返回当前配置的 base_url 和 node_id（不含 token）。
    /// 若未配置返回 None。
    pub fn current_config_display(&self) -> Option<ConfigDisplay> {
        let guard = self.running.lock().unwrap();
        guard.as_ref().map(|r| ConfigDisplay {
            base_url: r.cfg.base_url.clone(),
            node_id: r.cfg.node_id.clone(),
        })
    }

    // ── 内部方法 ─────────────────────────────────────────────────

    /// 停止当前运行中的 daemon（发送停止信号）。
    fn stop_current(&self) {
        let mut guard = self.running.lock().unwrap();
        if let Some(running) = guard.take() {
            // 连接状态立即置 false（写旧 flag，stop 后旧 RunningDaemon 即被丢弃）
            running.connected.store(false, Ordering::Relaxed);
            // 发送停止信号；watch::Receiver 在 client 的 select! 中检测
            let _ = running.stop_tx.send(true);
            log::info!("[supervisor] 已发送停止信号到旧 daemon");
        }
    }

    /// 以给定配置启动一个新的 daemon 线程。
    ///
    /// 每次调用分配一个**新的** `Arc<AtomicBool>` 作为本次运行的 connected flag，
    /// 并同时存入 `RunningDaemon`（供 `status()` 读取）和传给新建的 `DaemonClient`。
    /// 旧 client 退出时的写操作打到已孤立的旧 flag，对新 flag 完全无影响（I2 修复）。
    fn start_with_cfg(self: &Arc<Self>, cfg: DaemonConfig) {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let link = NodeLink::new(&cfg);

        log::info!(
            "[supervisor] 启动 daemon node_id={} base_url={}",
            cfg.node_id,
            cfg.base_url
        );

        // 每次启动分配全新 connected flag，启动时先 false，等 registered ACK
        let connected = Arc::new(AtomicBool::new(false));

        // 运行时记录（含新 flag 的 Arc，供 status() 读取）
        {
            let mut guard = self.running.lock().unwrap();
            *guard = Some(RunningDaemon {
                cfg: cfg.clone(),
                stop_tx,
                connected: connected.clone(),
            });
        }

        let bridge = self.bridge.clone();
        let auth_requests = self.auth_requests.clone();
        let hub = self.hub.lock().unwrap().clone();
        let pause = self.pause.clone();
        let quit_guard = self.quit_guard.clone();
        let me = self.clone();
        let uploads = self.uploads.clone();
        let previews = self.previews.clone();

        // 独立线程 + 独立 tokio runtime（与 GUI 线程完全解耦，同 spawn_daemon_if_configured 原模式）
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("[supervisor] 创建 tokio runtime 失败: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let mut client = DaemonClient::new(cfg, link, bridge, stop_rx, connected)
                    .with_auth_requests(auth_requests)
                    .with_controls(pause, quit_guard)
                    .with_uploads(uploads)
                    .with_previews(previews)
                    .with_outbound_hook(Arc::new(move |tx| me.set_outbound(tx)));
                if let Some(h) = hub {
                    client = client.with_hub(h);
                }
                client.run().await;
            });
        });
    }
}

// ────────────────────────────────────────────────────────────────
// 状态 DTO（Tauri 命令序列化用）
// ────────────────────────────────────────────────────────────────

/// daemon_status 命令返回值。
#[derive(Debug, serde::Serialize)]
pub struct DaemonStatus {
    /// 是否已有有效配置（env 或文件）
    pub configured: bool,
    /// 是否已成功注册到服务端
    pub connected: bool,
    /// 当前使用的节点 ID（未配置时为 None）
    pub node_id: Option<String>,
    /// 凭据绑定的执行体（登录时用的助手）；手填路径为 None
    pub agent_id: Option<String>,
    /// 最近一次连上的时间 HH:MM；从未连上为 None
    pub last_connected: Option<String>,
}

/// get_daemon_config 命令返回值（不含 token）。
#[derive(Debug, serde::Serialize)]
pub struct ConfigDisplay {
    pub base_url: String,
    pub node_id: String,
}

// ────────────────────────────────────────────────────────────────
// 单元测试（headless，不涉及真实 WS 连接）
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_supervisor() -> Arc<DaemonSupervisor> {
        let bridge = ApprovalBridge::new();
        DaemonSupervisor::new(bridge)
    }

    /// 新建 supervisor 状态 = 未配置、未连接、无 node_id。
    #[test]
    fn 新建状态为未配置() {
        let s = make_supervisor();
        let st = s.status();
        assert!(!st.configured);
        assert!(!st.connected);
        assert!(st.node_id.is_none());
    }

    /// current_config_display 在无运行状态时返回 None。
    #[test]
    fn 无运行时_current_config_display_为_none() {
        let s = make_supervisor();
        assert!(s.current_config_display().is_none());
    }

    /// 手动向 running 写入后，status 返回 configured=true，node_id 正确。
    #[test]
    fn 写入运行快照后_status_已配置() {
        let s = make_supervisor();
        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut guard = s.running.lock().unwrap();
            *guard = Some(RunningDaemon {
                cfg: DaemonConfig {
                    base_url: "https://x.example.com".into(),
                    token: "tok".into(),
                    node_id: "node_test".into(),
            agent_id: None,
                },
                stop_tx,
                connected: Arc::new(AtomicBool::new(false)),
            });
        }
        let st = s.status();
        assert!(st.configured);
        assert_eq!(st.node_id.as_deref(), Some("node_test"));
    }

    /// stop_current 清除 running 快照并将 connected 设为 false。
    /// 新 flag 保存在 RunningDaemon 内部；stop_current 把旧 flag 置 false 后 take() 丢弃。
    #[test]
    fn stop_current_清除快照() {
        let s = make_supervisor();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // 保存旧 flag 的 Arc，stop_current 后验证它被置 false
        let old_connected = Arc::new(AtomicBool::new(true)); // 模拟已连接
        {
            let mut guard = s.running.lock().unwrap();
            *guard = Some(RunningDaemon {
                cfg: DaemonConfig {
                    base_url: "https://x.example.com".into(),
                    token: "tok".into(),
                    node_id: "node_test".into(),
            agent_id: None,
                },
                stop_tx,
                connected: old_connected.clone(),
            });
        }

        s.stop_current();

        // 旧 flag 应被清 false
        assert!(!old_connected.load(Ordering::Relaxed));
        // running 应为 None
        assert!(s.running.lock().unwrap().is_none());
        // stop 信号应收到 true
        assert_eq!(*stop_rx.borrow(), true);
    }

    /// status() 读取当前 RunningDaemon 的 connected flag，不受旧 client 写操作影响（I2 验证）。
    #[test]
    fn status_读取当前_running_flag_不受旧_flag_影响() {
        let s = make_supervisor();
        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);
        let current_connected = Arc::new(AtomicBool::new(false));
        {
            let mut guard = s.running.lock().unwrap();
            *guard = Some(RunningDaemon {
                cfg: DaemonConfig {
                    base_url: "https://x.example.com".into(),
                    token: "tok".into(),
                    node_id: "node_i2".into(),
            agent_id: None,
                },
                stop_tx,
                connected: current_connected.clone(),
            });
        }

        // 模拟新 client 收到 registered ACK → 写 true
        current_connected.store(true, Ordering::Relaxed);
        assert!(s.status().connected, "新 flag=true 时 status 应返回 connected=true");

        // 模拟旧 client（孤立 Arc）退出写 false — 用独立 Arc 模拟
        let orphaned = Arc::new(AtomicBool::new(false));
        orphaned.store(false, Ordering::Relaxed);
        // current_connected 仍为 true，status() 应不受孤立 flag 影响
        assert!(s.status().connected, "孤立 flag 写 false 不应影响当前 status");
    }

    /// current_config_display 在有配置时返回正确值（不含 token）。
    #[test]
    fn current_config_display_不含_token() {
        let s = make_supervisor();
        let (stop_tx, _) = tokio::sync::watch::channel(false);
        {
            let mut guard = s.running.lock().unwrap();
            *guard = Some(RunningDaemon {
                cfg: DaemonConfig {
                    base_url: "https://display.example.com".into(),
                    token: "secret_token".into(),
                    node_id: "node_display".into(),
            agent_id: None,
                },
                stop_tx,
                connected: Arc::new(AtomicBool::new(false)),
            });
        }
        let display = s.current_config_display().unwrap();
        assert_eq!(display.base_url, "https://display.example.com");
        assert_eq!(display.node_id, "node_display");
        // token 不在 ConfigDisplay 结构中，无法序列化到前端
    }
}
