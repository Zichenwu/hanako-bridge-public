// src-tauri/src/daemon/client.rs
//! daemon WSS 出站客户端：连接云端 → 注册节点 → 心跳 → 接收派活 → 执行本地工具 → 回结果。
//!
//! 安全红线（spec §3.1）：本客户端只【主动出站】连云端，不监听任何入站端口。
//! 与 webview 无 IPC 通道——两者在同一进程但互不感知。
//!
//! # WebSocket split 设计
//! `tokio_tungstenite::WebSocketStream` 不能 clone，必须用
//! `futures_util::StreamExt::split()` 分成 `SplitSink`（发）和 `SplitStream`（收）。
//! 工具执行 spawn 到独立 task，结果经 `tokio::sync::mpsc` channel 回传主循环统一发送。
//!
//! # 热重启支持（P3.5）
//! `run()` 接受一个 `tokio::sync::watch::Receiver<bool>` 停止信号。
//! 当 `DaemonSupervisor::restart()` 发送 stop=true 后：
//! - 重连 backoff 中的 `sleep` 被 select! 打断，函数返回。
//! - connect_once 内的 select! 循环也检查 stop_rx，收到信号后 clean return。
//!
//! # 已连接状态
//! 收到服务端 `registered` ACK 后，设 `connected_flag = true`。
//! connect_once 返回（正常关闭/错误/停止）后，设 `connected_flag = false`。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::Message;

use super::approval::{ApprovalManager, ApprovalMode, Approver};
use super::approval_native::{ApprovalBridge, NativeWindowApprover};
use super::config::DaemonConfig;
use super::heartbeat::{backoff_delay, HEARTBEAT_INTERVAL, POLICY_POLL_INTERVAL};
use super::policy::Policy;
use super::register::{grants_changed_frame, roots_changed_frame, NodeLink, RegisterFrame};

/// 运行期上报的客户端版本字符串（register 帧 / 节点状态 appVersion）。
///
/// 基线 = Cargo 包版本（`tauri.conf.json` 恒为 0.1.0，单靠它真机分不出新旧包）。
/// 为区分构建产物，编译期若给了 `HANAKO_BUILD_SHA`（CI 注入 commit 短 sha）则拼在其后，
/// 形如 `0.1.0+g1a2b3c4`（semver build metadata）。本地/开发构建无此 env → 保持纯版本号。
pub fn build_app_version() -> String {
    let base = env!("CARGO_PKG_VERSION");
    match option_env!("HANAKO_BUILD_SHA") {
        Some(sha) if !sha.is_empty() => format!("{}+g{}", base, sha),
        _ => base.to_string(),
    }
}

/// 比对已发布快照与当前策略，返回需要推送的帧（roots 与 grants 分别判断）。
///
/// 只比对云端可见的部分（rootId/显示名/模式 与 grants），绝对路径变化但 rootId 不变不会触发。
pub fn policy_push_frames(published: &Policy, now: &Policy) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if published.roots_view() != now.roots_view() {
        out.push(roots_changed_frame(now));
    }
    if published.grants != now.grants {
        out.push(grants_changed_frame(now));
    }
    out
}

/// daemon 出站客户端。
pub struct DaemonClient {
    cfg: DaemonConfig,
    link: NodeLink,
    /// daemon↔GUI 审批桥：持有 pending 请求 + AppHandle 引用。
    /// 由 lib.rs::run() 构造后传入，AppHandle 在 GUI setup 后注入。
    bridge: Arc<ApprovalBridge>,
    /// 停止信号接收端（watch::Receiver<bool>）：收到 true 时退出重连循环。
    /// 由 DaemonSupervisor 传入；restart() 时 supervisor 发送 true 触发停止。
    stop_rx: tokio::sync::watch::Receiver<bool>,
    /// 连接状态标志（Arc<AtomicBool>），由 supervisor 共享：
    /// - 收到 registered ACK 时设 true
    /// - connect_once 退出（任何原因）后设 false
    connected_flag: Arc<AtomicBool>,
    /// 应用版本（随注册帧上报，服务端用于「有新版本」提示）
    app_version: String,
    /// 授权请求桥（票 15b）：服务端 auth_request 帧 → 本机弹窗 → 写 grants
    auth_requests: Arc<super::auth_request::AuthRequestBridge>,
    /// 托盘状态中枢（票 17）：连接事件 → 状态机 → 通知 + 托盘。None = 不接（测试 / headless）
    hub: Option<Arc<super::tray_hub::TrayHub>>,
    /// 键鼠空闲来源（票 17）：心跳上报 idleSeconds。取不到不上报
    idle: Arc<dyn super::idle::IdleSource>,
    /// 本机暂停（票 17）：暂停期间任务入口一律拒绝。跨 restart 共享（supervisor 注入），None = 从不暂停
    pause: Option<Arc<super::pause::PauseState>>,
    /// 退出保护（票 17）：写类任务进行中计数
    quit_guard: Option<Arc<super::quit_guard::QuitGuard>>,
    /// 上传弹窗桥（票 18）
    uploads: Option<Arc<super::upload_bridge::UploadBridge>>,
    /// 预览确认弹窗桥（本地文件预览 票 03）。**与上传桥是两个独立实例**：
    /// 上传桥的 ask 会顶掉旧请求，预览是用户连点多个文件、天然并发，必须排队不互顶。
    previews: Option<Arc<super::preview_bridge::PreviewBridge>>,
    /// 连接建立 / 断开时登记出站队列的回调（supervisor 注入；托盘「暂停」靠它主动推帧）
    on_outbound: Option<Arc<dyn Fn(Option<mpsc::Sender<String>>) + Send + Sync>>,
    /// 审计日志器（票 19）：心跳带当日读写计数到服务端。Arc 共享给各写任务。
    audit: Arc<super::audit::AuditLogger>,
}

impl DaemonClient {
    pub fn new(
        cfg: DaemonConfig,
        link: NodeLink,
        bridge: Arc<ApprovalBridge>,
        stop_rx: tokio::sync::watch::Receiver<bool>,
        connected_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            cfg,
            link,
            bridge,
            stop_rx,
            connected_flag,
            app_version: build_app_version(),
            auth_requests: super::auth_request::AuthRequestBridge::new(),
            hub: None,
            idle: Arc::new(super::idle::SystemIdle),
            pause: None,
            quit_guard: None,
            on_outbound: None,
            uploads: None,
            previews: None,
            audit: Arc::new(super::audit::AuditLogger::new(
                // 可被 HANAKO_DATA_DIR 覆盖（测试/集成测试隔离；Windows 上 home_dir 走 KNOWNFOLDER 不读 HOME）
                std::env::var_os("HANAKO_DATA_DIR").map(std::path::PathBuf::from)
                    .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join(".hanako-tauri")),
            )),
        }
    }

    /// 接入托盘状态中枢（lib.rs / supervisor 注入）。
    pub fn with_hub(mut self, hub: Arc<super::tray_hub::TrayHub>) -> Self {
        self.hub = Some(hub);
        self
    }

    /// 接入暂停状态与退出保护（supervisor 注入，跨 restart 共享同一实例）。
    pub fn with_controls(
        mut self,
        pause: Arc<super::pause::PauseState>,
        quit_guard: Arc<super::quit_guard::QuitGuard>,
    ) -> Self {
        self.pause = Some(pause);
        self.quit_guard = Some(quit_guard);
        self
    }

    pub fn with_uploads(mut self, b: Arc<super::upload_bridge::UploadBridge>) -> Self {
        self.uploads = Some(b);
        self
    }

    /// 接入预览确认弹窗桥（本地文件预览 票 03）。缺省不接 = 预览一律「未获允许」。
    pub fn with_previews(mut self, b: Arc<super::preview_bridge::PreviewBridge>) -> Self {
        self.previews = Some(b);
        self
    }

    pub fn with_outbound_hook(mut self, f: Arc<dyn Fn(Option<mpsc::Sender<String>>) + Send + Sync>) -> Self {
        self.on_outbound = Some(f);
        self
    }

    /// 把连接事件转给状态中枢（无中枢时为空操作）。
    fn emit(&self, ev: super::tray_state::Event) {
        if let Some(h) = &self.hub {
            h.on_event(ev);
        }
    }

    /// 换用外部共享的授权请求桥（lib.rs 需要与弹窗命令共用同一个桥）。
    pub fn with_auth_requests(mut self, b: Arc<super::auth_request::AuthRequestBridge>) -> Self {
        self.auth_requests = b;
        self
    }

    /// 把 http(s) base_url 转成 ws(s) 节点接入点。
    /// 路径与服务端 route-security 分类键一致：/api/execution-node/ws。
    fn ws_url(&self) -> String {
        let mut u = self
            .cfg
            .base_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        u.push_str("/api/execution-node/ws");
        u
    }

    /// 主循环：永不返回（除非收到停止信号）。
    pub async fn run(mut self) {
        let mut attempt = 0u32;
        loop {
            // 检查停止信号（在 backoff sleep 之前）
            if *self.stop_rx.borrow() {
                log::info!("[daemon] 收到停止信号，退出重连循环");
                return;
            }

            match self.connect_once().await {
                Ok(ConnectResult::Normal) => {
                    log::info!("[daemon] 连接正常结束（对端关闭）");
                    self.emit(super::tray_state::Event::Lost);
                    attempt = 0; // 正常结束后重置退避
                }
                Ok(ConnectResult::Stopped) => {
                    log::info!("[daemon] 收到停止信号，退出（connect_once 内）");
                    self.connected_flag.store(false, Ordering::Relaxed);
                    return;
                }
                // 被顶 / 注册被拒：重连没有意义，继续重连会与另一台机器无限互顶或空转打服务端
                Ok(ConnectResult::Displaced) => {
                    self.connected_flag.store(false, Ordering::Relaxed);
                    self.emit(super::tray_state::Event::Displaced);
                    log::warn!("[daemon] 不再重连（被顶），daemon 停止");
                    return;
                }
                Ok(ConnectResult::Rejected) => {
                    self.connected_flag.store(false, Ordering::Relaxed);
                    // 注册被拒的典型原因：协议版本过低 → 需升级（其余原因同样不会自愈，托盘提示升级最接近）
                    self.emit(super::tray_state::Event::NeedUpgrade);
                    log::warn!("[daemon] 不再重连（注册被拒），daemon 停止");
                    return;
                }
                Ok(ConnectResult::RemoteDisconnected) => {
                    self.connected_flag.store(false, Ordering::Relaxed);
                    self.emit(super::tray_state::Event::RemoteDisconnect);
                    log::warn!("[daemon] 网页已断开本机，不再自动重连");
                    return;
                }
                Err(e) => {
                    log::warn!("[daemon] 连接失败: {e}");
                    // 握手 403 = 凭据失效（不会自愈，重连只会被持续拒绝）；其余按网络掉线
                    if is_handshake_forbidden(&e) {
                        self.emit(super::tray_state::Event::CredentialInvalid);
                    } else {
                        self.emit(super::tray_state::Event::Lost);
                    }
                }
            }

            // 断连后 connected 设 false，并注销出站队列（否则托盘「暂停」会往已死的队列里塞）
            self.connected_flag.store(false, Ordering::Relaxed);
            if let Some(f) = &self.on_outbound { f(None); }

            let delay = backoff_delay(attempt);
            log::info!("[daemon] {} 后重连（第 {} 次）", humantime(delay), attempt + 1);

            // 在 backoff sleep 中也响应停止信号
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.stop_rx.changed() => {
                    if *self.stop_rx.borrow() {
                        log::info!("[daemon] backoff 中收到停止信号，退出");
                        return;
                    }
                }
            }

            attempt = attempt.saturating_add(1);
        }
    }

    /// 构造带 Bearer 认证的 WS 握手请求。
    ///
    /// 用 tungstenite 的 `client::IntoClientRequest` 生成标准握手请求（含 Sec-WebSocket-Key
    /// 等必需头），再补 Authorization——手写全套握手头容易漏字段导致 400。
    fn build_request(&self, url: &str) -> Result<Request, String> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("构造握手请求失败: {e}"))?;
        let value = format!("Bearer {}", self.cfg.token)
            .parse()
            .map_err(|_| "token 含非法字符，无法作为 header 值".to_string())?;
        request.headers_mut().insert(AUTHORIZATION, value);
        Ok(request)
    }

    /// 建立一次连接：握手（带 Bearer 认证）→ 注册 → 主循环（心跳 + 接收派活）。
    ///
    /// ⚠️ **token 必须放在握手的 Authorization header 里**，不能只放在 register 消息里。
    /// hanako 服务端的 `app.use("*")` 中间件对**所有**请求做认证，**包括 WS 升级那个 GET**。
    /// 实测（2026-07-29 生产容器）：无凭据 / 伪造 Bearer 都是**握手阶段就 403**，
    /// 根本走不到发消息那一步。register 消息只承载「这台机器的自述」（serverNodeId /
    /// capabilities），身份由握手认定。
    async fn connect_once(&mut self) -> Result<ConnectResult, String> {
        let url = self.ws_url();
        log::info!("[daemon] 连接 {url}（node={}）", self.cfg.node_id);

        let request = self.build_request(&url)?;
        let (ws, _resp) = connect_ws(request).await?;

        // ① 发送注册载荷（身份已由握手认定，此处只报机器自述）
        // 新协议帧：link + protocolVersion/appVersion/roots/grants。
        // 目录来自本机授权列表（env ∪ workspaces.json）；路径只在本机，帧里只有 rootId。
        // link 沿用构造时生成的 linkId，保证同一 client 多次重连可被服务端日志关联。
        let policy = Policy::load(self.cfg.agent_id.as_deref());
        let mut frame = RegisterFrame::from_policy(&self.cfg, &policy, &self.app_version);
        frame.link = self.link.clone();
        // 显示名现读策略文件（设置窗改名后经 supervisor 重启重连，下一次注册即带上）；读失败 = 不带，服务端回退默认
        frame.display_name = super::policy::PolicyFile::load().ok().and_then(|f| f.display_name);
        let register_msg = serde_json::to_value(&frame)
            .map_err(|e| format!("序列化注册帧失败: {e}"))?;

        let (mut ws_tx, mut ws_rx) = ws.split();
        let (task_result_tx, mut task_result_rx) = mpsc::channel::<String>(32);

        ws_tx
            .send(Message::Text(register_msg.to_string()))
            .await
            .map_err(|e| format!("发送注册失败: {e}"))?;
        log::info!(
            "[daemon] 已发送注册 linkId={} pv={} roots={} grants={}",
            self.link.link_id,
            frame.protocol_version,
            frame.roots.len(),
            frame.grants.len()
        );

        // ② 构造确认管理器（Task 6：NativeWindowApprover 替换 AutoApprover）
        // 票 17：外面再包一层「网页优先」装饰器——仅当本机开关开启 + 空闲 >2 分钟 + 非删除时才先问网页，
        // 否则（或网页办不到时）原样走本机原生窗口。开关现读磁盘，用户改设置立即生效。
        let native_approver = NativeWindowApprover::new(self.bridge.clone());
        let web_waiters = super::web_confirm::WebConfirmWaiters::new();
        // 审核 C-F6：服务端 task_cancel 的在途任务表（每条连接一张，断线即失效）
        let cancels = super::remote_frames::CancelRegistry::new();
        // 票 07：分片预览的「服务端批准水位」登记表。每条连接一张——断线后随栈帧销毁，
        // 在途传输的 watch 发送端一并 drop，传输任务读到 changed() Err 后自行结束。
        let preview_streams = super::preview_stream::StreamRegistry::new();
        let web_first = super::web_confirm::WebFirstApprover::new(
            Box::new(native_approver) as Box<dyn Approver>,
            Arc::new(web_confirm_switch_on),
            self.idle.clone(),
            web_waiters.clone(),
            task_result_tx.clone(), // 复用出站队列：主循环已把它里面的文本帧原样发给服务端
        );
        let approval_mgr = Arc::new(ApprovalManager::new(
            ApprovalMode::Strict,
            Box::new(web_first) as Box<dyn Approver>,
        ));

        // ③ 审计日志器（Task 7）：用 client 级共享实例（心跳要读当日计数上报）
        let audit = self.audit.clone();

        // ④ 主循环：心跳 + 接收派活 + 发回结果
        // 云端快照当前的样子：注册帧就是首次快照，之后每个心跳 tick 与它比对
        let mut published = policy;
        let mut policy_tick = tokio::time::interval(POLICY_POLL_INTERVAL);
        policy_tick.tick().await;
        let mut hb = tokio::time::interval(HEARTBEAT_INTERVAL);
        hb.tick().await;

        loop {
            tokio::select! {
                // 停止信号：干净退出
                _ = self.stop_rx.changed() => {
                    if *self.stop_rx.borrow() {
                        log::info!("[daemon] connect_once 收到停止信号，关闭连接");
                        let _ = ws_tx.send(Message::Close(None)).await;
                        return Ok(ConnectResult::Stopped);
                    }
                }

                // 心跳：定时发 ping
                _ = hb.tick() => {
                    ws_tx
                        .send(Message::Ping(vec![]))
                        .await
                        .map_err(|e| format!("发送心跳失败: {e}"))?;
                    // 票 17：应用层心跳帧带本机键鼠空闲秒（取不到则不带该字段），
                    // 服务端据此做来源判别与跨机网页确认门槛。服务端对 heartbeat 回 heartbeat_ack，旧版同样认识
                    // 票 19：顺带带当日读写计数（审计日志派生，只报计数），供网页「本机」页展示
                    let hb_frame = super::idle::heartbeat_frame_full(self.idle.idle(), Some(self.audit.today_counts()));
                    ws_tx
                        .send(Message::Text(hb_frame.to_string()))
                        .await
                        .map_err(|e| format!("发送应用心跳失败: {e}"))?;
                    // 顺带推进「>5min 离线」判定
                    if let Some(h) = &self.hub { h.tick(); }
                    log::debug!("[daemon] 心跳 ping");
                }

                // 策略快照比对：设置窗改了目录/读写/授权，秒级推给云端，无需重连
                _ = policy_tick.tick() => {
                    let now_policy = Policy::load(self.cfg.agent_id.as_deref());
                    for f in policy_push_frames(&published, &now_policy) {
                        ws_tx
                            .send(Message::Text(f.to_string()))
                            .await
                            .map_err(|e| format!("推送策略变更失败: {e}"))?;
                        log::info!("[daemon] 已推送 {}", f["type"]);
                    }
                    published = now_policy;
                }

                // 工具执行结果：从 channel 取出后发给服务端
                Some(response) = task_result_rx.recv() => {
                    ws_tx
                        .send(Message::Text(response))
                        .await
                        .map_err(|e| format!("发送结果失败: {e}"))?;
                }

                // 收到服务端消息
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Text(t))) => {
                            match register_ack(&t) {
                                Some(Ack::Registered) => {
                                    log::info!("[daemon] 注册成功: {t}");
                                    // 通知 supervisor：连接已建立
                                    self.connected_flag.store(true, Ordering::Relaxed);
                                    self.emit(super::tray_state::Event::Connected);
                                    if let Some(f) = &self.on_outbound {
                                        f(Some(task_result_tx.clone()));
                                    }
                                    // 票 17：重连后补发本机暂停状态。服务端暂停标记随连接走，重连等于新节点，
                                    // 不补发则「本机暂停」在网络抖动后被悄悄解除
                                    if let Some(p) = &self.pause {
                                        if let Some(info) = p.active(now_unix_ms()) {
                                            let _ = task_result_tx.try_send(super::pause::pause_frame(Some(info)).to_string());
                                        }
                                    }
                                }
                                Some(Ack::Failed) => {
                                    // 新协议客户端：服务端随后会关连接，且重连只会得到同样的拒绝
                                    // （版本过低 / 凭据缺 userId 等都不会自愈），故终止重连。
                                    log::warn!("[daemon] 注册被拒，不再重连: {t}");
                                    return Ok(ConnectResult::Rejected);
                                }
                                None if super::web_confirm::parse_decision(
                                    &serde_json::from_str::<serde_json::Value>(&t).unwrap_or(serde_json::Value::Null)
                                ).is_some() => {
                                    // 票 17：跨机网页确认的回执。解析失败/未知 id 静默忽略（迟到回执）
                                    if let Some((id, d)) = super::web_confirm::parse_decision(
                                        &serde_json::from_str::<serde_json::Value>(&t).unwrap_or(serde_json::Value::Null)
                                    ) {
                                        web_waiters.deliver(&id, d);
                                    }
                                }
                                None if disconnect_reason(&t).is_some() => {
                                    log::warn!("[daemon] 收到网页断开指令 reason={:?}，不再自动重连", disconnect_reason(&t));
                                    return Ok(ConnectResult::RemoteDisconnected);
                                }
                                None if is_displaced(&t) => {
                                    let stopping = *self.stop_rx.borrow();
                                    if stopping {
                                        log::info!("[daemon] 停止中收到 displaced（自己热重启造成的残余顶下线），忽略，不上报托盘");
                                    } else {
                                        log::warn!("[daemon] 被同账号另一台电脑顶下线，不再重连");
                                    }
                                    return Ok(displaced_outcome(stopping));
                                }
                                None => {
                                    // 尝试解析为 task 帧
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                                        if let Some(id) = super::remote_frames::parse_task_cancel(&v) {
                                            let hit = cancels.cancel(&id);
                                            log::info!("[daemon] 收到 task_cancel taskId={id} 命中在途={hit}");
                                        } else if let Some((root_id, kind)) = super::remote_frames::parse_trust_revoke(&v) {
                                            // 只收紧：always → ask；落盘失败只记日志（网页侧会看到本机快照未变）
                                            let dirs = super::workspace::Workspace::from_env().roots;
                                            match super::policy::PolicyFile::path() {
                                                Some(path) => match super::remote_frames::apply_trust_revoke(&path, &dirs, &root_id, kind) {
                                                    Ok(changed) => log::info!("[daemon] trust_revoke root={root_id} kind={kind:?} 已收回={changed}"),
                                                    Err(e) => log::warn!("[daemon] trust_revoke 写入失败（未生效）: {e}"),
                                                },
                                                None => log::warn!("[daemon] trust_revoke：找不到策略文件路径"),
                                            }
                                        } else if v.get("type").and_then(|t| t.as_str()) == Some("auth_request") {
                                            // 票 15b：网页「请求使用这台电脑」。弹窗等待可达 60s，不能阻塞主循环
                                            // （心跳、任务结果回传都在这个循环里），spawn 出去处理。
                                            match super::auth_request::parse_frame(&v) {
                                                Some(areq) => {
                                                    let bridge = self.auth_requests.clone();
                                                    let agent = self.cfg.agent_id.clone();
                                                    tokio::spawn(async move {
                                                        let decision = bridge.ask(areq.clone()).await;
                                                        let dirs = super::workspace::Workspace::from_env().roots;
                                                        let Some(path) = super::policy::PolicyFile::path() else { return };
                                                        match super::auth_request::apply_decision(&areq, &decision, &dirs, agent.as_deref(), &path) {
                                                            Ok(true) => log::info!("[auth-request] 已授权 {}", areq.agent_id),
                                                            Ok(false) => log::info!("[auth-request] 已拒绝 {}", areq.agent_id),
                                                            Err(e) => log::warn!("[auth-request] 写入授权失败（未生效）: {e}"),
                                                        }
                                                    });
                                                }
                                                None => log::warn!("[auth-request] 帧不合法，已丢弃"),
                                            }
                                        } else if let Some((pid, up_to)) = super::preview_stream::parse_pull(&v) {
                                            // 票 07：服务端「要下一片」。只推高对应预览的水位；未登记的 id 静默忽略。
                                            // 这是内联的纯内存操作（不读文件、不 await），不会阻塞心跳。
                                            preview_streams.on_pull(&pid, up_to);
                                        } else if let Some(pid) = super::preview_stream::parse_server_abort(&v) {
                                            // 票 07：服务端叫停（无进度超时 / 预算 / 校验失败）。注销即让传输任务
                                            // 的 watch 断开 → 它在下一次等待时安静结束，不再发帧。
                                            preview_streams.unregister(&pid);
                                        } else if v.get("type").and_then(|t| t.as_str()) == Some("preview_request") {
                                            // 票 02：网页预览请求。**必须 spawn**——本票虽只走拒绝路径，
                                            // 但放行路径要等用户确认（可达 60s）并读文件，内联会阻塞心跳
                                            // 导致被判离线（对抗审查 P0）。
                                            match super::preview::parse_preview_request(&v) {
                                                Some(preq) => {
                                                    // 暂停闸在**这里**显式取值：现有暂停闸只挂在下面的任务帧分支，
                                                    // 预览是新帧不会自动经过（对抗审查 P1；删掉这行有对应用例变红）。
                                                    let paused = self.pause.as_ref().and_then(|p| p.gate(now_unix_ms()));
                                                    let tx = task_result_tx.clone();
                                                    let agent_for_policy = self.cfg.agent_id.clone();
                                                    let audit = audit.clone();
                                                    let previews = self.previews.clone();
                                                    let streams = preview_streams.clone();
                                                    tokio::spawn(async move {
                                                        // 本机是真源：现读磁盘策略，不信注册时的快照
                                                        let policy = Policy::load(agent_for_policy.as_deref());
                                                        let grants = super::preview::session_grants();
                                                        let mut outcome = super::preview::evaluate(
                                                            &preq,
                                                            &policy,
                                                            paused,
                                                            super::preview::limit_bytes(preq.chunked),
                                                            // 偏好按命中的目录现读磁盘（用户改设置下次预览立即生效）
                                                            super::preview::pref_for,
                                                            grants,
                                                        )
                                                        .await;
                                                        // 要问 → 在**本机**弹确认（跨机来源同样只能本机点，
                                                        // 刻意不接 web_confirm 的「转网页」通道）。
                                                        if let super::preview::PreviewOutcome::NeedsConfirm {
                                                            facts_size,
                                                            root_id,
                                                            file_name,
                                                            folder_name,
                                                            real_path,
                                                        } = &outcome
                                                        {
                                                            outcome = match &previews {
                                                                Some(bridge) => {
                                                                    super::preview::confirm(
                                                                        &preq,
                                                                        bridge,
                                                                        grants,
                                                                        *facts_size,
                                                                        root_id,
                                                                        file_name,
                                                                        folder_name,
                                                                        real_path,
                                                                    )
                                                                    .await
                                                                }
                                                                // 没有弹窗桥（headless / 测试未注入）= 拒绝，绝不放行
                                                                None => super::preview::not_allowed(),
                                                            };
                                                        }
                                                        // 票 07：分片请求（transfer=chunked）→ 拉取式分片发送，**不整文件读入内存**，
                                                        // 同一时刻只持有 1 片。结果帧由 stream_file 自己入队（meta/chunk*/end 或 abort），
                                                        // 所以这条路径不再走下面的单帧回帧。
                                                        let mut streamed = false;
                                                        if preq.chunked {
                                                            if let super::preview::PreviewOutcome::Allowed { real_path, .. } = &outcome {
                                                                if let Some(kind) = super::preview_stream::kind_of(real_path) {
                                                                    streamed = true;
                                                                    let pull = streams.register(&preq.preview_id);
                                                                    // stop 通道：由 on abort 的 unregister 触发 pull 发送端 drop，
                                                                    // stream_file 在等待批准时读到 Err 即安静结束；这里不另设 stop 源。
                                                                    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
                                                                    let res = super::preview_stream::stream_file(
                                                                        &preq.preview_id,
                                                                        real_path,
                                                                        kind,
                                                                        pull,
                                                                        &tx,
                                                                        &stop_rx,
                                                                        super::preview_stream::CHUNK_BYTES,
                                                                        super::preview_stream::PULL_WAIT_TIMEOUT,
                                                                        &mut |_| {},
                                                                    )
                                                                    .await;
                                                                    streams.unregister(&preq.preview_id);
                                                                    match res {
                                                                        super::preview_stream::StreamOutcome::Failed(outward) => {
                                                                            outcome = super::preview::PreviewOutcome::Rejected {
                                                                                internal: super::preview_gate::DenyReason::NotAllowed,
                                                                                outward,
                                                                            };
                                                                        }
                                                                        // 审核 F5（10-09）：服务端叫停 / 久无 pull / 连接断 → 没传完，
                                                                        // 本机审计不得记成 approved。按「可重试」记（不另发帧：streamed=true 跳过回帧）。
                                                                        super::preview_stream::StreamOutcome::Stopped => {
                                                                            outcome = super::preview::PreviewOutcome::Rejected {
                                                                                internal: super::preview_gate::DenyReason::NotAllowed,
                                                                                outward: super::preview_gate::PreviewReject::Retry,
                                                                            };
                                                                        }
                                                                        super::preview_stream::StreamOutcome::Done { .. } => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        // 票 04：已获允许 → 现在才读字节。读失败 / 传输中被改
                                                        // 都把结果改写成拒绝，走下面同一条回帧路径。
                                                        let mut read_ok: Option<super::preview_read::PreviewBytes> = None;
                                                        if let (false, super::preview::PreviewOutcome::Allowed { real_path, .. }) = (streamed, &outcome) {
                                                            match super::preview_read::read_for_preview(real_path).await {
                                                                Ok(b) => read_ok = Some(b),
                                                                Err(outward) => {
                                                                    outcome = super::preview::PreviewOutcome::Rejected {
                                                                        internal: super::preview_gate::DenyReason::NotAllowed,
                                                                        outward,
                                                                    };
                                                                }
                                                            }
                                                        }
                                                        // 审计：只记相对授权根的路径与结果，不记内容、不记哈希
                                                        audit.log(&super::preview::audit_entry(&preq, &outcome));
                                                        if let Some(frame) = outcome.reject_frame(&preq.preview_id) {
                                                            // 分片路径中途失败时 stream_file 已入队过 abort 帧，不重复发
                                                            if !streamed {
                                                                let _ = tx.send(frame.to_string()).await;
                                                            }
                                                        } else if let Some(b) = read_ok {
                                                            // 步一单帧：meta → chunk → end。服务端按 meta.size 与实收核对
                                                            let pid = &preq.preview_id;
                                                            let size = b.bytes.len();
                                                            let _ = tx
                                                                .send(super::preview_read::meta_frame(pid, size, b.truncated).to_string())
                                                                .await;
                                                            let _ = tx
                                                                .send(super::preview_read::chunk_frame(pid, &b.bytes).to_string())
                                                                .await;
                                                            let _ = tx.send(super::preview_read::end_frame(pid).to_string()).await;
                                                        }
                                                        // ⚠️ 日志只许出现 previewId / 结果短码 / 字节数，**不得**出现
                                                        // 路径、文件名或内容（静态守卫会扫这一段）
                                                        log::info!(
                                                            "[preview] previewId={} 结果={}",
                                                            preq.preview_id,
                                                            outcome.audit_code().unwrap_or("allowed"),
                                                        );
                                                    });
                                                }
                                                None => log::warn!("[preview] 帧不合法，已丢弃"),
                                            }
                                        } else if v.get("type").and_then(|t| t.as_str()) == Some("task") {
                                            let task_id = v
                                                .get("taskId")
                                                .and_then(|t| t.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            let tool = v
                                                .get("tool")
                                                .and_then(|t| t.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            let mut params = v
                                                .get("params")
                                                .cloned()
                                                .unwrap_or(serde_json::json!({}));
                                            // 注入 taskId 到 params._task_id，供备份 meta 任务关联
                                            if let Some(obj) = params.as_object_mut() {
                                                obj.insert(
                                                    "_task_id".to_string(),
                                                    serde_json::Value::String(task_id.clone()),
                                                );
                                            }
                                            // 解析可选的 lease 字段（写类操作由服务端附带）
                                            let lease: Option<super::lease::Lease> = v
                                                .get("lease")
                                                .and_then(|l| serde_json::from_value(l.clone()).ok());
                                            let node_id = self.cfg.node_id.clone();

                                            // 票 17：跨机使用提醒。origin 由服务端标注（other_device 才算远程），缺失按信号不足
                                            if let Some(h) = &self.hub {
                                                let origin = v.get("origin").and_then(|o| o.as_str()).unwrap_or("");
                                                let session = params.get("_session_id").and_then(|s| s.as_str());
                                                h.on_task(origin, session);
                                            }
                                            let hub_for_task = self.hub.clone();
                                            if let Some(h) = &hub_for_task { h.task_started(); }

                                            // 票 17：本机暂停闸。本机是真源——服务端虽已在派活前拒绝，这里再拒一次
                                            // （覆盖断线空档 / 旧服务端 / 两端暂停状态不同步）。被拒的任务不占「活动中」。
                                            let paused_msg = self.pause.as_ref().and_then(|p| p.gate(now_unix_ms()));
                                            let quit_guard = self.quit_guard.clone();
                                            let upload_ctx = self.uploads.clone().map(|b| super::tools::upload::UploadCtx {
                                                bridge: b,
                                                origin: v.get("origin").and_then(|o| o.as_str()).unwrap_or("web").to_string(),
                                            });
                                            let session_for_task = params.get("_session_id").and_then(|s| s.as_str()).map(str::to_string);

                                            log::info!(
                                                "[daemon] 收到 task: {tool} taskId={task_id} params={}",
                                                log_head(&params.to_string(), 120)
                                            );
                                            // spawn 工具执行，结果经 channel 回传
                                            let tx = task_result_tx.clone();
                                            let approval_mgr = approval_mgr.clone();
                                            let audit = audit.clone();
                                            let agent_for_policy = self.cfg.agent_id.clone();
                                            let cancel_handle = cancels.register(&task_id);
                                            tokio::spawn(async move {
                                                // 本机是真源：每个任务现读磁盘策略，不信任注册时的快照
                                                let policy = Policy::load(agent_for_policy.as_deref());
                                                // 写类任务计入退出保护（RAII：panic/提前返回也会减）
                                                let _write_guard = quit_guard.as_ref().and_then(|g| g.begin(&tool));
                                                let result = if let Some(msg) = paused_msg {
                                                    super::tools::ToolResult::err(msg)
                                                } else {
                                                    let fut = super::web_confirm::CURRENT_TASK.scope(
                                                        super::web_confirm::TaskCtx { session_path: session_for_task },
                                                        super::tools::execute_tool(
                                                            &tool,
                                                            &params,
                                                            &policy,
                                                            lease,
                                                            &node_id,
                                                            &approval_mgr,
                                                            &audit,
                                                        ),
                                                    );
                                                    let fut = async move {
                                                        match upload_ctx {
                                                            Some(c) => super::tools::upload::UPLOAD_CTX.scope(c, fut).await,
                                                            None => fut.await,
                                                        }
                                                    };
                                                    // 服务端 task_cancel 先到 → 按拒绝结束（打断的只是等确认/等弹窗的 await）
                                                    super::remote_frames::run_cancellable(cancel_handle, fut).await.unwrap_or_else(|| {
                                                        super::tools::ToolResult::err(super::remote_frames::CANCELLED_MSG.into())
                                                    })
                                                };
                                                log::info!(
                                                    "[daemon] 执行 {tool} → ok={} result={} error={}",
                                                    result.ok,
                                                    result.result.as_deref().unwrap_or("").chars().take(120).collect::<String>(),
                                                    result.error.as_deref().unwrap_or("").chars().take(120).collect::<String>(),
                                                );
                                                if let Some(h) = &hub_for_task { h.task_finished(); }
                                                let mut response = serde_json::json!({
                                                    "type": "task_result",
                                                    "taskId": task_id,
                                                    "ok": result.ok,
                                                    "result": result.result,
                                                    "error": result.error,
                                                });
                                                // 票 18：搬运字节走独立字段，服务端据此落盘，绝不混进 result
                                                if let Some(u) = &result.upload {
                                                    response["upload"] = serde_json::json!({ "name": u.name, "base64": u.base64 });
                                                }
                                                let _ = tx.send(response.to_string()).await;
                                            });
                                        } else {
                                            log::info!(
                                                "[daemon] 收到: {}",
                                                log_head(&t, 200)
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Pong(_))) => {
                            log::debug!("[daemon] 心跳 pong");
                        }
                        Some(Ok(Message::Close(frame))) => {
                            // 关闭码 4001 = 被顶（与 displaced 帧二者任一即不重连，防帧丢失）
                            if is_displaced_close(frame.as_ref().map(|f| u16::from(f.code))) {
                                let stopping = *self.stop_rx.borrow();
                                if stopping {
                                    log::info!("[daemon] 停止中收到关闭码 4001（自己热重启造成的残余顶下线），忽略，不上报托盘");
                                } else {
                                    log::warn!("[daemon] 收到关闭码 4001（被顶），不再重连");
                                }
                                return Ok(displaced_outcome(stopping));
                            }
                            return Ok(ConnectResult::Normal); // 对端关闭
                        }
                        None => {
                            return Ok(ConnectResult::Normal); // 流结束
                        }
                        Some(Ok(_)) => {} // 其他帧忽略
                        Some(Err(e)) => {
                            return Err(format!("读消息失败: {e}"));
                        }
                    }
                }
            }
        }
    }
}

/// connect_once 的返回结果类型。
enum ConnectResult {
    /// 正常结束（对端关闭）
    Normal,
    /// 收到停止信号（supervisor 热重启）
    Stopped,
    /// 被同账号的另一台电脑顶下线（displaced 帧或关闭码 4001），不得重连
    Displaced,
    /// 注册被拒（register_failed），重连不会自愈，不得重连
    Rejected,
    /// 网页主动断开 / 吊销（disconnect 帧，票 06 契约）：收到后不自动重连，用户需在托盘手动重连
    RemoteDisconnected,
}

/// 服务端被顶关闭码（与 openhanako `DISPLACED_CLOSE_CODE` 一致）。
pub const DISPLACED_CLOSE_CODE: u16 = 4001;

/// 文本帧是否为 `displaced`。
pub fn is_displaced(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(|t| t == "displaced"))
        .unwrap_or(false)
}

/// 文本帧是否为网页主动断开（`disconnect`，reason: user_remote | revoked）。
/// 返回 reason；非 disconnect 帧返回 None。
pub fn disconnect_reason(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    if v.get("type")?.as_str()? != "disconnect" {
        return None;
    }
    Some(v.get("reason").and_then(|r| r.as_str()).unwrap_or("user_remote").to_string())
}

/// 收到「被顶」后应归为哪种结局。
///
/// 为什么要看 `stopping`：`supervisor.restart()` 先给旧 client 发停止信号、**立即**起新 client 注册；
/// 服务端「同账号人后连顶先连」，于是旧连接（已在被停掉的路上）会收到 displaced / 4001。
/// 这是**自己顶自己**，不是「另一台电脑上线」——若照常上报 Displaced，托盘终态（优先级高于已连接）
/// 会被旧连接锁死，即使新连接早已健康（2026-10-08 实测：同机名 1 秒内互顶，托盘显示「已在另一台电脑上线」）。
/// `stopping` = 本 client 的停止信号已置位。
fn displaced_outcome(stopping: bool) -> ConnectResult {
    if stopping { ConnectResult::Stopped } else { ConnectResult::Displaced }
}

/// 关闭码是否为被顶。
pub fn is_displaced_close(code: Option<u16>) -> bool {
    code == Some(DISPLACED_CLOSE_CODE)
}

/// 「不在电脑前时网页确认」开关现值。读磁盘；**读失败/文件损坏一律按关闭**——
/// 这是放宽类配置，宁可让人回电脑前点，也不能因为文件坏了就默认把确认转到网页。
pub fn web_confirm_switch_on() -> bool {
    super::policy::PolicyFile::load().map(|f| f.web_confirm).unwrap_or(false)
}

/// 当前 Unix 毫秒（暂停到期判定与 `pause_state.until` 同一口径）。
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 握手阶段被服务端 403（凭据失效 / 被吊销 / scope 不符）。tungstenite 的错误串里带 `HTTP error: 403`。
pub fn is_handshake_forbidden(err: &str) -> bool {
    err.contains("握手失败") && (err.contains("403") || err.to_ascii_lowercase().contains("forbidden"))
}

/// 把 Duration 友好显示（避免引入 humantime crate）。
fn humantime(d: Duration) -> String {
    format!("{}s", d.as_secs())
}

/// 服务端注册回执类型。
#[derive(Debug, PartialEq, Eq)]
pub enum Ack {
    Registered,
    Failed,
}

/// 从服务端文本帧里识别注册回执。非回执消息返回 None。
pub fn register_ack(text: &str) -> Option<Ack> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    match v.get("type")?.as_str()? {
        "registered" => Some(Ack::Registered),
        "register_failed" => Some(Ack::Failed),
        _ => None,
    }
}

/// 日志截断：按字符（不按字节）取前 `n` 个。按字节切片遇中文路径会切到 UTF-8 中间而 panic，
/// 主循环线程随之退出（审核 C-F1）。
fn log_head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_head_never_splits_utf8() {
        // 真实形态：中文路径参数，前面补 0..8 字节让第 120/200 字节落到字符中间
        for pad in 0..8 {
            let s = format!("{}{{\"path\":\"财务/2026年度预算/{}.xlsx\"}}", "x".repeat(pad), "汇总".repeat(200));
            assert_eq!(super::log_head(&s, 120).chars().count(), 120);
            assert_eq!(super::log_head(&s, 200).chars().count(), 200);
        }
        assert_eq!(super::log_head("短", 120), "短");
    }

    use super::*;
    use crate::daemon::config::DaemonConfig;

    #[test]
    fn 版本字符串_基线为包版本_可选拼接_build_sha() {
        // 本地构建无 HANAKO_BUILD_SHA：纯包版本，不带 +g
        let v = build_app_version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "版本应以 CARGO_PKG_VERSION 起头: {v}");
        assert_eq!(v, env!("CARGO_PKG_VERSION"), "本地构建应为纯版本号（CI 才注入 +g<sha>）");
    }
    // ── 票 17：disconnect 帧 / 握手 403 识别 ─────────────────────
    #[test]
    fn disconnect_帧识别_带原因与缺省() {
        assert_eq!(disconnect_reason(r#"{"type":"disconnect","reason":"user_remote"}"#).as_deref(), Some("user_remote"));
        assert_eq!(disconnect_reason(r#"{"type":"disconnect","reason":"revoked"}"#).as_deref(), Some("revoked"));
        assert_eq!(disconnect_reason(r#"{"type":"disconnect"}"#).as_deref(), Some("user_remote"), "缺 reason 按网页断开处理");
    }

    #[test]
    fn disconnect_帧识别_不误伤别的帧() {
        for t in [
            r#"{"type":"displaced","reason":"replaced_by_newer_node"}"#,
            r#"{"type":"registered"}"#,
            r#"{"type":"task","taskId":"t1"}"#,
            r#"{"type":"web_confirm_decision"}"#,
            "not json",
            "",
        ] {
            assert!(disconnect_reason(t).is_none(), "{t}");
        }
    }

    #[test]
    fn 握手_403_判凭据失效_其余判网络() {
        assert!(is_handshake_forbidden("握手失败: HTTP error: 403 Forbidden"));
        assert!(is_handshake_forbidden("握手失败: HTTP error: 403"));
        assert!(!is_handshake_forbidden("握手失败: IO error: Connection refused"));
        assert!(!is_handshake_forbidden("握手失败: HTTP error: 502 Bad Gateway"));
        assert!(!is_handshake_forbidden("发送心跳失败: ... 403 ..."), "只认握手阶段");
    }

    use crate::daemon::register::NodeLink;

    fn client() -> DaemonClient {
        let cfg = DaemonConfig {
            base_url: "https://x.example.com/hapi/hanako".into(),
            token: "tok-abc".into(),
            node_id: "node_t".into(),
            agent_id: None,
        };
        let link = NodeLink::new(&cfg);
        let bridge = crate::daemon::approval_native::ApprovalBridge::new();
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let connected = Arc::new(AtomicBool::new(false));
        DaemonClient::new(cfg, link, bridge, stop_rx, connected)
    }

    #[test]
    fn ws_url_与服务端路由一致() {
        assert_eq!(
            client().ws_url(),
            "wss://x.example.com/hapi/hanako/api/execution-node/ws"
        );
    }

    #[test]
    fn 握手请求带_bearer_认证头() {
        let c = client();
        let req = c.build_request(&c.ws_url()).unwrap();
        assert_eq!(
            req.headers().get(AUTHORIZATION).unwrap(),
            "Bearer tok-abc"
        );
    }

    #[test]
    fn 握手请求保留标准_websocket_头() {
        let c = client();
        let req = c.build_request(&c.ws_url()).unwrap();
        // 漏 Sec-WebSocket-Key 会让服务端回 400，故显式锁定
        assert!(req.headers().get("sec-websocket-key").is_some());
    }

    #[test]
    fn 识别注册回执() {
        assert_eq!(
            register_ack(r#"{"type":"registered","serverNodeId":"n"}"#),
            Some(Ack::Registered)
        );
        assert_eq!(
            register_ack(r#"{"type":"register_failed","error":"x"}"#),
            Some(Ack::Failed)
        );
        assert_eq!(register_ack(r#"{"type":"other"}"#), None);
        assert_eq!(register_ack("not json"), None);
    }

    #[test]
    fn 识别被顶帧() {
        assert!(is_displaced(r#"{"type":"displaced","reason":"replaced_by_newer_node","by":"laptop"}"#));
        assert!(!is_displaced(r#"{"type":"registered"}"#));
        assert!(!is_displaced(r#"{"type":"task"}"#));
        assert!(!is_displaced("not json"));
    }

    #[test]
    fn 识别被顶关闭码() {
        assert!(is_displaced_close(Some(4001)));
        assert!(!is_displaced_close(Some(1000)));
        assert!(!is_displaced_close(Some(1008)));
        assert!(!is_displaced_close(None));
    }

    /// 握手阶段发出的注册帧必须是新协议帧（否则服务端当旧帧处理，互顶与授权全部失效）。
    #[test]
    fn 注册帧含协议版本() {
        let c = client();
        let f = RegisterFrame::new(&c.cfg, &[], &c.app_version);
        let v = serde_json::to_value(&f).unwrap();
        assert!(v.get("protocolVersion").and_then(|x| x.as_u64()).is_some());
        assert_eq!(v["type"], "register");
    }

    /// 停止信号发送后，run() 中的 backoff sleep 被打断且函数返回。
    #[tokio::test]
    async fn 停止信号打断_backoff() {
        let cfg = DaemonConfig {
            base_url: "https://no-such-host-xyzzy.example.com/hapi/hanako".into(),
            token: "tok".into(),
            node_id: "node_t".into(),
            agent_id: None,
        };
        let link = NodeLink::new(&cfg);
        let bridge = crate::daemon::approval_native::ApprovalBridge::new();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let connected = Arc::new(AtomicBool::new(false));
        let client = DaemonClient::new(cfg, link, bridge, stop_rx, connected);

        // 在单独 task 里 run()，给它 10ms 尝试连接失败后再发停止
        let handle = tokio::spawn(async move {
            client.run().await;
        });

        // 给 client 时间触发第一次连接失败
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 发送停止信号
        let _ = stop_tx.send(true);

        // run() 应在合理时间内返回（backoff <= 1s，加上 50ms 余量）
        let timeout = tokio::time::timeout(Duration::from_secs(3), handle).await;
        assert!(timeout.is_ok(), "run() 未能在停止信号后及时退出");
        assert!(timeout.unwrap().is_ok());
    }

    #[test]
    fn 没在停止时被顶_才是真的被另一台电脑顶下线() {
        assert!(matches!(displaced_outcome(false), ConnectResult::Displaced));
    }

    #[test]
    fn 停止中收到被顶_是自己热重启的残余_按停止处理不上报托盘() {
        assert!(matches!(displaced_outcome(true), ConnectResult::Stopped));
    }

    // ── 策略变更推送判定 ──

    fn pol(dirs: &[std::path::PathBuf], agent: &str) -> Policy {
        Policy::build(dirs, &Default::default(), Some(agent))
    }

    #[test]
    fn 策略没变_不推送() {
        let d = tempfile::tempdir().unwrap();
        let a = pol(&[d.path().to_path_buf()], "bi--z");
        let b = pol(&[d.path().to_path_buf()], "bi--z");
        assert!(policy_push_frames(&a, &b).is_empty());
    }

    #[test]
    fn 新增目录_推_roots_和_grants() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let before = pol(&[d1.path().to_path_buf()], "bi--z");
        let after = pol(&[d1.path().to_path_buf(), d2.path().to_path_buf()], "bi--z");
        let kinds: Vec<_> = policy_push_frames(&before, &after).iter().map(|f| f["type"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, vec!["roots_changed", "grants_changed"]);
    }

    /// 审核 #2：开 / 收回永久允许 → 推 roots_changed，网页才看得到并能撤销；两类各自独立上报。
    /// 变异锁：roots_view 不带 upload_always / preview_always → 本用例红。
    #[test]
    fn 永久允许变化_推_roots_changed_且分两类() {
        let d = tempfile::tempdir().unwrap();
        let dirs = [d.path().to_path_buf()];
        let before = pol(&dirs, "bi--z");
        let rid = before.roots[0].root_id.clone();
        let mut f = crate::daemon::policy::PolicyFile::default();
        f.preview.insert(rid.clone(), "always".into());
        let after = Policy::build(&dirs, &f, Some("bi--z"));
        let frames = policy_push_frames(&before, &after);
        let r = frames.iter().find(|x| x["type"] == "roots_changed").expect("开永久允许必须推 roots_changed");
        assert_eq!(r["roots"][0]["previewAlways"], true);
        assert!(r["roots"][0].get("uploadAlways").is_none(), "只开预览不得显示成上传也一直允许");
        // 收回 → 再推一次，字段消失
        let back = policy_push_frames(&after, &before);
        let r2 = back.iter().find(|x| x["type"] == "roots_changed").expect("收回也必须推");
        assert!(r2["roots"][0].get("previewAlways").is_none());
    }

    #[test]
    fn 移除最后目录_推空_grants() {
        let d1 = tempfile::tempdir().unwrap();
        let before = pol(&[d1.path().to_path_buf()], "bi--z");
        let after = pol(&[], "bi--z");
        let frames = policy_push_frames(&before, &after);
        let g = frames.iter().find(|f| f["type"] == "grants_changed").unwrap();
        assert!(g["grants"].as_object().unwrap().is_empty(), "撤销必须推空表，云端才会 REVOKED");
        let r = frames.iter().find(|f| f["type"] == "roots_changed").unwrap();
        assert!(r["roots"].as_array().unwrap().is_empty());
    }

    #[test]
    fn 推送帧不含绝对路径() {
        let d = tempfile::tempdir().unwrap();
        let p = pol(&[d.path().to_path_buf()], "bi--z");
        let wire = format!("{}{}", roots_changed_frame(&p), grants_changed_frame(&p));
        assert!(!wire.contains(d.path().canonicalize().unwrap().to_str().unwrap()));
    }
}

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// 上次走通的 WS 代理（None = 直连可用）。进程内记忆。
static WS_STICKY_PROXY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// 建 WS：直连优先；**直连失败且系统配了代理**才走代理 CONNECT 隧道（见 net_proxy）。
/// 普通用户没配代理时行为与改动前完全一致。
pub async fn connect_ws(request: Request) -> Result<(WsStream, tokio_tungstenite::tungstenite::handshake::client::Response), String> {
    let sticky = WS_STICKY_PROXY.lock().unwrap().clone();
    if let Some(p) = sticky.as_deref() {
        match connect_ws_via_proxy(request.clone(), p).await {
            Ok(r) => return Ok(r),
            Err(e) if e.starts_with(HTTP_REACHED) => return Err(e),
            Err(e) => log::warn!("[net] 经代理 {p} 握手失败，重新探测: {e}"),
        }
    }
    let direct_err = match tokio_tungstenite::connect_async(request.clone()).await {
        Ok(r) => {
            *WS_STICKY_PROXY.lock().unwrap() = None;
            return Ok(r);
        }
        // HTTP 层拒绝（403 等）说明已到达服务器，不是网络问题，不该换路
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            return Err(format!("握手失败: HTTP {}", resp.status()));
        }
        Err(e) => e.to_string(),
    };
    for p in super::net_proxy::fallback_proxies() {
        if Some(&p) == sticky.as_ref() {
            continue;
        }
        match connect_ws_via_proxy(request.clone(), &p).await {
            Ok(r) => {
                log::info!("[net] 直连失败（{direct_err}），改走代理 {p}");
                *WS_STICKY_PROXY.lock().unwrap() = Some(p);
                return Ok(r);
            }
            Err(e) if e.starts_with(HTTP_REACHED) => {
                log::info!("[net] 直连失败（{direct_err}），改走代理 {p}（服务器已应答）");
                *WS_STICKY_PROXY.lock().unwrap() = Some(p);
                return Err(e);
            }
            Err(e) => log::warn!("[net] 代理 {p} 也失败: {e}"),
        }
    }
    Err(format!("握手失败: {direct_err}"))
}

/// 经 HTTP 代理 CONNECT 隧道建 WS（TLS 在隧道内由 tungstenite 完成）。
async fn connect_ws_via_proxy(
    request: Request,
    proxy: &str,
) -> Result<(WsStream, tokio_tungstenite::tungstenite::handshake::client::Response), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let proxy_addr = super::net_proxy::host_port(proxy).ok_or_else(|| format!("代理地址无效: {proxy}"))?;
    let uri = request.uri();
    let host = uri.host().ok_or("WS 地址缺少 host")?.to_string();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("ws") { 80 } else { 443 });

    let fut = async {
        let mut tcp = tokio::net::TcpStream::connect(&proxy_addr).await.map_err(|e| format!("连代理失败: {e}"))?;
        let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        tcp.write_all(req.as_bytes()).await.map_err(|e| format!("写 CONNECT 失败: {e}"))?;
        // 读到响应头结束；逐字节读，避免吞掉隧道后的 TLS 字节
        let mut head = Vec::with_capacity(256);
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 {
                return Err("代理响应头过长".to_string());
            }
            let n = tcp.read(&mut b).await.map_err(|e| format!("读代理响应失败: {e}"))?;
            if n == 0 {
                return Err("代理提前关闭连接".to_string());
            }
            head.push(b[0]);
        }
        let status_line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
        if status_line.split_whitespace().nth(1) != Some("200") {
            return Err(format!("代理拒绝隧道: {status_line}"));
        }
        match tokio_tungstenite::client_async_tls(request, tcp).await {
            Ok(r) => Ok(r),
            // 已经穿过代理到达服务器（401/403 等）：路是通的，交给上层按 HTTP 结果处理
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(format!("{HTTP_REACHED}{}", resp.status())),
            Err(e) => Err(format!("隧道内握手失败: {e}")),
        }
    };
    tokio::time::timeout(Duration::from_secs(20), fut).await.map_err(|_| "经代理握手超时".to_string())?
}

/// 经代理握手时「已到达服务器、被 HTTP 拒绝」的错误前缀。
const HTTP_REACHED: &str = "握手失败: HTTP ";
