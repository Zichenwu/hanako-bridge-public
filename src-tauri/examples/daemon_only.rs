// 联调专用 example：只跑 daemon 出站客户端，不起 GUI。
// 无头服务器上验证 daemon ↔ 云端派活路由的真实链路（GUI 在无头环境需软渲染，
// 且与 daemon 已解耦，联调时不必拉起）。
//
// 用法：
//   HANA_CLOUD_BASE_URL=http://localhost:3009 \
//   HANA_DAEMON_TOKEN=<device credential secret> \
//   HANA_NODE_ID=node_xxx \
//   cargo run --example daemon_only
//
// P3.5 注：正式应用使用 DaemonSupervisor 管理生命周期（热重启支持）。
// 联调 example 直接构造 DaemonClient，无需 supervisor。
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use hanako_tauri_lib::daemon::{ApprovalBridge, DaemonClient, DaemonConfig, NodeLink};

#[tokio::main]
async fn main() {
    hanako_tauri_lib::init_logger_for_tools();
    let cfg = DaemonConfig::from_env().expect("配置缺失（见文件头用法）");
    let link = NodeLink::new(&cfg);
    // 联调模式：无 GUI，ApprovalBridge 的 AppHandle 不会被注入。
    // 因此所有写操作确认均 Reject（headless 安全兜底）。
    let bridge = ApprovalBridge::new();
    // 联调不需要热重启：创建永不触发的停止信号
    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let connected = Arc::new(AtomicBool::new(false));
    DaemonClient::new(cfg, link, bridge, stop_rx, connected).run().await;
}
