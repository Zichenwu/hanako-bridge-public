// 联调工具：把 daemon 实际会发的新注册帧打印成 JSON，供服务端 registry 契约核对。
// 用法：HANA_AGENT_ID=team--alice HANA_LOCAL_WORKSPACES=/some/dir cargo run --example dump_register_frame
use hanako_tauri_lib::daemon::register::RegisterFrame;
use hanako_tauri_lib::daemon::workspace::Workspace;
use hanako_tauri_lib::daemon::DaemonConfig;

fn main() {
    let cfg = DaemonConfig {
        base_url: "https://x.example.com".into(),
        token: "unused".into(),
        node_id: std::env::var("HANA_NODE_ID").unwrap_or_else(|_| "node_contract".into()),
        agent_id: std::env::var("HANA_AGENT_ID").ok(),
    };
    let dirs = Workspace::from_env().roots;
    let frame = RegisterFrame::new(&cfg, &dirs, env!("CARGO_PKG_VERSION"));
    println!("{}", serde_json::to_string(&frame).unwrap());
}
