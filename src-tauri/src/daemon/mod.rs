// src-tauri/src/daemon/mod.rs
//! daemon 子模块：出站连云端的本地执行节点。

pub mod approval;
pub mod approval_native;
pub mod audit;
pub mod auth_flow;
pub mod auth_request;
pub mod auth_manager;
pub mod backup;
pub mod client;
pub mod commands;
pub mod config;
pub mod credential_store;
pub mod device_auth;
pub mod heartbeat;
pub mod idle;
pub mod hk_profile;
pub mod lease;
pub mod net_proxy;
pub mod path_guard;
pub mod pause;
pub mod policy;
pub mod preview;
pub mod preview_bridge;
pub mod preview_gate;
pub mod preview_open;
pub mod preview_read;
pub mod preview_stream;
pub mod quit_guard;
pub mod register;
pub mod remote_frames;
pub mod supervisor;
pub mod tray_hub;
pub mod tray_state;
pub mod upload_bridge;
pub mod upload_gate;
pub mod tools;
pub mod web_confirm;
pub mod workspace;

pub use approval_native::ApprovalBridge;
pub use client::DaemonClient;
pub use config::{ConfigError, DaemonConfig};
pub use register::{NodeLink, CAPABILITIES, NODE_ROLE, TRANSPORT_KIND};
pub use supervisor::DaemonSupervisor;
