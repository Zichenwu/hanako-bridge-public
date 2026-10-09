// src-tauri/src/daemon/upload_bridge.rs
//! 上传偏好弹窗桥（票 18）。沿用 `auth_request` 的模式：daemon 侧 `ask` 挂起等用户，UI 侧 `respond` 回答。
//!
//! 安全约束：
//! - 弹窗在**本机原生窗口**显示，云端伪造不了用户点击（P12）；
//! - **超时 = 拒绝**，没有弹窗实现（headless）= 拒绝，绝不默认允许；
//! - 用户只能选 仅此一次 / 本会话该目录 / 拒绝——**没有永久**（永久只能在本机设置里开）；
//! - 同时只处理一个请求：新请求顶掉旧请求，旧的得到拒绝。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use super::upload_gate::UserChoice;

/// 上传弹窗等待上限；超时 = 拒绝（设计稿 native.up.timeout）。
pub const UPLOAD_ASK_TIMEOUT: Duration = Duration::from_secs(60);

/// 展示给弹窗的请求。**不含绝对路径**，只给文件名与目录显示名。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UploadAsk {
    pub ask_id: String,
    pub file_name: String,
    pub size: u64,
    pub folder_name: String,
    pub root_id: String,
    pub agent_id: String,
    /// 模型给的用途说明（已截断），原样显示供用户判断
    pub purpose: Option<String>,
    /// "web" | "other_device"（跨机发起时弹窗要显式警示）
    pub origin: String,
}

struct Pending {
    ask: UploadAsk,
    tx: tokio::sync::oneshot::Sender<UserChoice>,
}

pub struct UploadBridge {
    pending: Mutex<HashMap<String, Pending>>,
    show: Mutex<Option<Arc<dyn Fn(&UploadAsk) -> bool + Send + Sync>>>,
}

impl UploadBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(HashMap::new()), show: Mutex::new(None) })
    }

    pub fn set_presenter(&self, f: Arc<dyn Fn(&UploadAsk) -> bool + Send + Sync>) {
        *self.show.lock().unwrap() = Some(f);
    }

    pub fn peek(&self) -> Option<UploadAsk> {
        self.pending.lock().unwrap().values().next().map(|p| p.ask.clone())
    }

    /// 弹窗提交。已超时/不存在返回 Err（迟到的点击不能生效）。
    pub fn respond(&self, ask_id: &str, choice: UserChoice) -> Result<(), String> {
        match self.pending.lock().unwrap().remove(ask_id) {
            None => Err(format!("上传确认不存在或已超时: {ask_id}")),
            Some(p) => {
                let _ = p.tx.send(choice);
                Ok(())
            }
        }
    }

    pub async fn ask(&self, ask: UploadAsk) -> UserChoice {
        self.ask_with_timeout(ask, UPLOAD_ASK_TIMEOUT).await
    }

    pub(crate) async fn ask_with_timeout(&self, ask: UploadAsk, timeout: Duration) -> UserChoice {
        let presenter = self.show.lock().unwrap().clone();
        let Some(present) = presenter else {
            log::warn!("[upload] 没有可用的弹窗实现（headless），拒绝");
            return UserChoice::Reject;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = ask.ask_id.clone();
        {
            let mut g = self.pending.lock().unwrap();
            g.clear(); // 顶掉旧请求：旧 tx 被 drop → 旧 ask 得到 Reject
            g.insert(id.clone(), Pending { ask: ask.clone(), tx });
        }
        if !present(&ask) {
            self.pending.lock().unwrap().remove(&id);
            return UserChoice::Reject;
        }
        let out = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(c)) => c,
            _ => UserChoice::Reject,
        };
        self.pending.lock().unwrap().remove(&id); // 超时后清理，迟到点击无效
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(id: &str) -> UploadAsk {
        UploadAsk { ask_id: id.into(), file_name: "a.xlsx".into(), size: 10, folder_name: "报表".into(), root_id: "r1".into(), agent_id: "bi--z".into(), purpose: None, origin: "web".into() }
    }

    #[tokio::test]
    async fn 没有弹窗实现_拒绝() {
        let b = UploadBridge::new();
        assert_eq!(b.ask(ask("1")).await, UserChoice::Reject);
    }

    #[tokio::test]
    async fn 弹窗打不开_拒绝且清理() {
        let b = UploadBridge::new();
        b.set_presenter(Arc::new(|_| false));
        assert_eq!(b.ask(ask("1")).await, UserChoice::Reject);
        assert!(b.peek().is_none());
    }

    #[tokio::test]
    async fn 用户选择原样返回() {
        for c in [UserChoice::Once, UserChoice::Session, UserChoice::Reject] {
            let b = UploadBridge::new();
            let b2 = b.clone();
            b.set_presenter(Arc::new(move |a| {
                let b3 = b2.clone();
                let id = a.ask_id.clone();
                tokio::spawn(async move { tokio::task::yield_now().await; let _ = b3.respond(&id, c); });
                true
            }));
            assert_eq!(b.ask(ask("1")).await, c);
        }
    }

    #[tokio::test]
    async fn 超时_拒绝_且迟到的点击无效() {
        let b = UploadBridge::new();
        b.set_presenter(Arc::new(|_| true));
        let r = b.ask_with_timeout(ask("1"), Duration::from_millis(30)).await;
        assert_eq!(r, UserChoice::Reject);
        assert!(b.respond("1", UserChoice::Once).is_err(), "超时后点允许不得生效");
    }

    #[tokio::test]
    async fn 新请求顶掉旧请求_旧的得到拒绝() {
        let b = UploadBridge::new();
        b.set_presenter(Arc::new(|_| true));
        let b1 = b.clone();
        let first = tokio::spawn(async move { b1.ask_with_timeout(ask("old"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let b2 = b.clone();
        let second = tokio::spawn(async move { b2.ask_with_timeout(ask("new"), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(first.await.unwrap(), UserChoice::Reject);
        assert!(b.respond("old", UserChoice::Once).is_err());
        b.respond("new", UserChoice::Once).unwrap();
        assert_eq!(second.await.unwrap(), UserChoice::Once);
    }

    #[test]
    fn 展示数据不含绝对路径字段() {
        let j = serde_json::to_string(&ask("1")).unwrap();
        assert!(!j.contains("path"), "{j}");
    }
}
