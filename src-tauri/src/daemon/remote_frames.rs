// src-tauri/src/daemon/remote_frames.rs
//! 服务端下行的两个「收紧类」帧（审核 C-F6 / R2-#10）。
//!
//! - `trust_revoke {trustId}`：网页「撤销永久上传」。`trustId` = 授权目录的 root_id。
//!   只能把该目录的上云偏好从 `always` 收回成 `ask`（放宽方向只存在于本机设置，见 upload_gate 模块注释）；
//!   未知 id / 本就是 ask → 无操作。此前本机不处理该帧，网页显示「已撤销」而本机仍一直放行。
//! - `task_cancel {taskId}`：服务端已判超时并告诉模型「失败」。本机若仍在等确认 / 等弹窗，
//!   用户随后点了同意就会「服务端报失败、文件其实改了」，agent 重试还会写第二次。
//!   收到即把该任务按拒绝结束。**取消只作用于 await 点**（等确认、等上传弹窗）：写操作本体
//!   `write_fn` 是同步调用，确认通过后不会被半途打断，不会出现写了一半的文件。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// 撤销的目标通道。
///
/// 预览与上传是两个独立的永久放行开关（本地文件预览 ADR 决策 1），撤销也必须分得开：
/// 网页上「撤销永久预览」不应把「允许助手把原文件传到云端」也一起关掉（反之亦然）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustKind {
    /// 原文件上云（既有行为）
    Upload,
    /// 网页预览
    Preview,
}

impl TrustKind {
    /// 解析帧里的 `kind`。
    ///
    /// **缺省 = `Upload`**，与该帧上线时的行为逐字节一致——旧版网页发来的不带 `kind` 的帧
    /// 必须仍然只收回上传偏好，不得顺手把预览也关了（纯加法兼容）。
    /// 未知值同样按 `Upload`（只收紧，解析不出来不会造成放宽）。
    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("preview") => TrustKind::Preview,
            _ => TrustKind::Upload,
        }
    }
}

/// 解析 `trust_revoke`，返回 (trustId（root_id）, 撤销的通道)。
pub fn parse_trust_revoke(v: &serde_json::Value) -> Option<(String, TrustKind)> {
    if v.get("type")?.as_str()? != "trust_revoke" {
        return None;
    }
    let id = v.get("trustId")?.as_str()?.trim();
    if id.is_empty() || id.len() > 128 {
        return None;
    }
    let kind = TrustKind::parse(v.get("kind").and_then(|k| k.as_str()));
    Some((id.to_string(), kind))
}

/// 解析 `task_cancel`，返回 taskId。
pub fn parse_task_cancel(v: &serde_json::Value) -> Option<String> {
    if v.get("type")?.as_str()? != "task_cancel" {
        return None;
    }
    let id = v.get("taskId")?.as_str()?;
    (!id.is_empty()).then(|| id.to_string())
}

/// 执行撤销：`always` → `ask`。返回是否真的改了。**只收紧，永不放宽**。
///
/// `kind` 决定动哪个字段：`Upload` 动 `upload`，`Preview` 动 `preview`。两者互不影响——
/// 网页侧**没有任何路径**能把某个目录改成 `always`（放宽只存在于本机设置的 `set_upload` /
/// `set_preview`），本函数只会写 `"ask"`。
pub fn apply_trust_revoke(
    policy_path: &Path,
    dirs: &[PathBuf],
    root_id: &str,
    kind: TrustKind,
) -> Result<bool, String> {
    let mut file = super::policy::PolicyFile::load_from(policy_path)?;
    let current = match kind {
        TrustKind::Upload => file.upload.get(root_id),
        TrustKind::Preview => file.preview.get(root_id),
    };
    if current.map(String::as_str) != Some("always") {
        return Ok(false);
    }
    match kind {
        TrustKind::Upload => super::policy::set_upload(&mut file, dirs, root_id, "ask")?,
        TrustKind::Preview => super::policy::set_preview(&mut file, dirs, root_id, "ask")?,
    }
    file.save_to(policy_path)?;
    Ok(true)
}

/// 在途任务的取消信号表。
#[derive(Clone, Default)]
pub struct CancelRegistry {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
}

/// 任务持有的取消接收端；drop 时自动从表里摘除（RAII，panic 也不泄漏）。
pub struct CancelHandle {
    pub rx: oneshot::Receiver<()>,
    _guard: CancelGuard,
}

struct CancelGuard {
    reg: CancelRegistry,
    id: String,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.reg.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 任务开始时登记。
    pub fn register(&self, task_id: &str) -> CancelHandle {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(task_id.to_string(), tx);
        CancelHandle { rx, _guard: CancelGuard { reg: self.clone(), id: task_id.to_string() } }
    }

    /// 收到 task_cancel。返回是否命中在途任务（未知/已结束 = 迟到帧，静默忽略）。
    pub fn cancel(&self, task_id: &str) -> bool {
        match self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(task_id) {
            Some(tx) => tx.send(()).is_ok(),
            None => false,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// 取消时给服务端的错误文案（服务端此时多半已 reject，仅供日志/迟到对账）。
pub const CANCELLED_MSG: &str = "LOCAL_TASK_CANCELLED: 服务端已取消该任务（超时），本机未执行";

/// 让任务与取消信号竞速：取消先到 → 返回 `None`（调用方按拒绝回传）。
pub async fn run_cancellable<F, T>(handle: CancelHandle, fut: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let CancelHandle { rx, _guard } = handle;
    tokio::select! {
        biased;
        r = fut => Some(r),
        Ok(()) = rx => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn 解析帧() {
        let v = serde_json::json!({"type":"trust_revoke","trustId":"r1"});
        assert_eq!(parse_trust_revoke(&v), Some(("r1".into(), TrustKind::Upload)));
        assert_eq!(parse_trust_revoke(&serde_json::json!({"type":"trust_revoke","trustId":""})), None);
        assert_eq!(parse_trust_revoke(&serde_json::json!({"type":"task_cancel","trustId":"r1"})), None);
        assert_eq!(parse_task_cancel(&serde_json::json!({"type":"task_cancel","taskId":"t1"})).as_deref(), Some("t1"));
        assert_eq!(parse_task_cancel(&serde_json::json!({"type":"task_cancel"})), None);
    }

    /// 旧版网页发来的帧没有 `kind` → 必须仍只收回**上传**偏好（纯加法兼容）。
    /// 变异锁：把缺省值改成 Preview（或改成「两个都收」）→ 本用例红。
    #[test]
    fn 撤销帧缺省只收上传_未知值同样按上传() {
        let k = |j: serde_json::Value| parse_trust_revoke(&j).unwrap().1;
        assert_eq!(k(serde_json::json!({"type":"trust_revoke","trustId":"r1"})), TrustKind::Upload);
        assert_eq!(k(serde_json::json!({"type":"trust_revoke","trustId":"r1","kind":"upload"})), TrustKind::Upload);
        assert_eq!(k(serde_json::json!({"type":"trust_revoke","trustId":"r1","kind":"preview"})), TrustKind::Preview);
        for weird in ["PREVIEW", "", "both", "all", "预览"] {
            assert_eq!(
                k(serde_json::json!({"type":"trust_revoke","trustId":"r1","kind":weird})),
                TrustKind::Upload,
                "kind={weird:?} 不得被当成预览"
            );
        }
    }

    #[test]
    fn 撤销只把_always_收回成_ask() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let dirs = vec![root.canonicalize().unwrap()];
        let path = dir.path().join("policy.json");
        let id = super::super::register::root_id_for(&dirs[0]);
        let mut f = super::super::policy::PolicyFile::default();
        super::super::policy::set_upload(&mut f, &dirs, &id, "always").unwrap();
        f.save_to(&path).unwrap();

        assert_eq!(apply_trust_revoke(&path, &dirs, &id, TrustKind::Upload), Ok(true));
        let f = super::super::policy::PolicyFile::load_from(&path).unwrap();
        assert!(f.upload.get(&id).is_none(), "撤销后应回到默认 ask");
        // 再撤一次 / 未知 id：无操作
        assert_eq!(apply_trust_revoke(&path, &dirs, &id, TrustKind::Upload), Ok(false));
        assert_eq!(apply_trust_revoke(&path, &dirs, "nope", TrustKind::Upload), Ok(false));
    }

    /// 变异锁（本地文件预览 票 03）：让两种撤销写同一个字段 → 本用例红。
    #[test]
    fn 撤销预览与撤销上传互不影响() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let dirs = vec![root.canonicalize().unwrap()];
        let path = dir.path().join("policy.json");
        let id = super::super::register::root_id_for(&dirs[0]);

        // 两个开关都开着
        let mut f = super::super::policy::PolicyFile::default();
        super::super::policy::set_upload(&mut f, &dirs, &id, "always").unwrap();
        super::super::policy::set_preview(&mut f, &dirs, &id, "always").unwrap();
        f.save_to(&path).unwrap();

        // 只撤预览
        assert_eq!(apply_trust_revoke(&path, &dirs, &id, TrustKind::Preview), Ok(true));
        let f = super::super::policy::PolicyFile::load_from(&path).unwrap();
        assert!(f.preview.get(&id).is_none(), "预览应被收回");
        assert_eq!(f.upload.get(&id).map(String::as_str), Some("always"), "上传不得被顺手关掉");

        // 再撤上传
        assert_eq!(apply_trust_revoke(&path, &dirs, &id, TrustKind::Upload), Ok(true));
        let f = super::super::policy::PolicyFile::load_from(&path).unwrap();
        assert!(f.upload.get(&id).is_none());
        // 预览已是 ask，重复撤销无操作
        assert_eq!(apply_trust_revoke(&path, &dirs, &id, TrustKind::Preview), Ok(false));
    }

    /// 网页侧**只能收紧**：撤销函数永不写 `always`，没有任何入参能让它放宽。
    #[test]
    fn 撤销永不放宽_网页写不进永久允许() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let dirs = vec![root.canonicalize().unwrap()];
        let path = dir.path().join("policy.json");
        let id = super::super::register::root_id_for(&dirs[0]);

        // 起点：两个开关都是默认「每次问」
        super::super::policy::PolicyFile::default().save_to(&path).unwrap();
        for kind in [TrustKind::Upload, TrustKind::Preview] {
            assert_eq!(apply_trust_revoke(&path, &dirs, &id, kind), Ok(false), "{kind:?} 无事可做");
            let f = super::super::policy::PolicyFile::load_from(&path).unwrap();
            assert!(f.upload.is_empty() && f.preview.is_empty(), "撤销不得凭空写出任何偏好");
        }
    }

    #[tokio::test]
    async fn 取消打断等待中的任务_未知id忽略_结束后自动摘除() {
        let reg = CancelRegistry::new();
        let h = reg.register("t1");
        assert!(!reg.cancel("unknown"));
        let r2 = reg.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(r2.cancel("t1"));
        });
        let out = run_cancellable(h, std::future::pending::<u8>()).await;
        assert_eq!(out, None);
        assert_eq!(reg.len(), 0);

        let h = reg.register("t2");
        assert_eq!(run_cancellable(h, async { 7u8 }).await, Some(7));
        assert_eq!(reg.len(), 0, "正常结束也要摘除");
        assert!(!reg.cancel("t2"), "结束后的迟到 cancel 无效");
    }
}
