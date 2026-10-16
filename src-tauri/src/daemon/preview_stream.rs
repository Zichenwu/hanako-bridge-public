// src-tauri/src/daemon/preview_stream.rs
//! 预览分片发送（本地文件预览 票 07 步二）：把一个已过全部闸的文件，按 4MB 一片、**拉取式**回传。
//!
//! ## 为什么是「服务端拉、Bridge 发」
//! 服务端内存有预算（单预览 100MB、全局 400MB，见 `core/preview-budget.js`）。若 Bridge 一口气把
//! 200MB 灌进出站队列，要么撑爆服务端，要么把共用的出站队列（容量 32，心跳 / 任务结果也走它）堵死。
//! 所以分片发送由服务端的 `preview_pull { upTo }` 驱动：只有收到「已批准到第 N 片」才发到第 N 片。
//!
//! ## 内存上界
//! 本模块**同一时刻只在内存里持有 1 片**（4MB 原始 + base64 约 5.3MB）：读一片 → 发出 → 丢弃 → 等批准
//! → 再读下一片。**不整文件读入内存**——这是 200MB 文件在用户电脑上也不吃 200MB 内存的前提。
//! 代价是「读后复核 mtime+size」要在**每片之后**做（文件在传输中途被改要立刻作废，而不是传完才发现）。
//!
//! ## 隐私红线（同 `preview_read.rs`，由 `tests/preview_privacy_guard.rs` 的静态守卫强制）
//! - 不得写文件；任何日志都不得引用分片、内容或本机路径。
//! - 本模块**一行日志都不打**。
//!
//! ## 与步一单帧路径的关系
//! 步一（能力 1）走 `preview_read::read_for_preview` + 三帧。本模块只服务 `transfer=chunked` 的请求，
//! 两条路径互不依赖，步一行为逐字节不变。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, watch};

use super::preview_gate::PreviewReject;
use super::preview_read::{fingerprint, preview_kind, Fingerprint, PreviewKind, TEXT_DISPLAY_BYTES};

/// 分片大小：4MB 原始字节。与服务端 `PREVIEW_CHUNK_BYTES`、共享契约样例 `constants.chunkBytes` 同值。
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// 等待服务端「要下一片」的无进度上限。服务端自己有 60 秒无进度作废；这里取同值，
/// 服务端不再理我们（断线 / 作废）时本任务自行结束，不永远挂着持有文件句柄。
pub const PULL_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// 按类型的 Bridge 侧上限（字节）。与服务端 `PREVIEW_KIND_MAX_BYTES` 同口径——
/// 服务端是第二道，**这里在弹窗之前就拒**，不让用户白点一次允许（用户 2026-10-09 拍板）。
pub fn kind_limit_bytes(kind: PreviewKind, ext: &str) -> u64 {
    const MB: u64 = 1024 * 1024;
    match kind {
        // 文本：读多少都只回前 2MB，大小由档位限制即可
        PreviewKind::Text => u64::MAX,
        PreviewKind::Binary => match ext {
            "docx" | "xlsx" => 20 * MB,
            // pdf / 图片
            _ => 100 * MB,
        },
    }
}

/// 某路径在当前档位下的有效上限：`min(用户档位, 类型上限)`。
pub fn limit_for_path(path: &Path, tier_bytes: u64) -> u64 {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match preview_kind(path) {
        Some(kind) => tier_bytes.min(kind_limit_bytes(kind, &ext)),
        None => 0,
    }
}

/// 一个在途分片预览的「已批准到第几片（不含）」水位。服务端 `preview_pull` 帧把它推高；只升不降。
#[derive(Debug, Clone)]
pub struct PullWatch {
    tx: Arc<watch::Sender<u64>>,
}

impl PullWatch {
    fn new() -> (Self, watch::Receiver<u64>) {
        let (tx, rx) = watch::channel(0u64);
        (Self { tx: Arc::new(tx) }, rx)
    }

    /// 推高水位。**只升不降**：迟到 / 重放的旧 pull（upTo 更小）不得让已发的片倒退，
    /// 也不得被伪造成「回收批准」。
    pub fn grant(&self, up_to: u64) {
        self.tx.send_if_modified(|cur| {
            if up_to > *cur {
                *cur = up_to;
                true
            } else {
                false
            }
        });
    }
}

/// 在途分片预览登记表：`previewId → PullWatch`。每条连接一张，断线即失效（随 `connect_once` 的栈帧销毁）。
#[derive(Debug, Clone, Default)]
pub struct StreamRegistry {
    inner: Arc<Mutex<std::collections::HashMap<String, PullWatch>>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个在途预览，返回它的水位接收端。同 id 重复登记会覆盖（服务端的 id 唯一，这只是兜底）。
    pub fn register(&self, preview_id: &str) -> watch::Receiver<u64> {
        let (w, rx) = PullWatch::new();
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(preview_id.to_string(), w);
        rx
    }

    pub fn unregister(&self, preview_id: &str) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(preview_id);
    }

    /// 服务端 `preview_pull` 到达：推高对应预览的水位。**未登记的 id（已结束 / 伪造）静默忽略**。
    pub fn on_pull(&self, preview_id: &str, up_to: u64) {
        let w = self.inner.lock().unwrap_or_else(|e| e.into_inner()).get(preview_id).cloned();
        if let Some(w) = w {
            w.grant(up_to);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 解析 `preview_pull` 帧 → `(previewId, upTo)`。字段缺失 / 类型不对 → None（整帧丢弃，不猜）。
pub fn parse_pull(v: &serde_json::Value) -> Option<(String, u64)> {
    if v.get("type")?.as_str()? != "preview_pull" {
        return None;
    }
    let id = v.get("previewId")?.as_str()?.trim();
    if id.is_empty() || id.len() > 128 {
        return None;
    }
    // 严格类型：只认非负整数。as_u64 对负数 / 小数 / 字符串都返回 None
    let up_to = v.get("upTo")?.as_u64()?;
    Some((id.to_string(), up_to))
}

/// 解析 `preview_abort` 帧（服务端 → Bridge：别发了）→ previewId。
pub fn parse_server_abort(v: &serde_json::Value) -> Option<String> {
    if v.get("type")?.as_str()? != "preview_abort" {
        return None;
    }
    let id = v.get("previewId")?.as_str()?.trim();
    if id.is_empty() || id.len() > 128 {
        return None;
    }
    Some(id.to_string())
}

/// `preview_chunk`（分片版，带 `seq`）。
pub fn chunk_frame_seq(preview_id: &str, seq: u64, bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "type": "preview_chunk",
        "previewId": preview_id,
        "seq": seq,
        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

/// 一次分片传输的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOutcome {
    /// 全部发完，`preview_end` 已入队
    Done { size: u64, chunks: u64 },
    /// 失败：已按需把 `preview_abort` 入队（服务端主动叫停的不再回 abort）
    Failed(PreviewReject),
    /// 服务端叫停 / 久无 pull / 出站通道已关：安静结束，不再发任何帧
    Stopped,
}

/// 分片传输的测试缝：在每片读完之后、复核之前调用。生产传 `|_| {}`。
/// 「传输中被改」是并发事件，没有缝无法确定性复现；而「每片后都复核」是本模块最关键的规则。
pub(crate) type MidHook<'a> = &'a mut (dyn FnMut(u64) + Send);

/// 把 `path` 按片发出。
///
/// - `size_hint`：闸阶段看到的文件大小（用于声明 meta）。**传输中以磁盘为准每片复核**。
/// - `kind`：文本类只发前 2MB 并标截断；二进制整文件。
/// - `pull`：服务端批准水位。第 N 片（从 0 数）发送前须 `pull ≥ N+1`。
/// - `out`：出站队列（与心跳 / 任务结果共用，容量 32）。
/// - `stop`：服务端 `preview_abort` 到达时置位。
pub async fn stream_file(
    preview_id: &str,
    path: &Path,
    kind: PreviewKind,
    mut pull: watch::Receiver<u64>,
    out: &mpsc::Sender<String>,
    stop: &watch::Receiver<bool>,
    chunk_bytes: usize,
    pull_timeout: Duration,
    mid: MidHook<'_>,
) -> StreamOutcome {
    // ① 读前指纹（任何一步取不到 = 读失败 = 可重试）
    let Some(before) = fingerprint(path).await else {
        return fail(preview_id, out, PreviewReject::Retry).await;
    };

    // ② 本次要回传的字节数：文本只回前 2MB（并标已截断），二进制整文件
    let (send_len, truncated) = match kind {
        PreviewKind::Text => {
            let n = before.size.min(TEXT_DISPLAY_BYTES as u64);
            (n, before.size > TEXT_DISPLAY_BYTES as u64)
        }
        PreviewKind::Binary => (before.size, false),
    };

    // ③ 打开文件（同一个句柄读到底；中途被替换 / 删除由每片后的复核发现）
    //     审核 F11：禁跟随符号链接 + 句柄确认是普通文件（过闸到打开之间路径被换成链接 → 拒）
    let Some(mut file) = super::preview_open::open_no_follow(path).await else {
        return fail(preview_id, out, PreviewReject::Retry).await;
    };

    // ③.5 审核 F9（10-09）：文本截断必须退到 UTF-8 字符边界（与单帧路径 `truncate_at_char_boundary` 同规则），
    //      否则截断处的汉字会被劈开、网页显示乱码方块。边界要在发 meta **之前**定下（meta 声明的字节数
    //      必须与实发一致），所以先看截断点前后 4 字节：只读这 4 字节，不整读。
    let send_len = if truncated {
        match boundary_len(&mut file, send_len).await {
            Some(n) => n,
            None => return fail(preview_id, out, PreviewReject::Retry).await,
        }
    } else {
        send_len
    };

    // ④ meta：服务端在这里独立校验声明大小（超类型上限 / 超预算 → abort，不收字节）
    if out
        .send(super::preview_read::meta_frame(preview_id, send_len as usize, truncated).to_string())
        .await
        .is_err()
    {
        return StreamOutcome::Stopped;
    }

    let total_chunks = if send_len == 0 { 0 } else { send_len.div_ceil(chunk_bytes as u64) };
    let mut buf = vec![0u8; chunk_bytes];
    let mut sent: u64 = 0;

    for seq in 0..total_chunks {
        // ⑤ 等批准：水位 ≥ seq+1 才能发第 seq 片。久无 pull → 自行结束（服务端自己也会作废）
        loop {
            if *stop.borrow() {
                return StreamOutcome::Stopped;
            }
            if *pull.borrow() > seq {
                break;
            }
            tokio::select! {
                changed = pull.changed() => {
                    if changed.is_err() { return StreamOutcome::Stopped; }
                }
                _ = tokio::time::sleep(pull_timeout) => return StreamOutcome::Stopped,
            }
        }
        if *stop.borrow() {
            return StreamOutcome::Stopped;
        }

        // ⑥ 读一片（末片可短）。读到的字节数必须等于预期——读不满说明文件在传输中变短了
        let want = (send_len - sent).min(chunk_bytes as u64) as usize;
        if file.read_exact(&mut buf[..want]).await.is_err() {
            return fail(preview_id, out, PreviewReject::Retry).await;
        }

        mid(seq);

        // ⑦ 每片之后复核：文件在传输中途被改 → 整个作废（grill Q8：不加锁不快照）
        match fingerprint(path).await {
            Some(after) if same(&before, &after) => {}
            _ => return fail(preview_id, out, PreviewReject::Retry).await,
        }

        // ⑧ 发出。出站队列满会在这里自然背压（send 等空位），不会无界堆内存
        if out.send(chunk_frame_seq(preview_id, seq, &buf[..want]).to_string()).await.is_err() {
            return StreamOutcome::Stopped;
        }
        sent += want as u64;
    }

    // 测试缝：序号 == 总片数 表示「所有片都已发出、end 之前」
    mid(total_chunks);
    // ⑨ 收尾复核：最后一片发完后文件若又变了，也不能报成功
    match fingerprint(path).await {
        Some(after) if same(&before, &after) => {}
        _ => return fail(preview_id, out, PreviewReject::Retry).await,
    }
    if out.send(super::preview_read::end_frame(preview_id).to_string()).await.is_err() {
        return StreamOutcome::Stopped;
    }
    StreamOutcome::Done { size: sent, chunks: total_chunks }
}

/// 截断长度退到 UTF-8 字符边界：读 `[limit-3, limit+1)` 这 4 字节，复用单帧路径同一规则。
/// 读完把读指针归零（随后从头按片读）。读失败 → None（按可重试处理）。
async fn boundary_len(file: &mut tokio::fs::File, limit: u64) -> Option<u64> {
    use tokio::io::AsyncSeekExt;
    let start = limit.saturating_sub(3);
    file.seek(std::io::SeekFrom::Start(start)).await.ok()?;
    let mut win = [0u8; 4];
    let n = file.read(&mut win).await.ok()?;
    file.seek(std::io::SeekFrom::Start(0)).await.ok()?;
    // 窗口内 limit 对应的下标
    let at = (limit - start) as usize;
    if n <= at {
        return Some(limit);
    }
    let kept = super::preview_read::truncate_at_char_boundary(&win[..n], at).len();
    Some(start + kept as u64)
}

fn same(a: &Fingerprint, b: &Fingerprint) -> bool {
    a == b
}

/// 失败：先把已持有的缓冲交给 drop，再入队 abort 帧（带粗粒度 code，不含路径 / 内容）。
async fn fail(preview_id: &str, out: &mpsc::Sender<String>, why: PreviewReject) -> StreamOutcome {
    let frame = serde_json::json!({
        "type": "preview_abort",
        "previewId": preview_id,
        "code": why.code(),
        "message": why.message(),
    });
    let _ = out.send(frame.to_string()).await;
    StreamOutcome::Failed(why)
}

/// 便捷：按 `PathBuf` 取种类并校验可分片。认不出 → None。
pub fn kind_of(path: &PathBuf) -> Option<PreviewKind> {
    preview_kind(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const C: usize = 8; // 测试用 8 字节一片

    fn write(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    /// 收集出站帧。
    async fn drain(rx: &mut mpsc::Receiver<String>) -> Vec<serde_json::Value> {
        let mut v = vec![];
        while let Ok(s) = rx.try_recv() {
            v.push(serde_json::from_str(&s).unwrap());
        }
        v
    }

    struct Rig {
        out_tx: mpsc::Sender<String>,
        out_rx: mpsc::Receiver<String>,
        stop_tx: watch::Sender<bool>,
        stop_rx: watch::Receiver<bool>,
        reg: StreamRegistry,
    }
    fn rig() -> Rig {
        let (out_tx, out_rx) = mpsc::channel(1024);
        let (stop_tx, stop_rx) = watch::channel(false);
        Rig { out_tx, out_rx, stop_tx, stop_rx, reg: StreamRegistry::new() }
    }

    async fn run(
        r: &Rig,
        id: &str,
        p: &Path,
        kind: PreviewKind,
        grant_up_to: u64,
        mid: &mut (dyn FnMut(u64) + Send),
    ) -> StreamOutcome {
        let rx = r.reg.register(id);
        r.reg.on_pull(id, grant_up_to);
        stream_file(id, p, kind, rx, &r.out_tx, &r.stop_rx, C, Duration::from_millis(80), mid).await
    }

    // ── 审核 F11：过闸后路径被换成符号链接 ──────────────────────

    /// 变异锁：把 `open_no_follow` 换回 `tokio::fs::File::open` → 本用例红（会读出授权目录外的内容）。
    #[cfg(unix)]
    #[tokio::test]
    async fn 过闸后被换成符号链接_拒绝_不发任何分片() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = write(outside.path(), "secret.pdf", b"SECRET-OUTSIDE-ROOT");
        let p = d.path().join("a.pdf");
        std::os::unix::fs::symlink(&secret, &p).unwrap();
        let mut r = rig();
        let out = run(&r, "pv_f11", &p, PreviewKind::Binary, 99, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let fr = drain(&mut r.out_rx).await;
        assert!(fr.iter().all(|f| f["type"] != "preview_chunk" && f["type"] != "preview_meta"), "不得发出 meta / 分片");
    }

    // ── 正常传输 ──────────────────────────────────────────────

    #[tokio::test]
    async fn 多片传输_字节逐位一致_序号严格递增_末片可短() {
        let d = tempfile::tempdir().unwrap();
        let body: Vec<u8> = (0..(C * 3 + 3)).map(|i| (i % 251) as u8).collect(); // 4 片，末片 3 字节
        let p = write(d.path(), "a.pdf", &body);
        let mut r = rig();
        let out = run(&r, "pv_1", &p, PreviewKind::Binary, 99, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Done { size: body.len() as u64, chunks: 4 });
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr[0]["type"], "preview_meta");
        assert_eq!(fr[0]["size"], body.len());
        assert_eq!(fr.last().unwrap()["type"], "preview_end");
        use base64::Engine as _;
        let mut got = vec![];
        for (i, f) in fr[1..fr.len() - 1].iter().enumerate() {
            assert_eq!(f["type"], "preview_chunk");
            assert_eq!(f["seq"], i as u64, "序号必须从 0 严格递增");
            got.extend(base64::engine::general_purpose::STANDARD.decode(f["data"].as_str().unwrap()).unwrap());
        }
        assert_eq!(got, body, "拼回来必须与磁盘逐字节一致");
    }

    #[tokio::test]
    async fn 空文件_只有_meta_和_end_没有分片() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "empty.png", b"");
        let mut r = rig();
        let out = run(&r, "pv_e", &p, PreviewKind::Binary, 0, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Done { size: 0, chunks: 0 });
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr.iter().map(|f| f["type"].as_str().unwrap()).collect::<Vec<_>>(), ["preview_meta", "preview_end"]);
    }

    #[tokio::test]
    async fn 文本只回前两兆并标截断_meta_报的是实际回传量() {
        let d = tempfile::tempdir().unwrap();
        let body = vec![b'x'; TEXT_DISPLAY_BYTES + 100];
        let p = write(d.path(), "big.txt", &body);
        // 用真实 4MB 分片：2MB 一片搞定
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (_stop_tx, stop_rx) = watch::channel(false);
        let reg = StreamRegistry::new();
        let rx = reg.register("pv_t");
        reg.on_pull("pv_t", 9);
        let o = stream_file("pv_t", &p, PreviewKind::Text, rx, &out_tx, &stop_rx, CHUNK_BYTES, PULL_WAIT_TIMEOUT, &mut |_| {}).await;
        assert_eq!(o, StreamOutcome::Done { size: TEXT_DISPLAY_BYTES as u64, chunks: 1 });
        let fr = drain(&mut out_rx).await;
        assert_eq!(fr[0]["size"], TEXT_DISPLAY_BYTES);
        assert_eq!(fr[0]["truncated"], true);
    }

    /// 审核 F9 变异：去掉 `boundary_len`（直接按 2MB 原始字节截）→ 本用例红。
    #[tokio::test]
    async fn 文本截断退到字符边界_不劈开汉字_且_meta_与实发一致() {
        let d = tempfile::tempdir().unwrap();
        // 让第 2MB 字节恰好落在「中」(3 字节) 的中间
        let mut body = vec![b'a'; TEXT_DISPLAY_BYTES - 1];
        body.extend("中文".repeat(10).as_bytes());
        let p = write(d.path(), "cut.txt", &body);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (_stop_tx, stop_rx) = watch::channel(false);
        let reg = StreamRegistry::new();
        let rx = reg.register("pv_u");
        reg.on_pull("pv_u", 9);
        let o = stream_file("pv_u", &p, PreviewKind::Text, rx, &out_tx, &stop_rx, CHUNK_BYTES, PULL_WAIT_TIMEOUT, &mut |_| {}).await;
        assert!(matches!(o, StreamOutcome::Done { .. }), "{o:?}");
        let fr = drain(&mut out_rx).await;
        use base64::Engine as _;
        let mut got = vec![];
        for f in fr.iter().filter(|f| f["type"] == "preview_chunk") {
            got.extend(base64::engine::general_purpose::STANDARD.decode(f["data"].as_str().unwrap()).unwrap());
        }
        assert!(std::str::from_utf8(&got).is_ok(), "截断后必须是合法 UTF-8");
        assert_eq!(got.len(), TEXT_DISPLAY_BYTES - 1, "退回到「中」之前");
        assert_eq!(fr[0]["size"], got.len(), "meta 声明的大小必须等于实发字节数（服务端逐片核对）");
        assert_eq!(fr[0]["truncated"], true);
    }

    // ── 拉取式：没批准就不发 ─────────────────────────────────────

    /// 变异：去掉「等批准」循环（直接发）→ 本用例红。
    #[tokio::test]
    async fn 没有被批准的片不发_只发_meta() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let mut r = rig();
        // 批准 0 片：久无 pull → 自行结束，且只发了 meta
        let out = run(&r, "pv_2", &p, PreviewKind::Binary, 0, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Stopped);
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0]["type"], "preview_meta");
    }

    /// 变异：用 `>=` 改成 `>`（批准水位差一）→ 本用例红。
    #[tokio::test]
    async fn 批准到第_n_片_恰好发_n_片() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let mut r = rig();
        let out = run(&r, "pv_3", &p, PreviewKind::Binary, 3, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Stopped, "只批准 3 片，第 4 片等不到批准");
        let n = drain(&mut r.out_rx).await.iter().filter(|f| f["type"] == "preview_chunk").count();
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn 边传边批准_全部发完() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![7u8; C * 6]);
        let mut r = rig();
        let rx = r.reg.register("pv_4");
        r.reg.on_pull("pv_4", 3);
        let reg2 = r.reg.clone();
        let feeder = tokio::spawn(async move {
            for up in 4..=6u64 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                reg2.on_pull("pv_4", up);
            }
        });
        let out = stream_file("pv_4", &p, PreviewKind::Binary, rx, &r.out_tx, &r.stop_rx, C, Duration::from_secs(2), &mut |_| {}).await;
        feeder.await.unwrap();
        assert_eq!(out, StreamOutcome::Done { size: (C * 6) as u64, chunks: 6 });
        let _ = drain(&mut r.out_rx).await;
    }

    /// 变异：`grant` 改成直接赋值（允许降）→ 本用例红。迟到 / 重放的旧 pull 不得让水位倒退。
    #[test]
    fn 水位只升不降() {
        let reg = StreamRegistry::new();
        let rx = reg.register("pv_5");
        reg.on_pull("pv_5", 5);
        reg.on_pull("pv_5", 2);
        assert_eq!(*rx.borrow(), 5, "旧的 pull 不得让水位回落");
        reg.on_pull("pv_5", 9);
        assert_eq!(*rx.borrow(), 9);
    }

    #[test]
    fn 未登记的_pull_静默忽略() {
        let reg = StreamRegistry::new();
        reg.on_pull("nobody", 3); // 不 panic
        assert!(reg.is_empty());
    }

    #[test]
    fn 登记表_注销后_pull_不再生效() {
        let reg = StreamRegistry::new();
        let rx = reg.register("pv_6");
        reg.unregister("pv_6");
        reg.on_pull("pv_6", 4);
        assert_eq!(*rx.borrow(), 0);
    }

    // ── 传输中被改 → 作废（每片后复核）────────────────────────────

    /// ⭐变异：把「每片之后复核」整段删掉 → 本用例红。
    /// 在第 1 片读完之后把文件改大——必须立刻作废，而不是等到传完才发现（那时已发出去 N 片）。
    #[tokio::test]
    async fn 传输中途文件变长_立即作废_不再发后续片() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let p2 = p.clone();
        let mut r = rig();
        let mut mid = move |seq: u64| {
            if seq == 1 {
                std::fs::write(&p2, vec![2u8; C * 9]).unwrap();
            }
        };
        let out = run(&r, "pv_7", &p, PreviewKind::Binary, 99, &mut mid).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let fr = drain(&mut r.out_rx).await;
        let chunks = fr.iter().filter(|f| f["type"] == "preview_chunk").count();
        assert_eq!(chunks, 1, "第 1 片读完后发现被改，之后不得再发任何分片（只发出了第 0 片）");
        assert_eq!(fr.last().unwrap()["type"], "preview_abort");
        assert!(fr.iter().all(|f| f["type"] != "preview_end"), "被改的传输绝不能以 end 收尾");
    }

    #[tokio::test]
    async fn 传输中途文件变短_作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let p2 = p.clone();
        let mut r = rig();
        let mut mid = move |seq: u64| {
            if seq == 0 {
                std::fs::write(&p2, b"short").unwrap();
            }
        };
        let out = run(&r, "pv_8", &p, PreviewKind::Binary, 99, &mut mid).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        assert!(drain(&mut r.out_rx).await.iter().all(|f| f["type"] != "preview_end"));
    }

    /// 变异：指纹去掉 mtime（只比 size）→ 本用例红。等长改写只有 mtime 变。
    #[tokio::test]
    async fn 传输中途等长改写_靠修改时间发现() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![b'A'; C * 4]);
        let p2 = p.clone();
        let mut r = rig();
        let mut mid = move |seq: u64| {
            if seq == 1 {
                std::thread::sleep(Duration::from_millis(30));
                std::fs::write(&p2, vec![b'B'; C * 4]).unwrap();
            }
        };
        let out = run(&r, "pv_9", &p, PreviewKind::Binary, 99, &mut mid).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let _ = drain(&mut r.out_rx).await;
    }

    #[tokio::test]
    async fn 传输中途文件被删_作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 4]);
        let p2 = p.clone();
        let mut r = rig();
        let mut mid = move |seq: u64| {
            if seq == 1 {
                std::fs::remove_file(&p2).unwrap();
            }
        };
        let out = run(&r, "pv_10", &p, PreviewKind::Binary, 99, &mut mid).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let _ = drain(&mut r.out_rx).await;
    }

    /// 变异：去掉「最后一片之后的收尾复核」⑨ → 本用例红。
    /// 每片复核（⑦）发生在该片发出**之前**；末片复核通过后到 end 之间文件仍可能被改，
    /// 此时前面所有片都已发出，只有收尾复核能拦住「以 end 收尾的坏文件」。
    #[tokio::test]
    async fn 最后一片发完后被改_不能以_end_收尾() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 2]);
        let p2 = p.clone();
        let mut r = rig();
        let mut mid = move |seq: u64| {
            // seq == 总片数(2)：所有片已发出、end 之前
            if seq == 2 {
                std::fs::write(&p2, vec![9u8; C * 2 + 5]).unwrap();
            }
        };
        let out = run(&r, "pv_11", &p, PreviewKind::Binary, 99, &mut mid).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr.iter().filter(|f| f["type"] == "preview_chunk").count(), 2, "两片都已发出");
        assert!(fr.iter().all(|f| f["type"] != "preview_end"), "收尾复核失败不得发 end");
        assert_eq!(fr.last().unwrap()["type"], "preview_abort");
    }

    // ── 叫停 / 断线 / 超时 ───────────────────────────────────────

    #[tokio::test]
    async fn 服务端叫停_立即安静结束_不再发帧() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let mut r = rig();
        r.stop_tx.send(true).unwrap();
        let out = run(&r, "pv_12", &p, PreviewKind::Binary, 99, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Stopped);
        let fr = drain(&mut r.out_rx).await;
        assert!(fr.iter().all(|f| f["type"] != "preview_chunk" && f["type"] != "preview_abort"), "被叫停后不回 abort（服务端已知）");
    }

    /// ⭐ 服务端叫停的真实路径：client.rs 收到 `preview_abort` 只做 `registry.unregister(id)`，
    /// 靠「水位发送端随登记项 drop → 接收端 changed() 返回 Err」让传输任务停下。
    /// 本用例走**同一条路径**（不碰 stop 通道），证明它真的会停、且停后不再发任何帧。
    /// 变异：`unregister` 改成不移除登记项（发送端不 drop）→ 本用例红（任务要等满 pull 超时）。
    #[tokio::test]
    async fn 服务端_abort_只靠注销登记项_传输任务就会停() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 6]);
        let mut r = rig();
        let rx = r.reg.register("pv_x");
        r.reg.on_pull("pv_x", 2); // 只批准 2 片，第 3 片开始要等
        let out_tx = r.out_tx.clone();
        let stop_rx = r.stop_rx.clone();
        let task = tokio::spawn(async move {
            // pull 超时设得很长：若不是被注销打断，测试会超时而非通过
            stream_file("pv_x", &p, PreviewKind::Binary, rx, &out_tx, &stop_rx, C, Duration::from_secs(30), &mut |_| {}).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await; // 让它发完 2 片并卡在等第 3 片
        r.reg.unregister("pv_x"); // client.rs 收到服务端 preview_abort 时做的唯一一件事
        let res = tokio::time::timeout(Duration::from_secs(3), task).await.expect("注销后传输任务必须很快停下").unwrap();
        assert_eq!(res, StreamOutcome::Stopped);
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr.iter().filter(|f| f["type"] == "preview_chunk").count(), 2, "只发了被批准的 2 片");
        assert!(fr.iter().all(|f| f["type"] != "preview_abort" && f["type"] != "preview_end"), "被叫停后不回任何终结帧");
    }

    #[tokio::test]
    async fn 出站队列关闭_安静结束() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", &vec![1u8; C * 5]);
        let r = rig();
        let Rig { out_tx, out_rx, stop_rx, reg, .. } = r;
        drop(out_rx);
        let rx = reg.register("pv_13");
        reg.on_pull("pv_13", 99);
        let o = stream_file("pv_13", &p, PreviewKind::Binary, rx, &out_tx, &stop_rx, C, Duration::from_millis(50), &mut |_| {}).await;
        assert_eq!(o, StreamOutcome::Stopped);
    }

    #[tokio::test]
    async fn 读不到文件_回可重试() {
        let d = tempfile::tempdir().unwrap();
        let mut r = rig();
        let out = run(&r, "pv_14", &d.path().join("ghost.pdf"), PreviewKind::Binary, 9, &mut |_| {}).await;
        assert_eq!(out, StreamOutcome::Failed(PreviewReject::Retry));
        let fr = drain(&mut r.out_rx).await;
        assert_eq!(fr[0]["type"], "preview_abort");
        assert_eq!(fr[0]["code"], PreviewReject::Retry.code());
    }

    // ── 帧解析 ───────────────────────────────────────────────

    #[test]
    fn 解析_pull_严格类型() {
        let ok = serde_json::json!({"type":"preview_pull","previewId":"pv_1","upTo":3});
        assert_eq!(parse_pull(&ok), Some(("pv_1".into(), 3)));
        for bad in [
            serde_json::json!({"type":"preview_pull","previewId":"pv_1","upTo":-1}),
            serde_json::json!({"type":"preview_pull","previewId":"pv_1","upTo":1.5}),
            serde_json::json!({"type":"preview_pull","previewId":"pv_1","upTo":"3"}),
            serde_json::json!({"type":"preview_pull","previewId":"pv_1"}),
            serde_json::json!({"type":"preview_pull","upTo":3}),
            serde_json::json!({"type":"preview_pull","previewId":"","upTo":3}),
            serde_json::json!({"type":"preview_pull","previewId":"x".repeat(129),"upTo":3}),
            serde_json::json!({"type":"preview_request","previewId":"pv_1","upTo":3}),
        ] {
            assert!(parse_pull(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn 解析服务端_abort() {
        assert_eq!(
            parse_server_abort(&serde_json::json!({"type":"preview_abort","previewId":"pv_1","code":"X"})),
            Some("pv_1".into())
        );
        assert!(parse_server_abort(&serde_json::json!({"type":"preview_abort"})).is_none());
        assert!(parse_server_abort(&serde_json::json!({"type":"task","previewId":"pv_1"})).is_none());
    }

    // ── 类型上限（弹窗前拒）────────────────────────────────────────

    #[test]
    fn 类型上限_pdf图片_100_docx_xlsx_20_文本不限() {
        const MB: u64 = 1024 * 1024;
        let t = 200 * MB;
        assert_eq!(limit_for_path(Path::new("a.pdf"), t), 100 * MB);
        assert_eq!(limit_for_path(Path::new("a.png"), t), 100 * MB);
        assert_eq!(limit_for_path(Path::new("a.docx"), t), 20 * MB);
        assert_eq!(limit_for_path(Path::new("a.xlsx"), t), 20 * MB);
        assert_eq!(limit_for_path(Path::new("a.txt"), t), t);
        assert_eq!(limit_for_path(Path::new("a.mp4"), t), 0, "认不出的类型上限为 0");
    }

    /// 变异：取 max 而不是 min → 本用例红。用户把档位调小（50MB）后，类型上限不得把它放大。
    #[test]
    fn 档位小于类型上限时以档位为准() {
        const MB: u64 = 1024 * 1024;
        assert_eq!(limit_for_path(Path::new("a.pdf"), 50 * MB), 50 * MB);
        assert_eq!(limit_for_path(Path::new("a.docx"), 10 * MB), 10 * MB);
    }

    #[test]
    fn 分片帧字段名与契约一致() {
        let c = chunk_frame_seq("pv_1", 7, b"hi");
        assert_eq!(c["type"], "preview_chunk");
        assert_eq!(c["seq"], 7);
        assert_eq!(c["data"], "aGk=");
    }
}
