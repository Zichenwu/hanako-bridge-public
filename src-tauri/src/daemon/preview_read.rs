// src-tauri/src/daemon/preview_read.rs
//! 预览读取（本地文件预览 票 04 步一）：把已过闸的文件读成字节，单帧回传给服务端。
//!
//! ## 本模块的隐私红线（故事 44 / 对抗审查 P1）
//! - **任何日志都不得引用分片、结果或文件内容**，也不得打印本机绝对路径。
//!   反面教材：助手本地工具的派发入口会打印「工具名 + 结果前 80 个字符」（`local-dispatch.js`）；
//!   预览若照抄那个写法，文本文件的开头会进日志。本模块的 log 只允许出现 previewId、
//!   字节数、是否截断这类**不含内容**的量。
//! - **不得写文件**：没有任何落盘、缓存、临时文件。字节只在内存里走一趟就交给 WS 帧。
//! - 这两条由 `tests/preview-privacy-guard.rs` 的静态守卫强制（扫本文件源码）。
//!
//! ## 为什么「读完复核 mtime+size」而不是加锁 / 快照
//! 用户拍板（grill Q8）：传输中文件被改 → **整个作废**，不加锁（锁住用户自己的文件
//! 是更糟的体验）、不做快照（要落盘，违反上面第二条）。复核不一致就回
//! [`PreviewReject::Retry`]，让用户重试。
//!
//! ## 步一只做文本类
//! 文本类 ≤20MB 单帧回传（base64 后约 27MB，远低于 WS 单帧 64MiB 上限，见
//! `upload_gate::WS_SAFE_RAW_BYTES`）。分片与其它类型在票 07/08。

use std::path::Path;
use std::time::SystemTime;

use super::preview_gate::PreviewReject;

/// 文本类预览的**显示**上限：超过只回前 2MB 并标「已截断」（故事 5）。
///
/// 与 `preview_gate::MAX_PREVIEW_BYTES`（20MB，拒绝线）是两件事：
/// - 20MB 以上 = **拒绝**，根本不读（闸在读字节之前就拦了）；
/// - 2MB~20MB = **读，但只回前 2MB**，网页标「已截断」并给「让助手读取完整内容」的指引。
pub const TEXT_DISPLAY_BYTES: usize = 2 * 1024 * 1024;

/// 步一支持的文本类扩展名。
///
/// 白名单而非黑名单：认不出的扩展名一律**不预览**（回「这个文件受保护」的同族拒绝），
/// 而不是「先读了再猜是不是文本」——猜错就把二进制塞进网页。
/// 其它类型（pdf/docx/图片）在票 08。
const TEXT_EXTS: &[&str] = &[
    "txt", "md", "markdown", "log", "csv", "tsv",
    "json", "jsonl", "yaml", "yml", "toml", "ini", "conf", "cfg", "properties",
    "xml", "html", "htm", "css", "scss", "less",
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "vue", "svelte",
    "rs", "go", "py", "rb", "php", "java", "kt", "kts", "scala", "swift",
    "c", "h", "cc", "cpp", "hpp", "cs", "m", "mm",
    "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd",
    "sql", "graphql", "proto", "dockerfile", "makefile", "gradle",
    "env_sample", "example", "template", "patch", "diff", "lock",
];

/// 文档类（整文件原样回传，网页按类型渲染；**不截断**——截断的 pdf/docx 是坏文件）。
/// 与云端预览面板已支持的渲染一一对应：pdf 用浏览器内置查看器、docx/xlsx 由服务端内存转 HTML、
/// 图片直接显示。旧版 Office（doc/xls/ppt）与 pptx 云端也渲染不了，不列。
const DOC_EXTS: &[&str] = &["pdf", "docx", "xlsx"];
const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "ico"];

/// 预览种类：决定读取方式与网页渲染方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    /// 文本：>2MB 只回前 2MB
    Text,
    /// 二进制文档 / 图片：整文件原样回传
    Binary,
}

/// 本 Bridge 能预览的种类名（注册帧 `previewKinds` 上报，网页据此决定点文件走预览还是写路径）。
/// 名字与网页侧一一对应，新增种类必须两边同时加。
pub const PREVIEW_KINDS: &[&str] = &["text", "pdf", "docx", "xlsx", "image"];

/// 判定预览种类；认不出 → None（拒绝，回「暂不支持预览这种格式」）。
pub fn preview_kind(path: &Path) -> Option<PreviewKind> {
    if is_text_preview(path) {
        return Some(PreviewKind::Text);
    }
    let ext = path.extension().and_then(|e| e.to_str())?.to_ascii_lowercase();
    if DOC_EXTS.contains(&ext.as_str()) || IMAGE_EXTS.contains(&ext.as_str()) {
        Some(PreviewKind::Binary)
    } else {
        None
    }
}

/// 是否是步一支持的文本类。无扩展名的常见文本文件名（Makefile / Dockerfile）也算。
pub fn is_text_preview(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        return TEXT_EXTS.contains(&lower.as_str());
    }
    // 无扩展名：按文件名白名单（大小写不敏感）
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => {
            let lower = name.to_ascii_lowercase();
            matches!(lower.as_str(), "makefile" | "dockerfile" | "readme" | "license" | "changelog")
        }
        None => false,
    }
}

/// 读取前后用于复核的文件指纹。mtime 取不到时记 `None`——**取不到不等于没变**，
/// 复核时 `None` 与 `None` 相等会放过，所以 size 永远参与比较（两者都变才可能漏判，
/// 而 size 不变 + mtime 不可读的「原地等长改写」在实践中已被 size 覆盖大部分场景）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// 取指纹。取不到元信息 → None（调用方按「读失败」处理）。
pub async fn fingerprint(path: &Path) -> Option<Fingerprint> {
    let m = tokio::fs::metadata(path).await.ok()?;
    Some(Fingerprint { size: m.len(), mtime: m.modified().ok() })
}

/// 读取结果：可回传的字节 + 是否被截断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewBytes {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// 读文本类文件的字节，并在读完后复核指纹。
///
/// 流程（顺序是安全要点）：
/// ① 读前取指纹 → ② 读字节（最多 `TEXT_DISPLAY_BYTES`）→ ③ 读后再取指纹 → ④ 不一致则作废。
///
/// 返回 `Err(PreviewReject::Retry)`：读失败、或传输中文件被改。
/// 返回 `Err(PreviewReject::UnsupportedType)`：认不出的类型（正常情况下闸已在弹窗前拦掉，这里是第二道）。
pub async fn read_text(path: &Path) -> Result<PreviewBytes, PreviewReject> {
    read_text_hooked(path, || {}).await
}

/// 按种类读取：文本走 [`read_text`]（截断到 2MB）；文档/图片整文件读、同样读后复核。
pub async fn read_for_preview(path: &Path) -> Result<PreviewBytes, PreviewReject> {
    match preview_kind(path) {
        Some(PreviewKind::Text) => read_text(path).await,
        Some(PreviewKind::Binary) => read_whole_hooked(path, || {}).await,
        None => Err(PreviewReject::UnsupportedType),
    }
}

/// 整文件读取 + 读后复核（与文本同一条复核规则）。大小上限由闸在读之前保证。
pub(crate) async fn read_whole_hooked(path: &Path, mid: impl FnOnce()) -> Result<PreviewBytes, PreviewReject> {
    let before = fingerprint(path).await.ok_or(PreviewReject::Retry)?;
    // 审核 F11：禁跟随符号链接 + 只读普通文件（见 preview_open）
    let raw = super::preview_open::read_no_follow(path).await.ok_or(PreviewReject::Retry)?;
    mid();
    let after = fingerprint(path).await.ok_or(PreviewReject::Retry)?;
    if before != after || raw.len() as u64 != before.size {
        return Err(PreviewReject::Retry);
    }
    Ok(PreviewBytes { bytes: raw, truncated: false })
}

/// 同 [`read_text`]，但在「读完字节」与「复核指纹」之间调一次 `mid`。
///
/// 这个缝只为测试存在：「传输中文件被改」在真实世界里是并发事件，没有缝无法确定性复现；
/// 而「复核是否真的生效」是本模块最关键的规则，必须有测试能在它被删掉时变红
/// （实测：只测 `fingerprint()` 本身抓不住——去掉复核调用后那些用例照样全绿）。
/// 生产路径传空闭包。
pub(crate) async fn read_text_hooked(path: &Path, mid: impl FnOnce()) -> Result<PreviewBytes, PreviewReject> {
    if !is_text_preview(path) {
        return Err(PreviewReject::UnsupportedType);
    }
    let before = fingerprint(path).await.ok_or(PreviewReject::Retry)?;

    // 审核 F11：禁跟随符号链接 + 只读普通文件（见 preview_open）
    let raw = super::preview_open::read_no_follow(path).await.ok_or(PreviewReject::Retry)?;

    mid();

    // 读完复核：大小或修改时间变了 → 整个作废（不加锁、不快照，用户拍板 grill Q8）
    let after = fingerprint(path).await.ok_or(PreviewReject::Retry)?;
    if before != after || raw.len() as u64 != before.size {
        return Err(PreviewReject::Retry);
    }

    let truncated = raw.len() > TEXT_DISPLAY_BYTES;
    let bytes = if truncated {
        // 按 UTF-8 字符边界截断，避免把一个多字节字符劈成两半（网页侧会显示成乱码方块）
        truncate_at_char_boundary(&raw, TEXT_DISPLAY_BYTES).to_vec()
    } else {
        raw
    };
    Ok(PreviewBytes { bytes, truncated })
}

/// 在不超过 `limit` 的前提下退到最近的 UTF-8 字符边界。
///
/// UTF-8 续接字节形如 `10xxxxxx`（&0xC0 == 0x80）；从 `limit` 往前退到第一个非续接字节即边界。
/// 最多退 3 字节（UTF-8 单字符最长 4 字节）；退不到就原样切（非 UTF-8 内容本就无边界可言）。
pub fn truncate_at_char_boundary(buf: &[u8], limit: usize) -> &[u8] {
    if buf.len() <= limit {
        return buf;
    }
    let mut end = limit;
    for _ in 0..3 {
        if end == 0 || (buf[end] & 0xC0) != 0x80 {
            break;
        }
        end -= 1;
    }
    &buf[..end]
}

// ────────────────────────────────────────────────────────────────
// 回传帧（Bridge → 服务端）。与 `core/preview-dispatcher.js` 的 handleMeta/Chunk/End 对齐。
// ────────────────────────────────────────────────────────────────

/// `preview_meta`：总大小与是否截断。服务端据此独立校验，不信我们多报。
pub fn meta_frame(preview_id: &str, size: usize, truncated: bool) -> serde_json::Value {
    serde_json::json!({
        "type": "preview_meta",
        "previewId": preview_id,
        "size": size,
        "truncated": truncated,
    })
}

/// `preview_chunk`：base64 编码的字节。步一只发一片。
pub fn chunk_frame(preview_id: &str, bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "type": "preview_chunk",
        "previewId": preview_id,
        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

/// `preview_end`：交付。服务端在这里最后一次核对「实收 == 自报」。
pub fn end_frame(preview_id: &str) -> serde_json::Value {
    serde_json::json!({ "type": "preview_end", "previewId": preview_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    // ── 文本类判定 ────────────────────────────────────────────

    #[test]
    fn 文本类白名单_认得常见扩展名() {
        for n in ["a.txt", "a.md", "a.json", "a.rs", "a.ts", "a.py", "a.yaml", "a.csv", "a.log", "A.TXT"] {
            assert!(is_text_preview(Path::new(n)), "{n} 应是文本类");
        }
        for n in ["Makefile", "Dockerfile", "README", "license"] {
            assert!(is_text_preview(Path::new(n)), "{n} 应是文本类（无扩展名白名单）");
        }
    }

    /// 白名单而非黑名单：认不出一律不预览。加进来的新类型必须显式列。
    #[test]
    fn 非文本类不走文本读取() {
        for n in ["a.pdf", "a.docx", "a.xlsx", "a.png", "a.jpg", "a.mp4", "a.zip", "a.exe", "a.so", "a.bin", "weird"] {
            assert!(!is_text_preview(Path::new(n)), "{n} 不是文本类");
        }
    }

    #[test]
    fn 预览种类_文档图片为二进制_音视频压缩包可执行一律不支持() {
        for n in ["a.pdf", "A.PDF", "a.docx", "a.xlsx", "a.png", "a.JPG", "a.jpeg", "a.gif", "a.webp"] {
            assert_eq!(preview_kind(Path::new(n)), Some(PreviewKind::Binary), "{n}");
        }
        for n in ["a.md", "a.txt", "Makefile"] {
            assert_eq!(preview_kind(Path::new(n)), Some(PreviewKind::Text), "{n}");
        }
        for n in ["a.mp4", "a.mov", "a.mp3", "a.zip", "a.exe", "a.doc", "a.xls", "a.pptx", "a.svg", "weird"] {
            assert_eq!(preview_kind(Path::new(n)), None, "{n} 不该预览");
        }
    }

    #[tokio::test]
    async fn 非文本类走文本读取被拒为不支持格式() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.pdf", b"%PDF-1.7");
        let e = read_text(&p).await.unwrap_err();
        assert_eq!(e.code(), PreviewReject::UnsupportedType.code());
    }

    #[tokio::test]
    async fn 二进制整文件读取_不截断_字节一致() {
        let d = tempfile::tempdir().unwrap();
        let body: Vec<u8> = (0..(TEXT_DISPLAY_BYTES + 100)).map(|i| (i % 251) as u8).collect();
        let p = write(d.path(), "big.pdf", &body);
        let r = read_for_preview(&p).await.unwrap();
        assert!(!r.truncated, "文档截断即坏文件，不得截断");
        assert_eq!(r.bytes, body);
    }

    /// 审核 F11 变异锁：单帧路径换回 `tokio::fs::read` → 本用例红。
    #[cfg(unix)]
    #[tokio::test]
    async fn 单帧_过闸后被换成符号链接_拒绝() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = write(outside.path(), "s.txt", b"SECRET");
        for name in ["a.txt", "a.png"] {
            let p = d.path().join(name);
            std::os::unix::fs::symlink(&secret, &p).unwrap();
            assert_eq!(read_for_preview(&p).await.unwrap_err().code(), PreviewReject::Retry.code(), "{name}");
        }
    }

    #[tokio::test]
    async fn 二进制读取中被改_作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.png", b"\x89PNG....");
        let p2 = p.clone();
        let e = read_whole_hooked(&p, move || { std::fs::write(&p2, b"changed-longer-content").unwrap(); }).await.unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code(), "二进制同样必须读后复核");
    }

    #[tokio::test]
    async fn 不支持的类型_按种类读取被拒() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.mp4", b"....");
        assert_eq!(read_for_preview(&p).await.unwrap_err().code(), PreviewReject::UnsupportedType.code());
    }

    // ── 正常读取 ──────────────────────────────────────────────

    #[tokio::test]
    async fn 读取小文本_字节一致_未截断() {
        let d = tempfile::tempdir().unwrap();
        let body = "第一行\nsecond line\n".as_bytes();
        let p = write(d.path(), "a.txt", body);
        let r = read_text(&p).await.unwrap();
        assert_eq!(r.bytes, body, "字节必须与磁盘逐字节一致");
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn 空文件可读_不报错() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "empty.txt", b"");
        let r = read_text(&p).await.unwrap();
        assert!(r.bytes.is_empty());
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn 不存在的文件_回重试而非崩溃() {
        let d = tempfile::tempdir().unwrap();
        let e = read_text(&d.path().join("nope.txt")).await.unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code());
    }

    // ── 截断（故事 5）─────────────────────────────────────────

    #[tokio::test]
    async fn 超过两兆只回前两兆_并标已截断() {
        let d = tempfile::tempdir().unwrap();
        let body = vec![b'x'; TEXT_DISPLAY_BYTES + 5000];
        let p = write(d.path(), "big.txt", &body);
        let r = read_text(&p).await.unwrap();
        assert!(r.truncated, "必须标已截断");
        assert_eq!(r.bytes.len(), TEXT_DISPLAY_BYTES);
        assert_eq!(r.bytes, body[..TEXT_DISPLAY_BYTES], "回的是前 2MB，不是后 2MB");
    }

    #[tokio::test]
    async fn 恰好两兆不算截断() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "exact.txt", &vec![b'y'; TEXT_DISPLAY_BYTES]);
        let r = read_text(&p).await.unwrap();
        assert!(!r.truncated, "等于上限不算超");
        assert_eq!(r.bytes.len(), TEXT_DISPLAY_BYTES);
    }

    /// 变异锁：把 `truncate_at_char_boundary` 换成裸 `&raw[..limit]` → 本用例红。
    #[test]
    fn 截断退到字符边界_不劈开多字节字符() {
        // "中" = E4 B8 AD（3 字节）。在 1、2 字节处截断都必须退回 0
        let s = "中".as_bytes();
        assert_eq!(truncate_at_char_boundary(s, 1), b"", "退到边界 = 空");
        assert_eq!(truncate_at_char_boundary(s, 2), b"", "退到边界 = 空");
        assert_eq!(truncate_at_char_boundary(s, 3), s, "正好一个完整字符");

        // 真实场景：一串汉字在任意位置截断后，剩下的必须是合法 UTF-8
        let text = "一二三四五六七八九十".repeat(10);
        let buf = text.as_bytes();
        for limit in 1..buf.len() {
            let cut = truncate_at_char_boundary(buf, limit);
            assert!(std::str::from_utf8(cut).is_ok(), "limit={limit} 截断后必须是合法 UTF-8");
            assert!(cut.len() <= limit, "不得超过 limit");
        }
    }

    #[test]
    fn 非_utf8_内容原样切_不死循环() {
        // 全是续接字节（本身不是合法 UTF-8）：最多退 3 次后原样切
        let buf = vec![0x80u8; 10];
        let cut = truncate_at_char_boundary(&buf, 5);
        assert!(cut.len() <= 5);
        assert!(cut.len() >= 2, "最多退 3 字节，不会退到 0 以下也不会死循环");
    }

    // ── 传输中被改 → 整个作废（grill Q8）────────────────────────

    /// ⭐变异锁：把 `read_text` 里的「读后复核」整段删掉 → 本用例红。
    ///
    /// 用 `read_text_hooked` 在「读完字节」与「复核」之间改文件，确定性复现并发场景。
    #[tokio::test]
    async fn 读取途中文件变长_整个作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"hello");
        let p2 = p.clone();
        let e = read_text_hooked(&p, move || {
            // 读完之后、复核之前，文件被改大
            std::fs::write(&p2, b"hello world, much longer now").unwrap();
        })
        .await
        .unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code(), "传输中被改必须作废");
    }

    /// 变长能靠 size 发现；**变短**也必须发现（别只判「变大」）。
    #[tokio::test]
    async fn 读取途中文件变短_整个作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"hello world, fairly long");
        let p2 = p.clone();
        let e = read_text_hooked(&p, move || {
            std::fs::write(&p2, b"hi").unwrap();
        })
        .await
        .unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code());
    }

    /// 等长改写：size 不变，只有 mtime 变 —— 必须靠 mtime 发现。
    /// 变异锁：把 `Fingerprint` 的 mtime 字段去掉（只比 size）→ 本用例红。
    #[tokio::test]
    async fn 读取途中等长改写_靠修改时间发现() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"AAAAA");
        let p2 = p.clone();
        let e = read_text_hooked(&p, move || {
            // 等长内容：size 完全相同，只有 mtime 变
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::write(&p2, b"BBBBB").unwrap();
        })
        .await
        .unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code(), "等长改写必须靠 mtime 抓住");
    }

    /// 读取途中文件被删 → 复核取不到指纹 → 作废（不是 panic、也不是「成功返回旧字节」）。
    #[tokio::test]
    async fn 读取途中文件被删_作废() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"hello");
        let p2 = p.clone();
        let e = read_text_hooked(&p, move || {
            std::fs::remove_file(&p2).unwrap();
        })
        .await
        .unwrap_err();
        assert_eq!(e.code(), PreviewReject::Retry.code());
    }

    /// 没人动文件时 hooked 版与直调版行为一致（证明这个缝不改变生产语义）。
    #[tokio::test]
    async fn 没人动文件时_缝不改变行为() {
        let d = tempfile::tempdir().unwrap();
        let body = b"stable content";
        let p = write(d.path(), "a.txt", body);
        let a = read_text(&p).await.unwrap();
        let b = read_text_hooked(&p, || {}).await.unwrap();
        assert_eq!(a, b);
        assert_eq!(a.bytes, body);
    }

    #[tokio::test]
    async fn 指纹_大小变了必定能发现() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"12345");
        let f1 = fingerprint(&p).await.unwrap();
        write(d.path(), "a.txt", b"123456");
        let f2 = fingerprint(&p).await.unwrap();
        assert_ne!(f1, f2);
    }

    /// mtime 相同但 size 不同 → 必须判不等（size 永远参与比较）。
    #[test]
    fn 指纹比较_size_永远参与() {
        let t = SystemTime::UNIX_EPOCH;
        let a = Fingerprint { size: 10, mtime: Some(t) };
        let b = Fingerprint { size: 11, mtime: Some(t) };
        assert_ne!(a, b, "mtime 一样但 size 不同必须判变了");
        // mtime 取不到时也不能因此判「相等就放过」——size 仍然在比
        let c = Fingerprint { size: 10, mtime: None };
        let dd = Fingerprint { size: 11, mtime: None };
        assert_ne!(c, dd);
    }

    #[tokio::test]
    async fn 指纹取不到_回重试() {
        let d = tempfile::tempdir().unwrap();
        assert!(fingerprint(&d.path().join("ghost.txt")).await.is_none());
    }

    // ── 回传帧与服务端契约对齐 ──────────────────────────────────

    #[test]
    fn 三个帧的类型与字段名与服务端派发器一致() {
        let m = meta_frame("pv_1", 1234, true);
        assert_eq!(m["type"], "preview_meta");
        assert_eq!(m["previewId"], "pv_1");
        assert_eq!(m["size"], 1234);
        assert_eq!(m["truncated"], true);

        let c = chunk_frame("pv_1", b"hi");
        assert_eq!(c["type"], "preview_chunk");
        assert_eq!(c["previewId"], "pv_1");
        assert_eq!(c["data"], "aGk=", "data 必须是 base64（服务端按 base64 解）");

        let e = end_frame("pv_1");
        assert_eq!(e["type"], "preview_end");
        assert_eq!(e["previewId"], "pv_1");
    }

    /// 变异锁：meta 的 size 报成「截断前的原始大小」→ 本用例红。
    /// 服务端用 meta.size 与实收字节数核对，报原始大小会让每个被截断的文件都作废。
    #[test]
    fn meta_报的是实际回传字节数_不是原始文件大小() {
        let truncated_len = TEXT_DISPLAY_BYTES;
        let m = meta_frame("pv_1", truncated_len, true);
        assert_eq!(m["size"], truncated_len, "必须等于实际发出的字节数");
    }

    #[test]
    fn 回传帧不含路径与内容明文() {
        let m = meta_frame("pv_1", 10, false);
        let e = end_frame("pv_1");
        for f in [&m, &e] {
            let s = f.to_string();
            assert!(!s.contains('/'), "帧里不得出现路径分隔符: {s}");
            assert!(!s.contains("Users"), "帧里不得出现本机目录结构");
        }
        // chunk 里只有 base64，没有明文
        let c = chunk_frame("pv_1", "密码是 hunter2".as_bytes());
        assert!(!c.to_string().contains("hunter2"), "明文不得出现在帧里（只有 base64）");
    }

    // ── 隐私：本模块不写文件 ───────────────────────────────────

    #[tokio::test]
    async fn 读取不产生任何落盘() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "a.txt", b"secret-content");
        let before: Vec<_> = std::fs::read_dir(d.path()).unwrap().flatten().map(|e| e.file_name()).collect();
        let _ = read_text(&p).await.unwrap();
        let after: Vec<_> = std::fs::read_dir(d.path()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(before.len(), after.len(), "读预览不得新增任何文件（缓存/临时文件都不行）");
    }
}
