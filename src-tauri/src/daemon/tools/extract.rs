// src-tauri/src/daemon/tools/extract.rs
//! 本机抽取 Office / PDF 为文本或表格（票 18，决策文档 §3.2 的 R1 路径）。
//!
//! 原文件**不出本机**，只回传抽取结果。这和 agent 读一段文本是同一性质，不算「上传」。
//!
//! ## 格式
//! | 扩展名 | 做法 |
//! |---|---|
//! | xlsx xlsm xls ods | `calamine` 读单元格，按 sheet 输出制表符分隔文本（公式输出计算后的缓存值） |
//! | docx | zip 里的 `word/document.xml`，取 `<w:t>` 文本，`</w:p>` 换行，`</w:tc>` 制表符 |
//! | pptx | zip 里 `ppt/slides/slideN.xml`，按页码序取 `<a:t>` |
//! | pdf  | `pdf-extract`（纯文本层；扫描件没有文本层会明确告知，不假装成功） |
//!
//! ## 资源保护（文件来自用户磁盘，但可能是别人发来的恶意文件）
//! - zip 炸弹：单个 XML 解压后上限 `MAX_XML_BYTES`，超了拒绝；
//! - 输出上限 `MAX_OUT_CHARS`，超了截断并提示；
//! - xlsx 每个 sheet 最多 `MAX_ROWS` 行、每行最多 `MAX_COLS` 列；
//! - 加密/损坏文件返回明确错误，不 panic（抽取在 `catch_unwind` 里，PDF 库对畸形文件偶发 panic）。

use std::io::Read;
use std::path::Path;

/// 单个 XML 解压后最大字节（防 zip 炸弹）。
const MAX_XML_BYTES: u64 = 30 * 1024 * 1024;
/// 输出文本最大字符数（防刷爆模型 context）。
pub const MAX_OUT_CHARS: usize = 60_000;
const MAX_ROWS: usize = 2_000;
const MAX_COLS: usize = 60;
/// docx/pptx 最多处理的 zip 条目数（防条目爆炸）。
const MAX_ZIP_ENTRIES: usize = 5_000;

/// 支持抽取的扩展名（小写、不含点）。
pub fn supported_ext(path: &str) -> Option<&'static str> {
    let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "xlsx" => "xlsx",
        "xlsm" => "xlsx",
        "xls" => "xls",
        "ods" => "ods",
        "docx" => "docx",
        "pptx" => "pptx",
        "pdf" => "pdf",
        _ => return None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExtractError {
    Unsupported(String),
    /// 文件损坏 / 加密 / 格式不符
    Unreadable(String),
    /// 资源保护触发
    TooLarge(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::Unsupported(s) => write!(f, "unsupported: {s}"),
            ExtractError::Unreadable(s) => write!(f, "unreadable: {s}"),
            ExtractError::TooLarge(s) => write!(f, "too large: {s}"),
        }
    }
}

/// 抽取入口。`bytes` 是文件全部内容（调用方已做路径授权与大小上限）。
/// PDF 库对畸形输入偶发 panic：统一包 `catch_unwind`，转成 `Unreadable`。
pub fn extract(name: &str, bytes: &[u8]) -> Result<String, ExtractError> {
    let kind = supported_ext(name).ok_or_else(|| ExtractError::Unsupported(name.to_string()))?;
    let owned = bytes.to_vec();
    let r = std::panic::catch_unwind(move || match kind {
        "xlsx" | "xls" | "ods" => extract_sheet(&owned),
        "docx" => extract_docx(&owned),
        "pptx" => extract_pptx(&owned),
        "pdf" => extract_pdf(&owned),
        _ => Err(ExtractError::Unsupported(kind.to_string())),
    });
    match r {
        Ok(Ok(s)) => Ok(cap(s)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ExtractError::Unreadable("解析器在该文件上崩溃（文件可能已损坏）".into())),
    }
}

// ── 子进程隔离（审核 B-F3/F4）──────────────────────────────────
//
// 恶意 xlsx（A1+XFD1048576 包围盒）让 calamine 一次分配 512GiB → alloc 失败直接 abort；
// 嵌套过深 / 自引用 Form XObject 的 PDF 让 pdf-extract 栈溢出 → abort。两者都不是 panic，
// catch_unwind 兜不住，且加大线程栈也挡不住自引用。在 daemon 进程内解析 = 一个文件就能让
// 整个客户端（GUI + daemon）退出。所以抽取一律在**同一可执行文件的子进程**里做：
// `<exe> --hanako-extract <name>`，stdin 喂字节、stdout 回 JSON；父进程限时、超时 kill，
// 子进程异常退出一律转 `Unreadable`。Unix 上子进程自设 RLIMIT_AS 兜内存。

/// 子进程模式参数。`main()` 必须在 Tauri 初始化之前识别它。
pub const CHILD_FLAG: &str = "--hanako-extract";
/// 单次抽取墙钟上限。
pub const EXTRACT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(unix)]
const CHILD_MEM_LIMIT: u64 = 1536 * 1024 * 1024;

/// 子进程入口：读 stdin → extract → 把 `{"ok":..}` 写 stdout。返回进程退出码。
pub fn child_main(name: &str) -> i32 {
    #[cfg(unix)]
    unsafe {
        let lim = libc::rlimit { rlim_cur: CHILD_MEM_LIMIT as libc::rlim_t, rlim_max: CHILD_MEM_LIMIT as libc::rlim_t };
        libc::setrlimit(libc::RLIMIT_AS, &lim);
        // 恶意文件让子进程 abort 是预期路径：不留 core dump（可能含文件内容）
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
    // panic 消息别打到 stderr 里污染日志（父进程只看退出码与 stdout）
    std::panic::set_hook(Box::new(|_| {}));
    let mut bytes = Vec::new();
    if std::io::stdin().read_to_end(&mut bytes).is_err() {
        return 2;
    }
    let out = match extract(name, &bytes) {
        Ok(text) => serde_json::json!({ "ok": true, "text": text }),
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    use std::io::Write;
    let mut so = std::io::stdout().lock();
    if so.write_all(out.to_string().as_bytes()).and_then(|_| so.flush()).is_err() {
        return 3;
    }
    0
}

/// 在子进程里抽取。`exe` 为可执行文件路径（生产传 `current_exe()`，测试传测试 bin）。
pub async fn extract_isolated(exe: &std::path::Path, name: &str, bytes: Vec<u8>) -> Result<String, ExtractError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    supported_ext(name).ok_or_else(|| ExtractError::Unsupported(name.to_string()))?;
    let mut child = tokio::process::Command::new(exe)
        .arg(CHILD_FLAG)
        .arg(name)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| ExtractError::Unreadable(format!("无法启动抽取子进程: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped");
    let mut stdout = child.stdout.take().expect("piped");
    let work = async move {
        // 写与读并发：大文件时子进程可能先写 stdout，串行会互相等管道缓冲
        let w = async move {
            let _ = stdin.write_all(&bytes).await;
            drop(stdin);
        };
        let mut buf = Vec::new();
        let r = stdout.read_to_end(&mut buf);
        let (_, r) = tokio::join!(w, r);
        r.map(|_| buf)
    };
    let buf = match tokio::time::timeout(EXTRACT_TIMEOUT, work).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(ExtractError::Unreadable(format!("抽取子进程读取失败: {e}"))),
        Err(_) => {
            let _ = child.kill().await;
            return Err(ExtractError::Unreadable(format!("解析超时（>{}s），文件可能过于复杂或已损坏", EXTRACT_TIMEOUT.as_secs())));
        }
    };
    let status = child.wait().await.map_err(|e| ExtractError::Unreadable(format!("抽取子进程异常: {e}")))?;
    let v: serde_json::Value = match (status.success(), serde_json::from_slice(&buf)) {
        (true, Ok(v)) => v,
        _ => return Err(ExtractError::Unreadable("解析器在该文件上崩溃（文件可能已损坏或构造异常）".into())),
    };
    if v["ok"].as_bool() == Some(true) {
        Ok(v["text"].as_str().unwrap_or_default().to_string())
    } else {
        Err(ExtractError::Unreadable(v["error"].as_str().unwrap_or("unknown").to_string()))
    }
}

fn cap(s: String) -> String {
    if s.chars().count() <= MAX_OUT_CHARS {
        return s;
    }
    let mut t: String = s.chars().take(MAX_OUT_CHARS).collect();
    t.push_str(&format!("\n\n[truncated: 输出超过 {MAX_OUT_CHARS} 字符已截断]\n"));
    t
}

// ── 表格 ────────────────────────────────────────────────────────

fn extract_sheet(bytes: &[u8]) -> Result<String, ExtractError> {
    use calamine::{Data, Reader};
    let cur = std::io::Cursor::new(bytes.to_vec());
    let mut wb = calamine::open_workbook_auto_from_rs(cur)
        .map_err(|e| ExtractError::Unreadable(format!("无法打开工作簿: {e}")))?;
    let mut out = String::new();
    let names = wb.sheet_names().to_vec();
    for name in names {
        let Ok(range) = wb.worksheet_range(&name) else { continue };
        out.push_str(&format!("## 工作表: {name}\n"));
        let mut rows = 0usize;
        for row in range.rows() {
            if rows >= MAX_ROWS {
                out.push_str(&format!("[truncated: 该工作表超过 {MAX_ROWS} 行，已截断]\n"));
                break;
            }
            let cells: Vec<String> = row
                .iter()
                .take(MAX_COLS)
                .map(|c| match c {
                    Data::Empty => String::new(),
                    Data::String(s) => s.replace(['\t', '\n', '\r'], " "),
                    Data::Float(f) if f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", *f as i64),
                    other => other.to_string().replace(['\t', '\n', '\r'], " "),
                })
                .collect();
            // 整行空白跳过（大量空行只会浪费 context）
            if cells.iter().all(|c| c.is_empty()) {
                continue;
            }
            out.push_str(&cells.join("\t"));
            out.push('\n');
            rows += 1;
        }
        out.push('\n');
    }
    if out.trim().is_empty() {
        return Err(ExtractError::Unreadable("工作簿里没有可读内容".into()));
    }
    Ok(out)
}

// ── docx / pptx（OOXML）─────────────────────────────────────────

fn read_zip_entry<R: Read + std::io::Seek>(z: &mut zip::ZipArchive<R>, name: &str) -> Result<Vec<u8>, ExtractError> {
    let mut f = z
        .by_name(name)
        .map_err(|_| ExtractError::Unreadable(format!("缺少 {name}（不是有效的 Office 文件）")))?;
    // 先看声明大小；声明可能造假，所以读取时再用 take 硬限制
    if f.size() > MAX_XML_BYTES {
        return Err(ExtractError::TooLarge(format!("{name} 解压后超过 {} MB", MAX_XML_BYTES / 1024 / 1024)));
    }
    let mut buf = Vec::new();
    f.by_ref().take(MAX_XML_BYTES + 1).read_to_end(&mut buf).map_err(|e| ExtractError::Unreadable(format!("读取 {name} 失败: {e}")))?;
    if buf.len() as u64 > MAX_XML_BYTES {
        return Err(ExtractError::TooLarge(format!("{name} 解压后超过 {} MB", MAX_XML_BYTES / 1024 / 1024)));
    }
    Ok(buf)
}

/// 从 OOXML 片段取文本。
/// - 段落结束 `para_end` → 换行，**但在表格单元格内不换行**（否则 `项目\n\t金额` 把一行表格拆碎，模型读不出表结构）；
/// - 单元格结束 `cell_end` → 制表符；
/// - 表格行结束 `</w:tr>` / `</a:tr>` → 换行。
fn ooxml_text(xml: &[u8], para_end: &[u8], cell_end: &[u8]) -> String {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut r = Reader::from_reader(xml);
    let mut out = String::new();
    let mut in_text = false;
    let mut cell_depth = 0u32; // 嵌套表格时 >1
    let mut buf = Vec::new();
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let n = e.local_name();
                if n.as_ref() == b"t" {
                    in_text = true;
                } else if n.as_ref() == cell_end {
                    cell_depth += 1;
                }
            }
            Ok(Event::End(e)) => {
                let n = e.local_name();
                if n.as_ref() == b"t" {
                    in_text = false;
                } else if n.as_ref() == cell_end {
                    cell_depth = cell_depth.saturating_sub(1);
                    out.push('\t');
                } else if n.as_ref() == b"tr" {
                    out.push('\n');
                } else if n.as_ref() == para_end && cell_depth == 0 {
                    out.push('\n');
                }
            }
            Ok(Event::Text(t)) if in_text => {
                if let Ok(s) = t.xml10_content() {
                    out.push_str(&s);
                }
            }
            // quick-xml 0.41 把 `&amp;` `&#x4e2d;` 这类引用拆成独立事件；不处理会把 "A&B" 静默抽成 "AB"
            Ok(Event::GeneralRef(r)) if in_text => {
                if let Ok(Some(ch)) = r.resolve_char_ref() {
                    out.push(ch);
                } else if let Ok(name) = r.xml10_content() {
                    match name.as_ref() {
                        "amp" => out.push('&'),
                        "lt" => out.push('<'),
                        "gt" => out.push('>'),
                        "quot" => out.push('"'),
                        "apos" => out.push('\''),
                        _ => {} // 自定义实体：OOXML 不会用，也不展开（避免 XXE 类问题）
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break, // 畸形 XML：已抽到的部分照常返回
            _ => {}
        }
        buf.clear();
    }
    out
}

fn open_zip(bytes: &[u8]) -> Result<zip::ZipArchive<std::io::Cursor<Vec<u8>>>, ExtractError> {
    let z = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec()))
        .map_err(|e| ExtractError::Unreadable(format!("不是有效的 Office 文件: {e}")))?;
    if z.len() > MAX_ZIP_ENTRIES {
        return Err(ExtractError::TooLarge(format!("压缩包条目过多（{}）", z.len())));
    }
    Ok(z)
}

fn extract_docx(bytes: &[u8]) -> Result<String, ExtractError> {
    let mut z = open_zip(bytes)?;
    let xml = read_zip_entry(&mut z, "word/document.xml")?;
    let text = ooxml_text(&xml, b"p", b"tc");
    let text = tidy(&text);
    if text.trim().is_empty() {
        return Err(ExtractError::Unreadable("文档里没有可读文本".into()));
    }
    Ok(text)
}

fn extract_pptx(bytes: &[u8]) -> Result<String, ExtractError> {
    let mut z = open_zip(bytes)?;
    // 幻灯片文件名 slide1.xml … slideN.xml，必须按页码数值排序（字典序会把 slide10 排在 slide2 前）
    let mut slides: Vec<(u32, String)> = (0..z.len())
        .filter_map(|i| z.by_index(i).ok().map(|f| f.name().to_string()))
        .filter_map(|n| {
            let num = n.strip_prefix("ppt/slides/slide")?.strip_suffix(".xml")?.parse::<u32>().ok()?;
            Some((num, n))
        })
        .collect();
    slides.sort_by_key(|(n, _)| *n);
    if slides.is_empty() {
        return Err(ExtractError::Unreadable("没有找到幻灯片".into()));
    }
    let mut out = String::new();
    for (num, name) in slides {
        let xml = read_zip_entry(&mut z, &name)?;
        let t = tidy(&ooxml_text(&xml, b"p", b"tc"));
        out.push_str(&format!("## 第 {num} 页\n{}\n\n", t.trim()));
    }
    Ok(out)
}

/// 合并连续空行，去掉行尾多余制表符。
fn tidy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank = 0;
    for line in s.lines() {
        let line = line.trim_end_matches('\t').trim_end();
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ── PDF ─────────────────────────────────────────────────────────

fn extract_pdf(bytes: &[u8]) -> Result<String, ExtractError> {
    let text = pdf_extract::extract_text_from_mem(bytes)
        .map_err(|e| ExtractError::Unreadable(format!("无法解析 PDF（可能已加密或损坏）: {e}")))?;
    let text = tidy(&text);
    if text.trim().is_empty() {
        // 扫描件没有文本层：明确告知，不要返回空串让模型以为文件是空的
        return Err(ExtractError::Unreadable("PDF 没有文本层（可能是扫描件），需要 OCR，本机抽取无法读取".into()));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 夹具由真实办公库（openpyxl / python-docx / python-pptx / reportlab）生成，见 /data/tmp-archive/t18fix。
    /// 仓库里只放小夹具（均 <40KB）。
    fn fx(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/office").join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("夹具缺失 {}: {e}", p.display()))
    }

    #[test]
    fn xlsx_抽出各工作表与中文与数字() {
        let t = extract("budget.xlsx", &fx("budget.xlsx")).unwrap();
        assert!(t.contains("## 工作表: Q3预算"), "{t}");
        assert!(t.contains("部门\t预算\t实际\t差异"), "{t}");
        assert!(t.contains("财务\t1200000\t1150000"), "整数不应显示成 1200000.0: {t}");
        assert!(t.contains("3400000.5"), "小数保留: {t}");
        assert!(t.contains("## 工作表: 备注") && t.contains("机密：仅限内部"), "多 sheet: {t}");
    }

    #[test]
    fn docx_抽出段落与表格() {
        let t = extract("contract.docx", &fx("contract.docx")).unwrap();
        assert!(t.contains("采购合同"), "{t}");
        assert!(t.contains("甲方：PalmPay 科技。乙方：某供应商。"), "{t}");
        assert!(t.contains("项目\t金额") && t.contains("服务器\t88000"), "表格单元格用制表符分隔: {t}");
    }

    #[test]
    fn pptx_按页码顺序抽出() {
        let t = extract("deck.pptx", &fx("deck.pptx")).unwrap();
        let p1 = t.find("## 第 1 页").expect("第 1 页");
        let p2 = t.find("## 第 2 页").expect("第 2 页");
        assert!(p1 < p2, "{t}");
        assert!(t.contains("季度复盘") && t.contains("收入增长 12%") && t.contains("成本下降 3%"), "{t}");
        assert!(t.contains("下季度计划") && t.contains("上线 IVR 孟加拉"), "{t}");
    }

    #[test]
    fn pdf_嵌入字体的中文_现代导出器主流形态() {
        // Identity-H + 嵌入 TrueType：Word / WPS / Chrome 打印导出的 PDF 基本都是这种
        let t = extract("report_cjk.pdf", &fx("report_cjk.pdf")).unwrap();
        assert!(t.contains("年度审计报告"), "{t}");
        assert!(t.contains("无重大缺陷") && t.contains("研发投入增长百分之十二"), "{t}");
    }

    #[test]
    fn pdf_冷门_cjk_预定义编码_明确报错而非崩溃() {
        // 老式 CJK PDF 用 UniGB-UCS2-H 等预定义 CMap，pdf-extract 不支持且会 panic。
        // 这是已知的库限制：必须被 catch_unwind 兜住并给出可行动的提示，不能拖垮 daemon。
        let r = extract("report.pdf", &fx("report.pdf"));
        assert!(matches!(&r, Err(ExtractError::Unreadable(m)) if m.contains("崩溃") || m.contains("无法解析")), "{r:?}");
    }

    #[test]
    fn 扩展名识别_大小写与不支持() {
        assert_eq!(supported_ext("A.XLSX"), Some("xlsx"));
        assert_eq!(supported_ext("a.docx"), Some("docx"));
        assert_eq!(supported_ext("a.txt"), None);
        assert_eq!(supported_ext("noext"), None);
        assert!(matches!(extract("a.txt", b"x"), Err(ExtractError::Unsupported(_))));
    }

    #[test]
    fn 损坏文件明确报错_不panic() {
        for name in ["a.xlsx", "a.docx", "a.pptx", "a.pdf"] {
            let r = extract(name, b"this is definitely not an office file");
            assert!(matches!(r, Err(ExtractError::Unreadable(_))), "{name}: {r:?}");
        }
        assert!(extract("a.pdf", b"").is_err());
        assert!(extract("a.xlsx", b"").is_err());
    }

    #[test]
    fn docx_缺少正文部件_报不是有效_office() {
        // 一个合法 zip 但没有 word/document.xml
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file("hello.txt", zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b"hi").unwrap();
            w.finish().unwrap();
        }
        let e = extract("a.docx", &buf).unwrap_err();
        assert!(matches!(&e, ExtractError::Unreadable(m) if m.contains("word/document.xml")), "{e:?}");
    }

    #[test]
    fn zip炸弹_解压后超限被拒绝() {
        // 声明/实际都超过 MAX_XML_BYTES 的 document.xml（压缩后很小）
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opt = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            w.start_file("word/document.xml", opt).unwrap();
            let chunk = vec![b'a'; 1024 * 1024];
            for _ in 0..(MAX_XML_BYTES / 1024 / 1024 + 2) {
                w.write_all(&chunk).unwrap();
            }
            w.finish().unwrap();
        }
        assert!(buf.len() < 5 * 1024 * 1024, "压缩后应很小，确认是炸弹形态: {}", buf.len());
        let e = extract("bomb.docx", &buf).unwrap_err();
        assert!(matches!(e, ExtractError::TooLarge(_)), "{e:?}");
    }

    #[test]
    fn 输出超长被截断并提示() {
        let long = "字".repeat(MAX_OUT_CHARS + 500);
        let c = cap(long);
        assert!(c.chars().count() < MAX_OUT_CHARS + 200);
        assert!(c.contains("[truncated"), "必须提示被截断，否则模型会把残缺当完整");
        assert_eq!(cap("短".into()), "短");
    }

    #[test]
    fn 文本里的实体与字符引用不丢字() {
        // 0.41 的 GeneralRef 事件若没处理，"R&D" 会变成 "RD"，"中" 会消失
        let xml = r#"<w:document xmlns:w="w"><w:p><w:r><w:t>R&amp;D &lt;机密&gt; &#x4e2d;&#25991; &quot;引号&quot;</w:t></w:r></w:p></w:document>"#;
        let t = ooxml_text(xml.as_bytes(), b"p", b"tc");
        assert!(t.contains(r#"R&D <机密> 中文 "引号""#), "实体/字符引用被吞: {t:?}");
    }

    #[test]
    fn 自定义实体不展开_防_xxe() {
        let xml = r#"<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><w:document xmlns:w="w"><w:p><w:r><w:t>a&x;b</w:t></w:r></w:p></w:document>"#;
        let t = ooxml_text(xml.as_bytes(), b"p", b"tc");
        assert!(!t.contains("root:"), "绝不能读到本机文件: {t:?}");
        assert!(t.contains('a') && t.contains('b'));
    }

    #[test]
    fn pptx_页码按数值排序而非字典序() {
        // 构造 slide1 / slide2 / slide10：字典序会得到 1,10,2
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let o = zip::write::SimpleFileOptions::default();
            for n in [10u32, 2, 1] {
                w.start_file(format!("ppt/slides/slide{n}.xml"), o).unwrap();
                let xml = format!(r#"<p:sld xmlns:a="a" xmlns:p="p"><a:p><a:r><a:t>内容{n}</a:t></a:r></a:p></p:sld>"#);
                w.write_all(xml.as_bytes()).unwrap();
            }
            w.finish().unwrap();
        }
        let t = extract("a.pptx", &buf).unwrap();
        let (i1, i2, i10) = (t.find("内容1\n").unwrap(), t.find("内容2").unwrap(), t.find("内容10").unwrap());
        assert!(i1 < i2 && i2 < i10, "必须 1,2,10: {t}");
    }
}
