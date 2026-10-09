// src-tauri/src/daemon/tools/read.rs
//! 本地只读工具实现：`local_read_file` / `local_list_dir` / `local_grep`。
//!
//! `local_read_file` 限制（MVP）：
//! - 最多读 2000 行，单行截断至 500 字符
//! - 超限时输出末尾提示 `start_line=N` 供续读
//! - 二进制文件（含 NUL 字节）拒绝
//! - 非 UTF-8 文件拒绝
//!
//! `local_list_dir` 限制：
//! - 含大小/mtime，按名称排序
//! - 默认隐藏以 '.' 开头的条目
//!
//! `local_grep` 限制：
//! - 递归遍历目录，正则匹配每行
//! - 结果上限 100 条（MAX_RESULTS）防刷爆 context

use serde_json::Value;

use super::ToolResult;
use crate::daemon::path_guard::PathGuard;
use crate::daemon::policy::{Policy, TaskScope};

/// 最多读取行数。
const MAX_LINES: usize = 2000;
/// 单行最大字符数（Unicode 字符数，非字节数）。
const MAX_LINE_WIDTH: usize = 500;

/// 读取本地文件内容。
///
/// # params 字段
/// - `path`（必填）: 相对于授权目录的路径
/// - `start_line`（可选，从 1 起）: 起始行号，默认 1
/// - `end_line`（可选）: 结束行号，默认读到文件末尾
pub async fn local_read_file(params: &Value, policy: &Policy) -> ToolResult {
    // 工作目录为空时直接返回友好提示

    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return ToolResult::err("path required".into());
    }

    let start_line = params.get("start_line").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
    let end_line = params.get("end_line").and_then(|v| v.as_u64()).map(|v| v as usize);

    // 路径安全校验
    let resolved = match policy.authorize(&TaskScope::from_params(params), path, false) {
        Ok(r) => r,
        Err(e) => return ToolResult::err(e.to_string()),
    };
    let target = resolved.path.clone();

    // 票 18：xlsx/docx/pptx/pdf 走本机抽取，只回传文本/表格，原文件不出本机。
    // 必须在「路径已授权」之后（上面 authorize 已过）、读字节之前分流。
    if let Some(name) = target.file_name().and_then(|n| n.to_str()) {
        if super::extract::supported_ext(name).is_some() {
            return read_office(&target, name).await;
        }
    }

    // 读文件字节，做二进制检测（使用 tokio::fs 避免阻塞 async runtime）
    let bytes = match tokio::fs::read(&target).await {
        Ok(b) => b,
        Err(e) => return ToolResult::err(format!("read failed: {}", e)),
    };

    // NUL 字节 → 二进制文件，拒绝
    if bytes.contains(&0) {
        return ToolResult::err("binary file not supported (MVP)".into());
    }

    // 非 UTF-8 → 拒绝
    let content = match String::from_utf8(bytes) {
        Ok(c) => c,
        Err(_) => return ToolResult::err("non-UTF-8 file not supported (MVP)".into()),
    };

    // 行范围切片
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let start = start_line.saturating_sub(1).min(total);
    let end = end_line.unwrap_or(total).min(total).max(start);

    let mut out = String::new();
    let mut truncated = false;

    for (i, line) in lines[start..end].iter().enumerate() {
        if i >= MAX_LINES {
            truncated = true;
            break;
        }
        // Unicode 字符级截断，避免多字节字符跨边界 panic
        let line = if line.chars().count() > MAX_LINE_WIDTH {
            line.chars().take(MAX_LINE_WIDTH).collect::<String>()
        } else {
            line.to_string()
        };
        out.push_str(&line);
        out.push('\n');
    }

    // 超限提示
    if truncated || end < total {
        out.push_str(&format!(
            "\n[truncated: total {} lines, call again with start_line={}]\n",
            total,
            start + MAX_LINES + 1
        ));
    }

    ToolResult::ok(out)
}

/// 抽取用的文件大小上限：超过的不读进内存。
/// 办公文件本身很少超过这个数；超大文件（几百 MB 的扫描 PDF）解析会吃光内存，直接拒绝并说明。
pub const MAX_EXTRACT_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// 读取并抽取 Office / PDF。CPU 密集（解压 + 解析），放进 blocking 线程池，避免卡住 async runtime
/// （心跳、其他任务的结果回传都在同一个运行时里）。
async fn read_office(target: &std::path::Path, name: &str) -> ToolResult {
    let meta = match tokio::fs::metadata(target).await {
        Ok(m) => m,
        Err(e) => return ToolResult::err(format!("read failed: {}", e)),
    };
    if meta.len() > MAX_EXTRACT_FILE_BYTES {
        return ToolResult::err(format!(
            "file too large to extract: {} MB (limit {} MB)",
            meta.len() / 1024 / 1024,
            MAX_EXTRACT_FILE_BYTES / 1024 / 1024
        ));
    }
    let bytes = match tokio::fs::read(target).await {
        Ok(b) => b,
        Err(e) => return ToolResult::err(format!("read failed: {}", e)),
    };
    // 审核 B-F3/F4：恶意文件会让解析器 abort / 栈溢出，必须在子进程里抽取
    match super::extract::extract_isolated(&extract_exe(), name, bytes).await {
        Ok(text) => ToolResult::ok(text),
        Err(e) => ToolResult::err(e.to_string()),
    }
}

/// 抽取子进程用的可执行文件。生产 = 自身；单测里 current_exe 是测试 harness（不认 CHILD_FLAG），
/// 故允许 `HANAKO_EXTRACT_EXE` 覆盖（仅测试设置）。
fn extract_exe() -> std::path::PathBuf {
    std::env::var_os("HANAKO_EXTRACT_EXE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_default()
}

/// 列出本地目录内容。
///
/// # params 字段
/// - `path`（必填）: 相对于授权目录的路径
/// - `show_hidden`（可选）: 是否显示以 '.' 开头的隐藏条目（默认 false）
pub async fn local_list_dir(params: &Value, policy: &Policy) -> ToolResult {
    // 工作目录为空时直接返回友好提示

    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let show_hidden = params.get("show_hidden").and_then(|v| v.as_bool()).unwrap_or(false);

    // 路径安全校验
    let resolved = match policy.authorize(&TaskScope::from_params(params), path, false) {
        Ok(r) => r,
        Err(e) => return ToolResult::err(e.to_string()),
    };
    let target = resolved.path.clone();

    // 读取目录条目
    let entries = match std::fs::read_dir(&target) {
        Ok(e) => e,
        Err(e) => return ToolResult::err(format!("read_dir failed: {}", e)),
    };

    let mut items = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // 默认过滤隐藏文件
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        // 格式：名称（目录加 /）\t大小\tmtime
        items.push(format!(
            "{}{}\t{} bytes\t{}",
            name,
            if is_dir { "/" } else { "" },
            size,
            mtime
        ));
    }
    // 按名称排序
    items.sort();

    ToolResult::ok(items.join("\n"))
}

/// 在本地目录递归搜索匹配正则的文件行。
///
/// # params 字段
/// - `path`（必填）: 相对于授权目录的搜索根目录
/// - `pattern`（必填）: 正则表达式
/// - `include`（可选）: 文件名过滤模式（当前未使用，预留接口）
pub async fn local_grep(params: &Value, policy: &Policy) -> ToolResult {
    // 工作目录为空时直接返回友好提示

    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let pattern = params.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
    if pattern.is_empty() {
        return ToolResult::err("pattern required".into());
    }

    // 路径安全校验
    let resolved = match policy.authorize(&TaskScope::from_params(params), path, false) {
        Ok(r) => r,
        Err(e) => return ToolResult::err(e.to_string()),
    };
    let target = resolved.path.clone();

    // 编译正则
    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => return ToolResult::err(format!("invalid regex: {}", e)),
    };

    const MAX_RESULTS: usize = 100;
    let mut results = Vec::new();

    /// 迭代遍历目录，收集正则匹配行（含文件路径:行号:行内容）。
    ///
    /// - 每个条目都 canonicalize 后再过围栏：目录里的符号链接可能指向授权目录之外（P9 的遍历变体）。
    /// - 敏感判定按「相对授权根」的路径段做（审核 L2），与 resolve 同一函数，链接名与目标各判一次。
    /// - 审核 R2-N3：`loop -> .` 自环链接曾让递归无限深入、栈溢出 abort 整个进程；
    ///   现改为显式栈 + 已访问目录集合（按 canonical 路径去重）+ 深度上限，且只读普通文件、单文件限长。
    fn walk(root: &std::path::Path, re: &regex::Regex, results: &mut Vec<String>, fence: &PathGuard) {
        const MAX_DEPTH: usize = 32;
        const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![(root.to_path_buf(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if results.len() >= MAX_RESULTS {
                return;
            }
            if !visited.insert(dir.clone()) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                if results.len() >= MAX_RESULTS {
                    return;
                }
                let raw = entry.path();
                if fence.is_sensitive_abs(&raw) {
                    continue;
                }
                let Ok(path) = raw.canonicalize() else { continue };
                if !fence.contains_canonical(&path) || fence.is_sensitive_abs(&path) {
                    continue;
                }
                let Ok(md) = std::fs::metadata(&path) else { continue };
                if md.is_dir() {
                    if depth < MAX_DEPTH {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                // FIFO / 设备文件读了会永久阻塞或无穷读：只读普通文件
                if !md.is_file() || md.len() > MAX_FILE_BYTES {
                    continue;
                }
                let Ok(content) = std::fs::read_to_string(&path) else { continue };
                for (i, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        results.push(format!("{}:{}: {}", raw.display(), i + 1, line));
                        if results.len() >= MAX_RESULTS {
                            return;
                        }
                    }
                }
            }
        }
    }

    walk(&target, &re, &mut results, &resolved.fence);

    if results.is_empty() {
        ToolResult::ok("no matches".into())
    } else {
        let mut out = results.join("\n");
        // 结果达到上限时追加截断提示
        if results.len() >= MAX_RESULTS {
            out.push_str(&format!("\n[truncated: {} results max]", MAX_RESULTS));
        }
        ToolResult::ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::policy::PolicyFile;
    use std::fs;

    pub(crate) const AGENT: &str = "bi--zhangsan";

    /// 单测里 current_exe 是 test harness（不认 CHILD_FLAG）：指向同一 target 下 cargo 已构建的主 bin。
    /// `target/debug/deps/<harness>` → `target/debug/hanako-tauri`。
    pub(crate) fn use_real_extract_exe() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let exe = std::env::current_exe().unwrap();
            let bin = exe.parent().unwrap().parent().unwrap().join(format!("hanako-tauri{}", std::env::consts::EXE_SUFFIX));
            assert!(bin.exists(), "主 bin 未构建: {}（先 cargo build）", bin.display());
            std::env::set_var("HANAKO_EXTRACT_EXE", bin);
        });
    }

    /// 测试用：单目录策略，AGENT 独占；任务帧参数用 `p()` 补 `_agent_id`。
    fn setup() -> (tempfile::TempDir, Policy) {
        use_real_extract_exe();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let pol = Policy::build(&[root], &PolicyFile::default(), Some(AGENT));
        (dir, pol)
    }

    /// 给测试参数补上服务端注入的执行体。
    fn p(mut v: serde_json::Value) -> serde_json::Value {
        v["_agent_id"] = serde_json::json!(AGENT);
        v
    }

    #[tokio::test]
    async fn 读文件成功() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("a.txt"), "hello\nworld\n").unwrap();
        let r = local_read_file(&p(serde_json::json!({"path": "a.txt"})), &ws).await;
        assert!(r.ok);
        assert!(r.result.unwrap().contains("hello"));
    }

    // ── 票 18：Office / PDF 本机抽取接入 ────────────────────────────
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/office").join(name)).unwrap()
    }

    #[tokio::test]
    async fn 读_xlsx_走抽取而非二进制拒绝() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("budget.xlsx"), fixture("budget.xlsx")).unwrap();
        let r = local_read_file(&p(serde_json::json!({"path": "budget.xlsx"})), &ws).await;
        assert!(r.ok, "{:?}", r.error);
        let t = r.result.unwrap();
        assert!(t.contains("财务\t1200000"), "{t}");
        assert!(!t.contains("binary"), "不能再落入「二进制不支持」分支");
    }

    #[tokio::test]
    async fn 读_docx_pptx_pdf_都能抽() {
        let (dir, ws) = setup();
        for (f, needle) in [("contract.docx", "采购合同"), ("deck.pptx", "季度复盘"), ("report_cjk.pdf", "年度审计报告")] {
            fs::write(dir.path().join(f), fixture(f)).unwrap();
            let r = local_read_file(&p(serde_json::json!({"path": f})), &ws).await;
            assert!(r.ok && r.result.as_deref().unwrap_or("").contains(needle), "{f}: {:?} {:?}", r.error, r.result);
        }
    }

    #[tokio::test]
    async fn 抽取仍受路径授权约束_目录外读不到() {
        // 授权在前、抽取在后：xlsx 也不能用来绕过围栏
        let (_dir, ws) = setup();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.xlsx"), fixture("budget.xlsx")).unwrap();
        let abs = outside.path().join("secret.xlsx");
        let r = local_read_file(&p(serde_json::json!({"path": abs.to_string_lossy()})), &ws).await;
        assert!(!r.ok, "目录外的 xlsx 必须被围栏拒绝");
        let r2 = local_read_file(&p(serde_json::json!({"path": "../secret.xlsx"})), &ws).await;
        assert!(!r2.ok);
    }

    #[tokio::test]
    async fn 抽取遵守符号链接围栏() {
        // 授权目录内放一个指向目录外 xlsx 的符号链接：必须拒绝，不能借抽取读到围栏外的文件
        #[cfg(unix)]
        {
            let (dir, ws) = setup();
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("real.xlsx"), fixture("budget.xlsx")).unwrap();
            std::os::unix::fs::symlink(outside.path().join("real.xlsx"), dir.path().join("link.xlsx")).unwrap();
            let r = local_read_file(&p(serde_json::json!({"path": "link.xlsx"})), &ws).await;
            assert!(!r.ok, "符号链接逃逸: {:?}", r.result);
        }
    }

    #[tokio::test]
    async fn 损坏的_office_文件给出明确错误() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("bad.docx"), b"not a zip").unwrap();
        let r = local_read_file(&p(serde_json::json!({"path": "bad.docx"})), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("unreadable"));
    }

    #[tokio::test]
    async fn 超大办公文件拒绝读入内存() {
        let (dir, ws) = setup();
        let f = fs::File::create(dir.path().join("huge.xlsx")).unwrap();
        f.set_len(MAX_EXTRACT_FILE_BYTES + 1).unwrap(); // 稀疏文件，不占磁盘
        let r = local_read_file(&p(serde_json::json!({"path": "huge.xlsx"})), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("too large"));
    }

    #[tokio::test]
    async fn 二进制拒绝() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("bin.dat"), vec![0u8, 159, 146, 150]).unwrap();
        let r = local_read_file(&p(serde_json::json!({"path": "bin.dat"})), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("binary"));
    }

    #[tokio::test]
    async fn 路径穿越拒绝() {
        let (_dir, ws) = setup();
        let r = local_read_file(&p(serde_json::json!({"path": "../outside.txt"})), &ws).await;
        assert!(!r.ok);
    }

    // ── local_list_dir 测试 ──────────────────────────────────────────────────

    #[tokio::test]
    async fn list_dir_成功列出目录() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("readme.txt"), "hello").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        let r = local_list_dir(&p(serde_json::json!({"path": "."})), &ws).await;
        assert!(r.ok, "期望成功，error={:?}", r.error);
        let out = r.result.unwrap();
        // 目录条目以 / 结尾
        assert!(out.contains("subdir/"), "期望含 subdir/，实际: {}", out);
        assert!(out.contains("readme.txt"), "期望含 readme.txt，实际: {}", out);
    }

    #[tokio::test]
    async fn list_dir_隐藏文件默认不显示() {
        let (dir, ws) = setup();
        fs::write(dir.path().join(".hidden"), "secret").unwrap();
        fs::write(dir.path().join("visible.txt"), "open").unwrap();
        let r = local_list_dir(&p(serde_json::json!({"path": ".", "show_hidden": false})), &ws).await;
        assert!(r.ok);
        let out = r.result.unwrap();
        assert!(!out.contains(".hidden"), "隐藏文件不应出现，实际: {}", out);
        assert!(out.contains("visible.txt"), "普通文件应出现，实际: {}", out);
    }

    #[tokio::test]
    async fn list_dir_show_hidden_显示隐藏文件() {
        let (dir, ws) = setup();
        fs::write(dir.path().join(".env"), "SECRET=x").unwrap();
        let r = local_list_dir(&p(serde_json::json!({"path": ".", "show_hidden": true})), &ws).await;
        assert!(r.ok);
        assert!(r.result.unwrap().contains(".env"), "开启 show_hidden 应显示 .env");
    }

    #[tokio::test]
    async fn list_dir_路径穿越拒绝() {
        let (_dir, ws) = setup();
        let r = local_list_dir(&p(serde_json::json!({"path": "../outside"})), &ws).await;
        assert!(!r.ok);
    }

    // ── local_grep 测试 ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn grep_成功匹配() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("log.txt"), "INFO: started\nERROR: boom\nINFO: done\n").unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "ERROR"})), &ws).await;
        assert!(r.ok, "期望成功，error={:?}", r.error);
        let out = r.result.unwrap();
        assert!(out.contains("ERROR"), "期望匹配到 ERROR，实际: {}", out);
    }

    #[tokio::test]
    async fn grep_无匹配返回no_matches() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("clean.txt"), "no issues here\n").unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "CRITICAL"})), &ws).await;
        assert!(r.ok);
        assert_eq!(r.result.unwrap(), "no matches");
    }

    #[tokio::test]
    async fn grep_路径穿越拒绝() {
        let (_dir, ws) = setup();
        let r = local_grep(&p(serde_json::json!({"path": "../outside", "pattern": "x"})), &ws).await;
        assert!(!r.ok);
    }

    #[tokio::test]
    async fn grep_结果上限100条() {
        let (dir, ws) = setup();
        // 写一个含 150 行匹配的文件
        let content = "match_line\n".repeat(150);
        fs::write(dir.path().join("big.txt"), &content).unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "match_line"})), &ws).await;
        assert!(r.ok);
        let out = r.result.unwrap();
        // 结果行数应被截断到 100
        let match_lines = out.lines().filter(|l| l.contains("match_line")).count();
        assert_eq!(match_lines, 100, "期望截断到 100 条，实际: {}", match_lines);
        assert!(out.contains("[truncated:"), "期望包含截断提示");
    }

    #[tokio::test]
    async fn grep_无效正则返回错误() {
        let (_dir, ws) = setup();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "[invalid"})), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("invalid regex"), "期望 invalid regex 错误");
    }

    // ── S3 本机闸（读侧）──────────────────────────────────────────────────────

    #[tokio::test]
    async fn 未授权执行体_读被拒且带机读码() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let mut params = serde_json::json!({"path": "a.txt"});
        params["_agent_id"] = serde_json::json!("wallet--zhangsan");
        let r = local_read_file(&params, &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("LOCAL_ACTOR_NOT_GRANTED"));
    }

    #[tokio::test]
    async fn 任务帧没带执行体_读被拒() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let r = local_read_file(&serde_json::json!({"path": "a.txt"}), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("LOCAL_ACTOR_NOT_GRANTED"));
    }

    #[tokio::test]
    async fn 会话绑定目录已撤销_读被拒() {
        let (dir, ws) = setup();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        let mut params = p(serde_json::json!({"path": "a.txt"}));
        params["_root_id"] = serde_json::json!("r_gone00000000");
        let r = local_read_file(&params, &ws).await;
        assert!(r.error.unwrap().starts_with("LOCAL_ROOT_REVOKED"));
    }

    #[tokio::test]
    async fn 只读根仍可读() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::write(root.join("a.txt"), "ro-content").unwrap();
        let mut file = PolicyFile::default();
        file.modes.insert(crate::daemon::register::root_id_for(&root), "ro".into());
        let pol = Policy::build(&[root], &file, Some(AGENT));
        let r = local_read_file(&p(serde_json::json!({"path": "a.txt"})), &pol).await;
        assert!(r.ok, "{:?}", r.error);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 读符号链接指向根外_被拒() {
        let (dir, ws) = setup();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "TOP-SECRET").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
        let r = local_read_file(&p(serde_json::json!({"path": "evil/secret.txt"})), &ws).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("LOCAL_PATH_OUT_OF_FENCE"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grep_遍历时不跟随符号链接到根外() {
        // 入口路径是合法的 "."，根外内容只能靠遍历里的符号链接泄漏
        let (dir, ws) = setup();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "TOP-SECRET-MARK\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
        fs::write(dir.path().join("ok.txt"), "TOP-SECRET-MARK inside\n").unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "TOP-SECRET-MARK"})), &ws).await;
        assert!(r.ok, "{:?}", r.error);
        let out = r.result.unwrap();
        assert!(out.contains("ok.txt"), "根内命中应保留: {out}");
        assert!(!out.contains("evil") && !out.contains("secret.txt"), "根外文件被读到: {out}");
    }

    #[tokio::test]
    async fn grep_遍历跳过敏感目录() {
        let (dir, ws) = setup();
        fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        fs::write(dir.path().join(".ssh/config"), "PASSWORD-MARK\n").unwrap();
        fs::write(dir.path().join("cert.pem"), "PASSWORD-MARK\n").unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "PASSWORD-MARK"})), &ws).await;
        assert_eq!(r.result.as_deref(), Some("no matches"), "{:?}", r.result);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grep_自环符号链接不崩且去重() {
        // 审核 R2-N3：`loop -> .` 曾无限递归栈溢出 abort 整个进程
        let (dir, ws) = setup();
        fs::write(dir.path().join("a.txt"), "LOOP-MARK\n").unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop2")).unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "LOOP-MARK"})), &ws).await;
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.result.unwrap().lines().filter(|l| l.contains("LOOP-MARK")).count(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grep_经符号链接或大写名进入敏感目录也跳过() {
        let (dir, ws) = setup();
        fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        fs::write(dir.path().join(".ssh/id_rsa"), "KEY-MARK\n").unwrap();
        fs::create_dir_all(dir.path().join(".AWS")).unwrap();
        fs::write(dir.path().join(".AWS/credentials"), "KEY-MARK\n").unwrap();
        fs::write(dir.path().join(".env"), "KEY-MARK\n").unwrap();
        std::os::unix::fs::symlink(dir.path().join(".ssh"), dir.path().join("keys")).unwrap();
        // 直接指向敏感文件的普通名链接：raw 名不敏感，只有 canonical 一侧能挡
        std::os::unix::fs::symlink(dir.path().join(".ssh/id_rsa"), dir.path().join("notes.txt")).unwrap();
        let r = local_grep(&p(serde_json::json!({"path": ".", "pattern": "KEY-MARK"})), &ws).await;
        assert_eq!(r.result.as_deref(), Some("no matches"), "{:?}", r.result);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grep_跳过_fifo_不阻塞() {
        let (dir, ws) = setup();
        let fifo = dir.path().join("pipe");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        fs::write(dir.path().join("a.txt"), "FIFO-MARK\n").unwrap();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            local_grep(&p(serde_json::json!({"path": ".", "pattern": "FIFO-MARK"})), &ws),
        ).await.expect("grep 在 FIFO 上阻塞");
        assert!(r.result.unwrap().contains("a.txt"));
    }

    #[tokio::test]
    async fn 恶意_xlsx_pdf_不拖垮本进程() {
        // 审核 B-F3/F4：包围盒 xlsx（512GiB 分配 abort）、深嵌套/自引用 PDF（栈溢出 abort）。
        // 进程内解析时本测试进程会直接 SIGABRT；子进程隔离后应得到 Unreadable 错误。
        let (dir, ws) = setup();
        for f in ["bbox.xlsx", "deep.pdf", "selfref.pdf"] {
            let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/office/hostile").join(f);
            fs::copy(&src, dir.path().join(f)).unwrap();
            let r = local_read_file(&p(serde_json::json!({"path": f})), &ws).await;
            assert!(!r.ok, "{f} 应失败而非成功");
            assert!(r.error.as_deref().unwrap_or("").contains("unreadable"), "{f}: {:?}", r.error);
        }
        // 正常文件不受影响（子进程链路通）
        fs::copy(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/office/budget.xlsx"), dir.path().join("ok.xlsx")).unwrap();
        assert!(local_read_file(&p(serde_json::json!({"path": "ok.xlsx"})), &ws).await.ok);
    }
}
