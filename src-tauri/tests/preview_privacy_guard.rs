// src-tauri/tests/preview_privacy_guard.rs
//! 本机文件预览 票 04 · Bridge 侧隐私静态守卫。
//!
//! 预览读取模块经手文件**原文字节**，所以有两条硬约束，用扫源码的方式强制：
//!  ① 不得写文件（没有落盘、缓存、临时文件）；
//!  ② 日志不得引用分片、结果或文件内容，也不得打印本机绝对路径。
//!
//! 反面教材（spec 明确点名）：助手本地工具的派发入口会打印「工具名 + 结果前 80 字符」。
//! 预览若照抄那个写法，文本文件的开头就会进日志。
//!
//! 变异验证：在 `preview_read.rs` 里加一行 `std::fs::write(...)`，或加一行
//! `log::info!("{:?}", bytes)` → 本文件对应用例变红。

use std::path::Path;

fn read_src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()))
}

/// 去掉注释行与测试模块，只留生产代码。
///
/// 必须去掉测试：测试里**合法地**写临时文件（造被预览的文件）并断言内容，
/// 不排除会把整个守卫变成空断言（它永远能在 `#[cfg(test)]` 里找到 `fs::write`）。
fn production_code(src: &str) -> String {
    let cut = src.find("#[cfg(test)]").unwrap_or(src.len());
    src[..cut]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 经手文件原文字节的两个模块（票 07 起含分片发送）。
const BYTE_HANDLING: [&str; 2] = ["src/daemon/preview_read.rs", "src/daemon/preview_stream.rs"];

#[test]
fn 预览读取模块不得写文件() {
  for module in BYTE_HANDLING {
    let code = production_code(&read_src(module));
    for banned in [
        "fs::write",
        "fs::File::create",
        "OpenOptions",
        "create_dir",
        "fs::copy",
        "BufWriter",
        "tempfile",
        "fs::rename",
        "fs::remove",
    ] {
        assert!(
            !code.contains(banned),
            "{module} 生产代码不得出现 `{banned}`（预览字节只在内存里走一趟，不落盘）"
        );
    }
  }
}

#[test]
fn 预览读取模块的日志不得引用内容或路径() {
  for module in BYTE_HANDLING {
    let code = production_code(&read_src(module));
    // 最省心也最严的守法：这个模块一行日志都不打
    for macro_name in ["log::info!", "log::warn!", "log::error!", "log::debug!", "log::trace!", "println!", "eprintln!", "dbg!"] {
        assert!(
            !code.contains(macro_name),
            "{module} 不得出现 `{macro_name}`：该模块持有文件原文，任何打印都有泄露风险"
        );
    }
  }
}

#[test]
fn 预览帧分支的日志不得打印路径或内容() {
    let src = read_src("src/daemon/client.rs");
    // 只看预览帧那一段（从预览分支到任务帧分支之前）
    let begin = src.find("preview_request").expect("找不到预览帧分支");
    let end = src[begin..].find(r#"Some("task")"#).map(|i| begin + i).unwrap_or(src.len());
    let section = &src[begin..end];

    // 该段内的每一处日志宏调用，都不得引用这些变量
    for forbidden in ["preq.path", "real_path", "b.bytes", "&b.bytes", "file_name", "folder_name"] {
        for line in section.lines() {
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with('*') {
                continue;
            }
            let is_log = t.contains("log::") || t.contains("println!") || t.contains("eprintln!");
            assert!(
                !(is_log && line.contains(forbidden)),
                "预览帧分支的日志行不得引用 `{forbidden}`：\n{line}"
            );
        }
    }
}

/// 预览回传帧**只能**带这三种类型，且 chunk 的内容字段是 base64（不是明文）。
#[test]
fn 回传帧类型固定且内容只走_base64() {
    let code = production_code(&read_src("src/daemon/preview_read.rs"));
    assert!(code.contains("\"preview_meta\""));
    assert!(code.contains("\"preview_chunk\""));
    assert!(code.contains("\"preview_end\""));
    // chunk 必须编码；直接塞 String::from_utf8 之类的明文是不允许的
    assert!(code.contains("encode("), "chunk 必须 base64 编码后再进帧");
    assert!(
        !code.contains("from_utf8_lossy") && !code.contains("String::from_utf8"),
        "不得把字节转成明文字符串塞进帧（base64 之外没有第二条路）"
    );
}

/// 票 07：分片发送模块的回传帧类型固定（meta/chunk/end/abort），chunk 内容只走 base64，
/// 且带 `seq`（服务端据此做乱序 / 重复检测——少了它服务端无法判断）。
#[test]
fn 分片模块帧类型固定且分片带序号只走_base64() {
    let code = production_code(&read_src("src/daemon/preview_stream.rs"));
    assert!(code.contains("\"preview_chunk\""));
    assert!(code.contains("\"preview_abort\""));
    assert!(code.contains("\"seq\""), "分片帧必须带 seq");
    assert!(code.contains("encode("), "分片必须 base64 编码后再进帧");
    assert!(
        !code.contains("from_utf8_lossy") && !code.contains("String::from_utf8"),
        "不得把字节转成明文字符串塞进帧"
    );
}

/// 票 07：分片模块不得整文件读入内存（200MB 文件会吃掉用户电脑 200MB）。
/// 变异：把 `read_exact` 换成 `tokio::fs::read(path)` → 本用例红。
#[test]
fn 分片模块不得整文件读入内存() {
    let code = production_code(&read_src("src/daemon/preview_stream.rs"));
    for banned in ["fs::read(", "read_to_end", "read_to_string"] {
        assert!(!code.contains(banned), "preview_stream.rs 不得出现 `{banned}`：必须一次只读一片");
    }
    assert!(code.contains("read_exact"), "应按片 read_exact");
}
