// src-tauri/tests/native_window_wiring.rs
//! 弹窗桥 → 原生窗口的接线守卫。
//!
//! 坑史（2026-10-08 验收）：预览确认桥（票 03）单测齐全，但**从没有人调 `set_presenter`**，
//! 桥在没有 presenter 时按 headless 立即拒绝 → 网页显示「未获允许」、电脑上什么都不弹。
//! 桥的单测用假 presenter，看不出生产里漏接。接线发生在 Tauri `setup` 闭包里，拿不到
//! AppHandle 做单测，所以用扫源码的方式锁住四件事：
//!  ① lib.rs 给桥装了 presenter；② 有取数 / 提交两个命令且已注册；
//!  ③ 窗口在 capabilities 与 tauri.conf.json 里声明；④ 页面调用的提交命令与 Rust 侧同名。
//!
//! 变异验证：删掉 lib.rs 里 `previews().set_presenter` 那段 → ① 红；
//! 从 capabilities 删掉 "preview-ask" → ③ 红。

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    // Windows CI 检出为 CRLF：归一后再按行匹配，否则 `"cmd,\n"` 永远对不上（10-08 踩过）
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display())).replace("\r\n", "\n")
}

/// (桥访问器, 窗口 label, 取数命令, 提交命令)
const BRIDGES: &[(&str, &str, &str, &str)] = &[
    ("uploads()", "upload-ask", "get_pending_upload_ask", "respond_upload_ask"),
    ("previews()", "preview-ask", "get_pending_preview_ask", "respond_preview_ask"),
];

#[test]
fn 每个弹窗桥都装了_presenter_且命令已注册() {
    let lib = read("src/lib.rs");
    for (accessor, label, get_cmd, respond_cmd) in BRIDGES {
        assert!(
            lib.contains(&format!("sup.{accessor}.set_presenter(")),
            "{accessor} 没装 presenter：桥会按 headless 立即拒绝，电脑上不弹窗"
        );
        for cmd in [get_cmd, respond_cmd] {
            assert!(lib.contains(&format!("fn {cmd}(")), "缺命令 {cmd}（{label}）");
            assert!(lib.contains(&format!("            {cmd},\n")), "命令 {cmd} 没进 invoke_handler（{label}）");
        }
    }
}

#[test]
fn 每个弹窗窗口都已声明且页面调对命令() {
    let caps = read("capabilities/default.json");
    let conf = read("tauri.conf.json");
    for (_, label, get_cmd, respond_cmd) in BRIDGES {
        assert!(caps.contains(&format!("\"{label}\"")), "capabilities 没声明窗口 {label}：页面拿不到 invoke 权限");
        assert!(conf.contains(&format!("\"label\": \"{label}\"")), "tauri.conf.json 没声明窗口 {label}");
        let js = read(&format!("ui/{label}.js"));
        assert!(js.contains(&format!("\"{get_cmd}\"")), "ui/{label}.js 没调 {get_cmd}");
        assert!(js.contains(&format!("\"{respond_cmd}\"")), "ui/{label}.js 没调 {respond_cmd}");
        assert!(read(&format!("ui/{label}.html")).contains(&format!("{label}.js")), "ui/{label}.html 没引 {label}.js");
    }
}

#[test]
fn 预览弹窗原样展示承诺文案_不出现上传字样() {
    let js = read("ui/preview-ask.js");
    assert!(js.contains("data.notice"), "承诺文案须用 Rust 下发的 data.notice，不在页面里改写");
    assert!(!js.contains("\"up."), "预览弹窗不得复用上传文案 key（两条通道文案独立）");
}

/// 审核 #5：守护进程固定 Strict 时，改文件确认窗不得出现「本次会话信任」按钮——
/// Strict 分支丢弃 `Decision::TrustSession`（approval.rs），按钮点了等于「同意一次」，文案却承诺会话内免确认。
/// 若将来真要开放会话信任：先把 client.rs 改为 SessionTrust 并补倒计时 / i18n，本守卫随之放行。
#[test]
fn 审核5_strict模式下改文件确认窗不出现会话信任按钮() {
    let client = read("src/daemon/client.rs");
    let page = read("ui/approval.html");
    if client.contains("ApprovalMode::Strict,") && !client.contains("ApprovalMode::SessionTrust") {
        assert!(!page.contains("data-decision=\"trust_session\""), "Strict 下不该有会话信任按钮（点了不生效）");
    }
}
