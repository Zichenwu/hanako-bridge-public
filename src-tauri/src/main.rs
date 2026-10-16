// src-tauri/src/main.rs
// 阻止 release 模式下 Windows 弹出控制台窗口
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 审核 B-F3/F4：Office/PDF 抽取子进程模式，必须早于任何 Tauri/GUI 初始化
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(hanako_tauri_lib::daemon::tools::extract::CHILD_FLAG) {
        let name = args.get(2).map(String::as_str).unwrap_or("");
        std::process::exit(hanako_tauri_lib::daemon::tools::extract::child_main(name));
    }
    hanako_tauri_lib::run();
}
