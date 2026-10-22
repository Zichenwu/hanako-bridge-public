// 票 17：「不在电脑前时网页确认」开关的 fail-closed 必须对真实磁盘文件成立。
//
// 为什么是集成测试：`web_confirm_switch_on` 读 `~/.hanako-tauri/policy.json`（真实路径），
// 单测里只能注入闭包，验证不到「文件不存在 / 损坏 / 被删后」这些真实磁盘状态下的行为。
// 用独立进程 + 临时 HOME，避免污染开发机真实配置；各用例串行（共享 HOME 环境变量）。

use hanako_tauri_lib::daemon::client::web_confirm_switch_on;
use std::sync::Mutex;

/// HOME 是进程级全局，用例必须串行。
static LOCK: Mutex<()> = Mutex::new(());

fn with_home<F: FnOnce(&std::path::Path)>(f: F) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let old = std::env::var_os("HOME");
    let old_pp = std::env::var_os("HANAKO_POLICY_PATH");
    std::env::set_var("HOME", dir.path());
    // Windows 上 home_dir 走 KNOWNFOLDER 不读 HOME/USERPROFILE，策略路径用显式覆盖隔离
    std::env::set_var("HANAKO_POLICY_PATH", dir.path().join(".hanako-tauri").join("policy.json"));
    f(dir.path());
    match old {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    match old_pp {
        Some(v) => std::env::set_var("HANAKO_POLICY_PATH", v),
        None => std::env::remove_var("HANAKO_POLICY_PATH"),
    }
}

fn write_policy(home: &std::path::Path, body: &str) {
    let d = home.join(".hanako-tauri");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("policy.json"), body).unwrap();
}

#[test]
fn 没有策略文件_开关为关() {
    with_home(|_| assert!(!web_confirm_switch_on(), "默认必须关"));
}

#[test]
fn 文件里显式开启_开关为开() {
    with_home(|h| {
        write_policy(h, r#"{"webConfirm": true}"#);
        assert!(web_confirm_switch_on());
    });
}

#[test]
fn 文件里显式关闭_开关为关() {
    with_home(|h| {
        write_policy(h, r#"{"webConfirm": false}"#);
        assert!(!web_confirm_switch_on());
    });
}

#[test]
fn 文件损坏_开关为关_而不是默认开() {
    with_home(|h| {
        write_policy(h, r#"{"webConfirm": true, "folders": [ 这不是合法 json"#);
        assert!(!web_confirm_switch_on(), "放宽类配置读失败必须 fail-closed");
    });
}

#[test]
fn 文件被清空_开关为关() {
    with_home(|h| {
        write_policy(h, "");
        assert!(!web_confirm_switch_on());
    });
}

#[test]
fn 改设置立即生效_不缓存() {
    with_home(|h| {
        write_policy(h, r#"{"webConfirm": false}"#);
        assert!(!web_confirm_switch_on());
        write_policy(h, r#"{"webConfirm": true}"#);
        assert!(web_confirm_switch_on(), "用户在设置窗开启后，下一次确认就该生效");
        write_policy(h, r#"{"webConfirm": false}"#);
        assert!(!web_confirm_switch_on(), "关闭同理立即生效");
    });
}
