// tests/pet_only.rs
//! 「只当桌宠」（10-15）：pet.json 里 `pet_only=true` 时，本机不参与任何执行。
//!
//! 单测只证明 `Policy::pet_only()` 本身为空；这里证明**生产读策略的唯一入口** `Policy::load`
//! 真的读了 pet.json——注册帧、策略推送、任务、预览都经它，入口漏读则全链失效。
//! 独立 test binary：用自己的 HANAKO_DATA_DIR / 目录 env，不碰真实 ~/.hanako-tauri。

use hanako_tauri_lib::daemon::pet::{save_state_to, PetState};
use hanako_tauri_lib::daemon::policy::{GateError, Policy, TaskScope};
use hanako_tauri_lib::daemon::register::RegisterFrame;
use hanako_tauri_lib::daemon::DaemonConfig;

const AGENT: &str = "bi--zhangsan";

#[test]
fn 只当桌宠_开关切换直接改变生产策略与注册帧() {
    let base = std::env::temp_dir().join(format!("pet-only-it-{}", std::process::id()));
    let data = base.join("data");
    let dir = base.join("folder");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    // 本测试是独立进程且只有这一个用例，改进程 env 安全
    std::env::set_var("HANAKO_DATA_DIR", &data);
    std::env::set_var("HANA_LOCAL_WORKSPACES", &dir);
    std::env::set_var("HANAKO_POLICY_PATH", base.join("policy.json"));
    std::env::set_var("HANAKO_WORKSPACES_PATH", base.join("workspaces.json"));
    let pet = data.join("pet.json");
    let cfg = DaemonConfig {
        base_url: "https://x.example.com".into(),
        token: "tok".into(),
        node_id: "node_t".into(),
        agent_id: Some(AGENT.into()),
    };
    let scope = TaskScope { agent_id: AGENT.into(), root_id: None };
    std::fs::write(dir.join("a.txt"), "hi").unwrap();

    // 关：有目录、有授权、能读
    save_state_to(&pet, &PetState::default()).unwrap();
    let p = Policy::load(Some(AGENT));
    assert_eq!(p.roots_view().len(), 1, "基线：关着时应上报目录（否则下面的断言是空过）");
    assert!(p.authorize(&scope, "a.txt", false).is_ok());

    // 开：零目录、零授权、拒绝原因说明是「只当桌宠」
    save_state_to(&pet, &PetState { pet_only: true, ..Default::default() }).unwrap();
    let p = Policy::load(Some(AGENT));
    let frame = RegisterFrame::from_policy(&cfg, &p, "0.1.0");
    assert!(frame.roots.is_empty() && frame.grants.is_empty(), "注册帧不得上报任何目录 / 授权");
    match p.authorize(&scope, "a.txt", false) {
        Err(GateError::PolicyUnavailable(why)) => assert!(why.contains("只当桌宠"), "{why}"),
        other => panic!("只当桌宠下读文件必须被拒: {other:?}"),
    }

    // 再关：目录配置没被动过，原样恢复
    save_state_to(&pet, &PetState::default()).unwrap();
    assert_eq!(Policy::load(Some(AGENT)).roots_view().len(), 1, "关掉即恢复，文件夹配置保留");

    let _ = std::fs::remove_dir_all(base);
}
