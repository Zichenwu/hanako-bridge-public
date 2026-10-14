//! 桌面桌宠（openhanako docs/issues/desktop-pet 票 05，spec docs/local-client/04-desktop-pet-spec-2026-10-14.md）。
//!
//! 本模块只放**纯逻辑**（可单测）；窗口创建 / 原生菜单在 lib.rs（必须主线程）。
//!
//! ## 流程
//! 1. 网页点「上桌面」→ 服务端经节点 WS 发 `{"type":"pet_show"}` → client.rs 回调 → lib.rs 开窗
//! 2. 开窗前用**节点凭据**换 companion.read 短票：`POST {base}/api/companion/pet-token`
//!    （⛔ 绝不把节点凭据本身交给网页——它能接派活）
//! 3. 窗口加载 `{base}/companion-pet#pt=<短票>`：票放 fragment，不进服务端日志、不进 Referer；
//!    页面读出即从地址栏抹掉。票失效时页面调 `pet_token_expired`，这里换新票重载。
//! 4. 「桌面模式」是本机持久状态（`~/.hanako-tauri/pet.json`）：Bridge 启动 / 重连后自动恢复。
//!
//! ## 安全边界：桌宠窗**零 IPC**
//! 桌宠窗加载的是**远程页面**，按「可能被 XSS」设计：不给它任何 Tauri 命令 / capability
//!（远程源调 app 命令需要 AppManifest + remote capability，那会把全部本地窗口命令也纳入 ACL，风险面大）。
//! 页面的交互一律表达为**导航到 `https://hanako-pet.invalid/<动作>`**，由 `on_navigation` 拦下解析、
//! 返回 false 阻止真实跳转（`.invalid` 是 RFC 2606 保留 TLD，真跳出去也解析不到任何主机）。
//! 动作白名单见 [`PetAction`]；参数只接 sessionRef（UUID 白名单）；打开的 URL 由本机拼，
//! 不接收页面传来的任何 URL。拖动也走这条协议（`/drag` → 原生 start_dragging），页面零 capability。
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PET_WINDOW_LABEL: &str = "pet";
/// 注册帧顶层 `petCapability`。服务端 fail-closed：缺字段 = 不支持，网页不出「上桌面」。
pub const PET_CAPABILITY: u32 = 1;
/// 窗口逻辑尺寸：cell 256×384 × 0.625 = 160×240，再给气泡留 24px
pub const PET_WINDOW_SIZE: (f64, f64) = (160.0, 264.0);

/// 本机持久状态。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PetState {
    /// 桌面模式开着（网页点过「上桌面」且没退出）→ Bridge 启动后自动恢复桌宠
    #[serde(default)]
    pub enabled: bool,
    /// 上次位置（逻辑坐标，物理屏原点为基准）；None = 右下角默认停靠
    #[serde(default)]
    pub position: Option<(f64, f64)>,
    /// 「隐藏 1 小时」到期时刻（unix ms）。到期前不显示，但 enabled 不变
    #[serde(default)]
    pub snooze_until_ms: Option<u64>,
}

pub fn state_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HANAKO_DATA_DIR") {
        return Some(PathBuf::from(p).join("pet.json"));
    }
    dirs_next::home_dir().map(|h| h.join(".hanako-tauri").join("pet.json"))
}

/// 读失败 / 坏文件一律当默认（关），不报错——桌宠是锦上添花，坏了不能拖垮 Bridge。
pub fn load_state_from(path: &std::path::Path) -> PetState {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn save_state_to(path: &std::path::Path, st: &PetState) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// 此刻该不该显示：开着 且 不在「隐藏 1 小时」窗口内。
pub fn should_show(st: &PetState, now_ms: u64) -> bool {
    st.enabled && st.snooze_until_ms.map_or(true, |t| now_ms >= t)
}

/// 桌宠页地址：`{base}/companion-pet#pt=<token>`。只认 hana_tt_ 短票（防误把节点长票塞进 URL）。
pub fn pet_page_url(base_url: &str, token: &str) -> Result<String, String> {
    if !token.starts_with("hana_tt_") || !token[8..].chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("桌宠票格式不对".into());
    }
    let base = base_url.trim().trim_end_matches('/');
    let lower = base.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("服务端地址不是 http(s)".into());
    }
    // 带尾斜杠：页面资源是相对路径；且不带斜杠的地址曾被网关 301 过（WebView 会永久缓存该跳转），
    // 直接用斜杠形态可绕开历史缓存（2026-10-15 实测：缓存跳转被导航白名单拦 → 页面零资源）。
    Ok(format!("{base}/companion-pet/#pt={token}"))
}

/// 换票端点。
pub fn pet_token_url(base_url: &str) -> String {
    format!("{}/api/companion/pet-token", base_url.trim().trim_end_matches('/'))
}

/// 解析换票响应：只取 token（hana_tt_）。
pub fn parse_pet_token(status: u16, body: &str) -> Result<String, String> {
    if status != 200 {
        return Err(format!("换桌宠票失败 HTTP {status}"));
    }
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("换桌宠票响应不是 JSON: {e}"))?;
    let t = v.get("token").and_then(|t| t.as_str()).ok_or("换桌宠票响应缺 token")?;
    if !t.starts_with("hana_tt_") {
        return Err("换桌宠票拿到的不是短票".into());
    }
    Ok(t.to_string())
}

/// 桌宠点击打开会话：`{base}/?session=<uuid>`；sessionRef 缺省 / 非 UUID → 打开首页。
/// 只接受 UUID 形状，页面传来的任何别的东西都不进 URL（防远程页借命令打开任意地址）。
pub fn session_open_url(base_url: &str, session_ref: Option<&str>) -> String {
    let base = base_url.trim().trim_end_matches('/');
    match session_ref {
        Some(r) if is_uuid(r) => format!("{base}/?session={r}"),
        _ => format!("{base}/"),
    }
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    parts.len() == 5 && parts.iter().zip(lens).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 「打开桌宠」回调槽：lib.rs setup 时注入（开窗必须主线程，回调内自行 run_on_main_thread）。
/// 用全局槽而不是挂在 DaemonClient 上：supervisor 每次 restart 都重建 client，全局槽免改构造链。
static ON_PET_SHOW: std::sync::OnceLock<std::sync::Arc<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

pub fn set_on_pet_show(f: std::sync::Arc<dyn Fn() + Send + Sync>) {
    let _ = ON_PET_SHOW.set(f);
}

/// client.rs 收到 pet_show 帧时调用。未注入（headless / 测试）= 空操作。
pub fn fire_pet_show() {
    if let Some(f) = ON_PET_SHOW.get() {
        f();
    }
}

/// 桌宠页可请求的动作（导航拦截协议）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PetAction {
    /// 单击：系统浏览器打开会话（None = 首页）
    OpenSession(Option<String>),
    /// 右键：弹原生菜单
    ContextMenu,
    /// 票失效：换新票重载
    TokenExpired,
    /// 指针按下后移动：原生拖窗
    Drag,
}

pub const PET_ACTION_HOST: &str = "hanako-pet.invalid";

/// 解析导航拦截：不是 `https://hanako-pet.invalid/...` 返回 None（放行正常导航）；
/// 是但动作未知 → Some(None)（拦下且不做事）。
pub fn parse_pet_action(url: &str) -> Option<Option<PetAction>> {
    let rest = url.strip_prefix("https://")?;
    let (host, path_q) = rest.split_once('/').unwrap_or((rest, ""));
    if !host.eq_ignore_ascii_case(PET_ACTION_HOST) {
        return None;
    }
    let (path, query) = path_q.split_once('?').unwrap_or((path_q, ""));
    let action = match path {
        "open" => {
            let r = query.split('&').find_map(|kv| kv.strip_prefix("ref=")).filter(|r| is_uuid(r)).map(str::to_string);
            Some(PetAction::OpenSession(r))
        }
        "menu" => Some(PetAction::ContextMenu),
        "token-expired" => Some(PetAction::TokenExpired),
        "drag" => Some(PetAction::Drag),
        _ => None,
    };
    Some(action)
}

/// 桌宠窗导航放行规则：只许留在本服务端的 /companion-pet 页（换票重载也是它）；其它一律拦。
pub fn is_allowed_pet_navigation(url: &str, base_url: &str) -> bool {
    let base = base_url.trim().trim_end_matches('/');
    url.strip_prefix(base)
        .map(|rest| {
            // 有无尾斜杠两种形态都放行（服务端两种都直接出页面）；其后只许 fragment / query
            let rest = rest.strip_prefix("/companion-pet").unwrap_or("x");
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            rest.is_empty() || rest.starts_with('#') || rest.starts_with('?')
        })
        .unwrap_or(false)
}

/// 控制帧识别：`{"type":"pet_show"}`。
pub fn is_pet_show(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(|t| t == "pet_show"))
        .unwrap_or(false)
}

/// 托盘「桌宠」子菜单展示的状态（A+B，2026-10-15 用户拍板）。
/// 由 pet.json + 窗口是否存在 + 是否登录 / 在线 派生，**不存盘**——托盘永远反映事实。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PetTrayState {
    /// 没开桌面模式：companion 在网页里
    InWeb,
    /// 桌宠窗在桌面上
    OnDesktop,
    /// 开着但处于「隐藏 1 小时」，到期自动回来（值 = 到期 unix ms）
    Snoozed(u64),
    /// 开着、该显示，但没登录：登录后自动回来
    NeedLogin,
    /// 开着、该显示，但连不上服务端：联网后自动回来
    Offline,
    /// 开着、在线、窗口还没出来（换票中 / 恢复器下一轮会开）
    Opening,
}

/// 派生托盘状态。`window_open` = 桌宠窗存在；`logged_in` = 有节点凭据；`connected` = 节点 WS 已连上。
pub fn tray_state(st: &PetState, window_open: bool, logged_in: bool, connected: bool, now_ms: u64) -> PetTrayState {
    if !st.enabled {
        return PetTrayState::InWeb;
    }
    if let Some(t) = st.snooze_until_ms.filter(|&t| now_ms < t) {
        return PetTrayState::Snoozed(t);
    }
    if window_open {
        return PetTrayState::OnDesktop;
    }
    if !logged_in {
        return PetTrayState::NeedLogin;
    }
    if !connected {
        return PetTrayState::Offline;
    }
    PetTrayState::Opening
}

/// 子菜单各项的可用性：(放到桌面, 收回到网页, 隐藏 1 小时)。
pub fn tray_actions(state: PetTrayState) -> (bool, bool, bool) {
    match state {
        PetTrayState::InWeb => (true, false, false),
        PetTrayState::OnDesktop => (false, true, true),
        // 隐藏中：可「立即显示」（复用放到桌面）或彻底收回
        PetTrayState::Snoozed(_) => (true, true, false),
        // 等登录 / 等网络 / 正在开：桌面模式已开，只允许收回（再点「放到桌面」也开不出来）
        PetTrayState::NeedLogin | PetTrayState::Offline | PetTrayState::Opening => (false, true, false),
    }
}

/// 托盘文案。`hhmm` 把到期 unix ms 格式化成本地「HH:MM」（由调用方注入，便于测试）。
pub fn tray_label(state: PetTrayState, hhmm: impl Fn(u64) -> String) -> (String, &'static str) {
    // (子菜单状态行, 「放到桌面」项文案)
    match state {
        PetTrayState::InWeb => ("在网页里".into(), "放到桌面"),
        PetTrayState::OnDesktop => ("在桌面上".into(), "放到桌面"),
        PetTrayState::Snoozed(t) => (format!("已隐藏，{} 回来", hhmm(t)), "立即显示"),
        PetTrayState::NeedLogin => ("未登录，登录后回到桌面".into(), "放到桌面"),
        PetTrayState::Offline => ("连不上服务器，联网后回到桌面".into(), "放到桌面"),
        PetTrayState::Opening => ("正在放到桌面…".into(), "放到桌面"),
    }
}

/// 托盘顶层子菜单标题：一眼看出在哪（不展开也能感知）。
pub fn tray_title(state: PetTrayState) -> &'static str {
    match state {
        PetTrayState::InWeb => "桌宠：在网页",
        PetTrayState::OnDesktop => "桌宠：在桌面",
        PetTrayState::Snoozed(_) => "桌宠：已隐藏",
        PetTrayState::NeedLogin | PetTrayState::Offline => "桌宠：等待连接",
        PetTrayState::Opening => "桌宠：正在打开",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> PetState { PetState { enabled: true, ..Default::default() } }

    #[test]
    fn 托盘状态_没开桌面模式_一律在网页() {
        // 窗口残留 / 离线都不影响：enabled=false 就是在网页
        assert_eq!(tray_state(&PetState::default(), true, true, true, 0), PetTrayState::InWeb);
        assert_eq!(tray_state(&PetState::default(), false, false, false, 0), PetTrayState::InWeb);
    }

    #[test]
    fn 托盘状态_隐藏期内优先于其它_到期后按事实() {
        let st = PetState { snooze_until_ms: Some(1000), ..on() };
        assert_eq!(tray_state(&st, false, false, false, 999), PetTrayState::Snoozed(1000));
        assert_eq!(tray_state(&st, false, true, true, 1000), PetTrayState::Opening, "到期即不再算隐藏");
        assert_eq!(tray_state(&st, true, true, true, 1000), PetTrayState::OnDesktop);
    }

    #[test]
    fn 托盘状态_开着但窗口不在_区分未登录_离线_正在开() {
        assert_eq!(tray_state(&on(), true, false, false, 0), PetTrayState::OnDesktop, "窗口在就是在桌面");
        assert_eq!(tray_state(&on(), false, false, false, 0), PetTrayState::NeedLogin);
        assert_eq!(tray_state(&on(), false, true, false, 0), PetTrayState::Offline);
        assert_eq!(tray_state(&on(), false, true, true, 0), PetTrayState::Opening);
    }

    #[test]
    fn 托盘动作_与状态一致() {
        assert_eq!(tray_actions(PetTrayState::InWeb), (true, false, false));
        assert_eq!(tray_actions(PetTrayState::OnDesktop), (false, true, true));
        assert_eq!(tray_actions(PetTrayState::Snoozed(5)), (true, true, false));
        for s in [PetTrayState::NeedLogin, PetTrayState::Offline, PetTrayState::Opening] {
            assert_eq!(tray_actions(s), (false, true, false), "{s:?} 只能收回");
        }
    }

    #[test]
    fn 托盘文案_隐藏态带回来时刻且放到桌面改叫立即显示() {
        let (line, show) = tray_label(PetTrayState::Snoozed(42), |t| format!("T{t}"));
        assert_eq!(line, "已隐藏，T42 回来");
        assert_eq!(show, "立即显示");
        assert_eq!(tray_title(PetTrayState::OnDesktop), "桌宠：在桌面");
        assert_eq!(tray_title(PetTrayState::InWeb), "桌宠：在网页");
    }

    #[test]
    fn 页面地址_票放_fragment_且只认短票() {
        assert_eq!(
            pet_page_url("https://x.example.com/hapi/hanako/", "hana_tt_abc_DEF-1").unwrap(),
            "https://x.example.com/hapi/hanako/companion-pet/#pt=hana_tt_abc_DEF-1"
        );
        assert!(pet_page_url("https://x", "hana_dev_longlived").is_err(), "节点长票绝不能进 URL");
        assert!(pet_page_url("https://x", "hana_tt_a&b=c").is_err(), "票里不许带 URL 元字符");
        assert!(pet_page_url("javascript:alert(1)", "hana_tt_a").is_err());
    }

    #[test]
    fn 换票响应_只接受短票() {
        assert_eq!(parse_pet_token(200, r#"{"ok":true,"token":"hana_tt_x"}"#).unwrap(), "hana_tt_x");
        assert!(parse_pet_token(200, r#"{"token":"hana_dev_x"}"#).is_err());
        assert!(parse_pet_token(403, r#"{"error":"node_credential_required"}"#).is_err());
        assert!(parse_pet_token(200, "not json").is_err());
        assert_eq!(pet_token_url("https://x/hapi/hanako/"), "https://x/hapi/hanako/api/companion/pet-token");
    }

    #[test]
    fn 打开会话_只认_uuid_其它一律回首页() {
        let b = "https://x/hapi/hanako";
        assert_eq!(session_open_url(b, Some("0192f5e2-8c1a-7000-8000-000000000001")), "https://x/hapi/hanako/?session=0192f5e2-8c1a-7000-8000-000000000001");
        for bad in ["https://evil.com", "../../etc", "0192f5e2", "", "0192f5e2-8c1a-7000-8000-00000000000g"] {
            assert_eq!(session_open_url(b, Some(bad)), "https://x/hapi/hanako/", "{bad}");
        }
        assert_eq!(session_open_url(b, None), "https://x/hapi/hanako/");
    }

    #[test]
    fn 持久状态_读写往返_坏文件当关() {
        let dir = std::env::temp_dir().join(format!("pet-test-{}", std::process::id()));
        let p = dir.join("pet.json");
        let st = PetState { enabled: true, position: Some((10.0, 20.0)), snooze_until_ms: Some(5) };
        save_state_to(&p, &st).unwrap();
        assert_eq!(load_state_from(&p), st);
        std::fs::write(&p, "{broken").unwrap();
        assert_eq!(load_state_from(&p), PetState::default());
        assert_eq!(load_state_from(&dir.join("missing.json")), PetState::default());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn 隐藏一小时_到期才再显示() {
        let st = PetState { enabled: true, position: None, snooze_until_ms: Some(1000) };
        assert!(!should_show(&st, 999));
        assert!(should_show(&st, 1000));
        assert!(!should_show(&PetState::default(), 0), "没开桌面模式不显示");
        assert!(should_show(&PetState { enabled: true, ..Default::default() }, 0));
    }

    #[test]
    fn 导航拦截协议_只认白名单动作与_uuid() {
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/open?ref=0192f5e2-8c1a-7000-8000-000000000001"),
            Some(Some(PetAction::OpenSession(Some("0192f5e2-8c1a-7000-8000-000000000001".into())))));
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/open"), Some(Some(PetAction::OpenSession(None))));
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/open?ref=https://evil.com"), Some(Some(PetAction::OpenSession(None))), "非 UUID 的 ref 丢弃");
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/menu"), Some(Some(PetAction::ContextMenu)));
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/token-expired"), Some(Some(PetAction::TokenExpired)));
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/drag"), Some(Some(PetAction::Drag)));
        assert_eq!(parse_pet_action("https://hanako-pet.invalid/rm-rf"), Some(None), "未知动作：拦下不做事");
        assert_eq!(parse_pet_action("https://x.example.com/companion-pet"), None, "非动作地址：交给放行规则");
        assert_eq!(parse_pet_action("https://hanako-pet.invalid.evil.com/open"), None);
    }

    #[test]
    fn 导航放行_只许停在本服务端桌宠页() {
        let b = "https://x.example.com/hapi/hanako";
        assert!(is_allowed_pet_navigation("https://x.example.com/hapi/hanako/companion-pet#pt=hana_tt_a", b));
        assert!(is_allowed_pet_navigation("https://x.example.com/hapi/hanako/companion-pet", b));
        assert!(is_allowed_pet_navigation("https://x.example.com/hapi/hanako/companion-pet/", b), "带斜杠（Bridge 默认打开形态）");
        assert!(is_allowed_pet_navigation("https://x.example.com/hapi/hanako/companion-pet/#pt=hana_tt_a", b));
        for bad in [
            "https://x.example.com/hapi/hanako/",
            "https://x.example.com/hapi/hanako/companion-pet-evil",
            "https://evil.com/companion-pet",
            "https://x.example.com/hapi/hanako/../../companion-pet",
            "https://x.example.com/hapi/hanakoX/companion-pet",
            "https://x.example.com/hapi/hanako/companion-pet/assets/x.js",
            "https://x.example.com/hapi/hanako/companion-pet//evil",
        ] {
            assert!(!is_allowed_pet_navigation(bad, b), "{bad}");
        }
    }

    #[test]
    fn 控制帧识别() {
        assert!(is_pet_show(r#"{"type":"pet_show"}"#));
        assert!(!is_pet_show(r#"{"type":"preview_request"}"#));
        assert!(!is_pet_show("garbage"));
    }
}
