// src-tauri/src/daemon/upload_gate.rs
//! 上传偏好闸（票 18，决策文档 §3.3「数据出境闸」）。
//!
//! 任何本机文件内容（原文件）进入云端持久存储之前都要过这道闸。
//! 本模块是**纯决策**：输入请求 + 本机策略 + 会话内授权，输出 `Verdict`。不碰 UI、不碰网络，
//! 这样安全边界能被穷举测试，UI 只是「把 `Verdict::Ask` 问出去」的壳。
//!
//! ## 规则（从紧到松，先命中先返回）
//! 1. **目录外永不放行**：路径没有落在任何授权目录内 → `Deny(OutOfFence)`，任何档位都不行；
//! 2. **执行体没被授权该目录** → `Deny(ActorNotGranted)`（上传比读更敏感，不能比读宽松）；
//! 3. **超过 50 MB 永不放行**（`Deny(TooBig)`）——票文明确「>50MB 永不放行」，
//!    不是「强制逐次确认」：大文件走 WS 帧既不可靠（见 MAX_UPLOAD_BYTES 注释）也不该悄悄出境；
//! 4. 偏好 `always`（目录级永久，**仅本机设置可开**）→ `Allow`；
//! 5. 会话内已授权同目录 → `Allow`；
//! 6. 否则 → `Ask`（默认每次问）。
//!
//! ## 为什么「永久」只能本机开、网页只能撤销
//! 网页/云端被攻破后，攻击者能伪造「用户点了允许」。永久放行会让一次点击变成永久后门，
//! 所以放宽方向的开关只存在于本机设置（`set_upload` 由本机 UI 命令调用），
//! 服务端的 `trust_revoke` 帧只能把 `always` 收回成 `ask`。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 单文件上传硬上限。
///
/// 50 MB 是产品口径（票文 / 设计稿 native.up.big）。实际传输走现有 WS 帧（用户拍板）：
/// base64 后体积 ×4/3，tungstenite 默认单消息上限 64 MiB，所以 50 MB 的原文件会被编码成约 66.7 MB 而**超帧**。
/// 因此**传输层的可靠上限是 `WS_SAFE_RAW_BYTES`（约 45 MB）**，本常量保持 50 MB 作为产品口径，
/// 实际放行取两者较小值——见 [`effective_limit`]。
pub const MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024;
/// 走 WS 单帧 base64 的可靠原文件上限：64 MiB 帧 ÷ 4/3，再留 2 MiB 给 JSON 包装与头部。
pub const WS_SAFE_RAW_BYTES: u64 = (64 * 1024 * 1024) * 3 / 4 - 2 * 1024 * 1024;

/// 实际放行上限 = min(产品口径, 传输可靠上限)。
pub fn effective_limit() -> u64 {
    MAX_UPLOAD_BYTES.min(WS_SAFE_RAW_BYTES)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// 文件不在任何授权目录内
    OutOfFence,
    /// 该执行体没被授权此目录
    ActorNotGranted,
    /// 超过上限
    TooBig { size: u64, limit: u64 },
    /// 不是普通文件（目录 / 设备 / 不存在）
    NotAFile,
}

impl DenyReason {
    /// 机读码（与服务端 `LOCAL_UPLOAD_REJECTED` 配套，reason 写进 details）。
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::OutOfFence => "out_of_fence",
            DenyReason::ActorNotGranted => "actor_not_granted",
            DenyReason::TooBig { .. } => "too_big",
            DenyReason::NotAFile => "not_a_file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 直接放行（永久信任 / 会话内信任）
    Allow,
    /// 需要弹窗问用户
    Ask,
    /// 拒绝（不弹窗）
    Deny(DenyReason),
}

/// 一次上传请求的事实（由调用方解析好，纯函数不碰磁盘）。
#[derive(Debug, Clone)]
pub struct UploadFacts {
    /// 已规范化（canonicalize，含符号链接解析）后的真实路径
    pub real_path: PathBuf,
    pub size: u64,
    pub is_file: bool,
    /// 命中的授权目录 rootId；`None` = 不在任何授权目录内
    pub root_id: Option<String>,
    /// 该执行体是否被授权此目录
    pub actor_granted: bool,
}

/// 本机策略里该目录的上传偏好。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pref {
    Ask,
    Always,
}

impl Pref {
    pub fn parse(s: &str) -> Pref {
        // 未知值一律按「每次问」：放宽方向的字段，解析不出来不能当成放行
        if s == "always" { Pref::Always } else { Pref::Ask }
    }
}

/// 会话内授权（「这个对话里，该目录的文件都直接传」）。内存态，对话结束即失效，不落盘。
///
/// 审核 P2「会话授权无 TTL」：`end_session` 没有调用方，授权实际永不过期——一次「本会话都允许」
/// 变成永久后门（云端被攻破后伪造会话 ID 即可无限上传）。故加绝对 TTL：授权超过
/// [`SESSION_GRANT_TTL`] 后 `has` 判失效并惰性清除。TTL 用 `Instant`（单调时钟，不受系统回拨影响）。
#[derive(Debug, Default)]
pub struct SessionGrants {
    /// (sessionId, rootId) → 授权时刻
    set: HashMap<(String, String), Instant>,
}

/// 会话内授权的绝对寿命：2 小时。够一场连续工作，又不会让一次点击变成永久后门。
pub const SESSION_GRANT_TTL: Duration = Duration::from_secs(2 * 3600);

impl SessionGrants {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn grant(&mut self, session: &str, root_id: &str) {
        if !session.is_empty() && !root_id.is_empty() {
            self.set.insert((session.to_string(), root_id.to_string()), Instant::now());
        }
    }
    pub fn has(&mut self, session: &str, root_id: &str) -> bool {
        if session.is_empty() {
            return false;
        }
        let key = (session.to_string(), root_id.to_string());
        match self.set.get(&key) {
            Some(at) if at.elapsed() <= SESSION_GRANT_TTL => true,
            // 过期：惰性清除（顺便防 map 只增不减）
            Some(_) => { self.set.remove(&key); false }
            None => false,
        }
    }
    /// 对话结束 / 本机重启时清掉该会话的全部授权。
    pub fn end_session(&mut self, session: &str) {
        self.set.retain(|(s, _), _| s != session);
    }
}

/// 核心决策。`grants` 取 `&mut`：会话授权命中要判 TTL，过期项惰性清除（见 SessionGrants::has）。
pub fn decide(facts: &UploadFacts, pref: Pref, session: &str, grants: &mut SessionGrants) -> Verdict {
    // 1. 目录外永不放行（任何档位）
    let Some(root_id) = facts.root_id.as_deref() else {
        return Verdict::Deny(DenyReason::OutOfFence);
    };
    // 不是普通文件（目录 / 设备 / 不存在）
    if !facts.is_file {
        return Verdict::Deny(DenyReason::NotAFile);
    }
    // 2. 执行体必须被授权该目录
    if !facts.actor_granted {
        return Verdict::Deny(DenyReason::ActorNotGranted);
    }
    // 3. 超限永不放行（任何档位，含永久信任）
    let limit = effective_limit();
    if facts.size > limit {
        return Verdict::Deny(DenyReason::TooBig { size: facts.size, limit });
    }
    // 4. 目录级永久信任
    if pref == Pref::Always {
        return Verdict::Allow;
    }
    // 5. 会话内信任
    if grants.has(session, root_id) {
        return Verdict::Allow;
    }
    // 6. 默认每次问
    Verdict::Ask
}

/// 用户在弹窗里的选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserChoice {
    /// 只传这一个文件
    Once,
    /// 这个对话里该目录的文件都直接传
    Session,
    Reject,
}

/// 处理用户选择：返回是否放行，并在选「本会话」时登记会话内授权。
/// **没有「永久」这个选项**——永久只能去本机设置里开（弹窗里只给一句引导文案 native.up.alwaysHint）。
pub fn apply_choice(choice: UserChoice, session: &str, root_id: &str, grants: &mut SessionGrants) -> bool {
    match choice {
        UserChoice::Once => true,
        UserChoice::Session => {
            grants.grant(session, root_id);
            true
        }
        UserChoice::Reject => false,
    }
}

/// 把 `rel` 解析到真实路径并判断是否仍在 `root` 内（解析符号链接后再比较前缀）。
/// 比较前必须 canonicalize——`root/../x`、符号链接都会让字符串前缀判断失效（同 P9）。
pub fn within_root(real_path: &Path, root: &Path) -> bool {
    match (real_path.canonicalize(), root.canonicalize()) {
        (Ok(p), Ok(r)) => p.starts_with(&r),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(size: u64) -> UploadFacts {
        UploadFacts { real_path: PathBuf::from("/r/a.xlsx"), size, is_file: true, root_id: Some("r1".into()), actor_granted: true }
    }
    const MB: u64 = 1024 * 1024;

    // ── 不可绕过的红线：任何档位都一样 ─────────────────────────────
    #[test]
    fn 目录外永不放行_含永久信任与会话信任() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        let mut f = facts(MB);
        f.root_id = None;
        for pref in [Pref::Ask, Pref::Always] {
            assert_eq!(decide(&f, pref, "s1", &mut g), Verdict::Deny(DenyReason::OutOfFence), "pref={pref:?}");
        }
    }

    #[test]
    fn 超限永不放行_含永久信任与会话信任() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        let big = facts(effective_limit() + 1);
        for pref in [Pref::Ask, Pref::Always] {
            assert!(matches!(decide(&big, pref, "s1", &mut g), Verdict::Deny(DenyReason::TooBig { .. })), "pref={pref:?}");
        }
        // 恰好等于上限可以
        assert_ne!(decide(&facts(effective_limit()), Pref::Always, "s1", &mut g), Verdict::Deny(DenyReason::TooBig { size: 0, limit: 0 }));
        assert_eq!(decide(&facts(effective_limit()), Pref::Always, "s1", &mut g), Verdict::Allow);
    }

    #[test]
    fn 执行体未授权该目录_永久信任也拒绝() {
        let mut f = facts(MB);
        f.actor_granted = false;
        assert_eq!(decide(&f, Pref::Always, "s1", &mut SessionGrants::new()), Verdict::Deny(DenyReason::ActorNotGranted));
    }

    #[test]
    fn 非普通文件拒绝() {
        let mut f = facts(0);
        f.is_file = false;
        assert_eq!(decide(&f, Pref::Always, "s", &mut SessionGrants::new()), Verdict::Deny(DenyReason::NotAFile));
    }

    // ── 三档语义 ───────────────────────────────────────────────────
    #[test]
    fn 默认每次问() {
        assert_eq!(decide(&facts(MB), Pref::Ask, "s1", &mut SessionGrants::new()), Verdict::Ask);
    }

    #[test]
    fn 目录级永久信任直接放行() {
        assert_eq!(decide(&facts(MB), Pref::Always, "s1", &mut SessionGrants::new()), Verdict::Allow);
    }

    #[test]
    fn 会话内信任_只对同会话同目录生效() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        assert_eq!(decide(&facts(MB), Pref::Ask, "s1", &mut g), Verdict::Allow);
        assert_eq!(decide(&facts(MB), Pref::Ask, "s2", &mut g), Verdict::Ask, "别的会话不继承");
        let mut other = facts(MB);
        other.root_id = Some("r2".into());
        assert_eq!(decide(&other, Pref::Ask, "s1", &mut g), Verdict::Ask, "别的目录不继承");
    }

    #[test]
    fn 会话结束后授权失效() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        g.end_session("s1");
        assert_eq!(decide(&facts(MB), Pref::Ask, "s1", &mut g), Verdict::Ask);
    }

    #[test]
    fn 会话授权超过_ttl_后失效_且被惰性清除() {
        // 审核 P2「会话授权无 TTL」：end_session 无调用方，授权曾永不过期。
        let mut g = SessionGrants::new();
        // 直接塞一个「3 小时前」的授权时刻（绕过 grant 的 Instant::now），模拟过期
        g.set.insert(("s1".to_string(), "r1".to_string()), Instant::now() - Duration::from_secs(3 * 3600));
        assert!(!g.has("s1", "r1"), "超过 TTL 的授权不得命中");
        assert!(g.set.is_empty(), "过期项应被惰性清除，防 map 只增不减");
        // 未过期的仍命中
        g.grant("s2", "r1");
        assert!(g.has("s2", "r1"));
    }

    #[test]
    fn 空会话标识不能被授权或命中() {
        let mut g = SessionGrants::new();
        g.grant("", "r1");
        assert_eq!(decide(&facts(MB), Pref::Ask, "", &mut g), Verdict::Ask, "空会话 ID 不得成为万能通行证");
    }

    // ── 用户选择 ───────────────────────────────────────────────────
    #[test]
    fn 用户选择_仅此一次与本会话与拒绝() {
        let mut g = SessionGrants::new();
        assert!(apply_choice(UserChoice::Once, "s1", "r1", &mut g));
        assert!(!g.has("s1", "r1"), "仅此一次不留授权");
        assert!(apply_choice(UserChoice::Session, "s1", "r1", &mut g));
        assert!(g.has("s1", "r1"));
        assert!(!apply_choice(UserChoice::Reject, "s1", "r2", &mut g));
        assert!(!g.has("s1", "r2"), "拒绝不留授权");
    }

    #[test]
    fn 弹窗选项里没有永久() {
        // UserChoice 只有 Once / Session / Reject —— 编译期保证；这里固化「选 Session 不会写永久偏好」
        let mut g = SessionGrants::new();
        apply_choice(UserChoice::Session, "s1", "r1", &mut g);
        assert_eq!(decide(&facts(MB), Pref::parse("ask"), "s2", &mut g), Verdict::Ask, "换会话立刻回到每次问");
    }

    // ── 偏好解析 fail-closed ───────────────────────────────────────
    #[test]
    fn 偏好未知值按每次问() {
        assert_eq!(Pref::parse("always"), Pref::Always);
        for s in ["ask", "", "ALWAYS", "yes", "true", "always ", "永久"] {
            assert_eq!(Pref::parse(s), Pref::Ask, "{s:?} 不能被当成永久放行");
        }
    }

    // ── 传输上限 ───────────────────────────────────────────────────
    #[test]
    fn 实际上限取产品口径与_ws_帧可靠值的较小者() {
        assert_eq!(MAX_UPLOAD_BYTES, 50 * MB);
        assert!(effective_limit() <= MAX_UPLOAD_BYTES);
        // 放行的最大文件 base64 后必须塞得进 64 MiB 帧
        let b64 = effective_limit().div_ceil(3) * 4;
        assert!(b64 < 64 * MB, "base64 后 {b64} 字节会超 WS 单帧 64MiB");
    }

    #[test]
    fn 五十兆的原文件被拒_因为会超帧() {
        // 产品口径 50MB，但走 WS 帧 base64 后约 66.7MB > 64MiB，所以 50MB 整的文件实际不可靠
        let r = decide(&facts(50 * MB), Pref::Always, "s", &mut SessionGrants::new());
        assert!(matches!(r, Verdict::Deny(DenyReason::TooBig { .. })), "{r:?}");
    }

    // ── 真实路径围栏（含符号链接）─────────────────────────────────
    #[test]
    fn within_root_解析符号链接与点点() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("in.txt"), "x").unwrap();
        std::fs::write(outside.path().join("out.txt"), "x").unwrap();
        assert!(within_root(&root.path().join("in.txt"), root.path()));
        assert!(!within_root(&outside.path().join("out.txt"), root.path()));
        // ../ 绕出去
        assert!(!within_root(&root.path().join("../").join(outside.path().file_name().unwrap()).join("out.txt"), root.path()));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path().join("out.txt"), root.path().join("ln.txt")).unwrap();
            assert!(!within_root(&root.path().join("ln.txt"), root.path()), "符号链接逃逸");
        }
        // 不存在的文件：canonicalize 失败 → 拒绝（fail-closed）
        assert!(!within_root(&root.path().join("nope.txt"), root.path()));
    }
}
