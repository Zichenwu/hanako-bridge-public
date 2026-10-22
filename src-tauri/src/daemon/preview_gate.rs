// src-tauri/src/daemon/preview_gate.rs
//! 网页预览闸（票 02，ADR 0009 决策 4/5）—— **纯决策**。
//!
//! 「预览」= 用户在网页上看一眼自己电脑里的文件；字节只过服务端内存，不落云端存储、不进对话。
//! 它与「上传到云端」（`upload_gate`）是**两条独立通道**：独立确认文案、独立永久放行开关、
//! 独立大小上限、独立审计来源。本模块只负责「该不该放行」，不碰 UI、不碰网络、不读字节，
//! 这样安全边界能被穷举测试。
//!
//! ## 规则（从紧到松，先命中先返回）
//! 1. 路径没落在该执行体可见的授权目录内 / 命中敏感黑名单 → `Deny(OutOfFence|Sensitive|ActorNotGranted)`；
//!    这三者**判定全部来自 [`crate::daemon::policy::Policy::authorize`]**（决策 5：围栏只在一处判定），
//!    本模块不自建第二套规则。
//! 2. 不是普通文件（目录 / 设备 / 不存在）→ `Deny(NotAFile)`；
//! 3. 超过预览上限 → `Deny(TooBig)`，在读任何字节之前按文件大小拒；
//! 4. 否则 → `Ask`（每个文件首次预览都要在**被读取的那台电脑上**弹确认）。
//!
//! ## 为什么对外的拒绝码刻意粗粒度
//! 故事 23/24：敏感文件一律拒绝，且「被拒时只看到『这个文件受保护，不能预览』，不暴露具体命中的规则」。
//! `GateError` 的 `Display` 会带上命中的规则（如 `sensitive path rejected: .env`），直接外传等于把
//! 黑名单告诉攻击者。所以 [`DenyReason::outward`] 把目录外 / 未授权 / 敏感 / 非普通文件**全部塌缩**
//! 成同一个 [`PreviewReject::Protected`]，文案逐字节相同。
//!
//! ## 为什么「永久允许」不在本模块
//! 放宽方向的开关只存在于本机设置（同 `upload_gate` 模块注释）。本票只做拒绝路径，
//! 偏好与会话级允许见票 03。

use std::path::PathBuf;

/// 步一（文本类单帧）的预览上限：20 MB。
///
/// 产品口径默认 200MB 且可在 Bridge 设置里调小（50/100/200），但那要等分片传输（票 07）；
/// 步一走单帧，20MB 是本阶段实际生效的硬上限。
pub const MAX_PREVIEW_BYTES: u64 = 20 * 1024 * 1024;

/// 设置窗「高级」里可选的预览上限档位（MB）。**只有这三档**，不提供自由输入
/// （自由输入会让用户把上限设成一个服务端根本兜不住的值，且无从校验）。
pub const PREVIEW_LIMIT_CHOICES_MB: [u64; 3] = [50, 100, 200];

/// 预览上限的缺省档位（MB），对齐书桌分片上传的 200MB。
pub const PREVIEW_LIMIT_DEFAULT_MB: u64 = 200;

/// 校验上限档位：只认 [`PREVIEW_LIMIT_CHOICES_MB`] 里的值。
///
/// 非法值**报错而非静默取最近档**——静默纠正会让「设了 500 结果生效 200」这种
/// 用户以为设成功了其实没有的情况发生。
pub fn validate_limit_mb(mb: u64) -> Result<u64, String> {
    if PREVIEW_LIMIT_CHOICES_MB.contains(&mb) {
        Ok(mb)
    } else {
        Err(format!("预览上限只能是 {:?} MB 之一，收到 {mb}", PREVIEW_LIMIT_CHOICES_MB))
    }
}

/// 实际生效上限（字节）：用户档位与本阶段硬上限**取较小值**。
///
/// 步一走单帧，[`MAX_PREVIEW_BYTES`]（20MB）恒小于任何档位，所以用户调档在步一**不改变行为**
/// ——这是刻意的：设置先落盘，票 07 接上分片后同一份偏好立即生效，不需要用户再设一遍。
pub fn effective_limit(pref_mb: Option<u64>) -> u64 {
    let mb = pref_mb.unwrap_or(PREVIEW_LIMIT_DEFAULT_MB);
    (mb * 1024 * 1024).min(MAX_PREVIEW_BYTES)
}

/// 分片传输（票 07）下的生效上限：就是用户档位（50/100/200MB，缺省 200）。
///
/// **档位值必须落在 [`PREVIEW_LIMIT_CHOICES_MB`] 内才认**——policy.json 被手改成 5000 之类的值，
/// 不能让它变成上限（服务端另有 200MB 绝对上限，但 Bridge 自己也不该信一个不在三档内的数）。
/// 没设过 → 缺省 200MB；**设了但不在三档内 → 回落最窄 50MB**（审核 #13：坏值往收紧方向兜，fail-closed）。
pub fn effective_limit_chunked(pref_mb: Option<u64>) -> u64 {
    let mb = match pref_mb {
        None => PREVIEW_LIMIT_DEFAULT_MB,
        Some(v) if PREVIEW_LIMIT_CHOICES_MB.contains(&v) => v,
        Some(_) => PREVIEW_LIMIT_CHOICES_MB[0],
    };
    mb * 1024 * 1024
}

/// 内部拒绝原因（**只用于本机审计与排障，不外传**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// 路径不在该执行体可见的授权目录内（含 `..`、符号链接逃逸）
    OutOfFence,
    /// 该执行体没被授权任何 / 这个目录
    ActorNotGranted,
    /// 命中敏感黑名单（`.env`、私钥、`.ssh` 等）
    Sensitive,
    /// 不是普通文件（目录 / 设备 / 不存在）
    NotAFile,
    /// 超过预览上限
    TooBig { size: u64, limit: u64 },
    /// 本机策略不可用（policy.json 损坏 → 全部拒绝）
    PolicyUnavailable,
    /// 用户点了拒绝，**或**确认弹窗超时（两者刻意合并，对外不可区分）
    NotAllowed,
}

impl DenyReason {
    /// 本机审计用的机读短码（**不进对外帧**）。
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::OutOfFence => "out_of_fence",
            DenyReason::ActorNotGranted => "actor_not_granted",
            DenyReason::Sensitive => "sensitive",
            DenyReason::NotAFile => "not_a_file",
            DenyReason::TooBig { .. } => "too_big",
            DenyReason::PolicyUnavailable => "policy_unavailable",
            DenyReason::NotAllowed => "not_allowed",
        }
    }

    /// 塌缩成对外可见的拒绝。
    ///
    /// 除「超限」与「未获允许」外全部变成 [`PreviewReject::Protected`]——
    /// 超限之所以可以单列，是因为文件大小网页在本地树里**本来就看得到**，不构成新泄露，
    /// 而且故事 32 要求给出「可以让助手读取」的替代办法；「未获允许」单列是因为用户需要知道
    /// 「电脑上没批准」这件事，但它内部已经把「拒绝」与「超时」合并掉了（故事 20）。
    pub fn outward(&self) -> PreviewReject {
        match self {
            DenyReason::TooBig { size, limit } => PreviewReject::TooBig { size: *size, limit: *limit },
            DenyReason::NotAllowed => PreviewReject::NotAllowed,
            _ => PreviewReject::Protected,
        }
    }
}

/// 对外（服务端 → 网页）可见的拒绝。网页按它归成「用户下一步能做什么」的几类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewReject {
    /// 受保护：目录外 / 未授权 / 敏感 / 非普通文件，**不区分**
    Protected,
    /// 超过本机预览上限
    TooBig { size: u64, limit: u64 },
    /// 未获允许：用户点了拒绝 **或** 弹窗超时，**两者对外不可区分**（故事 20）
    NotAllowed,
    /// 本机已暂停（故事 41）
    Paused(String),
    /// 可重试：读取失败（含 Windows 被占用）/ 文件在预览时被修改（故事 33）
    Retry,
    /// 这种格式暂不支持预览（音视频 / 压缩包 / 旧版 Office 等）。**在弹窗之前**判定，
    /// 不让用户白点一次允许；也不说成「受保护」（那会被误解成权限问题）。
    /// 扩展名网页本来就看得见，单列不构成新泄露。
    UnsupportedType,
}

impl PreviewReject {
    /// 机读码（服务端与网页按它分类，与 `LOCAL_*` 既有口径一致）。
    pub fn code(&self) -> &'static str {
        match self {
            PreviewReject::Protected => "LOCAL_PREVIEW_PROTECTED",
            PreviewReject::TooBig { .. } => "LOCAL_PREVIEW_TOO_BIG",
            PreviewReject::NotAllowed => "LOCAL_PREVIEW_NOT_ALLOWED",
            PreviewReject::Paused(_) => crate::daemon::pause::ERR_PAUSED,
            PreviewReject::Retry => "LOCAL_PREVIEW_RETRY",
            PreviewReject::UnsupportedType => "LOCAL_PREVIEW_UNSUPPORTED_TYPE",
        }
    }

    /// 对外文案。
    ///
    /// ⚠️ `Protected` 的文案对**所有**内部原因逐字节相同（故事 24）；
    /// `NotAllowed` 对「拒绝」与「超时」逐字节相同（故事 20）。
    pub fn message(&self) -> String {
        match self {
            PreviewReject::Protected => "这个文件受保护，不能预览".into(),
            PreviewReject::TooBig { limit, .. } => {
                format!("不能预览这个文件（超过 {} MB），可以让助手读取", limit / (1024 * 1024))
            }
            PreviewReject::NotAllowed => "未获允许".into(),
            PreviewReject::Paused(msg) => msg.clone(),
            PreviewReject::Retry => "文件在预览时被修改或读取失败，请重试".into(),
            PreviewReject::UnsupportedType => "暂不支持预览这种格式，可以让助手读取".into(),
        }
    }
}

/// 闸决策结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 直接放行（本机设置里的永久允许 / 本次会话该目录已允许）
    Allow,
    /// 需要在被读取的那台电脑上弹确认
    Ask,
    /// 拒绝（不弹窗）
    Deny(DenyReason),
}

/// 本机策略里该目录的**预览**偏好。
///
/// ⚠️ 与上传偏好 [`crate::daemon::upload_gate::Pref`] 是**两个独立字段**（ADR 决策 1）：
/// 用户为方便预览而开「永久允许在网页预览」时，不得同时放开「允许助手把原文件传到云端」。
/// 两者共用一个字段的变异测试见本文件末尾。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pref {
    /// 每次问（默认）
    Ask,
    /// 该目录永久允许在网页预览。**只能在本机设置里开**，网页只能收回。
    Always,
}

impl Pref {
    /// 未知值一律按「每次问」：放宽方向的字段，解析不出来不能当成放行（fail-closed）。
    pub fn parse(s: &str) -> Pref {
        if s == "always" {
            Pref::Always
        } else {
            Pref::Ask
        }
    }

    pub fn as_wire(self) -> &'static str {
        match self {
            Pref::Always => "always",
            Pref::Ask => "ask",
        }
    }
}

/// 「本目录本次会话都允许预览」。
///
/// **内存态，不落盘，Bridge 重启即清**（故事 16）——落盘会让一次点击变成永久后门，
/// 而「永久」必须走本机设置这条唯一入口。另设绝对 TTL 兜住「一直不关 Bridge」的情形
/// （同 `upload_gate::SessionGrants` 的审查结论）。
#[derive(Debug, Default)]
pub struct SessionGrants {
    /// (sessionId, rootId) → 授权时刻（`Instant` = 单调时钟，不受系统回拨影响）
    set: std::collections::HashMap<(String, String), std::time::Instant>,
}

/// 会话内预览授权的绝对寿命：2 小时（与上传同口径）。
pub const SESSION_GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 3600);

impl SessionGrants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, session: &str, root_id: &str) {
        if !session.is_empty() && !root_id.is_empty() {
            self.set.insert((session.to_string(), root_id.to_string()), std::time::Instant::now());
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
            Some(_) => {
                self.set.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn end_session(&mut self, session: &str) {
        self.set.retain(|(s, _), _| s != session);
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// 用户在预览确认弹窗里的选择。
///
/// **没有「永久」这个选项**——永久只能去本机设置里开（弹窗里只给一句引导文案），
/// 同 `upload_gate::UserChoice` 的理由：网页/云端被攻破后能伪造「用户点了允许」，
/// 永久放行会把一次点击变成永久后门。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserChoice {
    /// 仅这次
    Once,
    /// 本目录本次会话都允许
    Session,
    /// 拒绝
    Reject,
}

/// 处理用户选择：返回是否放行，并在选「本会话」时登记会话内授权。
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

/// 一次预览请求的事实（由调用方从 `Policy::authorize` 的结果 + 文件元信息解析好，纯函数不碰磁盘）。
#[derive(Debug, Clone)]
pub struct PreviewFacts {
    /// 已 canonicalize（含符号链接解析）的真实路径
    pub real_path: PathBuf,
    pub size: u64,
    pub is_file: bool,
    /// 命中的授权目录 rootId
    pub root_id: String,
}

/// 核心决策。围栏/授权/敏感三项已由 `Policy::authorize` 判完（调用方负责）。
///
/// 规则顺序（从紧到松，先命中先返回）：
/// 1. 非普通文件 → 拒；
/// 2. 超限 → 拒（**任何档位都拒，含永久允许**）；
/// 3. 目录级永久允许 → 放行；
/// 4. 本次会话该目录已允许 → 放行；
/// 5. 否则每次问。
pub fn decide(facts: &PreviewFacts, pref: Pref, session: &str, grants: &mut SessionGrants, limit: u64) -> Verdict {
    if !facts.is_file {
        return Verdict::Deny(DenyReason::NotAFile);
    }
    // 超限永不放行（任何档位）——放在永久/会话放行**之前**
    if facts.size > limit {
        return Verdict::Deny(DenyReason::TooBig { size: facts.size, limit });
    }
    if pref == Pref::Always {
        return Verdict::Allow;
    }
    if grants.has(session, &facts.root_id) {
        return Verdict::Allow;
    }
    Verdict::Ask
}

/// 把 `Policy::authorize` 的拒绝映射成本模块的内部原因。
///
/// **这是围栏判定的唯一入口**：预览不自建路径/敏感规则，全部复用已被穷举测试过的 `authorize`
/// （决策 5）。新增分支时注意不要把 `GateError` 的文案带出去，它含命中的规则名。
pub fn deny_of_gate_error(e: &crate::daemon::policy::GateError) -> DenyReason {
    use crate::daemon::policy::GateError;
    match e {
        GateError::NoRoots | GateError::ActorNotGranted => DenyReason::ActorNotGranted,
        GateError::RootRevoked => DenyReason::ActorNotGranted,
        // authorize 对敏感命中走 OutOfFence(「sensitive path rejected: …」)，这里只分「敏感」与「越界」
        // 两种内部原因用于审计；对外二者都是 Protected，所以分错也不会泄露，但审计要分得清。
        GateError::OutOfFence(detail) => {
            if detail.contains("sensitive") {
                DenyReason::Sensitive
            } else {
                DenyReason::OutOfFence
            }
        }
        GateError::ReadOnly => DenyReason::OutOfFence,
        GateError::PolicyUnavailable(_) => DenyReason::PolicyUnavailable,
        GateError::Path(_) => DenyReason::NotAFile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::policy::GateError;

    const MB: u64 = 1024 * 1024;

    fn facts(size: u64) -> PreviewFacts {
        PreviewFacts { real_path: PathBuf::from("/r/a.txt"), size, is_file: true, root_id: "r1".into() }
    }

    /// 票 02 的默认档：每次问、空会话。
    fn ask_only(f: &PreviewFacts, limit: u64) -> Verdict {
        decide(f, Pref::Ask, "", &mut SessionGrants::new(), limit)
    }

    // ── 不可绕过的红线 ─────────────────────────────────────────────

    #[test]
    fn 超限在读字节前就被拒() {
        let r = ask_only(&facts(MAX_PREVIEW_BYTES + 1), MAX_PREVIEW_BYTES);
        assert_eq!(r, Verdict::Deny(DenyReason::TooBig { size: MAX_PREVIEW_BYTES + 1, limit: MAX_PREVIEW_BYTES }));
        // 恰好等于上限放行到「要问」
        assert_eq!(ask_only(&facts(MAX_PREVIEW_BYTES), MAX_PREVIEW_BYTES), Verdict::Ask);
    }

    /// 变异锁：把超限判定挪到永久/会话放行之后 → 本用例红。
    #[test]
    fn 超限永不放行_含永久允许与会话允许() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        let big = facts(MAX_PREVIEW_BYTES + 1);
        for pref in [Pref::Ask, Pref::Always] {
            assert!(
                matches!(decide(&big, pref, "s1", &mut g, MAX_PREVIEW_BYTES), Verdict::Deny(DenyReason::TooBig { .. })),
                "pref={pref:?} 超限必须拒，哪怕开了永久允许"
            );
        }
    }

    #[test]
    fn 非普通文件拒绝_含永久允许() {
        let mut f = facts(0);
        f.is_file = false;
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        for pref in [Pref::Ask, Pref::Always] {
            assert_eq!(decide(&f, pref, "s1", &mut g, MAX_PREVIEW_BYTES), Verdict::Deny(DenyReason::NotAFile));
        }
    }

    #[test]
    fn 普通文件且未超限_落到要问() {
        assert_eq!(ask_only(&facts(MB), MAX_PREVIEW_BYTES), Verdict::Ask);
    }

    #[test]
    fn 步一上限是二十兆() {
        assert_eq!(MAX_PREVIEW_BYTES, 20 * MB);
    }

    // ── 上限档位（票 05）───────────────────────────────────────────

    #[test]
    fn 档位只有三个_默认二百兆() {
        assert_eq!(PREVIEW_LIMIT_CHOICES_MB, [50, 100, 200]);
        assert_eq!(PREVIEW_LIMIT_DEFAULT_MB, 200);
        assert!(PREVIEW_LIMIT_CHOICES_MB.contains(&PREVIEW_LIMIT_DEFAULT_MB), "默认档必须在档位里");
    }

    #[test]
    fn 校验档位_非法值报错而非取最近档() {
        for mb in PREVIEW_LIMIT_CHOICES_MB {
            assert_eq!(validate_limit_mb(mb).unwrap(), mb);
        }
        for bad in [0u64, 1, 49, 51, 99, 199, 201, 1024] {
            assert!(validate_limit_mb(bad).is_err(), "{bad} 必须报错");
        }
    }

    /// 变异：`effective_limit_chunked` 不校验三档（直接信 policy 里的数）/ 坏值回落 200 → 本用例红。
    #[test]
    fn 分片档位_只认三档_坏值回落最窄50() {
        for mb in [50u64, 100, 200] {
            assert_eq!(effective_limit_chunked(Some(mb)), mb * MB);
        }
        assert_eq!(effective_limit_chunked(None), 200 * MB, "没设过 = 缺省 200");
        for bad in [0u64, 1, 49, 51, 150, 201, 500, 5000, u64::MAX / (1024 * 1024)] {
            // 审核 #13：坏值回落最窄档（fail-closed），不是最宽的缺省 200
            assert_eq!(effective_limit_chunked(Some(bad)), 50 * MB, "policy 被手改成 {bad} 应回落 50");
        }
    }

    #[test]
    fn 步一单帧口径不受分片档位影响() {
        // 单帧仍被 20MB 夹住
        for mb in [50u64, 100, 200] {
            assert_eq!(effective_limit(Some(mb)), MAX_PREVIEW_BYTES);
        }
    }

    /// 变异锁：把 `effective_limit` 里的 `.min(MAX_PREVIEW_BYTES)` 去掉 → 本用例红
    /// （用户设 200MB 会让步一的单帧上限被撑到 200MB）。
    #[test]
    fn 生效上限_被本阶段硬上限夹住() {
        for mb in PREVIEW_LIMIT_CHOICES_MB {
            assert_eq!(effective_limit(Some(mb)), MAX_PREVIEW_BYTES, "步一一律 20MB 封顶");
        }
        assert_eq!(effective_limit(None), MAX_PREVIEW_BYTES, "没设过也走默认档再夹");
        // 档位最小值 50MB 仍大于硬上限，所以三档在步一不改变行为——这是刻意的（票 07 接分片后生效）
        assert!(PREVIEW_LIMIT_CHOICES_MB.iter().all(|mb| mb * MB > MAX_PREVIEW_BYTES));
    }

    // ── 三档语义（票 03）─────────────────────────────────────────────

    #[test]
    fn 默认每次问() {
        assert_eq!(decide(&facts(MB), Pref::Ask, "s1", &mut SessionGrants::new(), MAX_PREVIEW_BYTES), Verdict::Ask);
    }

    #[test]
    fn 目录级永久允许直接放行() {
        assert_eq!(decide(&facts(MB), Pref::Always, "s1", &mut SessionGrants::new(), MAX_PREVIEW_BYTES), Verdict::Allow);
    }

    #[test]
    fn 会话内允许_只对同会话同目录生效() {
        let mut g = SessionGrants::new();
        g.grant("s1", "r1");
        assert_eq!(decide(&facts(MB), Pref::Ask, "s1", &mut g, MAX_PREVIEW_BYTES), Verdict::Allow);
        assert_eq!(decide(&facts(MB), Pref::Ask, "s2", &mut g, MAX_PREVIEW_BYTES), Verdict::Ask, "别的会话不继承");
        let mut other = facts(MB);
        other.root_id = "r2".into();
        assert_eq!(decide(&other, Pref::Ask, "s1", &mut g, MAX_PREVIEW_BYTES), Verdict::Ask, "别的目录不继承");
    }

    #[test]
    fn 空会话标识不能被授权或命中() {
        let mut g = SessionGrants::new();
        g.grant("", "r1");
        assert_eq!(decide(&facts(MB), Pref::Ask, "", &mut g, MAX_PREVIEW_BYTES), Verdict::Ask, "空会话 ID 不得成为万能通行证");
    }

    #[test]
    fn 会话授权超过_ttl_后失效_且被惰性清除() {
        let mut g = SessionGrants::new();
        g.set.insert(
            ("s1".to_string(), "r1".to_string()),
            std::time::Instant::now() - std::time::Duration::from_secs(3 * 3600),
        );
        assert!(!g.has("s1", "r1"), "超过 TTL 的授权不得命中");
        assert!(g.is_empty(), "过期项应被惰性清除");
        g.grant("s2", "r1");
        assert!(g.has("s2", "r1"));
    }

    #[test]
    fn 用户选择_仅这次与本会话与拒绝() {
        let mut g = SessionGrants::new();
        assert!(apply_choice(UserChoice::Once, "s1", "r1", &mut g));
        assert!(!g.has("s1", "r1"), "仅这次不留授权");
        assert!(apply_choice(UserChoice::Session, "s1", "r1", &mut g));
        assert!(g.has("s1", "r1"));
        assert!(!apply_choice(UserChoice::Reject, "s1", "r2", &mut g));
        assert!(!g.has("s1", "r2"), "拒绝不留授权");
    }

    #[test]
    fn 弹窗选项里没有永久() {
        // UserChoice 只有 Once / Session / Reject —— 编译期保证；这里固化「选 Session 不写永久偏好」
        let mut g = SessionGrants::new();
        apply_choice(UserChoice::Session, "s1", "r1", &mut g);
        assert_eq!(
            decide(&facts(MB), Pref::parse("ask"), "s2", &mut g, MAX_PREVIEW_BYTES),
            Verdict::Ask,
            "换会话立刻回到每次问"
        );
    }

    #[test]
    fn 偏好未知值按每次问() {
        assert_eq!(Pref::parse("always"), Pref::Always);
        for s in ["ask", "", "ALWAYS", "yes", "true", "always ", "永久", "preview"] {
            assert_eq!(Pref::parse(s), Pref::Ask, "{s:?} 不能被当成永久放行");
        }
    }

    /// 变异锁（票 03）：让预览偏好与上传偏好共用同一字段/同一类型 → 本用例红。
    /// 两者是独立的枚举，且「开了预览永久允许」不得让上传闸放行。
    #[test]
    fn 预览偏好与上传偏好互不影响() {
        use crate::daemon::upload_gate;
        // 场景：某目录开了「永久允许在网页预览」，但上传偏好仍是默认「每次问」
        let preview_pref = Pref::Always;
        let upload_pref = upload_gate::Pref::Ask; // 独立字段，没被预览的 always 带动

        assert_eq!(
            decide(&facts(MB), preview_pref, "s1", &mut SessionGrants::new(), MAX_PREVIEW_BYTES),
            Verdict::Allow,
            "预览应放行"
        );
        let up = upload_gate::UploadFacts {
            real_path: PathBuf::from("/r/a.txt"),
            size: MB,
            is_file: true,
            root_id: Some("r1".into()),
            actor_granted: true,
        };
        assert_eq!(
            upload_gate::decide(&up, upload_pref, "s1", &mut upload_gate::SessionGrants::new()),
            upload_gate::Verdict::Ask,
            "开了预览永久允许，不得同时放开上传（ADR 决策 1）"
        );
        // 两套会话授权也必须是各自独立的表
        let mut pg = SessionGrants::new();
        pg.grant("s1", "r1");
        let mut ug = upload_gate::SessionGrants::new();
        assert!(pg.has("s1", "r1"));
        assert!(!ug.has("s1", "r1"), "预览的会话授权不得被上传闸看到");
    }

    // ── 对外拒绝码塌缩（故事 24：不暴露命中的规则）─────────────────

    /// 变异锁：把 `outward()` 改成区分敏感/越界/未授权（例如各给一个码或各给一句文案）→ 本用例红。
    #[test]
    fn 受保护类的对外拒绝逐字节相同_不暴露命中的规则() {
        let reasons = [
            DenyReason::OutOfFence,
            DenyReason::ActorNotGranted,
            DenyReason::Sensitive,
            DenyReason::NotAFile,
            DenyReason::PolicyUnavailable,
        ];
        let outs: Vec<PreviewReject> = reasons.iter().map(|r| r.outward()).collect();
        for (r, o) in reasons.iter().zip(&outs) {
            assert_eq!(*o, PreviewReject::Protected, "{r:?} 不应单独可辨");
        }
        // 码与文案都必须一致
        let codes: std::collections::HashSet<&str> = outs.iter().map(|o| o.code()).collect();
        let msgs: std::collections::HashSet<String> = outs.iter().map(|o| o.message()).collect();
        assert_eq!(codes.len(), 1, "对外码出现了可辨差异: {codes:?}");
        assert_eq!(msgs.len(), 1, "对外文案出现了可辨差异: {msgs:?}");
        // 文案里不得出现任何内部原因短码（.env / sensitive / out_of_fence 之类）
        let msg = outs[0].message();
        for r in &reasons {
            assert!(!msg.contains(r.code()), "对外文案泄漏了内部原因 {}: {msg}", r.code());
        }
        assert!(!msg.contains("sensitive") && !msg.contains(".env"), "对外文案泄漏了黑名单: {msg}");
    }

    #[test]
    fn 超限单列_因为大小本来就可见且要给替代办法() {
        let o = DenyReason::TooBig { size: 99 * MB, limit: 20 * MB }.outward();
        assert_eq!(o, PreviewReject::TooBig { size: 99 * MB, limit: 20 * MB });
        assert_ne!(o.code(), PreviewReject::Protected.code());
        assert!(o.message().contains("20 MB"), "{}", o.message());
        assert!(o.message().contains("助手"), "要给「可以让助手读取」的替代办法: {}", o.message());
    }

    /// 变异锁：把「拒绝」与「超时」改成不同文案/不同码 → 本用例红（故事 20）。
    /// 两者在本机都归到同一个 `NotAllowed`，这里固化「只有一种表示」。
    #[test]
    fn 未获允许只有一种对外表示() {
        let a = PreviewReject::NotAllowed;
        let b = PreviewReject::NotAllowed;
        assert_eq!(a.code(), b.code());
        assert_eq!(a.message(), b.message());
        // 不得暴露「是拒绝还是超时」
        let m = a.message();
        for leak in ["超时", "timeout", "拒绝", "reject", "不在电脑前"] {
            assert!(!m.contains(leak), "「未获允许」文案泄漏了区分信息 {leak}: {m}");
        }
    }

    #[test]
    fn 暂停沿用服务端既有机读码() {
        let r = PreviewReject::Paused("LOCAL_NODE_PAUSED: 本机已暂停，约 3 分钟后自动恢复".into());
        assert_eq!(r.code(), crate::daemon::pause::ERR_PAUSED);
        assert!(r.message().contains("已暂停"));
    }

    #[test]
    fn 五类拒绝的码互不相同() {
        let all = [
            PreviewReject::Protected,
            PreviewReject::TooBig { size: 1, limit: 1 },
            PreviewReject::NotAllowed,
            PreviewReject::Paused("x".into()),
            PreviewReject::Retry,
        ];
        let codes: std::collections::HashSet<&str> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len(), "对外分类撞码，网页无法分流: {codes:?}");
    }

    // ── 围栏判定只在 authorize 一处 ────────────────────────────────

    #[test]
    fn 围栏拒绝全部来自_authorize_的映射() {
        assert_eq!(deny_of_gate_error(&GateError::NoRoots), DenyReason::ActorNotGranted);
        assert_eq!(deny_of_gate_error(&GateError::ActorNotGranted), DenyReason::ActorNotGranted);
        assert_eq!(deny_of_gate_error(&GateError::RootRevoked), DenyReason::ActorNotGranted);
        assert_eq!(
            deny_of_gate_error(&GateError::OutOfFence("path escapes the authorized folder".into())),
            DenyReason::OutOfFence
        );
        assert_eq!(
            deny_of_gate_error(&GateError::OutOfFence("sensitive path rejected: .env".into())),
            DenyReason::Sensitive
        );
        assert_eq!(deny_of_gate_error(&GateError::PolicyUnavailable("坏了".into())), DenyReason::PolicyUnavailable);
        // 任何 authorize 拒绝对外都只能是 Protected
        for e in [
            GateError::NoRoots,
            GateError::ActorNotGranted,
            GateError::RootRevoked,
            GateError::OutOfFence("sensitive path rejected: id_rsa".into()),
            GateError::ReadOnly,
            GateError::PolicyUnavailable("x".into()),
            GateError::Path("io".into()),
        ] {
            assert_eq!(deny_of_gate_error(&e).outward(), PreviewReject::Protected, "{e:?}");
        }
    }
}
