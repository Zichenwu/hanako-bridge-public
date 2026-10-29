// src-tauri/src/daemon/tools/command.rs
//! 本机命令 `local_run_command`（openhanako ADR 0013 / spec 05，票 02）。
//!
//! # 闸序（任一不过即拒，审计记机读码）
//! 总开关 → 暂停（主循环已拦）→ lease（run_script 类）→ cwd 在会话绑定授权目录内（只读也可）
//! → 拒绝名单（票 03）→ 本会话免问（票 04）/ 本机原生确认（45s）→ 执行
//!
//! # 杀树
//! 命令在**新进程组**里跑（Unix `process_group(0)`），执行器持有 [`GroupKill`] 守卫：
//! 超时显式杀组；任务被取消时主循环丢弃 future，守卫 `Drop` 同样杀组——
//! 不依赖 tokio `kill_on_drop`（它只杀直接子进程，`sh -c` 起的孙进程会漏）。
//!
//! # 输出
//! 两流合计（含元信息）≤ [`MAX_RESULT_BYTES`]：单条工具结果在服务端有 32KB 硬上限，超了整条被拦。

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::AsyncReadExt;

use super::ToolResult;
use crate::daemon::audit::{AuditEntry, AuditLogger};
use crate::daemon::command_approval::{CommandApprover, CommandDecision, CommandRequest};
use crate::daemon::lease::{validate_scope, Lease, LeaseValidator};
use crate::daemon::policy::{Policy, TaskScope};

pub const TOOL_NAME: &str = "local_run_command";
/// 服务端签的命令类别（openhanako local-dispatch WRITE_CLASSES 里的 `run_script`）。
pub const LEASE_CLASS: &str = "run_script";
/// 本机命令能力版本（注册帧顶层 `shellCapability.version`）。
pub const SHELL_CAPABILITY_VERSION: u32 = 1;
/// 确认等待上限：与写文件一致，超时 = 拒绝。
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(45);

/// 执行器侧确认等待的**兜底总上限**：确认计时本身由确认器负责（桥从展示起算 45s），
/// 这里只防确认器永不返回；取「展示 45s × (1 + 排队上限)」。
/// 测试可经 `HANAKO_COMMAND_CONFIRM_TIMEOUT_MS` 缩短；只允许**缩短**，放不宽。
fn confirm_timeout() -> Duration {
    std::env::var("HANAKO_COMMAND_CONFIRM_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|d| *d < CONFIRM_TIMEOUT)
        .unwrap_or(CONFIRM_TIMEOUT * (1 + crate::daemon::command_approval::MAX_QUEUED as u32))
}
pub const DEFAULT_TIMEOUT_SEC: u64 = 120;
pub const MAX_TIMEOUT_SEC: u64 = 600;
/// 回传结果的总字节上限（两流 + 元信息 + 截断标记）。
pub const MAX_RESULT_BYTES: usize = 28 * 1024;
/// 每流默认头 / 尾各保留的字节（一流短时余量给另一流）。
const HEAD_TAIL: usize = 7 * 1024;

/// 机读拒绝码（只进审计与本机日志；对外文案统一，见 [`OUTWARD_DENIED`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    Disabled,
    NoLease,
    Lease,
    BadParams,
    Gate,
    DenyList,
    Rejected,
    Timeout,
}

impl Denied {
    pub fn code(self) -> &'static str {
        match self {
            Denied::Disabled => "disabled",
            Denied::NoLease => "no_lease",
            Denied::Lease => "lease",
            Denied::BadParams => "bad_params",
            Denied::Gate => "gate",
            Denied::DenyList => "denylist",
            Denied::Rejected => "rejected",
            Denied::Timeout => "timeout",
        }
    }
}

/// 回给服务端 / 模型的拒绝文案：所有拒绝分支**逐字相同**（ADR 0013：拒绝与超时对外不可区分，
/// 名单命中不回规则名）。机读前缀供服务端识别为「未批准」而非执行失败。
pub const OUTWARD_DENIED: &str = "LOCAL_COMMAND_NOT_APPROVED: 用户未批准这条命令";

/// 总开关现值（读磁盘；读失败 / 损坏一律按关，fail-closed）。
pub fn command_switch_on() -> bool {
    crate::daemon::policy::PolicyFile::load().map(|f| f.allow_commands).unwrap_or(false)
}

/// 任务局部上下文：命令确认器 + 总开关现值（主循环每个任务现读磁盘后注入）。
#[derive(Clone)]
pub struct CommandCtx {
    pub approver: Arc<dyn CommandApprover>,
    pub switch_on: bool,
    pub passes: Arc<crate::daemon::command_approval::SessionPasses>,
}

tokio::task_local! {
    pub static COMMAND_CTX: CommandCtx;
}

/// 本机平台与 shell（注册帧上报，服务端据此生成工具说明）。
pub fn platform_and_shell() -> (&'static str, String) {
    if cfg!(windows) {
        ("windows", "powershell".into())
    } else {
        let platform = if cfg!(target_os = "macos") { "macos" } else { "linux" };
        let shell = login_shell();
        let name = std::path::Path::new(&shell)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "sh".into());
        (platform, name)
    }
}

/// 用户登录 shell：`$SHELL`，缺失回落 mac `/bin/zsh`、其它 `/bin/bash`。
fn login_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.trim().is_empty() && std::path::Path::new(s).is_absolute())
        .unwrap_or_else(|| if cfg!(target_os = "macos") { "/bin/zsh".into() } else { "/bin/bash".into() })
}

/// 解析后的命令参数。
#[derive(Debug, Clone)]
struct Args {
    command: String,
    cwd_rel: String,
    timeout: Duration,
    reason: Option<String>,
    agent_id: String,
    session_id: String,
    task_id: String,
    origin: String,
}

fn parse_args(params: &Value) -> Result<Args, String> {
    let s = |k: &str| params.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let command = s("command").filter(|c| !c.trim().is_empty()).ok_or("command required")?;
    let cwd_rel = s("cwd").unwrap_or_else(|| ".".into());
    let secs = params
        .get("timeout_sec")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TIMEOUT_SEC)
        .clamp(1, MAX_TIMEOUT_SEC);
    Ok(Args {
        command,
        cwd_rel: if cwd_rel.trim().is_empty() { ".".into() } else { cwd_rel },
        timeout: Duration::from_secs(secs),
        reason: s("reason").filter(|r| !r.trim().is_empty()),
        agent_id: s("_agent_id").unwrap_or_default(),
        session_id: s("_session_id").unwrap_or_default(),
        task_id: s("_task_id").unwrap_or_else(|| "unknown".into()),
        origin: s("_origin").unwrap_or_else(|| "agent".into()),
    })
}

/// 一次执行的产物。
#[derive(Debug)]
pub struct RunOutput {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: Duration,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// `local_run_command` 入口。`approver` 为命令专用确认器（不经网页确认装饰器）。
pub async fn local_run_command(
    params: &Value,
    policy: &Policy,
    lease: Option<Lease>,
    node_id: &str,
    approver: &Arc<dyn CommandApprover>,
    switch_on: bool,
    passes: &Arc<crate::daemon::command_approval::SessionPasses>,
    audit: &Arc<AuditLogger>,
) -> ToolResult {
    let args = match parse_args(params) {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[command] 参数无效: {e}");
            return deny_and_audit(audit, params, None, Denied::BadParams, None);
        }
    };
    let deny = |why: Denied, cwd: Option<&str>| deny_and_audit(audit, params, Some(&args), why, cwd);

    // ① 总开关（电脑主人在本机打开；默认关）
    if !switch_on {
        return deny(Denied::Disabled, None);
    }
    // ② lease：run_script 类、本节点、未过期、执行体 / 目录与任务帧一致
    let Some(lease) = lease else { return deny(Denied::NoLease, None) };
    let scope = TaskScope::from_params(params);
    if let Err(e) = LeaseValidator::new().validate(&lease, node_id, LEASE_CLASS) {
        log::warn!("[command] lease 校验失败: {e}");
        return deny(Denied::Lease, None);
    }
    if let Err(e) = validate_scope(&lease, &scope.agent_id, scope.root_id.as_deref()) {
        log::warn!("[command] lease 与任务帧不符: {e}");
        return deny(Denied::Lease, None);
    }
    // ③ cwd 在会话绑定授权目录内（读口径：只读目录也允许，确认窗醒目提示）
    let resolved = match policy.authorize(&scope, &args.cwd_rel, false) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[command] cwd 未通过授权复核: {e}");
            return deny(Denied::Gate, None);
        }
    };
    if !resolved.path.is_dir() {
        return deny(Denied::Gate, None);
    }
    let cwd = resolved.path.to_string_lossy().to_string();
    let read_only_root = policy
        .roots
        .iter()
        .find(|r| r.path == resolved.root)
        .map(|r| r.mode != crate::daemon::policy::RootMode::ReadWrite)
        .unwrap_or(true);

    // ④ 拒绝名单（写死在 Bridge；类别只进审计 / 本机日志，不外传）
    if let Some(cat) = crate::daemon::command_guard::deny_category(&args.command) {
        log::warn!("[command] 命中拒绝名单 {cat}，拒绝 {}", args.task_id);
        audit_entry(audit, &args, Some(&cwd), Denied::DenyList.code(), false, Some(format!("denylist:{cat}")), None);
        return ToolResult::err(OUTWARD_DENIED.into());
    }

    // ⑤ 本机确认（展示起 45s，超时 = 拒绝）。展示的命令先脱敏（命令里可能直接带着 token）
    let req = CommandRequest {
        task_id: args.task_id.clone(),
        command: crate::daemon::command_guard::redact(&args.command).0,
        cwd: cwd.clone(),
        read_only_root,
        agent_id: args.agent_id.clone(),
        session_id: args.session_id.clone(),
        reason: args.reason.clone(),
    };
    // 本会话免问：同会话 + 逐字相同命令 + 同规范化 cwd。cwd 刚由现读策略复核过（撤销即到不了这里）
    let decision_code = if passes.hit(&args.session_id, &args.command, &cwd) {
        "session_pass_hit"
    } else {
        let decision = match tokio::time::timeout(confirm_timeout(), approver.ask(&req)).await {
            Ok(d) => d,
            Err(_) => return deny(Denied::Timeout, Some(&cwd)),
        };
        match decision {
            CommandDecision::Rejected => return deny(Denied::Rejected, Some(&cwd)),
            CommandDecision::Once => "once",
            CommandDecision::SessionPass => {
                passes.grant(&args.session_id, &args.command, &cwd);
                "session_pass"
            }
        }
    };

    // ⑥ 执行
    let out = match run(&args.command, &resolved.path, args.timeout).await {
        Ok(o) => o,
        Err(e) => {
            log::warn!("[command] 启动失败: {e}");
            audit_entry(audit, &args, Some(&cwd), decision_code, false, Some(format!("spawn: {e}")), None);
            return ToolResult::err(format!("LOCAL_COMMAND_SPAWN_FAILED: 命令无法启动（{e}）"));
        }
    };
    // 先脱敏后截断：截断可能把密钥劈开，劈开后的半截正则认不出
    let (stdout, r1) = crate::daemon::command_guard::redact(&String::from_utf8_lossy(&out.stdout));
    let (stderr, r2) = crate::daemon::command_guard::redact(&String::from_utf8_lossy(&out.stderr));
    let out = RunOutput { stdout: stdout.into_bytes(), stderr: stderr.into_bytes(), ..out };
    let mut text = format_result(&out);
    if r1 || r2 {
        text = text.replacen("\n--- stdout ---", "\nredacted: true（输出里的密钥已在本机打码）\n--- stdout ---", 1);
    }
    let summary = format!(
        "exit={} elapsed_ms={} timed_out={}",
        out.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
        out.elapsed.as_millis(),
        out.timed_out
    );
    audit_entry(audit, &args, Some(&cwd), decision_code, true, None, Some(summary));
    ToolResult::ok(text)
}

/// 统一拒绝：审计记机读码，对外一句。
fn deny_and_audit(audit: &Arc<AuditLogger>, params: &Value, args: Option<&Args>, why: Denied, cwd: Option<&str>) -> ToolResult {
    let fallback;
    let args = match args {
        Some(a) => a,
        None => {
            fallback = parse_args(params).unwrap_or_else(|_| Args {
                command: String::new(),
                cwd_rel: String::new(),
                timeout: Duration::from_secs(DEFAULT_TIMEOUT_SEC),
                reason: None,
                agent_id: params.get("_agent_id").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
                session_id: String::new(),
                task_id: params.get("_task_id").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
                origin: "agent".into(),
            });
            &fallback
        }
    };
    audit_entry(audit, args, cwd, why.code(), false, Some(why.code().into()), None);
    ToolResult::err(OUTWARD_DENIED.into())
}

/// 审计：命令（**已脱敏**）进 `path` 字段；**不记输出**。
fn audit_entry(
    audit: &Arc<AuditLogger>,
    args: &Args,
    cwd: Option<&str>,
    decision: &str,
    ok: bool,
    error: Option<String>,
    summary: Option<String>,
) {
    let cmd = crate::daemon::command_guard::redact(&args.command).0;
    let path = match cwd {
        Some(c) => format!("{c} $ {cmd}"),
        None => format!("{} $ {cmd}", args.cwd_rel),
    };
    audit.log(&AuditEntry {
        ts: crate::daemon::audit::now_ts(),
        agent_id: if args.agent_id.is_empty() { "unknown".into() } else { args.agent_id.clone() },
        tool: TOOL_NAME.into(),
        path,
        lease_id: None,
        task_id: args.task_id.clone(),
        decision: Some(decision.into()),
        backup_path: None,
        ok,
        error: error.or(summary),
        origin: args.origin.clone(),
    });
}

// ────────────────────────────────────────────────────────────────
// 执行
// ────────────────────────────────────────────────────────────────

/// 非交互环境变量：命令需要输入时立刻失败，而不是卡到超时。
const NON_INTERACTIVE_ENV: [(&str, &str); 4] =
    [("GIT_TERMINAL_PROMPT", "0"), ("PAGER", "cat"), ("GIT_PAGER", "cat"), ("GIT_ASKPASS", "")];

/// Bridge 自己的内部配置变量前缀：**不得**传给命令子进程。
/// `HANA_DAEMON_TOKEN` 是这台电脑接入服务端的连接凭据——命令 `echo $HANA_DAEMON_TOKEN` 或
/// `env | base64` 能绕过任何事后脱敏把它带到云端（对抗审核 B 路 P1-3）。
/// 用户自己的环境（AWS_* / KUBECONFIG / GH_TOKEN 等）按 ADR 0013 决策 3 照搬，不剔。
const BRIDGE_ENV_PREFIXES: [&str; 2] = ["HANA_", "HANAKO_"];

/// 是否为 Bridge 内部变量（Windows 环境变量名大小写不敏感，统一按大写比较）。
fn is_bridge_env(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    BRIDGE_ENV_PREFIXES.iter().any(|p| up.starts_with(p))
}

/// 构造平台命令（不含 spawn）。
fn build_command(command: &str, cwd: &std::path::Path) -> tokio::process::Command {
    #[cfg(windows)]
    let mut c = {
        // 票 05：PowerShell 5.1 + UTF-8 输出 + Job Object
        let mut c = tokio::process::Command::new("powershell.exe");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; {command}"),
        ]);
        c
    };
    #[cfg(not(windows))]
    let mut c = {
        let mut c = tokio::process::Command::new(login_shell());
        c.arg("-lc").arg(command);
        c.process_group(0);
        c
    };
    c.current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // 先剔 Bridge 内部变量，再叠加非交互变量
    for (k, _) in std::env::vars_os() {
        if k.to_str().map(is_bridge_env).unwrap_or(false) {
            c.env_remove(&k);
        }
    }
    for (k, v) in NON_INTERACTIVE_ENV {
        c.env(k, v);
    }
    c
}

/// 进程组守卫：`Drop` 杀整组（超时与任务取消两条路径共用）。
struct GroupKill {
    #[cfg(unix)]
    pgid: Option<i32>,
    #[cfg(windows)]
    job: Option<super::command_win::Job>,
}

impl GroupKill {
    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid.take() {
            // SAFETY: killpg 只发信号，pgid 来自我们刚 spawn 的子进程（process_group(0) 使其 pgid = pid）
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
        #[cfg(windows)]
        if let Some(job) = self.job.take() {
            job.terminate();
        }
    }
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        self.kill();
    }
}

/// 读一个流，最多保留头 / 尾各 [`KEEP`] 字节（中间只计数丢弃）。按块拷贝，数百 MB 输出也不吃 CPU。
/// 读端 EOF 或被外部 `abort()` 时返回；返回前把已读到的内容通过 `sink` 交出（abort 也不丢）。
const KEEP: usize = 64 * 1024;

#[derive(Default)]
struct Captured {
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    dropped: u64,
}

impl Captured {
    fn push(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        if self.head.len() < KEEP {
            let take = (KEEP - self.head.len()).min(rest.len());
            self.head.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        if rest.is_empty() {
            return;
        }
        // 超过 KEEP 的新块本身就够填满 tail：只留最后 KEEP 字节，其余全丢
        if rest.len() >= KEEP {
            self.dropped += (self.tail.len() + rest.len() - KEEP) as u64;
            self.tail.clear();
            self.tail.extend(&rest[rest.len() - KEEP..]);
            return;
        }
        let overflow = (self.tail.len() + rest.len()).saturating_sub(KEEP);
        if overflow > 0 {
            self.tail.drain(..overflow);
            self.dropped += overflow as u64;
        }
        self.tail.extend(rest);
    }

    fn finish(self) -> Vec<u8> {
        let mut out = self.head;
        if self.dropped > 0 {
            out.extend_from_slice(format!("\n…[本机已丢弃中间 {} 字节]…\n", self.dropped).as_bytes());
        }
        out.extend(self.tail);
        out
    }
}

type Shared = std::sync::Arc<std::sync::Mutex<Captured>>;

/// 持续把 `r` 读进共享缓冲，直到 EOF 或读错。
async fn drain_into<R: tokio::io::AsyncRead + Unpin>(mut r: R, buf: Shared) {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.lock().unwrap().push(&chunk[..n]),
        }
    }
}

/// 父进程退出（或超时被杀）后，给读端的宽限：`setsid` / 双 fork 的后台孙进程脱离了进程组、
/// 却仍持有输出管道，不设宽限就会一直等到它退出（对抗审核 B 路 P1-1）。
/// 宽限内读到的照常收；到点就放弃等待，返回已读内容。
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// 执行命令：新进程组、非交互、超时杀组。
pub async fn run(command: &str, cwd: &std::path::Path, timeout: Duration) -> Result<RunOutput, String> {
    let started = Instant::now();
    let mut cmd = build_command(command, cwd);
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    #[allow(unused_mut)]
    let mut guard = GroupKill {
        #[cfg(unix)]
        pgid: child.id().map(|p| p as i32),
        #[cfg(windows)]
        job: super::command_win::Job::attach(&child),
    };
    let out_buf: Shared = Default::default();
    let err_buf: Shared = Default::default();
    let out_task = tokio::spawn(drain_into(child.stdout.take().ok_or("no stdout")?, out_buf.clone()));
    let err_task = tokio::spawn(drain_into(child.stderr.take().ok_or("no stderr")?, err_buf.clone()));

    let (exit_code, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => (status.code(), false),
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => {
            guard.kill();
            let _ = child.wait().await;
            (None, true)
        }
    };
    // 父进程已退出但孙进程可能仍持有管道：先杀组（同组的会因此 EOF），
    // 脱离进程组的后台孙进程拦不住，所以读端只给 [`DRAIN_GRACE`] 宽限，到点 abort 并取已读内容
    guard.kill();
    let mut out_task = out_task;
    let mut err_task = err_task;
    let both = async {
        let _ = (&mut out_task).await;
        let _ = (&mut err_task).await;
    };
    if tokio::time::timeout(DRAIN_GRACE, both).await.is_err() {
        out_task.abort();
        err_task.abort();
    }
    let take = |b: &Shared| std::mem::take(&mut *b.lock().unwrap()).finish();
    Ok(RunOutput { exit_code, timed_out, elapsed: started.elapsed(), stdout: take(&out_buf), stderr: take(&err_buf) })
}

// ────────────────────────────────────────────────────────────────
// 输出格式化
// ────────────────────────────────────────────────────────────────

/// 头尾截断到 `budget` 字节（UTF-8 安全，按字符边界切）。返回 (文本, 是否截断)。
fn clip(bytes: &[u8], budget: usize) -> (String, bool) {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= budget {
        return (s.into_owned(), false);
    }
    let marker = "\n…[已截断]…\n";
    let keep = budget.saturating_sub(marker.len());
    let head_n = floor_char(&s, keep / 2);
    let tail_start = ceil_char(&s, s.len() - (keep - head_n));
    (format!("{}{marker}{}", &s[..head_n], &s[tail_start..]), true)
}

fn floor_char(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// 组装回给模型的文本，总长 ≤ [`MAX_RESULT_BYTES`]。
pub fn format_result(out: &RunOutput) -> String {
    let header = format!(
        "exit_code: {}\nelapsed_ms: {}{}\n",
        out.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
        out.elapsed.as_millis(),
        if out.timed_out { "\ntimed_out: true（已超时，整组进程已终止）" } else { "" },
    );
    let labels = "--- stdout ---\n\n--- stderr ---\n";
    let budget = MAX_RESULT_BYTES.saturating_sub(header.len() + labels.len() + 64);
    // 默认各占 HEAD_TAIL*2；一流短时余量给另一流
    let per = (HEAD_TAIL * 2).min(budget / 2);
    let out_len = String::from_utf8_lossy(&out.stdout).len();
    let err_len = String::from_utf8_lossy(&out.stderr).len();
    let (out_budget, err_budget) = if out_len < per {
        (out_len, budget - out_len)
    } else if err_len < per {
        (budget - err_len, err_len)
    } else {
        (per, budget - per)
    };
    let (so, so_cut) = clip(&out.stdout, out_budget);
    let (se, se_cut) = clip(&out.stderr, err_budget);
    let mut s = header;
    if so_cut || se_cut {
        s.push_str("truncated: true\n");
    }
    s.push_str("--- stdout ---\n");
    s.push_str(&so);
    s.push_str("\n--- stderr ---\n");
    s.push_str(&se);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(stdout: &[u8], stderr: &[u8]) -> RunOutput {
        RunOutput { exit_code: Some(0), timed_out: false, elapsed: Duration::from_millis(5), stdout: stdout.to_vec(), stderr: stderr.to_vec() }
    }

    #[test]
    fn 两流都超长时合计不超过上限且标记截断() {
        let big = vec![b'a'; 200 * 1024];
        let s = format_result(&out(&big, &big));
        assert!(s.len() <= MAX_RESULT_BYTES, "len={}", s.len());
        assert!(s.contains("truncated: true"));
    }

    #[test]
    fn 一流短时余量给另一流() {
        let big = vec![b'a'; 200 * 1024];
        let s = format_result(&out(&big, b"err"));
        assert!(s.len() <= MAX_RESULT_BYTES);
        // stdout 拿到的远超默认 14KB
        assert!(s.matches('a').count() > 20 * 1024, "{}", s.matches('a').count());
    }

    #[test]
    fn 中文多字节截断不劈字() {
        let big = "中".repeat(40 * 1024).into_bytes();
        let s = format_result(&out(&big, &big));
        assert!(s.len() <= MAX_RESULT_BYTES);
        assert!(!s.contains('\u{FFFD}'));
    }

    #[test]
    fn 短输出原样不截断() {
        let s = format_result(&out(b"hello\n", b""));
        assert!(s.contains("hello"));
        assert!(!s.contains("truncated"));
        assert!(s.starts_with("exit_code: 0\n"));
    }

    #[test]
    fn 超时参数夹在上限内() {
        let a = parse_args(&serde_json::json!({"command":"x","timeout_sec":99999})).unwrap();
        assert_eq!(a.timeout, Duration::from_secs(MAX_TIMEOUT_SEC));
        let a = parse_args(&serde_json::json!({"command":"x"})).unwrap();
        assert_eq!(a.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SEC));
        assert!(parse_args(&serde_json::json!({"command":"  "})).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 非交互_stdin关闭_环境变量注入() {
        let d = tempfile::tempdir().unwrap();
        let o = run("echo $GIT_TERMINAL_PROMPT $PAGER; cat; echo done", d.path(), Duration::from_secs(10)).await.unwrap();
        let s = String::from_utf8_lossy(&o.stdout);
        assert!(s.contains("0 cat"), "{s}");
        assert!(s.contains("done"), "cat 读空 stdin 应立刻结束: {s}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 超时杀整组_孙进程也没了() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid");
        let cmd = format!("sh -c 'sleep 30 & echo $! > {}; wait'", pidfile.display());
        let o = run(&cmd, d.path(), Duration::from_millis(800)).await.unwrap();
        assert!(o.timed_out);
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // SAFETY: 只探测进程是否存在（信号 0）
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "孙进程 {pid} 仍存活");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn future被丢弃时也杀整组() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid");
        let cmd = format!("sh -c 'sleep 30 & echo $! > {}; wait'", pidfile.display());
        let p = pidfile.clone();
        let dir = d.path().to_path_buf();
        let h = tokio::spawn(async move { run(&cmd, &dir, Duration::from_secs(30)).await });
        for _ in 0..50 {
            if p.exists() && !std::fs::read_to_string(&p).unwrap().trim().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        h.abort();
        let _ = h.await;
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // SAFETY: 只探测进程是否存在（信号 0）
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "任务被取消后孙进程 {pid} 仍存活");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn win_中文输出_utf8不乱码_退出码() {
        let d = tempfile::tempdir().unwrap();
        let o = run("Write-Output '中文输出'; exit 3", d.path(), Duration::from_secs(60)).await.unwrap();
        assert_eq!(o.exit_code, Some(3));
        assert!(String::from_utf8_lossy(&o.stdout).contains("中文输出"), "{:?}", String::from_utf8_lossy(&o.stdout));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn win_超时用job杀整棵进程树() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid.txt");
        let cmd = format!(
            "$p = Start-Process -PassThru -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Start-Sleep 60'; Set-Content -Path '{}' -Value $p.Id; Start-Sleep 60",
            pidfile.display()
        );
        let o = run(&cmd, d.path(), Duration::from_secs(8)).await.unwrap();
        assert!(o.timed_out);
        let pid: u32 = std::fs::read_to_string(&pidfile).expect("子进程应已启动").trim().parse().unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let out = std::process::Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH"]).output().unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(!s.contains(&pid.to_string()), "孙进程 {pid} 仍存活: {s}");
    }

    #[test]
    fn 捕获_头尾保留_中间计数_块边界正确() {
        // 小输出原样
        let mut c = Captured::default();
        c.push(b"hello");
        assert_eq!(c.finish(), b"hello");
        // 刚好 KEEP：全在 head，不丢
        let mut c = Captured::default();
        c.push(&vec![b'a'; KEEP]);
        let o = c.finish();
        assert_eq!(o.len(), KEEP);
        // 超大单块：头 KEEP + 尾 KEEP，丢 total-2*KEEP
        let total = KEEP * 3 + 777;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let mut c = Captured::default();
        c.push(&data);
        assert_eq!(c.dropped as usize, total - 2 * KEEP);
        let o = c.finish();
        assert_eq!(&o[..KEEP], &data[..KEEP], "头完整");
        assert_eq!(&o[o.len() - KEEP..], &data[total - KEEP..], "尾是最后 KEEP 字节");
        // 逐小块喂入与整块喂入结果一致（块边界不影响内容）
        let mut a = Captured::default();
        a.push(&data);
        let mut b = Captured::default();
        for ch in data.chunks(1000) {
            b.push(ch);
        }
        assert_eq!(a.dropped, b.dropped);
        assert_eq!(a.finish(), b.finish());
    }

    #[test]
    fn bridge内部环境变量名识别_大小写不敏感() {
        for n in ["HANA_DAEMON_TOKEN", "HANA_CLOUD_BASE_URL", "HANAKO_POLICY_PATH", "hana_node_id", "Hanako_Data_Dir"] {
            assert!(is_bridge_env(n), "{n} 应被剔除");
        }
        // 用户自己的环境照搬（ADR 0013 决策 3）；HANA 不带下划线的不是我们的前缀
        for n in ["GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "KUBECONFIG", "PATH", "HOME", "HANAN_X", "HANAFOO"] {
            assert!(!is_bridge_env(n), "{n} 不该被剔除");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 命令看不到bridge自己的token_用户环境仍在() {
        let d = tempfile::tempdir().unwrap();
        std::env::set_var("HANA_DAEMON_TOKEN", "BRIDGE_TOKEN_SHOULD_NOT_LEAK");
        std::env::set_var("HANAKO_POLICY_PATH", "/x/policy.json");
        std::env::set_var("MY_USER_VAR", "keep-me");
        let o = run("echo T=[$HANA_DAEMON_TOKEN] P=[$HANAKO_POLICY_PATH] U=[$MY_USER_VAR]; env | grep -c '^HANA' || true", d.path(), Duration::from_secs(10)).await.unwrap();
        std::env::remove_var("HANA_DAEMON_TOKEN");
        std::env::remove_var("HANAKO_POLICY_PATH");
        std::env::remove_var("MY_USER_VAR");
        let s = String::from_utf8_lossy(&o.stdout).to_string();
        assert!(s.contains("T=[]") && s.contains("P=[]"), "Bridge 变量应为空: {s}");
        assert!(!s.contains("BRIDGE_TOKEN_SHOULD_NOT_LEAK"));
        assert!(s.contains("U=[keep-me]"), "用户自己的环境变量必须保留: {s}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn setsid后台孙进程持有管道_超时与退出后读端宽限内返回() {
        let d = tempfile::tempdir().unwrap();
        // 父进程立刻退出，但脱离进程组的孙进程拿着 stdout 管道睡 30s
        let t = Instant::now();
        let o = run("setsid -f sleep 30; echo started", d.path(), Duration::from_secs(20)).await.unwrap();
        let took = t.elapsed();
        assert!(took < Duration::from_secs(6), "读端宽限失效，等了 {took:?}");
        assert!(String::from_utf8_lossy(&o.stdout).contains("started"), "已读内容不能丢");
        assert_eq!(o.exit_code, Some(0));
        // 超时路径同样
        let t = Instant::now();
        let o = run("setsid -f sleep 30; echo before; sleep 30", d.path(), Duration::from_secs(1)).await.unwrap();
        assert!(o.timed_out);
        assert!(t.elapsed() < Duration::from_secs(8), "超时路径读端也要有宽限: {:?}", t.elapsed());
        assert!(String::from_utf8_lossy(&o.stdout).contains("before"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 大输出_不卡_内存只留头尾() {
        let d = tempfile::tempdir().unwrap();
        let t = Instant::now();
        let o = run("yes abcdefghij | head -c 80000000", d.path(), Duration::from_secs(60)).await.unwrap();
        assert!(t.elapsed() < Duration::from_secs(20), "80MB 输出用了 {:?}", t.elapsed());
        assert!(o.stdout.len() < 2 * KEEP + 200, "stdout 应只留头尾: {}", o.stdout.len());
        assert!(String::from_utf8_lossy(&o.stdout).contains("本机已丢弃中间"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 退出码与工作目录() {
        let d = tempfile::tempdir().unwrap();
        let o = run("pwd; exit 3", d.path(), Duration::from_secs(10)).await.unwrap();
        assert_eq!(o.exit_code, Some(3));
        let canon = d.path().canonicalize().unwrap();
        assert!(String::from_utf8_lossy(&o.stdout).trim().ends_with(canon.file_name().unwrap().to_str().unwrap()));
    }
}
