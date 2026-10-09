// src-tauri/src/daemon/audit.rs
//! 审计日志模块：记录每次本地工具调用，按天滚动写入 JSONL 文件。
//!
//! 文件路径：`<data_dir>/audit/YYYY-MM-DD.jsonl`
//!
//! 设计原则：
//! - 成功/失败都记（工具失败不是审计失败）
//! - 写操作：在 execute_write 内部写（decision / backup_path 在那里才是完整的）
//! - 读操作：在 execute_tool dispatch 处写（无 decision/backup_path，留 None）
//! - AuditLogger 以 Arc 共享，内部仅用 OpenOptions::append，无需 Mutex

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

/// 审计日志保留天数（票 19：按天滚动 30 天）。
pub const AUDIT_RETENTION_DAYS: u32 = 30;

/// 写类工具名（计入口径与 quit_guard::WRITE_TOOLS 一致；upload 也算写——字节出境）。
fn is_write_tool_name(tool: &str) -> bool {
    matches!(tool, "local_write_file" | "local_edit_file" | "local_delete_file" | "local_upload_to_workspace")
}

/// 「今日」计数的三个桶（本地文件预览票 05）。
///
/// 预览**必须自成一桶**：它不是助手的行为（用户自己在网页看），把它混进「读」会让
/// 「助手今天读了几个文件」这句话变成假话——用户看几眼文件就被记成助手读了几次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Read,
    Write,
    Preview,
}

/// 按工具名分桶。预览判定优先于读写，避免落到「其余一律算读」的兜底分支。
fn bucket_of(tool: &str) -> Bucket {
    if tool == super::preview::PREVIEW_TOOL_NAME {
        Bucket::Preview
    } else if is_write_tool_name(tool) {
        Bucket::Write
    } else {
        Bucket::Read
    }
}

/// 当日三桶计数（读 / 写 / 预览）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TodayCounts {
    pub read: u64,
    pub write: u64,
    pub preview: u64,
}

/// 单条审计记录，序列化为 JSON 追加写入日期文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 UTC 时间戳（毫秒精度），如 "2026-07-30T12:34:56.789Z"
    pub ts: String,
    /// 派活的 agent 标识符；来自 params._agent_id，缺失时为 "unknown"
    pub agent_id: String,
    /// 工具名，如 "local_write_file"
    pub tool: String,
    /// 操作目标路径（工具参数的 path 字段）
    pub path: String,
    /// 执行租约 ID（写类工具携带，读类工具为 None）
    pub lease_id: Option<String>,
    /// 任务 ID（来自 params._task_id）
    pub task_id: String,
    /// 确认决策："approved" | "rejected" | "auto"（读类工具为 None）
    pub decision: Option<String>,
    /// 备份文件路径（写类工具备份后填入，读类工具 / 失败时为 None）
    pub backup_path: Option<String>,
    /// 工具执行是否成功
    pub ok: bool,
    /// 失败时的错误消息
    pub error: Option<String>,
    /// 操作来源：区分「网页浏览 / 搬运」与「助手读文件」。
    /// 缺省 `"agent"`（模型派发）；网页本地树浏览为 `"web_browse"`（来自 params._origin）；
    /// 搬运（upload）另有 `"local_web" | "other_device" | "web"` 来源。
    /// serde default：旧审计文件（无此字段）读取时回填 `"agent"`，不报错。
    #[serde(default = "default_origin")]
    pub origin: String,
}

/// `origin` 的 serde 缺省值：老日志行 / 未标注来源一律视为模型（助手）派发。
fn default_origin() -> String {
    "agent".into()
}

/// 审计日志写入器：线程安全，持有审计目录路径，每次 log 追加到当天文件。
///
/// 调用方以 `Arc<AuditLogger>` 共享，不需要 Mutex（文件追加写由 OS 保证原子性）。
pub struct AuditLogger {
    /// `<data_dir>/audit/` 目录路径
    audit_dir: PathBuf,
}


impl AuditLogger {
    /// 构造审计日志器，自动创建 `<data_dir>/audit/` 目录，并清掉超过 30 天的旧日志（票 19）。
    pub fn new(data_dir: PathBuf) -> Self {
        let audit_dir = data_dir.join("audit");
        // 目录不存在时静默创建；失败也不 panic（审计失败不应阻断主业务）
        let _ = std::fs::create_dir_all(&audit_dir);
        let s = Self { audit_dir };
        s.cleanup_old(AUDIT_RETENTION_DAYS);
        s
    }

    /// 清理超过 `days` 天的审计日志（按文件名 `YYYY-MM-DD.jsonl` 解析日期，比 mtime 可靠）。
    /// 解析不了日期的文件不动（不误删）。
    pub fn cleanup_old(&self, days: u32) {
        let today = chrono::Utc::now().date_naive();
        let entries = match std::fs::read_dir(&self.audit_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(date_str) = name.strip_suffix(".jsonl") else { continue };
            let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") else { continue };
            let age = today.signed_duration_since(date).num_days();
            if age > days as i64 {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// 当日计数（票 19「状态只报计数」，票 05 扩为读/写/预览三桶）：按 tool 名分桶。
    /// 文件不存在 / 读失败 → 全 0，不阻断。
    ///
    /// 审核 #11 口径（网页文案「读了 N 个文件，改了 N 个」说的是**助手**）：
    /// - 「今天」按**电脑本地时区**切日：文件名仍按 UTC 日期（保留期清理不变），
    ///   所以读 UTC 今天与昨天两份，再按每条 `ts` 换算成本地日期筛；
    /// - 用户自己在网页浏览本地树（origin=`web_browse`）不算助手读；
    /// - 上传（搬运）不改本机文件，不算「改」（也不另立一桶——网页文案只有读/改/看三项）。
    pub fn today_counts(&self) -> TodayCounts {
        self.counts_for_local_day(chrono::Local::now().date_naive(), &chrono::Local)
    }

    /// `today_counts` 的可测内核：时区作参数注入（测试用固定偏移模拟本地时区）。
    fn counts_for_local_day<Tz: chrono::TimeZone>(&self, local_day: chrono::NaiveDate, tz: &Tz) -> TodayCounts {
        let mut c = TodayCounts::default();
        let utc_today = chrono::Utc::now().date_naive();
        // 本地日跨两个 UTC 日（东八区 = UTC 前一天 16:00 起），读 UTC 今天 ±1 足以覆盖任意时区
        for d in [utc_today - chrono::Duration::days(1), utc_today, utc_today + chrono::Duration::days(1)] {
            let file_path = self.audit_dir.join(format!("{}.jsonl", d.format("%Y-%m-%d")));
            let Ok(content) = std::fs::read_to_string(&file_path) else { continue };
            for line in content.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                let Some(ts) = v.get("ts").and_then(|t| t.as_str()) else { continue };
                let Ok(at) = chrono::DateTime::parse_from_rfc3339(ts) else { continue };
                if at.with_timezone(tz).date_naive() != local_day {
                    continue;
                }
                let tool = v.get("tool").and_then(|t| t.as_str()).unwrap_or("");
                let origin = v.get("origin").and_then(|o| o.as_str()).unwrap_or("agent");
                match bucket_of(tool) {
                    Bucket::Read if origin == "web_browse" => {}
                    Bucket::Read => c.read += 1,
                    Bucket::Write if tool == "local_upload_to_workspace" => {}
                    Bucket::Write => c.write += 1,
                    // 审核 #19：网页文案是「在网页看了 N 个」——被拒 / 超时没看到，不计
                    Bucket::Preview if v.get("ok").and_then(|o| o.as_bool()) == Some(false) => {}
                    Bucket::Preview => c.preview += 1,
                }
            }
        }
        c
    }

    /// 将审计条目追加写入当天 JSONL 文件（`YYYY-MM-DD.jsonl`）。
    ///
    /// 写入失败时仅 log::warn，不 panic、不向上冒泡，保证不影响工具业务路径。
    pub fn log(&self, entry: &AuditEntry) {
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let file_path = self.audit_dir.join(format!("{}.jsonl", date));
        match serde_json::to_string(entry) {
            Ok(json) => {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&file_path)
                {
                    Ok(mut f) => {
                        if let Err(e) = writeln!(f, "{}", json) {
                            log::warn!("[audit] 写入失败 {}: {}", file_path.display(), e);
                        }
                    }
                    Err(e) => {
                        log::warn!("[audit] 打开文件失败 {}: {}", file_path.display(), e);
                    }
                }
            }
            Err(e) => {
                log::warn!("[audit] 序列化失败: {}", e);
            }
        }
    }

    /// 当天审计文件路径（仅供测试读取验证）。
    #[cfg(test)]
    pub fn today_file(&self) -> PathBuf {
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.audit_dir.join(format!("{}.jsonl", date))
    }
}

// ────────────────────────────────────────────────────────────────
// 审计条目构造辅助函数（内部使用）
// ────────────────────────────────────────────────────────────────

/// 从当前 UTC 时间生成 ISO-8601 毫秒精度时间戳字符串。
pub fn now_ts() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

// ────────────────────────────────────────────────────────────────
// 测试
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 构造可用于测试的最小 AuditEntry。
    fn entry(tool: &str, ok: bool, error: Option<&str>) -> AuditEntry {
        AuditEntry {
            ts: now_ts(),
            agent_id: "agent-test".into(),
            tool: tool.into(),
            path: "/workspace/test.txt".into(),
            lease_id: Some("lease-001".into()),
            task_id: "task-001".into(),
            decision: Some("approved".into()),
            backup_path: Some("/workspace/.hanako-backup/snap/test.txt".into()),
            ok,
            error: error.map(|s| s.to_string()),
            origin: "agent".into(),
        }
    }

    // ── 单条写入后 JSONL 文件应存在 ──

    #[test]
    fn log_写入后文件存在() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let e = entry("local_write_file", true, None);
        logger.log(&e);
        assert!(logger.today_file().exists(), "审计文件应已创建");
    }

    // ── 多次写入追加到同一文件 ──

    #[test]
    fn log_多次写入追加() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        logger.log(&entry("local_write_file", true, None));
        logger.log(&entry("local_edit_file", false, Some("approval failed")));
        logger.log(&entry("local_read_file", true, None));

        let content = fs::read_to_string(logger.today_file()).unwrap();
        // 三行（每行一个 JSON 对象）
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "期望 3 行，实际: {}", lines.len());
    }

    // ── 每行是合法 JSON，字段完整 ──

    #[test]
    fn log_每行是合法_json_字段完整() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let e = AuditEntry {
            ts: "2026-07-30T12:00:00.000Z".into(),
            agent_id: "agent-xyz".into(),
            tool: "local_delete_file".into(),
            path: "/workspace/del.txt".into(),
            lease_id: Some("lease-del-001".into()),
            task_id: "task-del".into(),
            decision: Some("approved".into()),
            backup_path: Some("/backup/del.txt.bak".into()),
            ok: false,
            error: Some("file not found".into()),
            origin: "agent".into(),
        };
        logger.log(&e);

        let content = fs::read_to_string(logger.today_file()).unwrap();
        let line = content.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).expect("每行应是合法 JSON");

        // 验证所有字段均存在且值正确
        assert_eq!(parsed["agent_id"], "agent-xyz");
        assert_eq!(parsed["tool"], "local_delete_file");
        assert_eq!(parsed["path"], "/workspace/del.txt");
        assert_eq!(parsed["lease_id"], "lease-del-001");
        assert_eq!(parsed["task_id"], "task-del");
        assert_eq!(parsed["decision"], "approved");
        assert_eq!(parsed["backup_path"], "/backup/del.txt.bak");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"], "file not found");
        assert_eq!(parsed["origin"], "agent", "origin 应序列化进 JSONL");
    }

    // ── 读类工具：decision 和 backup_path 为 null ──

    #[test]
    fn log_读类工具_decision_和_backup_path_为_null() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let e = AuditEntry {
            ts: now_ts(),
            agent_id: "unknown".into(),
            tool: "local_read_file".into(),
            path: "/workspace/readme.txt".into(),
            lease_id: None,
            task_id: "task-r1".into(),
            decision: None,
            backup_path: None,
            ok: true,
            error: None,
            origin: "agent".into(),
        };
        logger.log(&e);

        let content = fs::read_to_string(logger.today_file()).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(parsed["lease_id"].is_null(), "读类工具 lease_id 应为 null");
        assert!(parsed["decision"].is_null(), "读类工具 decision 应为 null");
        assert!(parsed["backup_path"].is_null(), "读类工具 backup_path 应为 null");
    }

    // ── 文件名应为当天日期 YYYY-MM-DD.jsonl ──

    #[test]
    fn log_文件名为当天日期() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        logger.log(&entry("local_list_dir", true, None));

        let expected_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let expected_name = format!("{}.jsonl", expected_date);
        let file_name = logger.today_file().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(file_name, expected_name, "审计文件名应为当天日期");
    }

    // ── audit 目录不存在时自动创建 ──

    #[test]
    fn new_自动创建_audit_目录() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("does_not_exist_yet");
        let logger = AuditLogger::new(data_dir.clone());
        // 写一条后目录应存在
        logger.log(&entry("local_read_file", true, None));
        assert!(data_dir.join("audit").exists(), "audit 目录应被自动创建");
    }

    // ── 票 19：按天滚动 30 天 + 当日计数 ──

    #[test]
    fn new_清掉超过30天的旧日志_保留近期() {
        let tmp = tempfile::tempdir().unwrap();
        let audit_dir = tmp.path().join("audit");
        fs::create_dir_all(&audit_dir).unwrap();
        // 40 天前 / 31 天前 / 30 天前 / 今天 / 非日期文件
        let old40 = audit_dir.join("2000-01-01.jsonl");
        let d31 = audit_dir.join((chrono::Utc::now().date_naive() - chrono::Duration::days(31)).format("%Y-%m-%d").to_string() + ".jsonl");
        let d30 = audit_dir.join((chrono::Utc::now().date_naive() - chrono::Duration::days(30)).format("%Y-%m-%d").to_string() + ".jsonl");
        let today = audit_dir.join(chrono::Utc::now().format("%Y-%m-%d").to_string() + ".jsonl");
        let notdate = audit_dir.join("notes.txt");
        for f in [&old40, &d31, &d30, &today, &notdate] { fs::write(f, "{}").unwrap(); }

        let _logger = AuditLogger::new(tmp.path().to_path_buf()); // new 内部调 cleanup_old(30)

        assert!(!old40.exists(), "40 天前应被清");
        assert!(!d31.exists(), "31 天前应被清");
        assert!(d30.exists(), "30 天整应保留");
        assert!(today.exists(), "今天应保留");
        assert!(notdate.exists(), "非日期文件不动");
    }

    #[test]
    fn today_counts_按读写分类() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        assert_eq!(logger.today_counts(), TodayCounts::default(), "无文件时全 0");
        logger.log(&entry("local_read_file", true, None));
        logger.log(&entry("local_list_dir", true, None));
        logger.log(&entry("local_write_file", true, None));
        logger.log(&entry("local_upload_to_workspace", true, None));
        logger.log(&entry("local_delete_file", false, Some("x")));
        let c = logger.today_counts();
        assert_eq!(c.read, 2, "read_file + list_dir");
        assert_eq!(c.write, 2, "write + delete（失败也计）；上传不改本机文件，不算改（审核 #11）");
        assert_eq!(c.preview, 0, "没有预览");
    }

    /// 审核 #11：网页文案说的是「助手读了 / 改了」——用户自己浏览本地树不算读，上传不算改。
    /// 变异锁：去掉 web_browse 或 upload 的排除 → 本用例红。
    #[test]
    fn today_counts_只计助手_网页浏览与上传不计() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let mut browse = entry("local_list_dir", true, None);
        browse.origin = "web_browse".into();
        logger.log(&browse);
        logger.log(&browse);
        logger.log(&entry("local_read_file", true, None));
        logger.log(&entry("local_upload_to_workspace", true, None));
        let c = logger.today_counts();
        assert_eq!(c.read, 1, "只有助手读算读");
        assert_eq!(c.write, 0, "上传不算改");
    }

    /// 审核 #11：「今天」按本地时区切日。东八区 00:30（= UTC 前一天 16:30）的条目属于本地今天；
    /// 同一 UTC 日早些时候（UTC 前一天 15:00 = 本地昨天 23:00）的不算。
    /// 变异锁：改回按 UTC 文件名 / 不按 ts 换算本地日期 → 本用例红。
    #[test]
    fn today_counts_按本地时区切日() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let utc_today = chrono::Utc::now().date_naive();
        let utc_yday = utc_today - chrono::Duration::days(1);
        let line = |ts: String| {
            let mut e = entry("local_read_file", true, None);
            e.ts = ts;
            serde_json::to_string(&e).unwrap()
        };
        // 两条都写进 UTC 昨天的文件
        std::fs::write(
            tmp.path().join("audit").join(format!("{}.jsonl", utc_yday.format("%Y-%m-%d"))),
            format!("{}\n{}\n",
                line(format!("{}T16:30:00.000Z", utc_yday.format("%Y-%m-%d"))),
                line(format!("{}T15:00:00.000Z", utc_yday.format("%Y-%m-%d")))),
        ).unwrap();
        let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
        let c = logger.counts_for_local_day(utc_today, &cst);
        assert_eq!(c.read, 1, "东八区今天 00:30 算今天，昨天 23:00 不算");
        let c_utc = logger.counts_for_local_day(utc_yday, &chrono::Utc);
        assert_eq!(c_utc.read, 2, "按 UTC 切日时两条都属于 UTC 昨天");
    }

    // ── 票 05：预览自成一桶 ────────────────────────────────

    /// 变异锁：把 `bucket_of` 里的预览判定去掉（让预览落回「其余一律算读」）/ 被拒也计 → 本用例红。
    #[test]
    fn today_counts_预览不被算进读() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        logger.log(&entry("local_read_file", true, None));
        logger.log(&entry(super::super::preview::PREVIEW_TOOL_NAME, true, None));
        logger.log(&entry(super::super::preview::PREVIEW_TOOL_NAME, false, Some("protected")));
        let c = logger.today_counts();
        assert_eq!(c.read, 1, "只有真的读才算读，预览不混进来");
        assert_eq!(c.preview, 1, "预览自成一桶；被拒的没看到，不计（审核 #19）");
        assert_eq!(c.write, 0, "预览更不能算写");
    }

    /// 预览既不是读也不是写：三桶互斥，分类函数对同一工具名只给一个桶。
    #[test]
    fn bucket_of_三桶互斥() {
        assert_eq!(bucket_of(super::super::preview::PREVIEW_TOOL_NAME), Bucket::Preview);
        assert_eq!(bucket_of("local_read_file"), Bucket::Read);
        assert_eq!(bucket_of("local_list_dir"), Bucket::Read);
        assert_eq!(bucket_of("local_write_file"), Bucket::Write);
        assert_eq!(bucket_of("local_upload_to_workspace"), Bucket::Write, "上传算写——字节出境");
        // 预览工具名不在写类名单里（否则会被 is_write_tool_name 先截走）
        assert!(!is_write_tool_name(super::super::preview::PREVIEW_TOOL_NAME));
    }

    // ── now_ts 格式符合 ISO-8601 毫秒精度 ──

    #[test]
    fn now_ts_格式正确() {
        let ts = now_ts();
        // 格式：YYYY-MM-DDTHH:MM:SS.mmmZ，固定 24 字符
        assert_eq!(ts.len(), 24, "ts 长度应为 24，实际: {}", ts);
        assert!(ts.ends_with('Z'), "ts 应以 Z 结尾");
        assert!(ts.contains('T'), "ts 应含 T 分隔符");
    }

    // ── 票 07：origin 字段（区分「网页浏览」与「助手读文件」）────────────

    #[test]
    fn origin_网页浏览记录为_web_browse() {
        let tmp = tempfile::tempdir().unwrap();
        let logger = AuditLogger::new(tmp.path().to_path_buf());
        let mut e = entry("local_list_dir", true, None);
        e.origin = "web_browse".into();
        logger.log(&e);

        let parsed: serde_json::Value =
            serde_json::from_str(fs::read_to_string(logger.today_file()).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(parsed["origin"], "web_browse");
        assert_eq!(parsed["tool"], "local_list_dir");
    }

    #[test]
    fn origin_旧格式行_无字段_反序列化回填_agent() {
        // 旧审计文件行（无 origin 字段）读取不报错，serde default 回填 "agent"
        let old_line = r#"{"ts":"2026-07-30T12:00:00.000Z","agent_id":"a","tool":"local_read_file","path":"/x","lease_id":null,"task_id":"t","decision":null,"backup_path":null,"ok":true,"error":null}"#;
        let e: AuditEntry = serde_json::from_str(old_line).expect("旧格式行必须可解析");
        assert_eq!(e.origin, "agent", "旧行缺 origin 应回填 agent");
        assert_eq!(e.tool, "local_read_file");
    }
}
