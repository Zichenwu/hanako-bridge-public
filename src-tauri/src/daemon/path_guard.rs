// src-tauri/src/daemon/path_guard.rs
//! 路径安全守卫（闸②）：对 daemon 收到的文件路径做二重验证。
//!
//! 两道检查：
//! 1. canonicalize 后前缀校验（防止 `../` 路径穿越）
//! 2. 敏感判定：词法路径与 canonical 路径各取「相对命中根」部分按段判（防大小写/符号链接/`//` 绕过）

use std::path::{Path, PathBuf};

/// 敏感**目录名**（任一路径段命中即拒；比较前统一转小写）。
const SENSITIVE_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".hanako-backup", ".docker", ".azure", ".gcloud"];

/// 敏感**文件名**（最后一段精确匹配，转小写；`id_rsa*` 等前缀另判）。
const SENSITIVE_FILES: &[&str] = &[
    ".git-credentials", ".npmrc", ".netrc", "_netrc", ".pypirc", ".pgpass", "credentials",
];

/// 敏感文件名前缀（转小写）：私钥与 `.env` 族。
const SENSITIVE_FILE_PREFIXES: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".env"];

/// 敏感文件扩展名黑名单（转小写；先剥尾随 `.`/空格与 `:` 之后的 ADS 部分）。
const SENSITIVE_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "kdbx"];

/// 按**路径段**判断一条相对路径是否敏感（审核 L2）。
///
/// 旧实现对原始输入做大小写敏感的子串匹配：`.SSH/`、`cert.PEM`、`.git//config`、
/// 经符号链接到达的 `.ssh` 全都能绕过。现在对每段转小写后精确比较，`.git` 与紧随的
/// `config` 成对判断，扩展名先归一化（Windows 会剥尾随点/空格、`a.pem::$DATA` 读主流）。
/// 只看「相对授权根」的部分——授权根本身叫 `.git-tools` 之类不误伤。
pub fn rel_is_sensitive(rel: &Path) -> Option<String> {
    use std::path::Component;
    let segs: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    for (i, seg) in segs.iter().enumerate() {
        let seg = normalize_seg(seg);
        if SENSITIVE_DIRS.contains(&seg) {
            return Some(seg.to_string());
        }
        if seg == ".git" && segs.get(i + 1).map(|n| normalize_seg(n)) == Some("config") {
            return Some(".git/config".into());
        }
    }
    let last = normalize_seg(segs.last()?);
    if SENSITIVE_FILES.contains(&last) || SENSITIVE_FILE_PREFIXES.iter().any(|p| last.starts_with(p)) {
        return Some(last.to_string());
    }
    if let Some(ext) = Path::new(last).extension().and_then(|e| e.to_str()) {
        if SENSITIVE_EXTENSIONS.contains(&ext) {
            return Some(format!("*.{ext}"));
        }
    }
    None
}

/// 段归一化：剥 `:` 之后（NTFS ADS）与尾随 `.`/空格（Windows 打开时会剥）。
fn normalize_seg(seg: &str) -> &str {
    let seg = seg.split(':').next().unwrap_or(seg);
    seg.trim_end_matches(|c| c == '.' || c == ' ')
}

/// 路径安全守卫，持有授权根目录列表。
#[derive(Debug, Clone)]
pub struct PathGuard {
    allowed_roots: Vec<PathBuf>,
}

/// 路径解析错误。
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("path escapes the workspace")]
    EscapesWorkspace,
    #[error("sensitive path rejected: {0}")]
    Sensitive(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl PathGuard {
    /// 绝对路径（已在某授权根内）是否敏感：取相对命中根的部分按段判断。
    /// 目录递归遍历（grep）逐条复用；不在任何根内时按敏感处理（fail-closed）。
    pub fn is_sensitive_abs(&self, abs: &Path) -> bool {
        match self.allowed_roots.iter().find_map(|r| abs.strip_prefix(r).ok()) {
            Some(rel) => rel_is_sensitive(rel).is_some(),
            None => true,
        }
    }

    /// 已 canonicalize 的绝对路径是否落在某个授权根内。
    pub fn contains_canonical(&self, canonical: &Path) -> bool {
        self.allowed_roots.iter().any(|r| canonical.starts_with(r))
    }

    /// 构造守卫，传入已 canonicalize 的授权根目录列表。
    pub fn new(allowed_roots: Vec<PathBuf>) -> Self {
        Self { allowed_roots }
    }

    /// 解析相对路径 → 受保护的绝对路径。
    ///
    /// 返回 `Ok(PathBuf)` 当且仅当路径：
    /// - 不包含任何敏感模式
    /// - canonicalize 后仍在某个 allowed_root 前缀内
    ///
    /// 写新文件（目标不存在）时走父目录 canonicalize。
    pub fn resolve(&self, rel_path: &str) -> Result<PathBuf, PathError> {
        self.resolve_with_root(rel_path).map(|(p, _)| p)
    }

    /// 同 `resolve`，并返回命中的授权根（备份存放、只读判定都要用「命中的那个根」）。
    pub fn resolve_with_root(&self, rel_path: &str) -> Result<(PathBuf, PathBuf), PathError> {
        // 2. 词法归一化（消掉 `.` / `..`）→ canonicalize（解析符号链接）→ 前缀校验。
        //    先归一化再 canonicalize：保证「校验的路径」与「返回并被操作的路径」是同一个，
        //    `nonexist/../../x` 这类穿过不存在段的写法会被还原成真实位置后再判越界，
        //    而不是把 `..` 静默丢掉得到另一个文件。
        //    绝对路径入参（模型常把授权目录内的绝对路径直接传来）按原样校验前缀。
        for root in &self.allowed_roots {
            let joined = if Path::new(rel_path).is_absolute() {
                PathBuf::from(rel_path)
            } else {
                root.join(rel_path)
            };
            let lexical = lexical_normalize(&joined);
            let canonical = canonicalize_allow_missing(&lexical)?;
            if canonical.starts_with(root) {
                // 敏感判定两道都要过：词法路径挡「链接名」（keys→.ssh 的 keys 不敏感，但用户写的
                // `.SSH/x` 是），canonical 路径挡「链接目标」（keys/id_rsa 实为 .ssh/id_rsa）。
                for p in [lexical.strip_prefix(root).ok(), canonical.strip_prefix(root).ok()].into_iter().flatten() {
                    if let Some(hit) = rel_is_sensitive(p) {
                        return Err(PathError::Sensitive(hit));
                    }
                }
                return Ok((canonical, root.clone()));
            }
        }

        Err(PathError::EscapesWorkspace)
    }
}

/// 词法归一化：消掉 `.` 与 `..`，不访问文件系统。`..` 越过根时停在根（随后由前缀校验拒绝）。
fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                // 只弹普通段；弹到根/盘符就保持不动
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// canonicalize，但允许末尾若干段尚不存在（写新文件）。
///
/// 向上找到第一个「存在」的祖先做 canonicalize，再把不存在的段拼回。
/// 「存在」用 `symlink_metadata` 判断而不是 `exists()`：`exists()` 跟随链接，
/// **悬空符号链接会被当成不存在**，于是其父目录通过前缀校验，而随后的 `fs::write`
/// 会顺着链接写到授权目录之外（P9 的变体）。悬空链接一律拒绝，即便它指向根内。
fn canonicalize_allow_missing(p: &Path) -> Result<PathBuf, PathError> {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        match cur.symlink_metadata() {
            Ok(md) => {
                let base = match cur.canonicalize() {
                    Ok(b) => b,
                    Err(_) if md.file_type().is_symlink() => return Err(PathError::EscapesWorkspace),
                    Err(e) => return Err(PathError::Io(e)),
                };
                let mut result = base;
                for part in suffix.iter().rev() {
                    result.push(part);
                }
                return Ok(result);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match (cur.file_name().map(|n| n.to_os_string()), cur.parent()) {
                    (Some(name), Some(parent)) => {
                        suffix.push(name);
                        cur = parent.to_path_buf();
                    }
                    _ => return Err(PathError::Io(e)),
                }
            }
            Err(e) => return Err(PathError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup() -> (tempfile::TempDir, PathGuard) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let guard = PathGuard::new(vec![root.clone()]);
        (dir, guard)
    }

    #[test]
    fn 正常路径通过() {
        let (_dir, guard) = setup();
        let r = guard.resolve("a/b.txt").unwrap();
        assert!(r.ends_with("a/b.txt"));
    }

    #[test]
    fn 点点穿越被拒() {
        let (_dir, guard) = setup();
        let r = guard.resolve("../outside.txt");
        assert!(matches!(r, Err(PathError::EscapesWorkspace)));
    }

    #[test]
    fn 敏感路径被拒() {
        let (_dir, guard) = setup();
        assert!(matches!(guard.resolve(".ssh/id_rsa"), Err(PathError::Sensitive(_))));
        assert!(matches!(guard.resolve("cert.pem"), Err(PathError::Sensitive(_))));
        assert!(matches!(guard.resolve(".git/config"), Err(PathError::Sensitive(_))));
    }

    #[test]
    fn 新文件走父目录_canonicalize() {
        let (dir, guard) = setup();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        let r = guard.resolve("sub/new.txt").unwrap();
        assert!(r.ends_with("sub/new.txt"));
    }

    #[test]
    #[cfg(unix)]
    fn 符号链接指向工作区外被拒() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let guard = PathGuard::new(vec![root.clone()]);
        // 在工作区内创建一个指向工作区外目录的符号链接
        std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
        let r = guard.resolve("evil/secret.txt");
        assert!(matches!(r, Err(PathError::EscapesWorkspace)));
    }

    #[test]
    #[cfg(unix)]
    fn 悬空符号链接指向根外被拒() {
        let (dir, guard) = setup();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("new.txt"), dir.path().join("dangling")).unwrap();
        assert!(matches!(guard.resolve("dangling"), Err(PathError::EscapesWorkspace)));
    }

    #[test]
    #[cfg(unix)]
    fn 悬空符号链接作为中间段被拒() {
        let (dir, guard) = setup();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("nodir"), dir.path().join("dangling")).unwrap();
        assert!(guard.resolve("dangling/x.txt").is_err());
    }

    #[test]
    fn 穿过不存在段的点点越界被拒() {
        let (_dir, guard) = setup();
        assert!(matches!(guard.resolve("nonexist/../../outside.txt"), Err(PathError::EscapesWorkspace)));
    }

    #[test]
    fn 点点在根内折返正常() {
        let (dir, guard) = setup();
        fs::create_dir_all(dir.path().join("a")).unwrap();
        let r = guard.resolve("a/../b.txt").unwrap();
        assert!(r.ends_with("b.txt") && !r.to_string_lossy().contains("/a/"));
    }

    #[test]
    fn 绝对路径在根内放行_在根外被拒() {
        let (dir, guard) = setup();
        let inside = dir.path().canonicalize().unwrap().join("x.txt");
        assert!(guard.resolve(inside.to_str().unwrap()).is_ok());
        assert!(matches!(guard.resolve("/etc/passwd"), Err(PathError::EscapesWorkspace)));
    }

    #[test]
    #[cfg(unix)]
    fn 根内符号链接指向根内放行() {
        let (dir, guard) = setup();
        fs::create_dir_all(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/f.txt"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("alias")).unwrap();
        let r = guard.resolve("alias/f.txt").unwrap();
        assert!(r.ends_with("real/f.txt"));
    }

    #[test]
    fn 敏感判断按段_大小写_尾随点_ads() {
        for bad in [
            "a/.ssh/id_rsa", ".SSH/x", "x/cert.pem", "cert.PEM", "cert.pem.", "cert.pem ", "cert.pem::$DATA",
            ".git/config", ".GIT/Config", "sub/.env", ".env.local", ".git-credentials", ".npmrc", "keys/id_ed25519.pub",
            ".aws/credentials", "db.kdbx",
        ] {
            assert!(rel_is_sensitive(Path::new(bad)).is_some(), "{bad} 应判敏感");
        }
        for ok in ["a/b.txt", ".github/workflows/ci.yml", ".git/HEAD", "config", "src/environment.rs", "docs/keys.md", "envoy.yaml"] {
            assert!(rel_is_sensitive(Path::new(ok)).is_none(), "{ok} 不应判敏感");
        }
    }

    #[test]
    fn 双斜杠与点段绕不过() {
        let (dir, guard) = setup();
        fs::create_dir_all(dir.path().join(".git/x")).unwrap();
        fs::write(dir.path().join(".git/config"), "token").unwrap();
        for p in [".git//config", ".git/./config", ".git/x/../config"] {
            assert!(matches!(guard.resolve(p), Err(PathError::Sensitive(_))), "{p}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn 符号链接指向敏感目录被拒() {
        let (dir, guard) = setup();
        fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        fs::write(dir.path().join(".ssh/id_rsa"), "KEY").unwrap();
        fs::write(dir.path().join("plain.txt"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path().join(".ssh"), dir.path().join("keys")).unwrap();
        std::os::unix::fs::symlink(dir.path().join(".ssh/id_rsa"), dir.path().join("innocent.txt")).unwrap();
        assert!(matches!(guard.resolve("keys/id_rsa"), Err(PathError::Sensitive(_))));
        assert!(matches!(guard.resolve("innocent.txt"), Err(PathError::Sensitive(_))));
        // 反向：链接名敏感、目标普通——只有词法一侧能挡（两侧缺一不可）
        std::os::unix::fs::symlink(dir.path().join("plain.txt"), dir.path().join(".env")).unwrap();
        assert!(matches!(guard.resolve(".env"), Err(PathError::Sensitive(_))));
    }

    #[test]
    fn 授权根本身名字含敏感词不误伤() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(".aws-tools");
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("a.txt"), "x").unwrap();
        let guard = PathGuard::new(vec![root.clone()]);
        assert!(guard.resolve("a.txt").is_ok());
        assert!(!guard.is_sensitive_abs(&root.join("a.txt")));
        assert!(guard.is_sensitive_abs(&root.join(".env")));
    }
}
