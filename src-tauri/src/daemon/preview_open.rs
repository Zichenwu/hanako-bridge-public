// src-tauri/src/daemon/preview_open.rs
//! 预览读取的「只读打开」（审核 F11：符号链接 TOCTOU）。
//!
//! `authorize` 把请求路径解析成**已规范化**的真实路径并校验落点；但从过闸到真正打开之间
//! 有一段时间（等用户点确认最长 60 秒）。这期间若本机有进程把该路径（或其某一层目录）
//! 换成指向授权目录外的符号链接，按路径打开就会顺着链接读到别处。
//!
//! 对策：`real_path` 已是规范化结果，**正常情况下任何一层都不该是符号链接**——
//! 那就在打开时直接禁止跟随：
//! - unix（含 macOS）：`O_NOFOLLOW`——末段是链接即拒；中间层被换由每片后的指纹复核兜一部分。
//!   ⚠️ **不用 macOS 的 `O_NOFOLLOW_ANY`**（10-09 CI 实测）：macOS 的 `/var`、`/tmp`、`/etc` 本身就是指向
//!   `/private/*` 的系统链接，而用户的授权目录也可能经过链接（外置盘挂载点、iCloud 目录）。
//!   `_ANY` 会把这些**正常文件全部拒掉**（CI 上 20 条预览用例全红）。末段 + fstat + 指纹复核已覆盖本票威胁。
//! - Windows：建符号链接需管理员或开发者模式，属「本机已有恶意进程」，本票不处理，按原方式打开。
//!
//! 打开后再用句柄（不是路径）确认是普通文件——FIFO / 设备文件不得被读。
//!
//! 本模块只**打开**、不读不写；放在独立文件是为了让 `preview_read` / `preview_stream`
//! 的「不落盘」静态守卫继续可以把 `OpenOptions` 整个列为禁用词。

use std::path::Path;

/// 只读打开要预览的文件：拒绝符号链接与非普通文件。失败一律 `None`（调用方按可重试处理）。
pub async fn open_no_follow(path: &Path) -> Option<tokio::fs::File> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // O_NONBLOCK：路径若被换成 FIFO，open 本身不阻塞（随后 fstat 判非普通文件拒掉）
        opts.custom_flags(flags);
    }
    let file = opts.open(path).await.ok()?;
    let meta = file.metadata().await.ok()?;
    if !meta.is_file() {
        return None;
    }
    Some(file)
}

/// 同 [`open_no_follow`]，整读到内存（单帧路径；大小上限由闸在读之前保证）。
pub async fn read_no_follow(path: &Path) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut file = open_no_follow(path).await?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn 普通文件可读() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.txt");
        std::fs::write(&p, b"hello").unwrap();
        assert_eq!(read_no_follow(&p).await.unwrap(), b"hello");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn 末段被换成符号链接_拒绝() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"SECRET").unwrap();
        let p = d.path().join("a.txt");
        std::os::unix::fs::symlink(&secret, &p).unwrap();
        assert!(open_no_follow(&p).await.is_none());
        assert!(read_no_follow(&p).await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_拒绝且不阻塞() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pipe.txt");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), open_no_follow(&p)).await;
        assert!(matches!(r, Ok(None)), "FIFO 必须被拒且 open 不阻塞");
    }

    #[tokio::test]
    async fn 目录拒绝() {
        let d = tempfile::tempdir().unwrap();
        assert!(open_no_follow(d.path()).await.is_none());
    }

    /// 回归锁（10-09 macOS CI）：路径中间层是**系统 / 用户的正常链接**时必须可读。
    /// macOS 上 `/var/folders/...` 天然经过 `/var -> /private/var`；这里在所有 unix 上人为构造同样形状。
    /// 变异锁：把 flags 改成 macOS 的 `O_NOFOLLOW_ANY` → 本用例在 macOS 上红。
    #[cfg(unix)]
    #[tokio::test]
    async fn 中间层是正常链接_可读() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("a.txt"), b"ok").unwrap();
        let via = d.path().join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        assert_eq!(read_no_follow(&via.join("a.txt")).await.unwrap(), b"ok");
    }
}
