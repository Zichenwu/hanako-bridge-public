// src-tauri/src/daemon/tools/command_win.rs
//! Windows：把命令进程挂进 Job Object（KILL_ON_JOB_CLOSE），终止 / 关闭句柄即杀整棵进程树（票 05）。
//!
//! 竞态说明：子进程 spawn 后才 Assign，极短窗口内它若已派生孙进程，孙进程不在 Job 里。
//! PowerShell 启动远慢于这一步（数百毫秒），实际可忽略；票 05 若 CI 暴露问题再改 CREATE_SUSPENDED。

#![cfg(windows)]

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub struct Job(HANDLE);

// SAFETY: Job 句柄是内核对象句柄，可跨线程使用
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    /// 新建 Job 并把子进程挂进去；任一步失败返回 None（退化为只杀直接子进程）。
    pub fn attach(child: &tokio::process::Child) -> Option<Self> {
        let raw = child.raw_handle()? as HANDLE;
        // SAFETY: 标准 Win32 调用；失败时句柄为 0 / 返回 0，均已检查
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 || AssignProcessToJobObject(job, raw) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Job(job))
        }
    }

    /// 终止 Job 内全部进程。
    pub fn terminate(self) {
        // SAFETY: 句柄有效；随后 Drop 关闭
        unsafe {
            TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: 关闭句柄；KILL_ON_JOB_CLOSE 使残留进程一并被杀
        unsafe {
            CloseHandle(self.0);
        }
    }
}
