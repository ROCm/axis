// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Job Object resource limits for Windows sandboxes.
//!
//! Job Objects provide process count limits, memory commit limits,
//! CPU rate caps, and KILL_ON_JOB_CLOSE (if AXIS crashes, all sandbox
//! processes die automatically). No admin required.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, OpenProcess,
};
use windows::Win32::System::Threading::{PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// Wrapper around a Win32 Job Object handle.
pub struct JobHandle {
    handle: HANDLE,
}

// Safety: Job handles can be sent across threads.
unsafe impl Send for JobHandle {}

impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Kill-on-close Job Object that also carries the sandbox resource limits.
/// Breakaway is not permitted, so every descendant (including the MXC
/// BaseContainer child) is accounted here. A zero value leaves that limit off.
/// The job is unnamed: `CreateJobObjectW` opens an existing job of the same
/// name, which another process could create and hold open.
pub fn create_limited_kill_on_close_job(
    max_processes: u32,
    max_memory_mb: u64,
    cpu_rate_percent: u32,
) -> Result<JobHandle, String> {
    let handle = unsafe { CreateJobObjectW(None, None) }
        .map_err(|e| format!("CreateJobObjectW failed: {e}"))?;
    let job = JobHandle { handle };
    let mut ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if max_processes > 0 {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        ext_info.BasicLimitInformation.ActiveProcessLimit = max_processes;
    }
    if max_memory_mb > 0 {
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        ext_info.JobMemoryLimit = (max_memory_mb * 1024 * 1024) as usize;
    }
    ext_info.BasicLimitInformation.LimitFlags = flags;
    unsafe {
        SetInformationJobObject(
            job.handle,
            JobObjectExtendedLimitInformation,
            &ext_info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|e| format!("SetInformationJobObject (limits) failed: {e}"))?;
    if cpu_rate_percent > 0 {
        let mut cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            ..Default::default()
        };
        let processors = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }.max(1);
        cpu_info.Anonymous.CpuRate = (cpu_rate_percent * 100)
            .div_ceil(processors)
            .clamp(1, 10_000);
        unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectCpuRateControlInformation,
                &cpu_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        }
        .map_err(|e| format!("SetInformationJobObject (CPU) failed: {e}"))?;
    }
    Ok(job)
}

/// Resume every thread of a process created with CREATE_SUSPENDED.
pub fn resume_process(pid: u32) -> Result<(), String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?;
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut resumed = 0;
    let mut more = unsafe { Thread32First(snapshot, &mut entry) }.is_ok();
    while more {
        if entry.th32OwnerProcessID == pid
            && let Ok(thread) =
                unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }
        {
            if unsafe { ResumeThread(thread) } != u32::MAX {
                resumed += 1;
            }
            unsafe {
                let _ = CloseHandle(thread);
            }
        }
        more = unsafe { Thread32Next(snapshot, &mut entry) }.is_ok();
    }
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    if resumed == 0 {
        return Err(format!("no suspended thread resumed for pid {pid}"));
    }
    Ok(())
}

/// Assign a process to a Job Object by PID.
pub fn assign_process_to_job(job: &JobHandle, pid: u32) -> Result<(), String> {
    let proc_handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) }
        .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;

    let result = unsafe { AssignProcessToJobObject(job.handle, proc_handle) };

    unsafe {
        let _ = CloseHandle(proc_handle);
    }

    result.map_err(|e| format!("AssignProcessToJobObject failed: {e}"))
}
