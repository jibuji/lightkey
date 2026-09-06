//! Windows 远端进程 PEB 读取原语（唯一一份；cfg(windows)）。
//!
//! 「读远端进程 PEB 块」的原语——`OpenProcess` + `NtQueryInformationProcess`
//! （ProcessBasicInformation → PEB 基址）+ `ReadProcessMemory`（偏移表寻址）——
//! 此前在 `starter`（进程链回溯读对端 cwd）与 lk-daemon `identity`（读对端
//! env 块）各有一份同款拷贝；偏移表漂移 = cwd/env 静默失真。本模块收拢为
//! 唯一一份，两个调用方共享（纯去重，零行为变更）。
//!
//! 偏移表（同架构假设——跨架构读取失败 → 调用方 fail-closed）：
//!
//! - `PEB + 0x20`（x64）/ `+0x10`（x86）→ `RTL_USER_PROCESS_PARAMETERS` 指针；
//! - `ProcessParameters + 0x38`（x64）/ `+0x24`（x86）→
//!   `CurrentDirectory.DosPath`（UNICODE_STRING；x64 布局中 `+0x30` 是
//!   StandardError 句柄——若读错位置，句柄低 16 位会被当作 Length、DosPath
//!   结构头会被当作 Buffer（垃圾小指针）：两道防线都 fail-closed——调用方
//!   长度 sanity check + ReadProcessMemory 对垃圾指针必然失败）；
//! - `ProcessParameters + 0x80`（x64）/ `+0x48`（x86）→ `Environment`
//!   环境块**基址指针**（无 UNICODE_STRING 头；按指针直读比按结构读更稳，
//!   UNICODE_STRING 读法会因 Buffer 字段落在 NULL 区而 fail-closed，见
//!   `docs/identity-binding.md` §5.1 Windows 注记）。
//!
//! （依据：RTL_USER_PROCESS_PARAMETERS x64 布局
//! MaximumLength@0x00/Length@0x04/…/StandardError@0x30/
//! CurrentDirectory.CURDIR{DosPath@0x38, Handle@0x48}/…/Environment@0x80；
//! 参考 Geoff Chappell 结构研究 / MS Learn winternl.h。）
//!
//! 失败语义：任一步失败（OpenProcess 权限 / 跨会话 / 进程消失 / 跨进程读失败）
//! → `None` → 调用方 fail-closed，与既有两处实现逐分支一致。

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32, // ProcessBasicInformation = 0
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn ReadProcessMemory(
        process: HANDLE,
        base_address: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        number_of_bytes_read: *mut usize,
    ) -> i32;
}

#[repr(C)]
struct BasicInfo {
    exit_status: i32,
    peb_base: *mut core::ffi::c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from: usize,
}

/// `PEB` → `ProcessParameters` 指针偏移（x64 `+0x20` / x86 `+0x10`）。
pub const PEB_PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_pointer_width = "64") {
    0x20
} else {
    0x10
};

/// `ProcessParameters` → `CurrentDirectory.DosPath`（UNICODE_STRING）偏移
/// （x64 `+0x38` / x86 `+0x24`；x64 布局中 `+0x30` 是 StandardError 句柄）。
pub const PROCESS_PARAMETERS_CWD_OFFSET: usize = if cfg!(target_pointer_width = "64") {
    0x38
} else {
    0x24
};

/// `ProcessParameters` → `Environment` 环境块基址指针偏移（x64 `+0x80` /
/// x86 `+0x48`；实测该位存环境块**基址指针**而非 UNICODE_STRING 头）。
pub const PROCESS_PARAMETERS_ENV_OFFSET: usize = if cfg!(target_pointer_width = "64") {
    0x80
} else {
    0x48
};

/// 已打开的远端进程（`OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`；
/// Drop 时 `CloseHandle`——含任一读取步骤失败后的早退路径，与既有手写
/// CloseHandle 收尾逐分支一致）。
pub struct RemoteProcess {
    handle: HANDLE,
}

impl RemoteProcess {
    /// 打开远端进程（同架构 cwd/env 读取所需的最小权限组合）；失败 → `None`。
    pub fn open(pid: u32) -> Option<RemoteProcess> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return None;
        }
        Some(RemoteProcess { handle })
    }

    /// `NtQueryInformationProcess(ProcessBasicInformation)` → PEB 基址 → 跨进程
    /// 读 `ProcessParameters` 指针。任一步失败或指针为 0 → `None`（两个既有
    /// 调用方都显式判 0，收进原语语义一致）。
    pub fn process_parameters(&self) -> Option<usize> {
        let mut basic: BasicInfo = unsafe { std::mem::zeroed() };
        let nt_status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                0,
                &mut basic as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<BasicInfo>() as u32,
                std::ptr::null_mut(),
            )
        };
        if nt_status < 0 {
            return None;
        }
        let params_ptr: usize =
            self.read_value(basic.peb_base as usize + PEB_PROCESS_PARAMETERS_OFFSET)?;
        (params_ptr != 0).then_some(params_ptr)
    }

    /// 跨进程读定长值（`T` 须为 Plain-Old-Data 且全零位为可接受的初值——
    /// 现仅 `usize` / `UNICODE_STRING` 两类既有用法）。失败 → `None`。
    pub fn read_value<T>(&self, base: usize) -> Option<T> {
        let mut out: T = unsafe { std::mem::zeroed() };
        self.read_bytes(base, unsafe {
            std::slice::from_raw_parts_mut(&mut out as *mut T as *mut u8, std::mem::size_of::<T>())
        })?;
        Some(out)
    }

    /// `ReadProcessMemory` 原语：读 `base` 起的 `buffer.len()` 字节；成功返回
    /// 实际读取字节数（调用方不需要时可忽略——既有 env 块按上界整块读、忽略
    /// 该值），失败 → `None`。
    pub fn read_bytes(&self, base: usize, buffer: &mut [u8]) -> Option<usize> {
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                base as *const core::ffi::c_void,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                buffer.len(),
                &mut read,
            )
        };
        (ok != 0).then_some(read)
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 原语冒烟（真实 PEB 回归钉在两个调用方：starter `real_peb_cwd_…` 与
    /// daemon identity `real_peer_path_…`）：本进程自身必然可读，
    /// `ProcessParameters` 指针非 0。
    #[test]
    fn own_process_parameters_is_readable() {
        let proc = RemoteProcess::open(std::process::id()).expect("本进程应可打开");
        let params = proc.process_parameters().expect("本进程 PEB 应可读");
        assert!(params != 0, "ProcessParameters 指针应为非 0");
    }
}
