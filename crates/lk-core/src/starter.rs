//! 启动者判定（规格：`docs/authorization-gate.md` §3）。
//!
//! 原则（D8，勿自行变更）：
//!
//! - **守护进程侧派生，不信任客户端**：`starter` 与 `cwd` 由守护进程从 IPC
//!   对端 PID 回溯/核对，客户端自报字段一律视为不可信输入。
//! - 判定依据 = **进程链回溯 + 工作目录**：回溯发起进程的父进程链，确定
//!   启动者（可归属的顶层进程，如终端/编辑器/agent 进程）；工作目录 = 发起
//!   命令时的 cwd（**以对端进程真实 cwd 为准**，并 canonicalize 解析符号链接）。
//! - **对端自身不可读（权限/跨会话/进程消失）→ `starter = "unknown"` →
//!   fail-closed**（授权门第 1 层默认拒绝）；**中间祖先不可读**（Windows
//!   Toolhelp32 不枚举 smss 等系统进程、进程竞态消失）→ 取**已回溯的最顶层
//!   可归属进程**（回溯结果依然真实，不 fail-open；授权仍由规则决定，
//!   starter 用于审计与第 1 层兜底）。
//! - 实现：Linux `/proc` 进程树；Windows Toolhelp32 + 进程 PEB（cwd）；
//!   macOS `sysctl`（kinfo_proc）/ `proc_pidpath`。
//!
//! 判定逻辑（[`resolve_starter`]）与进程表实现（[`ProcessTable`] trait）分离：
//! 纯逻辑可注入假进程表做确定性单测；平台实现按 `cfg` 隔离。

use std::collections::HashSet;

/// 启动者未知（fail-closed 标记；授权门第 1 层直接拒绝）。
pub const UNKNOWN_STARTER: &str = "unknown";

/// 回溯深度上限（正常链路 ≤ 10；超限取最顶层已确定进程，不 fail-closed——
/// 仍是有效回溯，只是链路过深）。
const MAX_WALK_DEPTH: usize = 32;

/// 启动者判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarterInfo {
    /// 顶层可归属进程的可执行文件规范化路径（无法取得时退化为进程名）；
    /// 回溯失败 → [`UNKNOWN_STARTER`]（fail-closed）。
    pub starter: String,
    /// 对端进程真实 cwd（canonical 形态；失败 → `None` → 授权门拒绝）。
    pub cwd: Option<String>,
}

/// 进程表抽象（测试注入假表；平台实现见模块尾部）。
///
/// 任一读取失败（权限/跨会话/进程消失）→ 返回 `None` → 整体 fail-closed。
pub trait ProcessTable: Send + Sync {
    /// 父进程 pid（读取失败 → `None`）。
    fn parent_pid(&self, pid: u32) -> Option<u32>;
    /// 进程名（Linux comm / Windows szExeFile / macOS p_comm）。
    fn process_name(&self, pid: u32) -> Option<String>;
    /// 可执行文件规范化路径（读取失败 → `None`；如 `/usr/bin/zsh`）。
    fn exe_path(&self, pid: u32) -> Option<String>;
    /// 会话组长判定：`pid` 是否为自身会话的组长（Linux：pid == session）。
    fn is_session_leader(&self, pid: u32) -> Option<bool>;
}

/// 进程链回溯：从对端 PID 沿父进程链逐级上溯，取**顶层可归属进程**。
///
/// 规则：
/// - 逐级回溯至会话组长/顶层；**对端自身读取失败**（权限/跨会话/进程消失）
///   → 整体失败 → [`UNKNOWN_STARTER`]（fail-closed）；
/// - **中间祖先读取失败**（Windows Toolhelp 不枚举 smss 等系统进程 / 进程
///   竞态消失）→ 取**已回溯的最顶层可归属进程**（不 fail-open：回溯结果
///   依然真实；授权仍由规则决定，starter 只用于审计与第 1 层兜底）；
/// - 父链成环 → 取已回溯的最顶层；深度超过 [`MAX_WALK_DEPTH`] 同语义。
///
/// 结果 starter 优先取可执行文件规范化路径（审计示例 `/usr/bin/zsh`），
/// 取不到时退化为进程名。
pub fn resolve_starter(peer_pid: u32, table: &dyn ProcessTable) -> String {
    walk_chain(peer_pid, table).map_or_else(
        || UNKNOWN_STARTER.to_string(),
        |(pid, name)| table.exe_path(pid).unwrap_or(name),
    )
}

/// 回溯进程链（顶层在前）：返回 `(顶层 pid, 顶层进程名)`；失败 → `None`。
fn walk_chain(peer_pid: u32, table: &dyn ProcessTable) -> Option<(u32, String)> {
    if peer_pid == 0 {
        return None;
    }
    let mut pid = peer_pid;
    let mut seen: HashSet<u32> = HashSet::new();
    let mut top: Option<(u32, String)> = None;
    for _ in 0..=MAX_WALK_DEPTH {
        if !seen.insert(pid) {
            break; // 父链成环 → 取已回溯的最顶层
        }
        let Some(name) = table.process_name(pid) else {
            break; // 祖先不可读 → 取已回溯的最顶层（对端自身不可读 → None）
        };
        let is_leader = table.is_session_leader(pid).unwrap_or(false);
        top = Some((pid, name));
        if is_leader {
            break; // 会话组长 = 顶层可归属进程
        }
        let Some(parent) = table.parent_pid(pid) else {
            break; // 祖先不可读 → 取已回溯的最顶层
        };
        if parent == pid || parent == 0 {
            break;
        }
        pid = parent;
    }
    top
}

// ---------------------------------------------------------------------------
// Linux（/proc 进程树；本机测试平台）
// ---------------------------------------------------------------------------

/// `/proc` 进程表实现。
///
/// - `parent_pid` / 会话组：解析 `/proc/<pid>/stat` 字段 4（ppid）/ 6（session）；
/// - `process_name`：`/proc/<pid>/comm`（同用户可读）；
/// - `exe_path`：`readlink /proc/<pid>/exe`（解析符号链接，得规范化路径）；
/// - 任何读取失败（权限/跨会话/进程消失）→ `None`。
#[cfg(target_os = "linux")]
pub struct ProcfsTable;

#[cfg(target_os = "linux")]
impl ProcessTable for ProcfsTable {
    fn parent_pid(&self, pid: u32) -> Option<u32> {
        proc_stat_field(pid, 3)
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(comm.trim().to_string())
    }

    fn exe_path(&self, pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    fn is_session_leader(&self, pid: u32) -> Option<bool> {
        proc_stat_field(pid, 5).map(|session| session == pid)
    }
}

/// `/proc/<pid>/stat` 字段解析（1-based 字段号；comm 可能含空格/括号，
/// 从最后一个 `)` 之后按空格切分——字段 3 起为 `state ppid pgrp session ...`）。
#[cfg(target_os = "linux")]
fn proc_stat_field(pid: u32, field_1based: usize) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // 字段 3（state）是 after_comm 的第 0 个 → ppid=字段4 → idx 1；session=字段6 → idx 3。
    let idx = match field_1based {
        3 => 1, // ppid
        5 => 3, // session
        _ => return None,
    };
    fields.get(idx)?.parse().ok()
}

/// 对端进程真实 cwd（canonical 形态；`/proc/<pid>/cwd` 是符号链接，readlink
/// 已解析全部符号链接 → 与规则 `projectDir` 比较用 canonical 形态，符号链接
/// 目录绕过必须失败——authorization-gate.md §7）。
#[cfg(target_os = "linux")]
pub fn resolve_peer_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

// ---------------------------------------------------------------------------
// macOS（sysctl KERN_PROC / proc_pidpath）
// ---------------------------------------------------------------------------
//
// libc crate 不导出 `kinfo_proc`；此处按 XNU `sys/proc.h` 公开布局手写
// 前缀结构（x86_64/arm64 指针 8B、pid_t/dev_t 4B）：`extern_proc` 56B
// （union 16 + p_vmspace 8 + p_ppid 8 + p_pid 4 + p_comm 17 + 对齐 3），
// `eproc` 自 kp_eproc 起 e_ppid 在偏移 40。本平台不在 CI 覆盖，保守实现
// （读取失败 → fail-closed）。

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacKinfoProc {
    p_starttime_union: [u64; 2], // union { p_forw/p_back | timeval } 16B
    p_vmspace: *mut core::ffi::c_void,
    p_ppid_ptr: *mut core::ffi::c_void, // struct proc *（父进程指针）
    p_pid: u32,
    p_comm: [i8; 17], // MAXCOMLEN=16 + NUL
    _pad0: [u8; 3],   // 对齐到 8 → extern_proc 56B
    e_paddr: *mut core::ffi::c_void,
    e_sess: *mut core::ffi::c_void,
    e_pgrp: *mut core::ffi::c_void,
    e_ucred: *mut core::ffi::c_void,
    e_vm: *mut core::ffi::c_void,
    e_ppid: u32, // 父进程 pid（kinfo_proc 偏移 96）
    e_pgid: u32,
    e_jobc: i16,
    _pad1: [u8; 2],
    e_tdev: i32,
    e_tpgid: u32,
    e_tsess: *mut core::ffi::c_void,
    e_login: [i8; 12],
    e_spare: [i64; 3],
}

#[cfg(target_os = "macos")]
pub struct SysctlTable;

#[cfg(target_os = "macos")]
impl ProcessTable for SysctlTable {
    fn parent_pid(&self, pid: u32) -> Option<u32> {
        kinfo_proc(pid).map(|k| k.e_ppid)
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        kinfo_proc(pid).map(|k| {
            let end = k
                .p_comm
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(k.p_comm.len());
            String::from_utf8_lossy(&k.p_comm[..end]).to_string()
        })
    }

    fn exe_path(&self, pid: u32) -> Option<String> {
        let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..n as usize]).to_string())
    }

    fn is_session_leader(&self, _pid: u32) -> Option<bool> {
        Some(false) // 顶层判定由 ppid<=1 + 深度上限决定（macOS 无可靠会话组长查询）
    }
}

/// `sysctl CTL_KERN/KERN_PROC/KERN_PROC_PID` → `kinfo_proc` 前缀字段。
#[cfg(target_os = "macos")]
fn kinfo_proc(pid: u32) -> Option<MacKinfoProc> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as i32,
    ];
    let mut info: MacKinfoProc = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<MacKinfoProc>();
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            &mut info as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size < std::mem::size_of::<MacKinfoProc>() {
        return None;
    }
    Some(info)
}

/// 对端进程真实 cwd（macOS 无 procfs；经 sysctl 取 `p_comm` 不可得 cwd——
/// 保守返回 `None` → 授权门拒绝（fail-closed）。桌面内嵌实例在 M2 desktop
/// 任务补充（与 Windows Hello 同批）。
#[cfg(target_os = "macos")]
pub fn resolve_peer_cwd(_pid: u32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Windows（Toolhelp32 进程表 + 对端 PEB cwd）
// ---------------------------------------------------------------------------

/// Toolhelp32 进程表实现（CreateToolhelp32Snapshot + Process32First/NextW）。
///
/// - `parent_pid` / `process_name`：快照进程项（`th32ParentProcessID` / `szExeFile`）；
/// - `is_session_leader`：Windows 无会话组长概念，顶层 = 父进程为 0/4（System）
///   或深度耗尽 → 恒 `false`（不提前截断）；
/// - 跨会话（对端与守护进程不同会话）→ 视为不可信 → fail-closed
///   （在 [`resolve_peer`] 侧先验）。
#[cfg(windows)]
pub struct ToolhelpTable;

#[cfg(windows)]
impl ProcessTable for ToolhelpTable {
    fn parent_pid(&self, pid: u32) -> Option<u32> {
        process_entry(pid).map(|e| e.th32ParentProcessID)
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        process_entry(pid).map(|e| {
            let end = e
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(e.szExeFile.len());
            String::from_utf16_lossy(&e.szExeFile[..end])
        })
    }

    fn exe_path(&self, pid: u32) -> Option<String> {
        self.process_name(pid)
    }

    fn is_session_leader(&self, _pid: u32) -> Option<bool> {
        Some(false) // 顶层判定由 parent 链 + 深度上限决定
    }
}

/// 取进程项（Toolhelp32 快照扫描）。
#[cfg(windows)]
fn process_entry(
    pid: u32,
) -> Option<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == pid {
                    found = Some(entry);
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found
    }
}

/// 对端进程真实 cwd（PEB 读取；同架构假设——跨架构读取失败 → `None` →
/// fail-closed）。步骤：OpenProcess → NtQueryInformationProcess(PEB 地址)
/// → ReadProcessMemory(ProcessParameters → CurrentDirectory.DosPath)。
///
/// 偏移（同架构）：x64 `PEB+0x20` → `RTL_USER_PROCESS_PARAMETERS+0x38`
/// CurrentDirectory.DosPath；x86 `PEB+0x10` → `+0x24`。x64 布局中
/// `+0x30` 是 StandardError 句柄而非 CurrentDirectory——若读错位置，
/// 句柄低 16 位会被当作 Length、DosPath 结构头会被当作 Buffer（垃圾小
/// 指针）：两道防线都 fail-closed（长度 sanity check + ReadProcessMemory
/// 对垃圾指针必然失败）。真实 PEB 回归测试见 mod tests。
/// （依据：RTL_USER_PROCESS_PARAMETERS x64 布局
/// MaximumLength@0x00/Length@0x04/…/StandardError@0x30/
/// CurrentDirectory.CURDIR{DosPath@0x38, Handle@0x48}；
/// 参考 Geoff Chappell 结构研究 / MS Learn winternl.h。）
#[cfg(windows)]
pub fn resolve_peer_cwd(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
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

    const PEB_PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_pointer_width = "64") {
        0x20
    } else {
        0x10
    };
    // CurrentDirectory.DosPath（UNICODE_STRING）：x64 @ +0x38（+0x30 是
    // StandardError 句柄）；x86 @ +0x24。
    const PROCESS_PARAMETERS_CWD_OFFSET: usize = if cfg!(target_pointer_width = "64") {
        0x38
    } else {
        0x24
    };
    // DosPath 长度上限（字节）：Windows 路径硬上限 32767 个 UTF-16 码元
    // （长路径形态的极限），×2 得字节数——合法 cwd 不可能超限，超出即视为
    // 读到错误位置 → fail-closed，不拿垃圾长度做第二次跨进程读取。
    // （注意：错位读到的小句柄值不会触发此上限，由下方 ReadProcessMemory
    // 对垃圾指针必然失败而兜底。）
    const MAX_CWD_DOS_PATH_BYTES: u16 = 32767 * 2;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }
        let result = (|| {
            let mut basic: BasicInfo = std::mem::zeroed();
            if NtQueryInformationProcess(
                handle,
                0,
                &mut basic as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<BasicInfo>() as u32,
                std::ptr::null_mut(),
            ) < 0
            {
                return None;
            }
            // PEB → ProcessParameters 指针
            let mut params_ptr: usize = 0;
            if ReadProcessMemory(
                handle,
                (basic.peb_base as usize + PEB_PROCESS_PARAMETERS_OFFSET) as *const _,
                &mut params_ptr as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            if params_ptr == 0 {
                return None;
            }
            // ProcessParameters → CurrentDirectory（CURDIR = UNICODE_STRING + HANDLE）
            let mut cwd: UNICODE_STRING = std::mem::zeroed();
            if ReadProcessMemory(
                handle,
                (params_ptr + PROCESS_PARAMETERS_CWD_OFFSET) as *const _,
                &mut cwd as *mut _ as *mut _,
                std::mem::size_of::<UNICODE_STRING>(),
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            // Sanity check：Length 为 0 或超出 Windows 路径硬上限都视为读到
            // 错误位置 → fail-closed。
            if cwd.Buffer.is_null() || cwd.Length == 0 || cwd.Length > MAX_CWD_DOS_PATH_BYTES {
                return None;
            }
            let mut buf = vec![0u16; (cwd.Length as usize).div_ceil(2)];
            if ReadProcessMemory(
                handle,
                cwd.Buffer as *const _,
                buf.as_mut_ptr() as *mut _,
                cwd.Length as usize,
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            let path = String::from_utf16_lossy(&buf);
            // 去除 \\?\ 前缀（长路径形态）并规范化
            let path = path
                .strip_prefix(r"\\?\")
                .unwrap_or(path.as_str())
                .to_string();
            std::fs::canonicalize(&path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        })();
        CloseHandle(handle);
        result
    }
}

/// 跨会话先验：对端与守护进程必须同会话，否则视为不可信 → fail-closed。
/// （Linux/macOS 由 /proc、sysctl 的读取权限天然限制跨会话访问。）
#[cfg(windows)]
pub fn peer_session_ok(peer_pid: u32) -> bool {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    unsafe {
        let mut peer_session: u32 = 0;
        let mut self_session: u32 = 0;
        ProcessIdToSessionId(peer_pid, &mut peer_session) != 0
            && ProcessIdToSessionId(std::process::id(), &mut self_session) != 0
            && peer_session == self_session
    }
}

/// 非 Windows 平台跨会话先验恒为真（权限/会话由各平台读取层把关）。
#[cfg(not(windows))]
pub fn peer_session_ok(_peer_pid: u32) -> bool {
    true
}

/// 平台进程表（守护进程装配用）。
#[cfg(target_os = "linux")]
pub fn platform_table() -> Box<dyn ProcessTable> {
    Box::new(ProcfsTable)
}

#[cfg(target_os = "macos")]
pub fn platform_table() -> Box<dyn ProcessTable> {
    Box::new(SysctlTable)
}

#[cfg(windows)]
pub fn platform_table() -> Box<dyn ProcessTable> {
    Box::new(ToolhelpTable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 假进程表（测试注入）。
    struct FakeTable {
        parents: std::collections::HashMap<u32, u32>,
        names: std::collections::HashMap<u32, String>,
        exes: std::collections::HashMap<u32, String>,
        leaders: std::collections::HashSet<u32>,
    }

    impl FakeTable {
        fn new() -> FakeTable {
            FakeTable {
                parents: Default::default(),
                names: Default::default(),
                exes: Default::default(),
                leaders: Default::default(),
            }
        }
        fn chain(&mut self, chain: &[(u32, u32, &str)]) {
            // (pid, parent, exe)
            for &(pid, parent, exe) in chain {
                self.parents.insert(pid, parent);
                self.names.insert(pid, format!("proc{pid}"));
                self.exes.insert(pid, exe.to_string());
            }
        }
    }

    impl ProcessTable for FakeTable {
        fn parent_pid(&self, pid: u32) -> Option<u32> {
            self.parents.get(&pid).copied()
        }
        fn process_name(&self, pid: u32) -> Option<String> {
            self.names.get(&pid).cloned()
        }
        fn exe_path(&self, pid: u32) -> Option<String> {
            self.exes.get(&pid).cloned()
        }
        fn is_session_leader(&self, pid: u32) -> Option<bool> {
            Some(self.leaders.contains(&pid))
        }
    }

    #[test]
    fn walk_finds_topmost_ancestor() {
        // lk(10) ← tool(20) ← agent(30) ← zsh(40, 会话组长)
        let mut t = FakeTable::new();
        t.chain(&[
            (10, 20, "/bin/lk"),
            (20, 30, "/opt/tool"),
            (30, 40, "/usr/bin/agent"),
            (40, 0, "/usr/bin/zsh"),
        ]);
        t.leaders.insert(40);
        assert_eq!(resolve_starter(10, &t), "/usr/bin/zsh");
    }

    #[test]
    fn walk_ends_at_session_leader_immediately() {
        let mut t = FakeTable::new();
        t.chain(&[(10, 20, "/bin/lk"), (20, 20, "/bin/sh")]);
        t.leaders.insert(10);
        assert_eq!(resolve_starter(10, &t), "/bin/lk");
    }

    #[test]
    fn unknown_when_peer_unreadable() {
        // 对端自身读不到（权限/跨会话/进程消失）→ fail-closed unknown
        let t = FakeTable::new();
        assert_eq!(resolve_starter(999_999, &t), UNKNOWN_STARTER);
        assert_eq!(resolve_starter(0, &t), UNKNOWN_STARTER);
    }

    #[test]
    fn topmost_when_middle_ancestor_unreadable() {
        // 中间祖先读不到（Windows Toolhelp 不枚举 smss 等）→ 取已回溯的
        // 最顶层可归属进程（回溯结果依然真实，不 fail-open）
        let mut t = FakeTable::new();
        t.chain(&[(10, 20, "/bin/lk"), (30, 0, "/bin/zsh")]);
        t.leaders.insert(30);
        assert_eq!(resolve_starter(10, &t), "/bin/lk");
    }

    #[test]
    fn unknown_when_peer_missing() {
        let t = FakeTable::new();
        assert_eq!(resolve_starter(999_999, &t), UNKNOWN_STARTER);
        assert_eq!(resolve_starter(0, &t), UNKNOWN_STARTER);
    }

    #[test]
    fn topmost_on_parent_loop() {
        // 父链成环 → 取已回溯的最顶层（不无限循环）
        let mut t = FakeTable::new();
        t.chain(&[(10, 20, "/bin/lk"), (20, 10, "/bin/x")]);
        assert_eq!(resolve_starter(10, &t), "/bin/x");
    }

    #[test]
    fn deep_chain_caps_at_depth() {
        // 深度上限内仍给出顶层（不 fail-closed）；超限取最深层已确定进程
        let mut t = FakeTable::new();
        let mut chain = vec![];
        let mut parent = 0u32;
        for i in (1..=50).rev() {
            chain.push((i, parent, "/bin/deep"));
            parent = i;
        }
        t.chain(&chain);
        let starter = resolve_starter(1, &t);
        assert_ne!(starter, UNKNOWN_STARTER);
        assert_eq!(starter, "/bin/deep");
    }

    #[test]
    fn exe_fallback_to_name() {
        // exe 读不到 → 退化为进程名
        let mut t = FakeTable::new();
        t.chain(&[(10, 20, "/bin/lk"), (20, 0, "/bin/zsh")]);
        t.leaders.insert(20);
        t.exes.remove(&20);
        assert_eq!(resolve_starter(10, &t), "proc20");
    }

    /// Linux 真实进程链：spawn `sh -c sleep`，回溯 sleep 的父链必须经过 sh，
    /// 且顶层给出真实可执行文件路径（本机测试平台）。
    #[cfg(target_os = "linux")]
    #[test]
    fn real_procfs_walk_finds_shell_ancestor() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // 找到 sleep 子进程（sh 的子进程；有界重试，防 pgrep 缺失时挂死）
        let sleep_pid = std::thread::scope(|s| {
            let handle = s.spawn(|| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    assert!(std::time::Instant::now() < deadline, "未找到 sleep 子进程");
                    let table = ProcfsTable;
                    let sh_pid = child.id();
                    // 找一个 sleep 进程：它是 sh 的直接子进程
                    let out = Command::new("pgrep")
                        .args(["-P", &sh_pid.to_string()])
                        .output()
                        .unwrap();
                    let out = String::from_utf8_lossy(&out.stdout);
                    let pid: u32 = out
                        .split_whitespace()
                        .next()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(0);
                    if pid == 0 {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    // sleep 的父进程 = sh
                    assert_eq!(table.parent_pid(pid), Some(sh_pid));
                    // sleep 的父链回溯 → 顶层不是 unknown，且是真实路径
                    let starter_sleep = resolve_starter(pid, &table);
                    assert_ne!(starter_sleep, UNKNOWN_STARTER);
                    assert!(std::path::Path::new(&starter_sleep).exists());
                    // cwd = 我们 spawn 时的目录（canonical）
                    let cwd = resolve_peer_cwd(pid).unwrap();
                    assert_eq!(
                        cwd,
                        std::fs::canonicalize(std::env::current_dir().unwrap())
                            .unwrap()
                            .to_string_lossy()
                            .to_string()
                    );
                    return pid;
                }
            });
            handle.join().unwrap()
        });
        let _ = child.kill();
        let _ = child.wait();
        assert_ne!(sleep_pid, 0);
    }

    /// 符号链接 cwd：/proc/<pid>/cwd readlink 已解析符号链接 → 与 canonical
    /// 规则目录比较成功（authorization-gate.md §7「符号链接目录」）。
    #[cfg(target_os = "linux")]
    #[test]
    fn real_procfs_cwd_resolves_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .current_dir(&link)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let cwd = resolve_peer_cwd(child.id()).unwrap();
        let canonical_real = std::fs::canonicalize(&real)
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(cwd, canonical_real, "cwd 必须是解析符号链接后的真实路径");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Windows x64 真实 PEB 解析：spawn 一个保持存活的子进程
    /// （`cmd /c ping -n 30 127.0.0.1`，约 29s 存活，防退出过快读取不稳），
    /// 走真实 `resolve_peer_cwd`（NtQueryInformationProcess + PEB 偏移 +
    /// ReadProcessMemory），断言读到子进程真实 cwd。覆盖 issue #33 的
    /// x64 CurrentDirectory.DosPath @ +0x38 偏移。
    #[cfg(all(target_os = "windows", target_pointer_width = "64"))]
    #[test]
    fn real_peb_cwd_reads_child_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "ping -n 30 127.0.0.1 > nul"])
            .current_dir(dir.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // 子进程初始化需要时间；有界重试，防 CI 慢启动时偶发 None。
        let expected = std::fs::canonicalize(dir.path())
            .unwrap()
            .to_string_lossy()
            .to_string();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let cwd = loop {
            assert!(child.try_wait().unwrap().is_none(), "子进程提前退出");
            if let Some(cwd) = resolve_peer_cwd(child.id()) {
                break cwd;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "10s 内未能从 PEB 读出子进程 cwd"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(cwd, expected, "PEB 读出的 cwd 必须等于子进程真实目录");
    }
}
