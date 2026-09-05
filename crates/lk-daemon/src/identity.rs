//! 规则程序指纹绑定的 daemon 侧（M2.98，identity-binding.md §5/§6）：
//!
//! 1. **对端真实 env PATH 读取**（[`PeerEnv`]，§5.1「信 daemon 不信客户端」）：
//!    - Linux：`/proc/<pid>/environ`（同用户可读）；
//!    - Windows：PEB `ProcessParameters.Environment`（复用 `lk_core::starter`
//!      的 PEB 读取基建——同款偏移表 + 长度 sanity check，读 `PATH=...`）；
//!    - macOS：`sysctl KERN_PROCARGS2`（§12：实现期验证权限与可达性；**失败
//!      → fail-closed**，机制与 `resolve_peer_cwd` 现状同口径）；
//! 2. **`command[0]` → canonical 候选**（[`resolve_exe_path`]，§5.1）：按 PATH
//!    序 + 对端真实 cwd 兜底解析（绝对路径免解析），canonicalize 得绝对路径。
//! 3. **绑定裁决比对序**（[`adjudicate_binding`]，§5.2）+ **内存指纹缓存 +
//!    元信息失效**（[`FingerprintCache`]，§6）：先比路径（免 stat/hash）、再
//!    比 size（先 stat，免 hash）、一致才哈希比对（走缓存，元信息一致复用
//!    = O(stat)）。**缓存不落盘**（落盘可被同用户进程投毒成"自己二进制"的
//!    哈希——正是要防的冒充）。
//!
//! 解析与比对分平台逻辑做成可注入 trait / 纯函数（单测：注入假 env / 假文件
//! 源做确定性断言）；Linux/Windows/macOS 专属读取按 cfg 隔离，macOS 失败
//! fail-closed（cfg 门测试）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lk_core::authz::FingerprintMismatch;
use lk_core::fingerprint;
use lk_core::model::ProgramFingerprint;
use lk_core::Result;

// ---------------------------------------------------------------------------
// 1. 对端真实 env PATH 读取（§5.1）
// ---------------------------------------------------------------------------

/// 对端进程真实 env 的 PATH/PATHEXT（守护进程侧读取；客户端自报一律视为
/// 不可信输入）。失败（不可读/同架构不符/无该变量）→ `None`（调用方按
/// fail-closed 处置）。
pub trait PeerEnv: Send + Sync {
    /// 对端真实 PATH（原始字符串，`:` / `;` 分隔；None = 无法读取 → fail-closed）。
    fn peer_path(&self, pid: u32) -> Option<String>;
    /// 对端真实 PATHEXT（Windows；`;` 分隔的后缀表，issue #133 解析 `command[0]`
    /// 的扩展名探测用）。默认 None：非 Windows 平台无 PATHEXT 语义；Windows
    /// 实现读对端 env 块。None = 无法读取/未设置 → 调用方按平台缺省处理
    /// （Windows 回落常见后缀表，其余平台不探测后缀）。
    fn peer_pathext(&self, _pid: u32) -> Option<String> {
        None
    }
}

/// 平台默认对端 env 读取（Linux `/proc` / Windows PEB / macOS fail-closed）。
#[derive(Default)]
pub struct PlatformPeerEnv;

impl PeerEnv for PlatformPeerEnv {
    fn peer_path(&self, pid: u32) -> Option<String> {
        read_peer_path(pid)
    }
    fn peer_pathext(&self, pid: u32) -> Option<String> {
        #[cfg(windows)]
        {
            read_peer_pathext(pid)
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            None
        }
    }
}

/// 平台分派：读对端真实 env 的 PATH。
#[cfg(target_os = "linux")]
fn read_peer_path(pid: u32) -> Option<String> {
    // /proc/<pid>/environ：NUL 分隔的 `NAME=VALUE` 键值；同用户可读。
    let bytes = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    parse_path_from_environ(&bytes)
}

/// 跨平台通用解析：从 NUL 分隔的键值字节流提取 `PATH=...`（`?` 原样返回）。
/// 纯函数，可注入假 env 字节做单测。无 PATH / 空 → `None`（fail-closed 边界）。
pub fn parse_path_from_environ(bytes: &[u8]) -> Option<String> {
    let path = bytes
        .split(|&b| b == 0)
        .filter(|e| !e.is_empty())
        .find(|e| e.starts_with(b"PATH="))
        .map(|e| String::from_utf8_lossy(&e[5..]).trim().to_string())?;
    (!path.is_empty()).then_some(path)
}

/// 解析 Windows PATHEXT（`;` 分隔，形如 `.COM;.EXE;.BAT;.CMD`）：每项规范化
/// （去空白、补前导 `.`、去空项）后返回；输入为空/纯分隔符 → 空表。纯函数，
/// 跨平台可测（生产仅 Windows 使用——对端 env 无 PATHEXT 时由调用方按平台
/// 缺省处理，见 [`pathext_extensions`]）。大小写保留（Windows FS 大小写不
/// 敏感，探测与比对不受影响）。
pub fn parse_pathext(pathext: &str) -> Vec<String> {
    pathext
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('.') {
                s.to_string()
            } else {
                format!(".{s}")
            }
        })
        .collect()
}

/// Windows env 块（NUL 分隔的 UTF-16 `NAME=VALUE` 串）中按名提取变量值。
/// 纯函数，可注入假块做单测。**env 名大小写不敏感**（Windows 环境块常把
/// PATH 存为 `Path=`/`path=` 等混合大小写；CRT 的 `getenv` 也是大小写无关），
/// 须按 `=` 前段 `eq_ignore_ascii_case` 匹配，否则漏掉真实变量 → fail-closed
/// 误判不可读。无该变量 / 空值 → `None`。
/// 仅 Windows PEB 路径使用（`read_peer_env_block`），其它平台不编译（避免
/// Linux/macOS 构建 dead-code 告警——CI `-D warnings`）。
#[cfg(windows)]
fn extract_var_from_env_block_utf16(block: &str, want: &str) -> Option<String> {
    block.split('\0').find_map(|e| {
        let mut it = e.splitn(2, '=');
        let (name, val) = (it.next()?, it.next()?);
        (name.eq_ignore_ascii_case(want) && !val.is_empty()).then(|| val.to_string())
    })
}

#[cfg(windows)]
fn extract_path_from_env_block_utf16(block: &str) -> Option<String> {
    extract_var_from_env_block_utf16(block, "PATH")
}

#[cfg(windows)]
fn extract_pathext_from_env_block_utf16(block: &str) -> Option<String> {
    extract_var_from_env_block_utf16(block, "PATHEXT")
}

#[cfg(target_os = "macos")]
fn read_peer_path(pid: u32) -> Option<String> {
    // KERN_PROCARGS2：pid → 参数与环境块。实现期验证权限与可达性；读取失败 →
    // fail-closed（None），机制与 resolve_peer_cwd 现状同口径（identity-binding
    // §5.1 / §12：不可行则该平台指纹绑定规则按未命中处理）。
    read_peer_path_procargs2(pid)
}

/// macOS `sysctl CTL_KERN/KERN_PROCARGS2`：取内核返回的 argv/env 块，解析 PATH。
///
/// 布局（XNU）：sysctl 输出开头为 `int argc`（4 字节）+ 8 字节保留
/// （args_length，现已弃用/0），其后是 NUL 结尾的 `argv[0]`（executable 路径），
/// 续接其余 argv[]、env[]（NUL 分隔）。env 项均为 `VAR=VALUE` 形态（含 `=`），
/// argv 项不含 `=`。权限不足 / 布局异常 → 保守 fail-closed（None）。
#[cfg(target_os = "macos")]
fn read_peer_path_procargs2(pid: u32) -> Option<String> {
    // 两次 sysctl：先取回填大小（合理上界防滥用），再读取。
    let mut size: usize = 0;
    let ret = unsafe {
        libc::sysctl(
            [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32].as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 || size > 1_048_576 {
        return None; // 失败 / 超限 → fail-closed
    }
    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32].as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    // 跳过 `argc`（4）+ `args_length`（8）头部；随后自 NUL 分隔段序列中找
    // 第一个 `VAR=VALUE` 形态的段（env 起点的判据——argv 不含 `=`），取其 PATH。
    let rest = &buf[12.min(buf.len())..];
    for seg in rest.split(|&b| b == 0) {
        if let Some(eq) = seg.iter().position(|&b| b == b'=') {
            if eq > 0 && seg.starts_with(b"PATH=") {
                let val = String::from_utf8_lossy(&seg[5..]).trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Windows：PEB `ProcessParameters.Environment`（复用 starter.rs 的 PEB 读取
/// 基建——同款 NtQueryInformationProcess + ReadProcessMemory + 偏移表 + 长度
/// sanity check）。Environment 是 NUL 分隔的 UTF-16 键值块，据此取 `PATH=...`
/// 与 `PATHEXT=...`。
#[cfg(windows)]
fn read_peer_path(pid: u32) -> Option<String> {
    read_peer_env_block(pid).and_then(|b| extract_path_from_env_block_utf16(&b))
}

#[cfg(windows)]
fn read_peer_pathext(pid: u32) -> Option<String> {
    read_peer_env_block(pid).and_then(|b| extract_pathext_from_env_block_utf16(&b))
}

/// Windows PEB 环境块整块读取（UTF-16 → String；PATH/PATHEXT 共用一次读取
/// 基建，两次跨进程读取各自独立）。
#[cfg(windows)]
fn read_peer_env_block(pid: u32) -> Option<String> {
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
    const PEB_PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_pointer_width = "64") {
        0x20
    } else {
        0x10
    };
    // RTL_USER_PROCESS_PARAMETERS.Environment：x64 @ +0x80；x86 @ +0x48。
    // 与 starter.rs 读 CurrentDirectory.DosPath 同款偏移表方法（cwd x64 @
    // +0x38；Environment 在 CommandLine@+0x70 之后 @+0x80）。实测该位存的是
    // 环境块**基址指针**（无 UNICODE_STRING 头）：按指针直读比按结构读更稳。
    const PROCESS_PARAMETERS_ENV_OFFSET: usize = if cfg!(target_pointer_width = "64") {
        0x80
    } else {
        0x48
    };
    // env 块字节长度上限（sanity）：环境块一般 <64 KiB；长度超限或读错位置 →
    // fail-closed，不拿垃圾长度做第二次跨进程读取（与 starter.rs cwd 同防线）。
    const MAX_ENV_BLOCK_BYTES: usize = 32767 * 2;
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
            // Environment 在 `RTL_USER_PROCESS_PARAMETERS` 中为可选的 UTF-16 环境块
            // 指针（x64 @ +0x80；实测该位直接存环境块基址指针，而非 UNICODE_STRING
            // 头——UNICODE_STRING 读法会因 Buffer 字段落在 NULL 区而 fail-closed，
            // 见 identity-binding.md §5.1 Windows 注记）。先读 8 字节指针：
            let mut env_base: usize = 0;
            if ReadProcessMemory(
                handle,
                (params_ptr + PROCESS_PARAMETERS_ENV_OFFSET) as *const _,
                &mut env_base as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            // sanity：基址有效 + 非奇异值（错位读到的小句柄值不触发拷贝）
            if env_base == 0 || env_base == usize::MAX {
                return None;
            }
            // 环境块为引用计数/连续分配，读上界字节（NUL 结尾；UTF-16）。
            // length = 读取的实际字节数（环境块大小未知，按上界读一次，
            // 超限由长度上界守卫；非 NUL 结尾说明读错位置 → 无 PATH fail-closed）
            let mut rawb = vec![0u16; MAX_ENV_BLOCK_BYTES.div_ceil(2)];
            let mut read: usize = 0;
            if ReadProcessMemory(
                handle,
                env_base as *const _,
                rawb.as_mut_ptr() as *mut _,
                MAX_ENV_BLOCK_BYTES,
                &mut read,
            ) == 0
            {
                return None;
            }
            // 截到首个双 NUL（环境块用 `\0\0` 结尾）或实际读取长度，转 UTF-16。
            let uk = rawb.len();
            let end = rawb[..uk]
                .windows(2)
                .position(|w| w[0] == 0 && w[1] == 0)
                .map(|i| i + 2)
                .unwrap_or(uk);
            // 环境块为 NUL 分隔的 `NAME=VALUE` 串（值通常 ASCII，lossy 已是
            // 既有做法）。PATH/PATHEXT 提取在调用方完成——**Windows env 名
            // 大小写不敏感**：环境块里 PATH 常存为 `Path=`（实测）而非
            // `PATH=`，严格前缀会漏掉真实环境 → fail-closed 误判不可读
            // （`eq_ignore_ascii_case` 处理，见
            // [`extract_var_from_env_block_utf16`]）。
            Some(String::from_utf16_lossy(&rawb[..end.min(uk)]))
        })();
        CloseHandle(handle);
        result
    }
}

// ---------------------------------------------------------------------------
// 2. `command[0]` → canonical 候选路径（§5.1；只解析路径，不触碰文件内容）
// ---------------------------------------------------------------------------

/// 解析 `command[0]` → canonical 绝对候选路径：
///
/// - 从对端真实 env 取 PATH（不可读 → fail-closed）；绝对命令免 PATH 解析；
/// - 按 PATH 序 `resolve_exe`（第一个命中即是候选，入参可执行性谓词 =
///   is_file，见 [`resolve_exe_path`] 的调用处）+ 对端真实 cwd 兜底；
/// - canonicalize 得绝对路径（相对候选解析符号链接）。
///
/// 返回 `None` 表示无法解析（env/cwd 缺失、候选不存在、canonical 失败）→
/// 调用方按 fail-closed（绑定规则视同未命中，见 §5.1）。
///
/// **注意**：本函数只做路径解析（不 stat/不哈希），使调用方可以先把路径与
/// 规则比对（§5.2 第 1 步，免其余 IO）。
pub fn resolve_exe_path(
    peer_env: &dyn PeerEnv,
    pid: u32,
    cwd: &str,
    command: &str,
) -> Option<PathBuf> {
    // 对端真实 env PATH（客户端自报不信任）；不可读 → fail-closed
    let path_str = peer_env.peer_path(pid)?;
    #[cfg(windows)]
    let sep = ';';
    #[cfg(not(windows))]
    let sep = ':';
    let path_dirs: Vec<PathBuf> = path_str
        .split(sep)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    // resolve_exe 内置 `cwd` 兜底（PATH 全未命中时的最后一个候选）
    // issue #133：Windows 无扩展名命令（`npm`/`git`/`npx`…）按对端 PATHEXT
    // 逐后缀探测（见 [`pathext_extensions`]），解析结果 = 带后缀的真实文件；
    // 非 Windows 无后缀表 = 探测空、行为与 #132 前完全一致。
    let exts = pathext_extensions(peer_env, pid);
    let ext_refs: Vec<&str> = exts.iter().map(String::as_str).collect();
    let resolved = fingerprint::resolve_exe(command, &path_dirs, Path::new(cwd), &ext_refs, |p| {
        p.is_file()
    })?;
    std::fs::canonicalize(&resolved).ok()
}

/// 本次解析用的可执行后缀表（issue #133）：对端真实 PATHEXT 解析结果；对端
/// 未设置/读取失败 → Windows 平台缺省（cmd 缺省 PATHEXT 序，
/// [`lk_core::fingerprint::EXEC_EXTENSIONS`]），非 Windows 为空表（不探测后缀，
/// 行为与 #132 前完全一致）。
fn pathext_extensions(peer_env: &dyn PeerEnv, pid: u32) -> Vec<String> {
    match peer_env.peer_pathext(pid) {
        Some(p) => parse_pathext(&p),
        None => default_pathext_extensions(),
    }
}

fn default_pathext_extensions() -> Vec<String> {
    #[cfg(windows)]
    {
        lk_core::fingerprint::EXEC_EXTENSIONS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// 绑定裁决结果（调用方据此决定放行 / 转审批）。
pub enum BindingOutcome {
    /// 候选路径/size/哈希与**某条**绑定规则一致 → 静态放行 + 审计。
    Allowed,
    /// 候选解析成功但指纹不符（路径/size/哈希任一）→ 视同未命中 → NeedsApproval
    /// + 失配展示（当前解析路径 + 8 位哈希摘要）。
    Mismatch(FingerprintMismatch),
    /// 候选无法解析（env 读取失败 / PATH+cwd 全未命中 / canonicalize 失败）→
    /// 视同未命中 → NeedsApproval（不携带失配展示——无可解析路径）。
    Unresolved,
}

/// 绑定规则比对（§5.2 比对序），在已解析出候选路径的前提下裁决：
///
/// 1. **路径**：候选 canonical 路径与绑定规则 `exe_path` 不一致 → 失配（免
///    stat/hash，§5.1「PATH 前置假程序」场景）；
/// 2. **size**：先 `stat`（走缓存计数），与规则 `size` 不符 → 失配（免 hash，§6-3）；
/// 3. **hash**：流式 SHA-256（走缓存，元信息一致复用 = O(stat)），不符 → 失配。
///
/// 规则：对绑定规则集，候选路径**与至少一条**匹配即放行（注入由任一条授权
/// 规则裁定；多条绑定不同 exe 的规则对同一 `command[0]` 各自独立——本命令由
/// 匹配的那条裁定）。
///
/// 花销一次 stat + 一次 hash 的上界（hash 仅在路径与 size 都通过后发生，且
/// 元信息一致时复用缓存哈希）。
pub fn adjudicate_binding(
    peer_env: &dyn PeerEnv,
    pid: u32,
    cwd: &str,
    command: &str,
    bound_fps: &[ProgramFingerprint],
    cache: &mut FingerprintCache,
) -> BindingOutcome {
    if bound_fps.is_empty() {
        return BindingOutcome::Allowed; // 未绑定 → 现状语义
    }
    let Some(path) = resolve_exe_path(peer_env, pid, cwd, command) else {
        return BindingOutcome::Unresolved;
    };
    // 1. 路径：候选与任一绑定规则路径一致？（Path 平台无关等值）
    if !bound_fps
        .iter()
        .any(|fp| Path::new(&path) == Path::new(&fp.exe_path))
    {
        // 失配展示：当前解析路径 + 8 位哈希摘要（哈希仅为展示而算，属失配
        // 罕见的人机路径，不违背「决策免哈希」——决策在第 1 步已免哈希判失配）。
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    // 2. size：stat 候选（缓存计数），与任一绑定规则 size 一致？
    let Some(meta) = cache.stat(&path) else {
        return BindingOutcome::Unresolved; // stat 失败（候选消失/不可读）→ fail-closed
    };
    if !bound_fps.iter().any(|fp| fp.size == meta.size) {
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    // 3. hash：流式 SHA-256（缓存；元信息一致复用），与任一绑定规则一致？
    let Some(sha256) = cache.sha256(&path, meta) else {
        return BindingOutcome::Unresolved; // 读取失败 → fail-closed
    };
    if !bound_fps.iter().any(|fp| fp.sha256 == sha256) {
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    BindingOutcome::Allowed
}

/// 构造失配展示信息（当前解析路径 + 8 位哈希摘要；不展示完整值）。
fn mismatch_info(path: &Path, cache: &mut FingerprintCache) -> FingerprintMismatch {
    // 展示时有缓存则给摘要，否则留空（安全不泄露完整值）。
    let sha256_short = cache.resolve_sha256_short(path).unwrap_or_default();
    FingerprintMismatch {
        resolved_exe_path: path.to_string_lossy().into_owned(),
        sha256_short,
    }
}

/// 审批 finalize 侧重算指纹（§5.3「以新指纹重新授权」）：**不信任客户端上报
/// 的 sha256/size**，对请求绑定的 exe_path 重新 canonicalize + stat + 流式
/// SHA-256（走缓存，元信息一致复用）。失败（路径不可解析 / 文件不可读）→
/// `None`（调用方据此 fail：无法绑定到不可达的可执行文件）。
pub fn recompute_fingerprint(
    exe_path: &str,
    cache: &mut FingerprintCache,
) -> Option<ProgramFingerprint> {
    let canonical = std::fs::canonicalize(exe_path).ok()?;
    let meta = cache.stat(&canonical)?;
    let sha256 = cache.sha256(&canonical, meta)?;
    Some(ProgramFingerprint {
        exe_path: canonical.to_string_lossy().into_owned(),
        sha256,
        size: meta.size,
    })
}

// ---------------------------------------------------------------------------
// 3. 指纹缓存（§6：内存 + 元信息失效，不落盘）
// ---------------------------------------------------------------------------

/// 文件元信息快照（**只做失效提示，不作安全依据**——安全依据始终是 SHA-256）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaSnapshot {
    pub size: u64,
    /// 修改时间（unix 纪元纳秒；跨平台归一化）。
    pub mtime_nanos: u64,
    /// 文件索引号（unix inode / Windows file index；平台不可得 → 0）。
    pub file_id: u64,
}

/// 文件源抽象（缓存评估先 stat；hash 流式重算）。注入假实现做确定性单测。
pub trait FingerprintSource: Send + Sync {
    /// stat → 元信息快照（文件不存在 / 不可读 → `None`）。
    fn stat(&self, path: &Path) -> Option<MetaSnapshot>;
    /// 流式 SHA-256（hex 小写；1 MiB 块，不高驻全量）。
    fn hash(&self, path: &Path) -> Result<String>;
}

/// 真实文件系统源。
#[derive(Default)]
pub struct FsFingerprintSource;

impl FingerprintSource for FsFingerprintSource {
    fn stat(&self, path: &Path) -> Option<MetaSnapshot> {
        let meta = std::fs::metadata(path).ok()?;
        Some(snapshot_from_meta(&meta))
    }
    fn hash(&self, path: &Path) -> Result<String> {
        fingerprint::file_sha256(path)
    }
}

/// 平台无关：`std::fs::Metadata` → [`MetaSnapshot`]。
pub(crate) fn snapshot_from_meta(meta: &std::fs::Metadata) -> MetaSnapshot {
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let file_id = file_index(meta);
    MetaSnapshot {
        size: meta.len(),
        mtime_nanos,
        file_id,
    }
}

/// 平台文件索引号（unix inode / Windows file index；不可得 → 0）。
#[cfg(unix)]
fn file_index(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(windows)]
fn file_index(_meta: &std::fs::Metadata) -> u64 {
    // Windows `MetadataExt::file_index` 为 unstable API——本平台遥控返回 0
    // （元信息失效由 size+mtime 承担；file_id 只是失效提示、不作安全依据）。
    0
}

/// 内存指纹缓存条目（daemon 进程内；**不落盘**，§6-1）。
struct CacheEntry {
    meta: MetaSnapshot,
    sha256: String,
}

/// 指纹缓存配额（64 MiB 预计算阈值只决定预计算时机，不改变安全语义——缓存
/// 本身总是按需计算；数值保留为语义文档化，见 identity-binding.md §6-2）。
pub const FINGERPRINT_PRECOMPUTE_THRESHOLD: u64 = 64 * 1024 * 1024;

/// 内存指纹缓存：`exe_path → {sha256, size, mtime, file-id}`。调用方先 `stat`
/// 拿 meta（§5.2 第 2 步），再 `sha256` 复用/重算：
///
/// - `stat` 只做元信息取样计数（`stat_calls`）；
/// - `sha256(path, meta)`：`meta` 与快照一致 → 复用缓存哈希（O(stat)）；不一致
///   或冷态 → 流式全量重算（1 MiB 块）并更新快照（`hash_calls` 计数）。
pub struct FingerprintCache {
    source: Box<dyn FingerprintSource>,
    entries: HashMap<PathBuf, CacheEntry>,
    /// stat 取样计数（测试断言「元信息一致复用 → 只 stat 不重算」）。
    stat_calls: std::sync::atomic::AtomicU64,
    /// 哈希重算计数（测试断言）。用于失配展示的摘要读取也计为 hash_calls。
    hash_calls: std::sync::atomic::AtomicU64,
}

impl FingerprintCache {
    /// 以真实文件系统源构造。
    pub fn new() -> FingerprintCache {
        FingerprintCache::with_source(Box::new(FsFingerprintSource))
    }

    /// 注入文件源（测试用；生产走真实文件系统）。
    pub fn with_source(source: Box<dyn FingerprintSource>) -> FingerprintCache {
        FingerprintCache {
            source,
            entries: HashMap::new(),
            stat_calls: std::sync::atomic::AtomicU64::new(0),
            hash_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for FingerprintCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintCache {
    /// stat 取样 → 元信息快照（文件不存在 / 不可读 → `None` → 调用方 fail-closed）。
    /// 每次调用计数 `stat_calls`。
    pub fn stat(&mut self, path: &Path) -> Option<MetaSnapshot> {
        let meta = self.source.stat(path)?;
        self.stat_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(meta)
    }

    /// 取 `path` 的 SHA-256：传入调用方已 stat 到的 `meta`；若快照元信息与之一致
    /// → 复用缓存哈希（**不重算**）；不一致/冷态 → 流式全量重算并更新快照。
    /// 读取失败 → `None`（调用方 fail-closed）。重算计数 `hash_calls`。
    pub fn sha256(&mut self, path: &Path, meta: MetaSnapshot) -> Option<String> {
        if let Some(e) = self.entries.get(path) {
            if e.meta == meta {
                // 元信息一致 → O(stat) 复用（与文件大小无关）
                return Some(e.sha256.clone());
            }
        }
        let sha256 = self.source.hash(path).ok()?;
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.entries.insert(
            path.to_path_buf(),
            CacheEntry {
                meta,
                sha256: sha256.clone(),
            },
        );
        Some(sha256)
    }

    /// 取 `path` 的 8 位 SHA-256 前缀摘要（失配展示用）。内部先 stat（计
    /// `stat_calls`）再 `sha256`（元信息一致即复用）。文件不可读 → `None`。
    pub(crate) fn resolve_sha256_short(&mut self, path: &Path) -> Option<String> {
        let meta = self.source.stat(path)?;
        self.stat_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sha = if let Some(e) = self.entries.get(path) {
            if e.meta == meta {
                e.sha256.clone()
            } else {
                self.rehash(path, meta)?
            }
        } else {
            self.rehash(path, meta)?
        };
        Some(sha.chars().take(8).collect())
    }

    fn rehash(&mut self, path: &Path, meta: MetaSnapshot) -> Option<String> {
        let sha256 = self.source.hash(path).ok()?;
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.entries.insert(
            path.to_path_buf(),
            CacheEntry {
                meta,
                sha256: sha256.clone(),
            },
        );
        Some(sha256)
    }

    /// stat 取样次数（测试断言）。
    pub fn stat_calls(&self) -> u64 {
        self.stat_calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 哈希重算次数（测试断言）。
    pub fn hash_calls(&self) -> u64 {
        self.hash_calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 假对端 env（测试注入；pathext None = 平台缺省/不探测）。
    #[derive(Clone)]
    struct FakePeerEnv {
        path: Option<String>,
        pathext: Option<String>,
    }
    impl PeerEnv for FakePeerEnv {
        fn peer_path(&self, _pid: u32) -> Option<String> {
            self.path.clone()
        }
        fn peer_pathext(&self, _pid: u32) -> Option<String> {
            self.pathext.clone()
        }
    }

    /// 从 NUL 分隔的 env 字节流提取 PATH（纯函数单测）。
    #[test]
    fn parse_path_from_environ_extracts_path() {
        let bytes = b"HOME=/root\0PATH=/usr/bin:/bin\0SHELL=/bin/sh\0";
        assert_eq!(parse_path_from_environ(bytes), Some("/usr/bin:/bin".into()));
        // 无 PATH → None
        assert_eq!(parse_path_from_environ(b"HOME=/root\0"), None);
        // 空 → None（与 fail-closed 语义一致）
        assert_eq!(parse_path_from_environ(b""), None);
        // PATH 空值 → None（PATH 目录集为空 = 不可解析）
        assert_eq!(parse_path_from_environ(b"PATH=\0"), None);
    }

    /// parse_pathext（issue #133）：PATHEXT `;` 分隔后缀表的解析与规范化。
    #[test]
    fn parse_pathext_normalizes_extension_list() {
        assert_eq!(
            parse_pathext(".COM;.EXE;.BAT;.CMD"),
            vec![".COM", ".EXE", ".BAT", ".CMD"]
        );
        // 去空白 / 补前导点 / 去空项；大小写保留（FS 大小写不敏感）
        assert_eq!(
            parse_pathext(" EXE ;cmd;;.vbs;"),
            vec![".EXE", ".cmd", ".vbs"]
        );
        assert_eq!(parse_pathext("exe;.cmd"), vec![".exe", ".cmd"]);
        // 空 / 纯分隔符 → 空表（不探测任何后缀）
        assert_eq!(parse_pathext(""), Vec::<String>::new());
        assert_eq!(parse_pathext(";; ;"), Vec::<String>::new());
    }

    /// resolve_exe_path 按对端 PATHEXT 逐后缀解析（issue #133 核心路径）：
    /// 命令 "npm publish" → command[0] "npm" 无扩展名 → 无后缀字面候选不存在
    /// → 按 PATHEXT ".EXE;.CMD" 探测到 `<bin>\npm.cmd` → canonicalize 返回
    /// 真实文件路径（含后缀）。用真实临时文件 + 注入假对端 env（PATH+PATHEXT），
    /// 跨平台可跑（Windows 形态在任意 OS 上由假 env 注入复现）。
    #[test]
    fn resolve_exe_path_probes_peer_pathext_extensions() {
        let bin = tempfile::tempdir().unwrap();
        let raw = bin.path().join("npm.cmd");
        std::fs::write(&raw, b"@echo off\r\nset FOO=bar\r\n").unwrap();
        let canonical = std::fs::canonicalize(&raw).unwrap();

        // 带 PATHEXT：无扩展名命令 → 探测到 npm.cmd（大小写敏感 FS 上用同形后缀
        // 复现顺序探测机制；真实 Windows FS 大小写不敏感，大写 `.CMD` 同样
        // 命中小写 `npm.cmd`）
        let env = FakePeerEnv {
            path: Some(bin.path().to_string_lossy().into_owned()),
            pathext: Some(".EXE;.cmd".into()),
        };
        let got = resolve_exe_path(&env, 1, "/proj", "npm publish")
            .expect("PATHEXT 探测应解析出 npm.cmd");
        assert_eq!(got, canonical, "解析结果应为带后缀的真实文件路径");

        // 控制组：对端 PATHEXT 读取失败/未设置 → **平台缺省语义**（issue #133
        // 缺省回落）：Windows 回落 cmd 缺省表（.COM;.EXE;.BAT;.CMD）→ 仍
        // 探测到 npm.cmd；非 Windows 不探测后缀 → 无扩展名命令不可解析
        // （fail-closed 审批）。
        let env2 = FakePeerEnv {
            path: Some(bin.path().to_string_lossy().into_owned()),
            pathext: None,
        };
        #[cfg(windows)]
        assert_eq!(
            resolve_exe_path(&env2, 1, "/proj", "npm publish"),
            Some(canonical),
            "Windows 缺省 PATHEXT 回落应仍解析出 npm.cmd"
        );
        #[cfg(not(windows))]
        assert_eq!(
            resolve_exe_path(&env2, 1, "/proj", "npm publish"),
            None,
            "无 PATHEXT 时无扩展名命令不可解析（fail-closed 审批）"
        );
    }

    /// 假文件源：元信息 + 确定性哈希（测试缓存复用/失效）。
    #[derive(Clone)]
    struct FakeSource {
        meta: MetaSnapshot,
        sha: String,
    }
    impl FingerprintSource for FakeSource {
        fn stat(&self, _path: &Path) -> Option<MetaSnapshot> {
            Some(self.meta)
        }
        fn hash(&self, _path: &Path) -> Result<String> {
            Ok(self.sha.clone())
        }
    }

    fn sha64(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// 元信息一致 → 复用缓存哈希：同路径两次 `stat`+`sha256`，第二次只 stat
    /// （stat_calls=2）不重算（hash_calls=1），且哈希正确返回。
    #[test]
    fn cache_reuses_when_meta_unchanged() {
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 42,
                file_id: 7,
            },
            sha: sha64('a'),
        }));
        let p = PathBuf::from("/bin/node");
        let m1 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m1), Some(sha64('a')));
        let m2 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m2), Some(sha64('a')));
        assert_eq!(cache.hash_calls(), 1, "元信息一致应复用，不重算");
        assert_eq!(cache.stat_calls(), 2, "每次评估先 stat");
    }

    /// 内容改 + mtime/file-id 变 → 重算（hash_calls 增）+ 新哈希。
    #[test]
    fn cache_recomputes_when_meta_changes() {
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 1,
                file_id: 1,
            },
            sha: sha64('a'),
        }));
        let p = PathBuf::from("/bin/node");
        let m1 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m1).unwrap(), sha64('a'));
        // 内容改（同 size）+ mtime 变 → 重算为新哈希
        cache.source = Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 2,
                file_id: 1,
            },
            sha: sha64('b'),
        });
        let m2 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m2).unwrap(), sha64('b'));
        assert_eq!(cache.hash_calls(), 2, "mtime 变应触发重算");
    }

    /// 解析：绝对命令行 command[0] 免 PATH 解析（用解析纯函数的部分断言在
    /// lk-core T1；此处通过注入假 PATH 走完整 `adjudicate_binding` 的路径门）。
    /// 真实文件系统路径测试见集成层（tests/identity_binding.rs）。
    #[test]
    fn platform_peer_env_dispatches_read() {
        // 至少验证 trait 对象可调用（生产平台装配路径不变）。
        let env: Box<dyn PeerEnv> = Box::new(FakePeerEnv {
            path: Some("/bin".into()),
            pathext: Some(".EXE;.CMD".into()),
        });
        assert_eq!(env.peer_path(123), Some("/bin".into()));
        assert_eq!(env.peer_pathext(123), Some(".EXE;.CMD".into()));
        // 缺省实现（生产非 Windows 形态）：未注入 PATHEXT → None（不探测）
        let env2: Box<dyn PeerEnv> = Box::new(FakePeerEnv {
            path: Some("/bin".into()),
            pathext: None,
        });
        assert_eq!(env2.peer_pathext(123), None);
    }

    /// env 块 PATH 提取（Windows PEB 共用纯函数）：**大小写不敏感**——真实
    /// Windows 环境块常把 PATH 存为 `Path=`（实测），严格 `PATH=` 前缀会漏掉
    /// 致 fail-closed 误判不可读。覆盖 `PATH=`/`Path=`/`path=` 与首尾无关的空段、
    /// 驱动隐藏变量（`=C:=C:\...`）、无 PATH / 空值 → None。
    #[cfg(windows)]
    #[test]
    fn env_block_path_extraction_case_insensitive() {
        use crate::identity::extract_path_from_env_block_utf16;
        // 大写（Linux 风格块也被同一纯函数处理）
        assert_eq!(
            extract_path_from_env_block_utf16("HOME=/u\0PATH=/usr/bin:/bin\0PWD=/u"),
            Some("/usr/bin:/bin".into())
        );
        // Windows 实测形态：`Path=` 混合大小写
        assert_eq!(
            extract_path_from_env_block_utf16(
                "ALLUSERSPROFILE=C:\\ProgramData\0AppData=...\0Path=C:\\Windows;C:\\bin\0PWD"
            ),
            Some(r"C:\Windows;C:\bin".into())
        );
        // 驱动隐藏变量（`=C:=C:\...`）不影响 PATH 匹配
        assert_eq!(
            extract_path_from_env_block_utf16("=C:=C:\\work\0PATH=C:\\Windows"),
            Some(r"C:\Windows".into())
        );
        // 无 PATH / 空值 / PATH 非首个 `=` 段 → None（fail-closed 边界）
        assert_eq!(extract_path_from_env_block_utf16("HOME=/u\0PWD=/u"), None);
        assert_eq!(extract_path_from_env_block_utf16("PATH="), None);
        assert_eq!(extract_path_from_env_block_utf16(""), None);
        assert_eq!(extract_path_from_env_block_utf16("MY_PATH=C:\\x"), None);
        // 全小写 path= 命中；PATH_FOO（非精确名）不误命中
        assert_eq!(
            extract_path_from_env_block_utf16("LOCALAPPDATA=C:\\x\0path=C:\\bin\0PATH_FOO=1"),
            Some(r"C:\bin".into())
        );
    }

    /// env 块 PATHEXT 提取（issue #133）：大小写不敏感 + 与 PATH 恰为独立变量
    /// （`PATH=` 段不误取为 PATHEXT）；无 PATHEXT / 空值 → None。
    #[cfg(windows)]
    #[test]
    fn env_block_pathext_extraction_case_insensitive() {
        use crate::identity::extract_pathext_from_env_block_utf16;
        // 标准大写形态
        assert_eq!(
            extract_pathext_from_env_block_utf16("PATHEXT=.COM;.EXE;.BAT;.CMD\0HOME=/u"),
            Some(".COM;.EXE;.BAT;.CMD".into())
        );
        // 混合大小写（Windows env 名大小写不敏感）
        assert_eq!(
            extract_pathext_from_env_block_utf16("PathExt=.EXE;.CMD\0PATH=C:\\bin"),
            Some(".EXE;.CMD".into())
        );
        // 只读 PATH / PATH_FOO 不得误命中；空值 → None（fail-closed 边界）
        assert_eq!(
            extract_pathext_from_env_block_utf16("PATH=C:\\Windows"),
            None
        );
        assert_eq!(extract_pathext_from_env_block_utf16("PATHEXT="), None);
        assert_eq!(extract_pathext_from_env_block_utf16(""), None);
        assert_eq!(
            extract_pathext_from_env_block_utf16("PATHEXT_FOO=.EXE\0TMP=C:\\x"),
            None
        );
    }

    /// 平台侧真实对端 env PATHEXT 读取（Windows PEB，issue #133 主平台回灌）：
    /// 本进程 PEB env 块的 PATHEXT 应可读且与本进程 env 一致（PEB 直读与
    /// CRT `std::env` 同源）。缺失时宽松跳过（极端自定义环境并非失败）。
    #[cfg(windows)]
    #[test]
    fn real_peer_pathext_reads_current_process_pathext() {
        let got = PlatformPeerEnv.peer_pathext(std::process::id());
        let own = std::env::var("PATHEXT").unwrap_or_default();
        if own.is_empty() {
            return; // 环境未设 PATHEXT（异常环境）→ 不硬性断言
        }
        let got = got.expect("本进程 PEB env 的 PATHEXT 应可读");
        assert!(
            got.eq_ignore_ascii_case(&own),
            "PEB 读出的 PATHEXT 与本进程 env 不一致：peb={got:?} own={own:?}"
        );
    }

    /// 平台侧真实对端 env PATH 读取（Windows PEB，regression）：当前测试
    /// 进程自身必然可读（OpenProcess 当前 pid + PROCESS_VM_READ），读出的
    /// PATH 应包含本进程 env 的 `PATH=...` 值（至少非空、且与本进程自上而下
    /// 的 `std::env::var("PATH")` 共享同一份环境）。守卫：改为按指针直读
    /// RTL_USER_PROCESS_PARAMETERS.Environment（非 UNICODE_STRING 头），
    /// 该回归测试可防止再次落到「Buffer 读 NULL → fail-closed」；并钉住
    /// **Windows env 名大小写不敏感**（真实块常把 PATH 存为 `Path=`，严格
    /// 大写 `PATH=` 前缀会漏掉 → 误判不可读，见下方 `eq_ignore_ascii_case`）。
    #[cfg(windows)]
    #[test]
    fn real_peer_path_reads_current_process_path() {
        let path = PlatformPeerEnv.peer_path(std::process::id());
        assert!(
            matches!(&path, Some(p) if !p.is_empty()),
            "本进程的 PEB env PATH 应可读，got: {path:?}"
        );
        // PATH 值应与本进程真实 PATH 一致（同源；分隔符由平台解析，此处只
        // 断言「读出值存在于本进程 PATH」的强度：检出任一目录段非空即可）。
        let own = std::env::var("PATH").unwrap_or_default();
        if !own.is_empty() {
            let sep = if cfg!(windows) { ';' } else { ':' };
            let own_dirs: Vec<&str> = own.split(sep).filter(|s| !s.is_empty()).collect();
            assert!(
                !own_dirs.is_empty() || own.is_empty(),
                "本进程 PATH 段缺失，无法对照"
            );
            let p = path.unwrap();
            let read_dirs: Vec<&str> = p.split(sep).filter(|s| !s.is_empty()).collect();
            // 宽松断言：读出的 PATH 与本进程 PATH 至少有一个共通非空段
            assert!(
                read_dirs.iter().any(|d| own_dirs.contains(d)),
                "PEB 读出的 PATH 段与本进程 PATH 无交集：read={:?} own={:?}",
                read_dirs,
                own_dirs
            );
        }
    }
}
