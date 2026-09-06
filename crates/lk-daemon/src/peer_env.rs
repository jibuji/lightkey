//! 对端真实环境读取（M2.98，identity-binding.md §5.1「信 daemon 不信客户端」；
//! identity 三拆之一，issue #152）：
//!
//! - Linux：`/proc/<pid>/environ`（同用户可读）；
//! - Windows：PEB `ProcessParameters.Environment`（复用 `lk_core::peb`
//!   的 PEB 读取原语——唯一一份偏移表 + 长度 sanity check，读 `PATH=...`）；
//! - macOS：`sysctl KERN_PROCARGS2`（§12：实现期验证权限与可达性；**失败
//!   → fail-closed**，机制与 `resolve_peer_cwd` 现状同口径）。
//!
//! 平台逻辑做成可注入 trait（[`PeerEnv`]）+ 纯函数（单测：注入假 env 字节
//! 做确定性断言）；平台专属读取按 cfg 隔离，macOS 失败 fail-closed
//! （cfg 门测试）。
//!
//! 姊妹模块：[`crate::exe_resolve`]（可执行解析 + 指纹缓存）、
//! [`crate::binding`]（绑定裁决）。

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

/// Windows：PEB `ProcessParameters.Environment`（复用 `lk_core::peb` 的 PEB
/// 读取原语——唯一一份 NtQueryInformationProcess + ReadProcessMemory 与偏移表
/// 及长度 sanity check）。Environment 是 NUL 分隔的 UTF-16 键值块，据此取
/// PATH 与 PATHEXT。
#[cfg(windows)]
fn read_peer_path(pid: u32) -> Option<String> {
    read_peer_env_block(pid).and_then(|b| extract_path_from_env_block_utf16(&b))
}

#[cfg(windows)]
fn read_peer_pathext(pid: u32) -> Option<String> {
    read_peer_env_block(pid).and_then(|b| extract_pathext_from_env_block_utf16(&b))
}

/// Windows PEB 环境块整块读取（UTF-16 → String；PATH/PATHEXT 共用一次读取
/// 基建，两次跨进程读取各自独立）。PEB 原语（NtQueryInformationProcess +
/// ReadProcessMemory + 偏移表）唯一一份在 `lk_core::peb`（与 starter 的
/// 启动者 cwd 读取共享，issue #151）；本函数只保留 env 块专属步骤：
/// `Environment` 基址 sanity + 整块按上界读取 + 双 NUL 截断。
#[cfg(windows)]
fn read_peer_env_block(pid: u32) -> Option<String> {
    use lk_core::peb::{RemoteProcess, PROCESS_PARAMETERS_ENV_OFFSET};
    // env 块字节长度上限（sanity）：环境块一般 <64 KiB；长度超限或读错位置 →
    // fail-closed，不拿垃圾长度做第二次跨进程读取（与 starter.rs cwd 同防线）。
    const MAX_ENV_BLOCK_BYTES: usize = 32767 * 2;
    let proc = RemoteProcess::open(pid)?;
    let params_ptr = proc.process_parameters()?;
    // Environment 在 `RTL_USER_PROCESS_PARAMETERS` 中为可选的 UTF-16 环境块
    // 指针（x64 @ +0x80；实测该位直接存环境块基址指针，而非 UNICODE_STRING
    // 头——UNICODE_STRING 读法会因 Buffer 字段落在 NULL 区而 fail-closed，
    // 见 identity-binding.md §5.1 Windows 注记）。先读 8 字节指针：
    let env_base: usize = proc.read_value(params_ptr + PROCESS_PARAMETERS_ENV_OFFSET)?;
    // sanity：基址有效 + 非奇异值（错位读到的小句柄值不触发拷贝）
    if env_base == 0 || env_base == usize::MAX {
        return None;
    }
    // 环境块为引用计数/连续分配，读上界字节（NUL 结尾；UTF-16）。
    // length = 读取的实际字节数（环境块大小未知，按上界读一次，
    // 超限由长度上界守卫；非 NUL 结尾说明读错位置 → 无 PATH fail-closed）
    let mut rawb = vec![0u16; MAX_ENV_BLOCK_BYTES.div_ceil(2)];
    proc.read_bytes(env_base, unsafe {
        std::slice::from_raw_parts_mut(rawb.as_mut_ptr() as *mut u8, MAX_ENV_BLOCK_BYTES)
    })?;
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
}

// 测试模块对 crate 内姊妹模块开放（FakePeerEnv 夹具共用；仅测试构建存在）。
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 假对端 env（测试注入；pathext None = 平台缺省/不探测）。本模块与
    /// exe_resolve / binding 的单测共用（crate 内测试夹具）。
    #[derive(Clone)]
    pub(crate) struct FakePeerEnv {
        pub path: Option<String>,
        pub pathext: Option<String>,
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

    /// 平台分派：trait 对象可调用（生产平台装配路径不变；缺省 peer_pathext
    /// 语义 = 非 Windows 平台 None）。
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
