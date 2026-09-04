//! 进程级内存加固（issue #76 `lk inject` secret 值在 CLI 进程的内存生命周期）。
//!
//! 目标：给注入的 secret 值在 CLI 进程里的明文持有最短化：
//! - `harden_process()`：进程启动早期把本进程的崩溃转储（core dump / WER）
//!   路径关掉，使崩溃时内存里的 secret 明文不落下磁盘；
//! - `zeroize_env()`：secret env 值在写入子进程 env 后立即清零。
//!
//! 实现注记（issue #119 / decisions.md 补充拍板 #26）：Linux 分支**不用**
//! `prctl(PR_SET_DUMPABLE, 0)`——非 dumpable 进程的 `/proc/<pid>/cwd` /
//! `environ` / `exe` 对同用户守护进程返回 EACCES（`ptrace_may_access` 门），
//! 启动者归因（#66）取不到对端 cwd → 授权门第 1 层 fail-closed，Linux 上
//! inject / 读 / 写全拒。改为 `setrlimit(RLIMIT_CORE, {0, 0})`：禁 core dump
//! 落盘的承诺保留；且 rlimit 可被 fork/exec 继承——`lk inject` 注入的整棵
//! 命令子树同样禁 core，比原实现覆盖更广（子进程 exec 后 dumpable 会复位，
//! 原 `PR_SET_DUMPABLE` 只护住 CLI 自身）。代价：失去「限制非相关进程
//! ptrace」的副产品——该能力本就在 #15/#17 声明边界外（不防同用户调试器），
//! 且 Debian/Ubuntu 默认 `kernel.yama.ptrace_scope=1` 已限制非父子进程
//! ptrace。威胁模型其余边界不变：这些加固**降低**同用户调试器/tracer 读取
//! 内存的成功面，但**不防**持有同用户身份的调试器直接 ptrace/inject 本进程
//! （进程内存仍可被读取）；同用户进程互信被划在防护边界之外，见
//! docs/decisions.md 补充拍板 #15 与本条目 decisions.md 补充拍板 #17/#26。

use std::collections::BTreeMap;
use zeroize::Zeroize;

/// 应用进程级加固（各平台尽力实现）。
///
/// - Linux：`setrlimit(RLIMIT_CORE, {0, 0})`，禁用 core dump（软/硬限都置 0，
///   子进程继承；**不再清 PR_SET_DUMPABLE**——非 dumpable 会令同用户守护进程
///   读 `/proc/<pid>/{cwd,environ,exe}` 得 EACCES，启动者归因 fail-closed 致
///   授权门全拒，见 issue #119 与 decisions.md 补充拍板 #26）。
/// - Windows：`SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)`，
///   尽力抑制 WER 错误框，减少崩溃时被采样的窗口（尽力实现，验收以 Linux 主；
///   见 decisions.md 补充拍板 #17）。
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // 失败不致命：加固是尽力而为，任何 setrlimit 返回 -1 都保持进程可继续运行。
        // 软/硬限都置 0 是合法降级（降低硬限不需要特权），子进程继承后无法再抬高。
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &zero);
        }
    }
    #[cfg(windows)]
    {
        unsafe {
            let _ = windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(
                windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS
                    | windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX,
            );
        }
    }
    // 其他平台（macOS 等）：暂无等效进程级设置；core dump 由 shell `ulimit -c`
    // 控制，文档层面声明边界（见模块级文档）。
}

/// 清零 secret env 值的内存（每个 `String` 的整个堆容量）。
///
/// 注入路径在 `child.envs(&env)` 之后调用：`Command::envs` 只是借用——
/// 子进程所需值已被 Command 拷贝进自己的存储，调用后 `env` 仍归调用方所有，
/// 可继续可变借用逐一清零，再随 drop 释放。`String::zeroize()` 直接原地擦除
/// 底层堆缓冲并截断为空串（zeroize crate 对 `String` 的内建实现，无 unsafe
/// 绕路）。
pub fn zeroize_env(env: &mut BTreeMap<String, String>) {
    for value in env.values_mut() {
        value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zeroize_env` 清零所有值：每个值被 `String::zeroize()` 截断为空串
    /// （连同其堆缓冲一起清零）。
    #[test]
    fn zeroize_env_clears_all_values() {
        let mut env = BTreeMap::new();
        env.insert("NPM_TOKEN".into(), "s3cr3t-t0ken".into());
        env.insert("AWS_SECRET".into(), "x".into());
        env.insert("EMPTY".into(), String::new());

        zeroize_env(&mut env);

        for v in env.values() {
            assert!(v.is_empty(), "zeroize 后值应为空串（长度截断为 0）：{v:?}");
        }
    }

    /// 真实验证 `String` 的底层堆缓冲被清零（NUL），而非仅截断长度。
    ///
    /// `String::into_bytes()` 与 `String` 共享同一堆分配（O(1) 无拷贝），
    /// 其上的 `Zeroize` 正是 `String::zeroize()` 的同一条内部路径。这里保留
    /// 原始缓冲指针，清零后用 `slice::from_raw_parts` 读回原长度字节区，断言
    /// 全部为 NUL——证明明文字节确实被抹除；测试内的窄 unsafe 探针是验证该
    /// 安全性质的直接手段。
    #[test]
    fn zeroize_zeroes_heap_buffer() {
        let secret = "s3cr3t-t0ken";
        let mut bytes = String::from(secret).into_bytes();
        let cap = bytes.len();
        let ptr = bytes.as_mut_ptr();

        bytes.zeroize(); // 与 String::zeroize 同一 `as_mut_vec().zeroize()` 路径

        unsafe {
            let restored = std::slice::from_raw_parts(ptr, cap);
            assert!(
                restored.iter().all(|&b| b == 0),
                "原始长度区域内字节应全部被抹为 NUL"
            );
        }
        // 长度已随 zeroize 截断为 0。
        assert_eq!(bytes.len(), 0);
    }

    /// issue #119 回归：`harden_process()` 不得破坏 daemon 侧启动者归因。
    ///
    /// 根因：旧实现 Linux 分支 `prctl(PR_SET_DUMPABLE, 0)` 使本进程非
    /// dumpable——同用户守护进程跨进程读 `/proc/<pid>/{cwd,environ,exe}` 走
    /// `ptrace_may_access` 门返回 EACCES，`starter::resolve_peer_cwd` 取不到
    /// 对端 cwd → 授权门第 1 层 fail-closed，Linux 上 inject/读/写全拒
    /// （issue #119，探针实证见 PR #118 与本测试）。
    ///
    /// 本测试 fork 一个子进程执行 `harden_process()` 后挂起（模拟已加固的
    /// CLI 对端），父进程（模拟 daemon）以真实跨进程身份断言：
    ///   1. `lk_core::starter::resolve_peer_cwd(pid)` 仍可读（授权门第 1 层
    ///      数据源不 fail-closed）；
    ///   2. `lk_daemon::identity::PlatformPeerEnv::peer_path(pid)`（对端
    ///      `/proc/<pid>/environ` 的 PATH）仍可读（M2.98 指纹绑定 Linux 面，
    ///      identity-binding.md §5.1）；
    ///   3. 子进程保持 dumpable（`PR_GET_DUMPABLE` 自报 1，经退出码回传）——
    ///      `/proc` 可视性的开关；
    ///   4. 子进程 `RLIMIT_CORE` 为 0（自报，经退出码回传）——#76「core dump
    ///      不落明文」的目标由 rlimit 承接。
    #[cfg(target_os = "linux")]
    #[test]
    fn hardening_keeps_peer_attribution_readable() {
        use lk_daemon::identity::PeerEnv;
        let rc = unsafe { libc::fork() };
        assert!(rc >= 0, "fork 失败");
        let pid = rc as u32;
        if rc == 0 {
            // 子进程：与 lk CLI 启动同款加固，然后自检两项安全性质并挂起，
            // 让父进程以真实跨进程身份读 /proc。
            harden_process();
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let gr = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
            // 退出码比特位：1 = RLIMIT_CORE 非 0，2 = 非 dumpable（0 = 全好）。
            let code = (gr != 0 || lim.rlim_cur != 0) as i32 | ((dumpable != 1) as i32) << 1;
            unsafe {
                libc::kill(libc::getpid(), libc::SIGSTOP);
                libc::_exit(code);
            }
        }
        // 父进程：等待子进程 SIGSTOP（加固已完成、进程存续）→ 读对端 /proc。
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED);
        }
        // 1) cwd 归因（daemon 授权门第 1 层数据源；issue #119 的直接断点）
        let cwd = lk_core::starter::resolve_peer_cwd(pid);
        assert!(
            cwd.is_some(),
            "harden 后对端 cwd 必须仍可读——非 dumpable 致 /proc EACCES 时授权门全拒（issue #119）：{cwd:?}"
        );
        // 2) 对端 environ PATH（M2.98 指纹绑定数据源；与 cwd 同门）
        let path = lk_daemon::identity::PlatformPeerEnv.peer_path(pid);
        assert!(
            path.is_some(),
            "harden 后对端 environ PATH 必须仍可读（issue #119 / identity-binding.md §5.1）：{path:?}"
        );
        // 收尾：恢复子进程并回收，核对子进程自报的 dumpable / RLIMIT_CORE。
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGCONT);
            libc::waitpid(pid as libc::pid_t, &mut status, 0);
        }
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "子进程自检失败：应保持 dumpable（1）且 RLIMIT_CORE=0（#76），退出码 = {}",
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            }
        );
    }
}
