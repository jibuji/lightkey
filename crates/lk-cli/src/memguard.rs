//! 进程级内存加固（issue #76 `lk inject` secret 值在 CLI 进程的内存生命周期）。
//!
//! 目标：给注入的 secret 值在 CLI 进程里的明文持有最短化：
//! - `harden_process()`：进程启动早期把本进程的崩溃转储（core dump / WER）
//!   路径关掉，使崩溃时内存里的 secret 明文不落下磁盘；
//! - `zeroize_env()`：secret env 值在写入子进程 env 后立即清零。
//!
//! 威胁模型边界（诚实声明）：这些加固**降低**同用户调试器/tracer 读取内存的
//! 成功面，但**不防**持有同用户身份的调试器直接 ptrace/inject 本进程（进程
//! 内存仍可被读取）；同用户进程互信被划在防护边界之外，见 docs/decisions.md
//! 补充拍板 #15 与本条目 decisions.md 补充拍板 #17。

use std::collections::BTreeMap;
use zeroize::Zeroize;

/// 应用进程级加固（各平台尽力实现）。
///
/// - Linux：`prctl(PR_SET_DUMPABLE, 0)`，禁用 core dump（同时限制非相关进程
///   直接 ptrace 本进程；同用户父进程/调试器边界外，见模块级文档与
///   decisions.md 补充拍板 #17）。
/// - Windows：`SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)`，
///   尽力抑制 WER 错误框，减少崩溃时被采样的窗口（尽力实现，验收以 Linux 主；
///   见 decisions.md 补充拍板 #17）。
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // 失败不致命：加固是尽力而为，任何 prctl 返回 -1 都保持进程可继续运行。
        unsafe {
            let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
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

    /// Linux：`prctl(PR_SET_DUMPABLE, 0)` 后 `/proc/self/status` 的
    /// `Dumpable:` 字段为 0（0 = 禁止 dump）。设置后恢复原值，避免影响同进程
    /// 其他测试/环境。
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dumpable_becomes_zero_and_restores() {
        let original = read_dumpable();
        harden_process();
        assert_eq!(
            read_dumpable(),
            0,
            "prctl(PR_SET_DUMPABLE, 0) 后 Dumpable 应为 0"
        );
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, original, 0, 0, 0);
        }
        assert_eq!(read_dumpable(), original, "恢复原 dumpable 值");
    }

    /// 取当前 dumpable 值：`prctl(PR_GET_DUMPABLE)`（不依赖 procfs——部分
    /// 内核/WSL2 的 `/proc/self/status` 不暴露 `Dumpable:` 字段，但 prctl
    /// 本身生效，见 issue #76 验证记录）。
    #[cfg(target_os = "linux")]
    fn read_dumpable() -> i32 {
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }
    }
}
