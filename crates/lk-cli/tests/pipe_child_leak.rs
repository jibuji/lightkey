//! 回归测试 #59：Windows Git Bash 下 `lk` CLI 的输出管道写句柄不得被自动拉起
//! 的 daemon 子进程继承。
//!
//! 场景：CLI 的 stdout 是（带继承标志的）匿名管道写端——Git Bash 的
//! `lk ... | cat` 正是此形态。`Command::spawn` 走 `CreateProcess` 且
//! `bInheritHandles = TRUE`，若写端仍带继承标志，daemon 会在自己的句柄表里
//! 保留一份副本；即使 CLI 已退出，消费其 stdout 的进程（cat/jq/tail）也永远
//! 等不到 EOF。
//!
//! 本测试在**真实二进制 + 真实拉起路径**上断言最终症状：把本进程 stdout 换成
//! 可继承管道写端（模拟 MSYS），经 `spawn_daemon_exe` 拉起真实 `lk.exe daemon`，
//! 关闭本地写端副本后，读端必须在有限时间内收到 EOF——收到即证明不存在任何
//! 进程（含 daemon）握着写端副本。
//!
//! 仅 Windows 有意义（MSYS/Git Bash 场景；Unix 侧 `pre_exec(setsid)` 无此问题）。

#![cfg(windows)]

use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// 轮询 `daemon.json`（最多 5s）取 daemon pid；拿不到说明拉起失败。
fn poll_daemon_pid(dir: &Path) -> Option<i64> {
    let ep_path = dir.join("daemon.json");
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&ep_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(pid) = v.get("pid").and_then(|p| p.as_i64()) {
                    return Some(pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// 强制结束 daemon（测试清理；避免残留进程占用临时目录/管道）。
fn terminate(pid: i64) {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if !h.is_null() {
            TerminateProcess(h, 0);
            CloseHandle(h);
        }
    }
}

/// 句柄是裸指针（!Send）；跨线程传递先转 usize 再还原（仅句柄值，无所有权语义）。
#[test]
fn daemon_does_not_retain_parent_stdout_pipe_write_handle() {
    // —— 模拟 Git Bash：stdout 是带继承标志的匿名管道写端 ——
    let mut sa: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.bInheritHandle = 1; // BOOL: 两个端都带继承标志，与 MSYS 一致

    let mut read_h: HANDLE = std::ptr::null_mut();
    let mut write_h: HANDLE = std::ptr::null_mut();
    let ok = unsafe { CreatePipe(&mut read_h, &mut write_h, &sa, 0) };
    assert_ne!(
        ok,
        0,
        "CreatePipe 失败：{:?}",
        std::io::Error::last_os_error()
    );

    let orig_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    assert_ne!(
        unsafe { SetStdHandle(STD_OUTPUT_HANDLE, write_h) },
        0,
        "SetStdHandle 失败：{:?}",
        std::io::Error::last_os_error()
    );

    // —— 走真实拉起路径（注入真实 lk 二进制；生产为 current_exe()） ——
    let dir = tempfile::tempdir().expect("临时目录");
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_lk"));
    lk_daemon::transport::spawn_daemon_exe(&exe, dir.path()).expect("拉起 daemon 失败");

    // 恢复 stdout；确认 daemon 确实起来了（防“daemon 秒崩 → 误绿”）
    unsafe { SetStdHandle(STD_OUTPUT_HANDLE, orig_stdout) };
    let pid = poll_daemon_pid(dir.path());
    assert!(pid.is_some(), "daemon 未在 5s 内写出 daemon.json");

    // —— 关闭本地写端副本：若 daemon 继承了一份，读端将永远等不到 EOF ——
    unsafe { CloseHandle(write_h) };

    // 后台阻塞读：EOF（所有写端关闭）→ ReadFile 返回；否则 5s 超时
    let (tx, rx) = std::sync::mpsc::channel::<i32>();
    let read_h_val = read_h as usize;
    std::thread::spawn(move || unsafe {
        let read_h = read_h_val as HANDLE;
        let mut buf = [0u8; 64];
        let mut nread: u32 = 0;
        let r = ReadFile(
            read_h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut nread,
            std::ptr::null_mut(),
        );
        let _ = tx.send(r);
    });

    let result = rx.recv_timeout(Duration::from_secs(5));
    // 无论结果先清理 daemon：杀死后其句柄副本关闭，读线程自然解除阻塞，不泄漏
    if let Some(pid) = pid {
        terminate(pid);
    }

    assert!(
        result.is_ok(),
        "daemon 继承了 CLI stdout 的管道写句柄：读端 5s 未收到 EOF（Git Bash `lk | cat` 即挂死于此，#59）"
    );
}
