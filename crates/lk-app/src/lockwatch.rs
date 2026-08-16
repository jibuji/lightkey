//! 锁屏自动锁定（`docs/ipc.md` §5；决策 #4 A 配套）。
//!
//! 检测系统会话锁 → 守护进程 `lock_with_reason(LockReason::Lockscreen)`
//! → 事件总线广播 `session.locked(reason=lockscreen)` → 通知桥推送前端
//! 回解锁页（spec §6.1）。
//!
//! 平台实现（cfg 隔离；验收平台 = Windows，CI 在 Windows 检查）：
//! - **Windows**：隐藏消息窗口 + `WTSRegisterSessionNotification`，
//!   `WM_WTSSESSION_CHANGE`（wParam=WTS_SESSION_LOCK）→ 锁定（事件驱动）；
//! - **macOS**：`CGSessionCopyCurrentDictionary` 会话字典轮询（2s），
//!   `CGSSessionScreenIsLocked` → 锁定（CoreGraphics C API，免 objc 绑定）；
//! - **Linux**：非验收平台，no-op。

use std::sync::{Arc, Mutex};

use lk_core::bus::LockReason;

/// 启动锁屏监听（守护进程引用；锁定为进程内直接调用）。
#[cfg(windows)]
pub fn spawn(daemon: Arc<Mutex<lk_daemon::Daemon>>) {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::RemoteDesktop::WTSRegisterSessionNotification;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, RegisterClassW, WNDCLASSW,
    };

    const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
    /// WTS_SESSION_LOCK（wtsapi32.h；会话锁事件）。
    const WTS_SESSION_LOCK: usize = 0x7;
    /// NOTIFY_FOR_THIS_SESSION（仅本会话的通知）。
    const NOTIFY_FOR_THIS_SESSION: u32 = 0;

    /// 隐藏窗口进程：收到 WTS 会话锁 → 锁定守护（幂等：已锁则无操作）。
    static DAEMON: std::sync::OnceLock<Arc<Mutex<lk_daemon::Daemon>>> = std::sync::OnceLock::new();
    let _ = DAEMON.set(daemon);

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_WTSSESSION_CHANGE && wparam == WTS_SESSION_LOCK {
            if let Some(daemon) = DAEMON.get() {
                if let Ok(mut guard) = daemon.lock() {
                    guard.lock_with_reason(LockReason::Lockscreen);
                }
            }
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = widestring("LightKeyLockscreenWnd");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );
        // 主线程消息泵（Tauri/tao 事件循环）会派发 WM_WTSSESSION_CHANGE
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
    }

    fn widestring(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

/// macOS：CGSessionCopyCurrentDictionary 轮询（2s；会话字典无「已锁」键
/// 或获取失败 → 不锁定——headless 不误锁）。
#[cfg(target_os = "macos")]
pub fn spawn(daemon: Arc<Mutex<lk_daemon::Daemon>>) {
    use core_foundation::base::{CFTypeRef, TCFType};
    use core_foundation::boolean::kCFBooleanTrue;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    // CoreGraphics 会话字典 API（登录会话/屏幕锁状态）；kCFBooleanTrue 由
    // core-foundation crate 链接 CoreFoundation。
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
    }

    fn screen_is_locked() -> bool {
        unsafe {
            let dict = CGSessionCopyCurrentDictionary();
            if dict.is_null() {
                return false;
            }
            let dict = CFDictionary::wrap_under_create_rule(dict as *const _);
            let key = CFString::new("CGSSessionScreenIsLocked");
            dict.find(&key)
                .map(|v| *v as usize == kCFBooleanTrue as usize)
                .unwrap_or(false)
        }
    }

    std::thread::Builder::new()
        .name("lk-lockscreen".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if screen_is_locked() {
                if let Ok(mut guard) = daemon.lock() {
                    guard.lock_with_reason(LockReason::Lockscreen);
                }
            }
        })
        .expect("锁屏监听线程可启动");
}

/// Linux：非验收平台（CI 仅 Windows），不注册锁屏监听。
#[cfg(all(unix, not(target_os = "macos")))]
pub fn spawn(_daemon: Arc<Mutex<lk_daemon::Daemon>>) {}
