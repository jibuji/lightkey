//! 用户数据目录解析（跨平台）。
//!
//! 决策 #2 A 下沉共享：`lk-cli`（`lk --dir`）与桌面应用（M2 desktop，
//! 内置守护实例）复用同一解析逻辑，保证 CLI 与桌面访问同一数据目录。
//!
//! 优先级：`lk --dir <path>` > 环境变量 `LIGHTKEY_HOME` > 平台默认。
//! 平台默认（与用户级私密数据一致，目录本身 0700 / 用户私有）：

use std::path::PathBuf;

/// 解析数据目录。
pub fn data_dir(flag: Option<&std::path::Path>) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Ok(h) = std::env::var("LIGHTKEY_HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    platform_default()
}

#[cfg(windows)]
fn platform_default() -> PathBuf {
    // %APPDATA%\lightkey（RoamingAppData，用户私有）
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("lightkey")
}

#[cfg(target_os = "macos")]
fn platform_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("Library/Application Support/lightkey")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_default() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("lightkey");
        }
    }
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local/share/lightkey")
}
