//! 剪贴板：复制后 30 秒自动清除（`lk item copy`，与 browser-fill.md §2 同款行为）。

/// 剪贴板自动清除延迟。
pub const CLEAR_AFTER_SECS: u64 = 30;

/// 复制到剪贴板，并安排 30 秒后清除。
///
/// 清除逻辑：后台线程在 30 秒后把剪贴板置空；若期间剪贴板已被其他程序
/// 改写，仍按「30 秒后清除」语义置空（与规格一致）。
pub fn copy_and_schedule_clear(value: String) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("无法访问剪贴板: {e}"))?;
    cb.set_text(value).map_err(|e| format!("复制失败: {e}"))?;
    drop(cb); // 释放平台句柄，避免后台线程再取时冲突

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(CLEAR_AFTER_SECS));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(String::new());
        }
    });
    Ok(())
}
