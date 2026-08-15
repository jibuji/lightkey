//! 剪贴板：复制后 30 秒自动清除（`lk item copy`，与 browser-fill.md §2 同款行为）。
//!
//! 清除由调用方主线程 sleep 后**同步**执行（见 `main.rs` `cmd_item_copy`），
//! 不 spawn 后台线程：`process::exit` 不 join 线程、会立即杀死后台线程，
//! 清除是否执行是竞态（G2 修复）。

/// 剪贴板自动清除延迟。
pub const CLEAR_AFTER_SECS: u64 = 30;

/// 复制到剪贴板。
pub fn copy(value: String) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("无法访问剪贴板: {e}"))?;
    cb.set_text(value).map_err(|e| format!("复制失败: {e}"))?;
    Ok(())
}

/// 清空剪贴板（30 秒自动清除的同步执行）。
///
/// 若期间剪贴板已被其他程序改写，仍按「30 秒后清除」语义置空（与规格一致）。
pub fn clear() -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("无法访问剪贴板: {e}"))?;
    cb.set_text(String::new())
        .map_err(|e| format!("清空失败: {e}"))?;
    Ok(())
}
