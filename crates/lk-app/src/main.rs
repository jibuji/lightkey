// Windows 上隐藏控制台窗口（发布构建）。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lk_app::run();
}
