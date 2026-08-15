//! LightKey 桌面应用（Tauri 2 壳）。
//!
//! M2 里程碑接入：主窗口、前端 IPC 桥、解锁/锁定联动、审批弹窗、托盘。
//! 骨架阶段仅启动一个空窗口承载前端占位页。桌面与 CLI 共享 `lk-core`，
//! 通过守护进程的本地 IPC 访问已解锁库（见 `docs/ipc.md`）。

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running LightKey desktop app");
}
