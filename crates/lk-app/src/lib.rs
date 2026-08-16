//! LightKey 桌面应用（Tauri 2 壳）——M2 desktop（`docs/milestones.md` M2）。
//!
//! C 层壳职责（`docs/plugin-architecture.md` §3.3：宿主只做编排与呈现，
//! 不复制业务逻辑）：
//!
//! - **内置守护实例**（决策 #2 A）：进程内起守护线程（`lk_daemon` 共享
//!   crate），同时 serve 本地 socket 供 `lk` CLI 复用；托盘退出 = 守护
//!   退出 = 锁定，生命周期一致；
//! - **tauri command 桥**：前端 `invoke` → 守护进程 JSON-RPC（`rpc`），
//!   通知订阅（`subscribe`：PushHub → 本进程线程 → Tauri 事件 → 前端
//!   翻译为 Cordis 事件，决策 #3 A）；
//! - **窗口/托盘**（决策 #4 A）：关闭 = 隐藏托盘、保持解锁；侧栏「锁定」
//!   = 锁定；托盘「退出」= 退出即锁；托盘菜单含 显示/锁定/退出；
//! - **锁屏自动锁定**（`docs/ipc.md` §5）：Windows WTS / macOS
//!   CGSession → `LockReason::Lockscreen`（[`lockwatch`]）；
//! - **配置读写**（`config_get`/`config_set`）：设置页（ui-settings）
//!   走 config.json（非敏感运行时配置，与 `lk config` 同文件）；
//! - **目录选择器**（`pick_dir`）：ui-rules 新建规则的「项目目录选择器」
//!   （spec §6.4；tauri-plugin-dialog 原生对话框）。

mod lockwatch;
mod state;

use std::sync::Arc;

use lk_core::ipc::{M_SUBSCRIBE, M_VAULT_STATUS};
use lk_core::sync::SyncConfig;
use lk_daemon::config::write_config;
use lk_daemon::transport::{self, Endpoint};
use serde_json::{json, Value};

use state::AppState;

pub use state::{AppState as DesktopState, PushStream};

/// 前端通知事件名（Rust → Tauri 事件；ipc-bridge 监听并翻译为 Cordis 事件）。
pub const NOTIFY_EVENT: &str = "lk-notify";

/// 应用入口：接管陈旧守护端点 → 进程内起守护线程 → Tauri 装配。
pub fn run() {
    let dir = lk_daemon::dirs::data_dir(None);
    take_over_stale_daemon(&dir);
    let (daemon_thread, daemon, shared) = match lk_daemon::serve_embedded(&dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("LightKey: 守护启动失败：{e}");
            std::process::exit(1);
        }
    };
    let handler = lk_daemon::make_handler(&daemon, &shared);
    let lockwatch_daemon = Arc::clone(&daemon);
    let state = AppState::new(
        dir.clone(),
        Arc::clone(&daemon),
        Arc::clone(&shared),
        handler,
        daemon_thread,
    );

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            rpc,
            subscribe,
            unsubscribe,
            config_get,
            config_set,
            pick_dir,
            app_quit,
        ])
        .setup(|app| {
            // 托盘（决策 #4 A）：显示 / 锁定 / 退出
            setup_tray(app)?;
            // 锁屏自动锁定（Windows WTS / macOS CGSession；Linux no-op）
            lockwatch::spawn(lockwatch_daemon);
            Ok(())
        })
        .on_window_event(|window, event| {
            // 决策 #4 A：关闭 = 隐藏到托盘、保持解锁（空闲超时仍自动锁）
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building LightKey desktop app")
        .run(|app, event| match event {
            // 守护退出清理：置位 + 删令牌/端点（join 语义见
            // [`AppState::shutdown_on_exit`]：Windows pipe 阻塞不 join）
            tauri::RunEvent::ExitRequested { .. } => {
                use tauri::Manager;
                app.state::<AppState>().shutdown_on_exit();
            }
            _ => {}
        });
}

/// 接管陈旧守护端点（决策 #2 A：桌面拥有守护生命周期）。端点在跑 → 终止
/// 旧进程（守护退出即锁定；磁盘数据安全）；端点陈旧 → 清理后由
/// [`serve_embedded`] 重新绑定。
fn take_over_stale_daemon(dir: &std::path::Path) {
    let Some(ep) = transport::read_endpoint(dir) else {
        return;
    };
    if probe_endpoint(&ep) {
        // 旧守护在跑（可能是 `lk daemon` CLI 实例）：桌面接管
        if transport::pid_alive(ep.pid) {
            transport::kill_pid(ep.pid);
        }
        // 等旧进程清理（unix SIGTERM 优雅退出；Windows 直接终止）
        for _ in 0..20 {
            if !transport::pid_alive(ep.pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    transport::cleanup(dir, &ep);
}

/// 端点探测（`vault.status` 无需令牌，锁态也可响应）。
fn probe_endpoint(ep: &Endpoint) -> bool {
    let req = json!({ "jsonrpc": "2.0", "id": 0, "method": M_VAULT_STATUS, "params": {} });
    transport::request(ep, &req.to_string()).is_ok()
}

// ---------------------------------------------------------------------------
// tauri command 桥
// ---------------------------------------------------------------------------

/// 前端 `invoke` → 守护进程 JSON-RPC（一行请求一行响应；`make_handler`
/// 保证 sync.trigger / authz.evaluate 走命令锁外路径，G1）。
/// 返回完整 JSON-RPC 响应（result/error 由前端适配器解析，错误码不丢失）。
#[tauri::command]
fn rpc(state: tauri::State<'_, AppState>, method: String, params: Value) -> Result<Value, String> {
    let line = json!({ "jsonrpc": "2.0", "id": 0, "method": method, "params": params }).to_string();
    let resp = (state.handler)(&line, &AppState::desktop_peer());
    serde_json::from_str(&resp).map_err(|e| format!("守护进程响应解析失败：{e}"))
}

/// 通知订阅（决策 #3 A）：令牌经守护进程校验（错令牌 → `session.invalid`
/// 原样返回），通过后建立进程内推送流 → 前端 `NOTIFY_EVENT` 事件。
#[tauri::command]
fn subscribe(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    token: String,
) -> Result<(), String> {
    let line = json!({
        "jsonrpc": "2.0", "id": 0, "method": M_SUBSCRIBE,
        "params": { "token": token }
    })
    .to_string();
    let resp = (state.handler)(&line, &AppState::desktop_peer());
    let v: Value = serde_json::from_str(&resp).map_err(|e| format!("守护进程响应解析失败：{e}"))?;
    if let Some(err) = v.get("error") {
        return Err(err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("subscribe failed")
            .to_string());
    }
    state.start_push_stream(&app)
}

/// 停止推送流（幂等；前端锁定/卸载时调用）。
#[tauri::command]
fn unsubscribe(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.stop_push_stream();
    Ok(())
}

// ---------------------------------------------------------------------------
// 配置读写（ui-settings；config.json 明文非敏感，与 `lk config` 同文件）
// ---------------------------------------------------------------------------

/// `config.get` 结果（前端设置页形态；同步凭据不经此面——凭据走
/// `lk config sync set` 系统钥匙串）。
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigView {
    auto_lock_minutes: u64,
    approval_timeout_secs: u64,
    sync: Option<SyncView>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncView {
    url: String,
    interval_secs: u64,
}

/// `config.set` 补丁（缺省字段不修改；`syncUrl` 空串 = 移除同步配置）。
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigPatch {
    auto_lock_minutes: Option<u64>,
    /// 空串 = 移除同步配置。
    #[serde(default)]
    sync_url: Option<String>,
    /// 轮询间隔（spec §6.6：15s~3600s(1h)）。
    #[serde(default)]
    poll_secs: Option<u64>,
}

#[tauri::command]
fn config_get(state: tauri::State<'_, AppState>) -> Result<ConfigView, String> {
    let cfg = state.shared.config.read().unwrap();
    Ok(ConfigView {
        auto_lock_minutes: cfg.auto_lock_minutes,
        approval_timeout_secs: cfg.approval_timeout_secs,
        sync: cfg.sync.as_ref().map(|s| SyncView {
            url: s.url.clone(),
            interval_secs: s.interval_secs,
        }),
    })
}

#[tauri::command]
fn config_set(state: tauri::State<'_, AppState>, patch: ConfigPatch) -> Result<(), String> {
    let mut cfg = state.shared.config.read().unwrap().clone();
    if let Some(m) = patch.auto_lock_minutes {
        // 空闲自动锁定分钟数（1~1440；0 = 禁用空闲锁，设置页不提供）
        if m == 0 || m > 1440 {
            return Err("自动锁定分钟数须在 1~1440 之间".into());
        }
        cfg.auto_lock_minutes = m;
    }
    if let Some(u) = patch.sync_url {
        let url = u.trim().to_string();
        if url.is_empty() {
            cfg.sync = None;
        } else {
            let interval = patch
                .poll_secs
                .or_else(|| cfg.sync.as_ref().map(|s| s.interval_secs))
                .unwrap_or(60)
                .clamp(15, 3600);
            let sc = SyncConfig {
                url,
                interval_secs: interval,
            };
            sc.validate().map_err(|e| e.to_string())?;
            cfg.sync = Some(sc);
        }
    }
    write_config(&state.dir, &cfg).map_err(|e| e.to_string())?;
    *state.shared.config.write().unwrap() = cfg;
    Ok(())
}

// ---------------------------------------------------------------------------
// 目录选择器 / 退出
// ---------------------------------------------------------------------------

/// 原生目录选择器（ui-rules 新建规则「项目目录选择器」；取消 → null）。
#[tauri::command]
async fn pick_dir(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let picked = app.dialog().file().blocking_pick_folder();
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| {
        // canonical 形态（与 rule.add 校验一致：符号链接/相对形态已解析）
        std::fs::canonicalize(&p)
            .map(|c| c.to_string_lossy().to_string())
            .unwrap_or_else(|_| p.to_string_lossy().to_string())
    }))
}

/// 托盘「退出」（决策 #4 A：退出即锁——守护随进程退出清理）。
#[tauri::command]
fn app_quit(app: tauri::AppHandle) {
    app.exit(0);
}

// ---------------------------------------------------------------------------
// 托盘（决策 #4 A）
// ---------------------------------------------------------------------------

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;
    use tauri::Manager;

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "锁定", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &lock, &quit])?;
    let mut tray = TrayIconBuilder::with_id("lightkey-tray")
        .tooltip("LightKey · 轻钥")
        .menu(&menu)
        .show_menu_on_left_click(false);
    // 无默认窗口图标时省略（TrayIconBuilder 内部仍回退默认图标）
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, event| match event.id.as_ref() {
        "show" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }
        "lock" => {
            // 侧栏「锁定」同语义：立即锁定（manual）
            app.state::<AppState>()
                .lock_with_reason(lk_core::bus::LockReason::Manual);
        }
        "quit" => app.exit(0),
        _ => {}
    })
    .build(app)?;
    Ok(())
}

/// 数据目录（桌面壳与 CLI 共用同一解析；测试/调试经 `LIGHTKEY_HOME` 覆盖）。
pub fn data_dir() -> std::path::PathBuf {
    lk_daemon::dirs::data_dir(None)
}
