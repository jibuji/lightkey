//! 桌面壳共享状态（C 层，`docs/plugin-architecture.md` §3.3/C 层宿主）。
//!
//! [`AppState`] = 内置守护实例（命令锁 + 共享态 + 请求处理器）+ 推送流
//! （前端通知订阅：PushHub → 本进程线程 → Tauri 事件 → 前端 ipc-bridge
//! 翻译为 Cordis 事件，决策 #3 A）。
//!
//! 生命周期（决策 #2 A / #4 A）：守护线程与应用进程同生共死——托盘「退出」
//! → `app.exit(0)` → `RunEvent::ExitRequested` 置位 `global_shutdown` →
//! serve 循环退出 → 守护清理（删令牌/端点）→ `RunEvent::Exit` join 线程。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use tauri::Emitter;

use lk_daemon::transport::{Handler, PeerInfo};
use lk_daemon::{Daemon, SharedDaemon};

/// 推送流：订阅连接在**进程内**的等价物（不占 socket）。
/// 校验通过的 `subscribe` 命令 → PushHub 登记 + writer 线程 → Tauri 事件。
pub struct PushStream {
    id: u64,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// 桌面壳共享状态（Tauri `manage` 注册；命令/tray/锁屏回调共用）。
pub struct AppState {
    /// 数据目录（与 CLI 同解析，`lk_daemon::dirs`）。
    pub dir: PathBuf,
    /// 命令锁（守护状态；锁屏/托盘直接调用锁定）。
    pub daemon: Arc<Mutex<Daemon>>,
    /// 跨线程共享态（推送通道 / 配置热更新 / vault）。
    pub shared: Arc<SharedDaemon>,
    /// 请求处理器（`make_handler`：sync.trigger / authz.evaluate 走命令锁
    /// 外路径，G1；其余命令在命令锁内串行）。
    pub handler: Handler,
    /// 当前推送流（`subscribe` 替换旧流；仅一个前端订阅者）。
    push: Mutex<Option<PushStream>>,
    /// 守护线程句柄（退出时 detach；进程退出即终止）。
    daemon_thread: Mutex<Option<std::thread::JoinHandle<i32>>>,
}

impl AppState {
    pub fn new(
        dir: PathBuf,
        daemon: Arc<Mutex<Daemon>>,
        shared: Arc<SharedDaemon>,
        handler: Handler,
        daemon_thread: std::thread::JoinHandle<i32>,
    ) -> AppState {
        AppState {
            dir,
            daemon,
            shared,
            handler,
            push: Mutex::new(None),
            daemon_thread: Mutex::new(Some(daemon_thread)),
        }
    }

    /// 建立推送流（`subscribe` 命令：令牌已由守护进程校验通过）。
    /// 替换旧流：先停旧 writer 线程再登记新订阅（同进程只有一个订阅者）。
    pub fn start_push_stream(&self, app: &tauri::AppHandle) -> Result<(), String> {
        let (id, rx) = self.shared.push.subscribe();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut guard = self.push.lock().unwrap();
            if let Some(old) = guard.take() {
                old.stop.store(true, Ordering::Relaxed);
                self.shared.push.unsubscribe(old.id);
                if let Some(t) = old.thread {
                    let _ = t.join();
                }
            }
            let app = app.clone();
            let hub = Arc::clone(&self.shared.push);
            let stop2 = Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name("lk-notify".into())
                .spawn(move || loop {
                    if stop2.load(Ordering::Relaxed) {
                        break;
                    }
                    match rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(frame) => {
                            // JSON-RPC notification 帧 → 前端（ipc-bridge 翻译）
                            let _ = app.emit("lk-notify", frame);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    hub.unsubscribe(id);
                })
                .map_err(|e| e.to_string())?;
            *guard = Some(PushStream {
                id,
                stop,
                thread: Some(thread),
            });
        }
        Ok(())
    }

    /// 停止推送流（幂等；`unsubscribe` / 退出清理）。
    pub fn stop_push_stream(&self) {
        if let Some(old) = self.push.lock().unwrap().take() {
            old.stop.store(true, Ordering::Relaxed);
            self.shared.push.unsubscribe(old.id);
            if let Some(t) = old.thread {
                let _ = t.join();
            }
        }
    }

    /// 锁定（带原因；进程内直接调用，不经 IPC——锁屏/托盘/退出路径）。
    pub fn lock_with_reason(&self, reason: lk_core::bus::LockReason) {
        if let Ok(mut guard) = self.daemon.lock() {
            guard.lock_with_reason(reason);
        }
    }

    /// 应用退出清理：置位全局退出标志 + 守护收尾（删令牌/端点/存同步水位）。
    ///
    /// 不在进程退出时 join 守护线程：Windows named pipe 的 serve 循环阻塞在
    /// `ConnectNamedPipe`（等客户端连接），join 会挂起退出流程；进程退出
    /// 自然终止线程（桌面侧清理已在此完成，双清理幂等）。
    pub fn shutdown_on_exit(&self) {
        lk_daemon::global_shutdown().store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.daemon.lock() {
            guard.shutdown();
        }
        self.stop_push_stream();
        if let Ok(mut t) = self.daemon_thread.lock() {
            t.take(); // detach（unix serve 循环会自行收尾；windows 由进程退出终止）
        }
    }

    /// 桌面侧请求的对端身份：未知（pid=0）——授权路径 fail-closed
    /// （`authz.evaluate` 走 CLI 对端回溯；桌面前端不调用该方法）。
    pub fn desktop_peer() -> PeerInfo {
        PeerInfo::unknown()
    }
}
