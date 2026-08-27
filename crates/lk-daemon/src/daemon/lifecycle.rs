//! 生命周期入口：传输装配、内嵌实例、信号处理、后台轮询线程。
//!
//! 作为 [`super`] 的子模块以访问守护进程私有状态；对外经 `lk_daemon::run`
//! 等路径再导出。

use super::*;
use crate::config::read_config;
use crate::config::CONFIG_FILE;
use crate::sync::run_sync_round;
use crate::{router, transport};

/// 后台锚点 flush 间隔（异步低频；热路径不阻塞）。
const ANCHOR_FLUSH_INTERVAL_SECS: u64 = 60;
pub(crate) fn load_config(dir: &Path) -> Config {
    let path = dir.join(CONFIG_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Config>(&bytes).unwrap_or_default(),
        Err(_) => {
            let cfg = Config::default();
            let _ = std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap_or_default());
            cfg
        }
    }
}

#[cfg(unix)]
pub(crate) fn install_shutdown_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(windows)]
pub(crate) fn install_shutdown_handlers() {
    // Windows 控制台 Ctrl+C：进程默认终止；令牌文件残留由下次启动覆盖。
}

#[cfg(unix)]
extern "C" fn handle_signal(_: libc::c_int) {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// 全局信号标志的引用（供 transport 主循环轮询）。
pub fn global_shutdown() -> &'static AtomicBool {
    &SHUTDOWN
}

// ---------------------------------------------------------------------------
// 请求 → 响应装配（执行计划路由的唯一生产装配点；ADR-0001）
// ---------------------------------------------------------------------------

/// 装配请求处理器：全部方法经 [`router::route`] 按执行策略编排命令锁
/// （`sync.trigger` / `authz.evaluate` 的锁外阶段不阻塞其他命令，G1）。
///
/// 生产（`lk daemon` / 桌面内嵌实例）与测试共用本装配，保证行为一致；
/// 本函数只是 route 主缝的薄闭包（Arc 克隆 + 转发）。
pub fn make_handler(state: &Arc<Mutex<Daemon>>, shared: &Arc<SharedDaemon>) -> transport::Handler {
    let handler_state = Arc::clone(state);
    let handler_shared = Arc::clone(shared);
    Arc::new(move |line: &str, peer: &PeerInfo| -> String {
        router::route(&handler_state, &handler_shared, line, peer)
    })
}

// ---------------------------------------------------------------------------
// 守护进程入口（CLI / 桌面内嵌实例共用；决策 #2 A）
// ---------------------------------------------------------------------------

/// 绑定端点 + 装配守护（Daemon::start + 后台同步轮询线程），在后台线程
/// 运行 serve 循环直至 [`global_shutdown`] 置位。
///
/// - CLI（`lk daemon`）：经 [`run`] 调用，绑定失败直接报错退出；
/// - 桌面内嵌（M2 desktop）：进程内起守护线程，**同时 serve 本地 socket 供
///   `lk` CLI 复用**（决策 #2 A）；返回句柄供 tauri command 桥转发
///   JSON-RPC 与订阅推送。
///
/// 返回（守护线程句柄, 命令锁, 跨线程共享态）。
pub type EmbeddedDaemon = (
    std::thread::JoinHandle<i32>,
    Arc<Mutex<Daemon>>,
    Arc<SharedDaemon>,
);

pub fn serve_embedded(dir: &Path) -> std::result::Result<EmbeddedDaemon, String> {
    let bind = transport::bind_server(dir);
    #[cfg(unix)]
    let listener = match bind {
        Ok(l) => l,
        Err(e) => return Err(format!("绑定失败：{e}")),
    };
    #[cfg(windows)]
    if let Err(e) = bind {
        return Err(format!("绑定失败：{e}"));
    }
    let daemon = match Daemon::start(dir) {
        Ok(d) => d,
        Err(e) => return Err(format!("启动失败：{e}")),
    };
    let anchor = daemon.anchor();
    let shared = daemon.shared();
    let state = Arc::new(Mutex::new(daemon));
    // 后台同步轮询线程（M1）：只在解锁态 + 已配置时执行一轮；锁定即停止。
    // 间隔 = 配置值 × 2^风暴等级（封顶 1h）；失败静默（下一轮重试）。
    spawn_sync_poller(Arc::clone(&shared));
    // 后台审计锚点 flush（issue #75）：异步低频把链尾写入锚点，保证即使未
    // 触发轮换/锁定/关闭，长解锁会话的链尾也被锚定。非阻塞热路径。
    let flush_dir = dir.to_path_buf();
    spawn_anchor_flusher(flush_dir, anchor);
    let handler = make_handler(&state, &shared);
    let hub = Some(Arc::clone(&shared.push));
    let serve_state = Arc::clone(&state);
    #[cfg(windows)]
    let serve_dir = dir.to_path_buf();
    let thread = std::thread::Builder::new()
        .name("lk-daemon".into())
        .spawn(move || {
            #[cfg(unix)]
            let result = transport::serve(listener, handler, hub, global_shutdown());
            #[cfg(windows)]
            let result = transport::serve(&serve_dir, handler, hub, global_shutdown());
            // 优雅退出清理：删令牌 + 端点（serve 循环结束后由本线程执行；
            // 桌面端进程退出路径由 lk-app 侧 `shutdown_on_exit` 兜底，双清理幂等）
            if let Ok(mut guard) = serve_state.lock() {
                guard.shutdown();
            }
            match result {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("lk daemon: {e}");
                    1
                }
            }
        })
        .map_err(|e| format!("守护线程启动失败：{e}"))?;
    Ok((thread, state, shared))
}

/// 后台审计锚点 flush（issue #75）：直接持有组合锚点 + 数据目录，周期读
/// 链尾写锚点。与命令线程（`Mutex<Daemon>`）解耦——热路径 append 不会因为
/// 这里写 keychain 而阻塞（异步低频）。`global_shutdown` 置位后退出。
fn spawn_anchor_flusher(
    dir: std::path::PathBuf,
    anchor: Arc<lk_core::audit_anchor::CompositeAuditAnchor>,
) {
    std::thread::Builder::new()
        .name("lk-anchor-flush".into())
        .spawn(move || {
            // 独立 AuditLog 句柄（append/open 幂等；flush 线程与命令线程并发
            // 读写同一 0600 日志文件，read 按需 open 新 fd 保证新鲜）。
            let log = match lk_core::audit::AuditLog::open(&dir) {
                Ok(l) => l,
                Err(_) => return,
            };
            loop {
                std::thread::sleep(std::time::Duration::from_secs(ANCHOR_FLUSH_INTERVAL_SECS));
                if SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let events = match log.read() {
                    Ok(e) => e,
                    Err(_) => continue, // 下一轮重试
                };
                let value = lk_core::audit_anchor::anchor_from_chain(&events);
                // 平台不可用：store 内部降到侧写（fail-open），这里只在完全
                // 失败（连侧写都写不进）时告警一次，不阻塞、不 panic。
                if let Err(e) = anchor.store(&value) {
                    eprintln!(
                        "lk daemon: 警告：后台审计锚点写入失败（{e}）——防篡改能力减弱（issue #75）"
                    );
                }
            }
        })
        .expect("审计锚点 flush 线程可启动");
}

/// 后台同步轮询线程（解锁态 + 已配置时按风暴退避间隔执行轮次）。
fn spawn_sync_poller(shared: Arc<SharedDaemon>) {
    use lk_core::sync::{next_poll_interval, DEFAULT_SYNC_INTERVAL_SECS};
    let poller = shared;
    std::thread::Builder::new()
        .name("lk-sync-poller".into())
        .spawn(move || {
            let mut next_sleep = DEFAULT_SYNC_INTERVAL_SECS;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(next_sleep));
                {
                    let mut cfg = poller.config.write().unwrap();
                    *cfg = read_config(&poller.dir);
                }
                let (base, enabled, unlocked) = {
                    let cfg = poller.config.read().unwrap();
                    let base = cfg
                        .sync
                        .as_ref()
                        .filter(|c| c.validate().is_ok())
                        .map(|c| c.interval_secs)
                        .unwrap_or(DEFAULT_SYNC_INTERVAL_SECS);
                    (
                        base,
                        cfg.sync.is_some(),
                        poller.vault.read().unwrap().is_some(),
                    )
                };
                if unlocked && enabled {
                    if let Err(e) = run_sync_round(&poller) {
                        eprintln!("lk daemon: 同步失败（下一轮重试）：{}", e.message());
                    }
                    next_sleep =
                        next_poll_interval(base, poller.sync.lock().unwrap().state.storm_level);
                } else {
                    next_sleep = next_poll_interval(base, 0);
                }
            }
        })
        .expect("同步轮询线程可启动");
}

/// 以守护进程方式运行（CLI `lk daemon` 入口）：绑定 → 装配 → 服务直至退出。
/// 返回进程退出码。
pub fn run(dir: &Path) -> i32 {
    eprintln!(
        "lk daemon: 监听于 {}（pid {}）",
        dir.display(),
        std::process::id()
    );
    match serve_embedded(dir) {
        Ok((thread, _state, _shared)) => {
            // 服务直至退出（SIGINT/SIGTERM → serve 循环置位退出）
            thread.join().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("lk daemon: {e}");
            1
        }
    }
}
