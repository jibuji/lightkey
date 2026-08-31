use std::sync::Arc;

use serde_json::{json, Value};

use crate::config::*;
use crate::sync::*;
use crate::{global_shutdown, transport};
use lk_core::authz::ApprovalDecision;
use lk_core::bus::LockReason;
use lk_core::ipc::*;
use lk_core::vault::UnlockedVault;

use crate::{make_handler, Daemon, PeerInfo, PeerOrigin, SharedDaemon};
use lk_core::audit::AuditLog;
use lk_core::bus::{FnSink, SessionVia, VaultEvent};
use lk_core::crypto::test_kdf_params;
use lk_core::storage::{GetResult, LocalStorage, PutOutcome, RemoteObject};
use lk_core::sync::SyncConfig;
use lk_core::vault::init_vault_with_params;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// 串行化触碰 global_shutdown / 真实传输层的测试（并行测试互相置位
/// shutdown 标志会打断对方的 serve 循环，且负载下时间断言易误报）。
static TRANSPORT_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 取传输层测试锁（毒化容忍）：一个传输层测试失败不应级联成同锁兄弟
/// 测试的 PoisonError 假失败（#92）；锁只提供互斥、不保护共享不变量
/// （各测试自置 global_shutdown 起点），恢复使用是安全的。
pub fn transport_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TRANSPORT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// 审批/事件帧等待上界。负载下 `authz.evaluate` 的 begin 段（线程调度 +
/// Windows 启动者进程链回溯，单机实测满载 >1s、3× 过载下 >5s，见 #92）
/// 把帧的到达时刻推得很晚；上界放宽对健康路径零成本（收到帧即返回）。
/// 200ms/300ms 级的**负向**等待（断言无帧）不在此列，须保持短。
pub const FRAME_WAIT: Duration = Duration::from_secs(30);

/// 「不该发生等待」路径的上界——与 `FRAME_WAIT` 语义相反，勿混用：
/// `FRAME_WAIT` 等帧**到达**（越宽越稳），本常数断言某条路径**没有等**
/// （越窄越有判别力），用于「无审批界面必须立即拒绝」「审批等待期间其他
/// 命令不被阻塞」这类判据。
///
/// 取值被两侧夹住，两侧各留 2–3× 余量：
/// - **必须远小于**夹具审批窗口（生产默认 30s，#92 起不再调小）——否则
///   误入审批等待要跑满整个窗口才返回，本界便失去快速失败能力；
/// - **必须远大于** `authz.evaluate` begin 段在负载下的最坏耗时（线程调度
///   + Windows 启动者进程链回溯，3× 过载实测 >5s，#92）。
pub const NO_WAIT_BOUND: Duration = Duration::from_secs(15);

/// 等待真实传输层可连接（Windows named pipe：serve 线程创建首个监听实例
/// 之前客户端 connect 报 ERROR_FILE_NOT_FOUND，`connect_with_retry` 的
/// 瞬态重试总窗口 ~200ms 在并行满载下会被 serve 线程启动延迟挤爆，#92）。
/// 与生产 `ensure_daemon` 的就绪轮询同型；unix 侧 listener 在 bind 时已
/// 就绪，此等待立即返回。探测成功的连接随手丢弃（服务端按 EOF 收尾）。
fn wait_transport_ready(ep: &transport::Endpoint) {
    let deadline = Instant::now() + FRAME_WAIT;
    loop {
        if transport::connect(ep).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "传输层 30s 内未就绪");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 构造 JSON-RPC 请求行。
fn rpc_line(method: &str, token: Option<&str>, params: Value) -> String {
    let mut p = params;
    if let Some(t) = token {
        p["token"] = json!(t);
    }
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": p
    }))
    .unwrap()
}

fn rpc_result(resp: &str) -> Value {
    serde_json::from_str::<Value>(resp).unwrap()["result"].clone()
}

/// 完整响应对象（含 error；路由表断言用）。
fn rpc_json(resp: &str) -> Value {
    serde_json::from_str::<Value>(resp).unwrap()
}

/// M2 测试夹具：已初始化 + 已解锁的守护进程（命令锁 + 共享态）。
/// 可选 seed 一个 secret 条目（key 名 → 值）。
fn m2_daemon(
    dir: &std::path::Path,
    secret: Option<(&str, &str)>,
) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>, String) {
    m2_daemon_with(dir, secret, false)
}

/// [`m2_daemon`] 的装配变体：显式指定规则 E2E 自动批准门（补充拍板 #22；
/// 生产经 `Daemon::start` 读 env 一次，测试显式传值避免并行竞争）。
fn m2_daemon_with(
    dir: &std::path::Path,
    secret: Option<(&str, &str)>,
    rule_auto: bool,
) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>, String) {
    {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }
    let mut daemon = Daemon::start_with_rule_auto(dir, rule_auto).unwrap();
    // 审批窗口维持生产默认 30s（#92）：需要审批回传落地的测试不再与
    // 真实时钟赛跑（并行满载下测试线程从收到帧到提交回传可被调度延迟
    // 挤出 1s 窗口）；只测超时边界的测试在本测试内显式调小（秒级等待
    // 由 await_decision 真实时钟驱动，行为面不变）。
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    if let Some((name, value)) = secret {
        daemon.handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": name, "value": value,
                    "purpose": "", "expiresAt": null
                } }),
            ),
            &PeerInfo::unknown(),
        );
    }
    let shared = daemon.shared();
    let state = Arc::new(Mutex::new(daemon));
    (state, shared, token)
}

/// 测试用对端：真实 PID + 指定 cwd（授权判定走真实进程链回溯）。
/// cwd 以 canonical 形态给出（与生产传输层 `resolve_peer_cwd` 一致：
/// Windows 短名/符号链接须解析，否则与 canonical 规则 projectDir 不匹配）。
fn test_peer(cwd: Option<&std::path::Path>) -> PeerInfo {
    PeerInfo {
        pid: std::process::id(),
        cwd: cwd.map(|p| {
            std::fs::canonicalize(p)
                .map(|c| c.to_string_lossy().to_string())
                .unwrap_or_else(|_| p.to_string_lossy().to_string())
        }),
        origin: PeerOrigin::Socket,
    }
}

/// 审计事件（守护进程审计文件读取）。
fn audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    AuditLog::open(dir).unwrap().read().unwrap()
}

/// 审计中 `lk inject` 事件（第 1/2/3 层授权结果；测试断言用）。
fn inject_audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    audit_events(dir)
        .into_iter()
        .filter(|e| e.command.starts_with("lk inject"))
        .collect()
}

mod audit_anchor;
mod audit_attribution;
mod authz;
mod disclosure;
mod rule_gate;
mod rules;
mod session_token;
mod sync_race;

/// 慢网络后端（G1 回归夹具，同 M1.5）。
struct SlowBackend {
    inner: LocalStorage,
    delay: Duration,
    signals: mpsc::Sender<()>,
}

mod vault_events;
