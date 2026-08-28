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
    {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }
    let mut daemon = Daemon::start(dir).unwrap();
    // 审批超时调小（测试不等真实 30s）
    daemon
        .shared()
        .config
        .write()
        .unwrap()
        .approval_timeout_secs = 1;
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
