//! 审计锚点集成测试（issue #75：截断可证明）。
//! 覆盖：`audit.verify` 交叉核对锚点 → 截尾/锚点缺失/锚定事件被换 → truncated
//! 置位（CLI 据此退出非零）；链在锚点之后追加不误报。

use super::*;
use lk_core::audit_anchor::{
    AuditAnchorStore, AuditAnchorValue, CompositeAuditAnchor, FakeAnchorStore, FileAnchorSidecar,
    UnavailablePlatformStore,
};

/// 构造一个已解锁 + 已注入指定平台锚点（fake）的守护进程。
fn anchored_daemon(
    dir: &std::path::Path,
    platform: Option<Box<dyn AuditAnchorStore>>,
) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>, String) {
    {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }
    let mut daemon = Daemon::start(dir).unwrap();
    // 注入可控锚点（替代真实 keyring+侧写组合），保证单测确定
    let comp = Arc::new(CompositeAuditAnchor::new(
        platform,
        FileAnchorSidecar::new(dir),
    ));
    daemon.set_anchor(comp);
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    let shared = daemon.shared();
    let state = Arc::new(Mutex::new(daemon));
    (state, shared, token)
}

/// fake 平台版本（默认测试用）。
fn anchored_daemon_fake(dir: &std::path::Path) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>, String) {
    anchored_daemon(dir, Some(Box::new(FakeAnchorStore::new())))
}

/// 触发 `audit.verify`，返回结果 JSON（含 truncated / anchorOk）。
fn verify(state: &Arc<Mutex<Daemon>>, token: &str) -> Value {
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_AUDIT_VERIFY, Some(token), json!({})),
        &PeerInfo::unknown(),
    );
    rpc_result(&resp)
}

#[test]
fn verify_reports_ok_when_chain_matches_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon_fake(dir.path());
    // 解锁后链 = [vault.unlock, vault.status?]；fake 锚点在解锁时已被 sync 覆盖。
    // 直接重新把链尾写进 fake → 应一致。
    {
        let daemon = state.lock().unwrap();
        let events = daemon_audit_read(dir.path());
        let v = AuditAnchorValue {
            ordinal: events.len() as u64,
            last_hmac: events.last().map(|e| e.hmac.clone()).unwrap_or_default(),
        };
        // 组合 store 写入 fake（platform）；guard 在进入 verify 前 drop
        daemon.anchor().store(&v).expect("fake 平台写入应成功");
    }
    let r = verify(&state, &token);
    assert_eq!(r["truncated"].as_bool(), Some(false));
    assert_eq!(r["anchorOk"].as_bool(), Some(true));
}

#[test]
fn verify_reports_truncated_when_chain_shorter_than_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon_fake(dir.path());
    {
        let daemon = state.lock().unwrap();
        // 伪造：锚点宣称链应有 50 条，但实际链更短（宽松截断场景）
        daemon
            .anchor()
            .store(&AuditAnchorValue {
                ordinal: 50,
                last_hmac: "fake-tail".to_string(),
            })
            .unwrap();
    }
    let r = verify(&state, &token);
    assert_eq!(r["truncated"].as_bool(), Some(true));
    assert_eq!(r["anchorOk"].as_bool(), Some(false));
    assert_eq!(r["anchorOrdinal"].as_u64(), Some(50));
}

#[test]
fn verify_reports_truncated_when_anchor_event_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon_fake(dir.path());
    {
        let daemon = state.lock().unwrap();
        let events = daemon_audit_read(dir.path());
        // 链 ordinal 不变，但把 last_hmac 改成伪造值 → 锚定事件被换/伪造
        daemon
            .anchor()
            .store(&AuditAnchorValue {
                ordinal: events.len() as u64,
                last_hmac: "forged-value".to_string(),
            })
            .unwrap();
    }
    let r = verify(&state, &token);
    assert_eq!(r["truncated"].as_bool(), Some(true));
    assert_eq!(r["anchorOk"].as_bool(), Some(false));
}

#[test]
fn verify_reports_truncated_when_anchor_missing() {
    // 平台 keychain 不可用（降级到侧写），随后攻击者连侧写都删光 → 锚点缺失。
    // 解锁的 sync_anchor 会落到侧写；把侧写文件删掉后再 verify = 无锚点。
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon(
        dir.path(),
        Some(Box::new(UnavailablePlatformStore(
            "no keyring in test".to_string(),
        ))),
    );
    // 解锁后侧写应有锚点；攻击者删掉侧写与平台（平台本就不可用）→ 无锚点
    let sidecar = dir.path().join(lk_core::audit_anchor::AUDIT_ANCHOR_SIDECAR);
    assert!(sidecar.exists(), "解锁应已在侧写降级写入锚点");
    std::fs::remove_file(&sidecar).unwrap();
    let r = verify(&state, &token);
    assert_eq!(r["truncated"].as_bool(), Some(true));
    assert_eq!(r["anchorOk"].as_bool(), Some(false));
    assert_eq!(r["anchorOrdinal"], Value::Null);
}

#[test]
fn verify_ok_when_chain_longer_than_anchor_not_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon_fake(dir.path());
    {
        // 锚点建于更早的 1 条；解锁后链更长 → AnchorBehind，不算截断
        let daemon = state.lock().unwrap();
        daemon
            .anchor()
            .store(&AuditAnchorValue {
                ordinal: 1,
                last_hmac: "legacy".to_string(),
            })
            .unwrap();
    }
    let r = verify(&state, &token);
    assert_eq!(r["truncated"].as_bool(), Some(false));
}

#[test]
fn physical_truncation_of_log_tail_is_detected() {
    // 验收标准核心：把审计文件尾部 3 条事件真实删掉 → verify 报截断。
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = anchored_daemon_fake(dir.path());
    // 追加 3 条事件，让链变长（此时解锁 sync 的锚点还停留在解锁尾）
    {
        let mut daemon = state.lock().unwrap();
        let mut h = json!({ "item": {
            "type": "login", "name": "X", "username": "u",
            "password": "p", "uris": [], "custom": []
        } });
        for i in 0..3 {
            h["item"]["name"] = json!(format!("C{i}"));
            daemon.handle(
                &rpc_line(M_ITEM_PUT, Some(&token), h.clone()),
                &PeerInfo::unknown(),
            );
        }
        // 现在把锚点更新到此刻的链尾（模拟在一次低频点已同步过）
        let events = daemon_audit_read(dir.path());
        daemon
            .anchor()
            .store(&AuditAnchorValue {
                ordinal: events.len() as u64,
                last_hmac: events.last().unwrap().hmac.clone(),
            })
            .unwrap();
    }
    // 攻击者截尾：删掉审计文件最后 3 条事件行
    let full = std::fs::read(dir.path().join("audit.log")).unwrap();
    let lines: Vec<&[u8]> = full
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    let survivor = lines[..lines.len().saturating_sub(3)].join(&b'\n');
    std::fs::write(dir.path().join("audit.log"), survivor).unwrap();

    let r = verify(&state, &token);
    assert_eq!(
        r["truncated"].as_bool(),
        Some(true),
        "物理截尾应被锚点检测：{r}"
    );
    assert_eq!(r["anchorOk"].as_bool(), Some(false));
    assert!(r["anchorOrdinal"].as_u64().unwrap() > r["chainOrdinal"].as_u64().unwrap());
}

/// 读取审计事件（测试助手）。
fn daemon_audit_read(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    AuditLog::open(dir).unwrap().read().unwrap()
}
