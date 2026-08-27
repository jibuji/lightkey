//! #66 回归：常规命令（item.* / vault.* / rule.*）审计的调用方归因——
//! starter 为真实进程链回溯结果（不再硬编码 "lk"），桌面内嵌直调记
//! `channel=desktop`，守护进程自身触发的锁定记 `starter=daemon`。

use super::*;
use lk_core::audit::AuditChannel;

/// 最近一条 `command` 以 `prefix` 开头的审计事件。
fn last_event_like(dir: &std::path::Path, prefix: &str) -> lk_core::audit::AuditEvent {
    audit_events(dir)
        .into_iter()
        .rfind(|e| e.command.starts_with(prefix))
        .unwrap_or_else(|| panic!("审计缺少 {prefix} 事件"))
}

/// 建库 + 启动守护（不解锁；解锁由各测试用指定对端完成）。
fn started_daemon(dir: &std::path::Path) -> Daemon {
    {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }
    Daemon::start(dir).unwrap()
}

#[test]
fn socket_peer_item_reads_audit_real_starter() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = started_daemon(dir.path());
    // 解锁同样经 socket 对端 → vault.unlock 应记真实回溯 starter
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &test_peer(None),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();

    let put = rpc_result(&daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "secret", "name": "k1", "value": "v1",
                "purpose": "", "expiresAt": null
            } }),
        ),
        &test_peer(None),
    ));
    let item_id = put["item"]["id"].as_str().unwrap().to_string();
    let _ = daemon.handle(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &test_peer(None),
    );

    for cmd in ["vault.unlock", "item.put", "item.get"] {
        let e = last_event_like(dir.path(), cmd);
        assert_ne!(e.starter, "lk", "{cmd} 不得硬编码 starter=lk（#66）");
        assert_ne!(
            e.starter,
            lk_core::starter::UNKNOWN_STARTER,
            "{cmd} 真实对端进程链回溯不应失败"
        );
        assert_eq!(
            e.channel,
            AuditChannel::Cli,
            "{cmd} socket 对端 channel=cli"
        );
    }
}

#[test]
fn desktop_calls_audit_desktop_channel() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = started_daemon(dir.path());
    let desktop = PeerInfo::desktop();
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &desktop,
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    let _ = daemon.handle(&rpc_line(M_ITEM_LIST, Some(&token), json!({})), &desktop);
    // rule.* 不带 channel 参数 → 按对端来源回退 desktop（参数标注优先的兜底分支）
    let _ = daemon.handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": dir.path(), "name": "n", "command": "npm *",
                    "keys": ["K"] }),
        ),
        &desktop,
    );
    // 锁屏路径：桌面壳进程内直接调用（不经 IPC）
    daemon.lock_with_reason(LockReason::Lockscreen);

    for cmd in ["vault.unlock", "item.list", "rule.add", "vault.lock"] {
        let e = last_event_like(dir.path(), cmd);
        assert_eq!(e.starter, "desktop", "{cmd} 桌面内嵌直调 starter=desktop");
        assert_eq!(
            e.channel,
            AuditChannel::Desktop,
            "{cmd} 桌面内嵌直调 channel=desktop"
        );
    }
}

#[test]
fn idle_timeout_lock_audits_daemon_self() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = started_daemon(dir.path());
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &test_peer(None),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    // 空闲超时 = 0 → 下一次请求即触发自动锁定（Timeout）
    daemon.shared().config.write().unwrap().auto_lock_minutes = 0;
    let _ = daemon.handle(
        &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
        &test_peer(None),
    );
    let e = last_event_like(dir.path(), "vault.lock");
    assert_eq!(
        e.starter, "daemon",
        "空闲自动锁定是守护进程自身触发，应记 starter=daemon"
    );
}
