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
    let proj = tempfile::tempdir().unwrap();
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

    // M2.97 写门：socket 写是授权事件——预插写规则（desktop 豁免，与桌面
    // 规则页同路径）让 socket put 走「规则命中静默放行」的常规授权路径，
    // 归因链路（#66 真实 starter + channel=cli）不受门影响；读规则同理
    // （值披露读通道，M2.9）
    let canonical = lk_core::path_ns::canonical_project_dir(
        &std::fs::canonicalize(proj.path())
            .unwrap()
            .to_string_lossy(),
    );
    {
        let shared = daemon.shared();
        let mut guard = shared.vault.write().unwrap();
        guard
            .as_mut()
            .unwrap()
            .put_rule(
                lk_core::model::RuleDraft {
                    project_dir: canonical.clone(),
                    name: "write-seed".into(),
                    command: String::new(),
                    keys: vec!["k1".into()],
                    capability: lk_core::model::RULE_CAPABILITY_WRITE.into(),
                    actions: vec![lk_core::model::RULE_ACTION_CREATE.into()],
                    fingerprint: None,
                },
                None,
            )
            .unwrap();
    }
    let _ = daemon.handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": canonical, "name": "read-seed",
                    "command": "", "capability": "read", "keys": ["k1"],
                    "channel": "cli" }),
        ),
        &PeerInfo::desktop(),
    );
    let peer = test_peer(Some(proj.path()));
    let put = rpc_result(&daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "secret", "name": "k1", "value": "v1",
                "purpose": "", "expiresAt": null
            } }),
        ),
        &peer,
    ));
    let item_id = put["item"]["id"].as_str().unwrap().to_string();
    let _ = daemon.handle(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &peer,
    );

    for cmd in ["vault.unlock", "item.create", "item.get"] {
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
