//! vault_events 域测试（自原 lib.rs tests 模块拆出；助手见 `super`）。

use super::*;

/// M1.5 事件总线装配回归：守护进程解锁 → `session.unlocked(password)`、
/// 写条目 → `item.changed`、锁定 → `session.locked(manual)`。
#[test]
fn daemon_emits_session_and_item_events_on_bus() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut audit = AuditLog::open(dir.path()).unwrap();
        init_vault_with_params(
            dir.path(),
            "pw123456",
            false,
            &mut audit,
            &test_kdf_params(),
        )
        .unwrap();
    }
    let mut daemon = Daemon::start(dir.path()).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let e = Arc::clone(&events);
    daemon.bus().subscribe(Arc::new(FnSink::new(move |ev| {
        e.lock().unwrap().push(ev.clone());
    })));

    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "login", "name": "X", "username": "u",
                "password": "p", "uris": [], "custom": []
            } }),
        ),
        // M2.97 写门：种子走 desktop 直调豁免（GUI 同路径）
        &PeerInfo::desktop(),
    );
    daemon.handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );

    let seen = events.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "解锁 + 写条目 + 锁定 = 3 个事件：{seen:?}");
    assert!(matches!(
        &seen[0],
        VaultEvent::SessionUnlocked {
            via: SessionVia::Password
        }
    ));
    match &seen[1] {
        VaultEvent::ItemChanged {
            revision_date,
            kind,
            deleted,
            ..
        } => {
            assert!(!revision_date.is_empty());
            assert_eq!(kind, "login");
            assert!(!deleted);
        }
        other => panic!("第 2 个事件应为 item.changed：{other:?}"),
    }
    assert!(matches!(
        &seen[2],
        VaultEvent::SessionLocked {
            reason: LockReason::Manual
        }
    ));
}

/// M2.5 首启检测：`vault.status` 的 `initialized` 标志——无库 = 首启（前端
/// 据此进初始化向导）；`vault.init` 建库后翻转；`vault.init` 的弱密码/
/// 已存在均被拒绝（错误码不同，UI 层统一文案不区分，ipc.md §3）。
#[test]
fn vault_status_reports_initialized_and_init_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = Daemon::start(dir.path()).unwrap();

    // 无库：initialized=false（首启）
    let resp = daemon.handle(
        &rpc_line(M_VAULT_STATUS, None, json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["initialized"], false);
    assert_eq!(v["result"]["unlocked"], false);

    // 弱主密码（<8 位）→ 拒绝（ERR_WEAK_PASSWORD）
    let resp = daemon.handle(
        &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "short" })),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_WEAK_PASSWORD);
    assert_eq!(v["error"]["message"], MSG_WEAK_PASSWORD);
    // 弱密码未建库：仍为未初始化
    let resp = daemon.handle(
        &rpc_line(M_VAULT_STATUS, None, json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["initialized"], false);

    // 合法主密码 → 建库 + 恢复码（仅展示一次）+ initialized=true
    let resp = daemon.handle(
        &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "pw123456" })),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(v["error"].is_null());
    let code = v["result"]["recoveryCode"].as_str().unwrap();
    assert_eq!(code.len(), 5 * 8 + 4, "恢复码 5 组 × 8 字符 + 4 空格");

    // 已存在库 → 再次 init 拒绝（ERR_VAULT_EXISTS；前端统一文案）
    let resp = daemon.handle(
        &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "pw123456" })),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_VAULT_EXISTS);

    // 有库：initialized=true（锁态也可响应，无需令牌）
    let resp = daemon.handle(
        &rpc_line(M_VAULT_STATUS, None, json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["initialized"], true);
    assert_eq!(v["result"]["unlocked"], false);

    // 建库后即可用同一主密码解锁（向导 Step4 = init + unlock 两段）
    let resp = daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(v["error"].is_null());
    assert!(v["result"]["token"].as_str().unwrap().len() >= 32);
}

impl lk_core::storage::StorageBackend for SlowBackend {
    fn name(&self) -> &'static str {
        "slow"
    }
    fn get(&self, key: &str) -> lk_core::Result<Option<GetResult>> {
        let _ = self.signals.send(());
        std::thread::sleep(self.delay);
        self.inner.get(key)
    }
    fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> lk_core::Result<PutOutcome> {
        let _ = self.signals.send(());
        std::thread::sleep(self.delay);
        self.inner.put(key, data, expected)
    }
    fn delete(&self, key: &str) -> lk_core::Result<()> {
        let _ = self.signals.send(());
        std::thread::sleep(self.delay);
        self.inner.delete(key)
    }
    fn list(&self) -> lk_core::Result<Vec<RemoteObject>> {
        let _ = self.signals.send(());
        std::thread::sleep(self.delay);
        self.inner.list()
    }
    fn etag(&self, key: &str) -> lk_core::Result<Option<String>> {
        let _ = self.signals.send(());
        std::thread::sleep(self.delay);
        self.inner.etag(key)
    }
}

/// 订阅校验：错令牌 → session.invalid（连接不转流模式）。
#[test]
fn subscribe_requires_valid_token() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_SUBSCRIBE, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(v["result"].is_object());
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_SUBSCRIBE, None, json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["message"], MSG_SESSION_INVALID);
}

/// 推送通道：解锁/写条目/锁定 → session.*/item.changed 通知帧（非阻塞）。
#[test]
fn push_channel_notifies_session_and_item_events() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let (_sid, rx) = shared.push.subscribe(true); // 桌面壳模拟（#72/#78 起订阅带来源标签）
                                                  // 写条目 → item.changed 帧
    state.lock().unwrap().handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "login", "name": "X", "username": "u",
                "password": "p", "uris": [], "custom": []
            } }),
        ),
        // M2.97 写门：种子走 desktop 直调豁免（GUI 同路径）
        &PeerInfo::desktop(),
    );
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "item.changed");
    assert_eq!(fv["params"]["type"], "login");
    // 锁定 → session.locked 帧
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "session.locked");
    assert_eq!(fv["params"]["reason"], "manual");
    // 重新解锁 → session.unlocked 帧（旧订阅连接保持有效）
    state.lock().unwrap().handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "session.unlocked");
    assert_eq!(fv["params"]["via"], "password");
    assert!(shared.push.subscriber_count() >= 1);
}
