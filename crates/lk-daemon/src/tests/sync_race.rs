//! sync_race 域测试（自原 lib.rs tests 模块拆出；助手见 `super`）。

use super::*;

/// G1 根治回归（M1.5 既有）：同步轮次进行中（慢网络后端持网络 I/O 窗口），
/// 前台命令不被阻塞；且轮次应用阶段不覆盖同步期间命令的更新。
#[test]
fn sync_round_does_not_block_commands_and_apply_respects_races() {
    let dir = tempfile::tempdir().unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
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
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    {
        let cfg = Config {
            auto_lock_minutes: 60,
            sync: Some(SyncConfig {
                url: "file:///unused".into(),
                interval_secs: 60,
            }),
            approval_timeout_secs: 30,
        };
        *daemon.shared().config.write().unwrap() = cfg;
    }
    let put_x = rpc_result(&daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "login", "name": "X", "username": "u1",
                "password": "p1", "uris": [], "custom": []
            } }),
        ),
        // M2.97 写门：种子走 desktop 直调豁免（GUI 同路径）
        &PeerInfo::desktop(),
    ));
    let x_id = put_x["item"]["id"].as_str().unwrap().to_string();
    let x_rev1 = put_x["item"]["revision"].as_str().unwrap().to_string();
    let shared = daemon.shared();
    run_sync_round_with(
        &shared,
        Box::new(LocalStorage::new(remote_dir.path().to_path_buf())),
    )
    .unwrap();
    // 远端较新 X（rev2）：第二个客户端（同钥拷贝）编辑并同步
    {
        let b_dir = tempfile::tempdir().unwrap();
        for name in ["vault.json", "index.lk", "audit.log", "recovery.envelope"] {
            std::fs::copy(dir.path().join(name), b_dir.path().join(name)).unwrap();
        }
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            if name.ends_with(".item.lk") {
                std::fs::copy(dir.path().join(&name), b_dir.path().join(&name)).unwrap();
            }
        }
        let mut b = UnlockedVault::unlock(b_dir.path(), "pw123456").unwrap();
        b.put(
            Some(uuid::Uuid::parse_str(&x_id).unwrap()),
            lk_core::model::ItemDraft::Login {
                name: "X".into(),
                username: "remote-new".into(),
                password: "p1".into(),
                uris: vec![],
                custom: vec![],
            },
            Some(x_rev1.clone()),
        )
        .unwrap();
        use lk_core::sync::SyncEngine;
        SyncEngine::new(&LocalStorage::new(remote_dir.path().to_path_buf()))
            .run_round(&mut b, &lk_core::crypto::now_iso())
            .unwrap();
    }
    daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                    "type": "login", "name": "Y", "username": "u2",
                    "password": "p2", "uris": [], "custom": []
                } }),
        ),
        // M2.97 写门：种子走 desktop 直调豁免（GUI 同路径）
        &PeerInfo::desktop(),
    );
    let (tx, rx) = mpsc::channel();
    // 慢后端间隔 800ms 与断言上界 700ms 成对：回归态（命令在网络 I/O 中
    // 被阻塞）至少等满一个慢 op ≥800ms 必然超界；健康路径在重载下的
    // 调度延迟实测 ~360ms（#92 双套件碰撞观测），上界留出 >2× 余量
    let slow = Box::new(SlowBackend {
        inner: LocalStorage::new(remote_dir.path().to_path_buf()),
        delay: Duration::from_millis(800),
        signals: tx,
    });
    let round_shared = Arc::clone(&shared);
    let round = std::thread::spawn(move || run_sync_round_with(&round_shared, slow));

    rx.recv_timeout(FRAME_WAIT).unwrap();
    let t0 = Instant::now();
    let list = daemon.handle(
        &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(700),
        "item.list 在同步网络 I/O 中被阻塞 {elapsed:?}"
    );
    assert_eq!(rpc_result(&list)["items"].as_array().unwrap().len(), 2);

    rx.recv_timeout(FRAME_WAIT).unwrap();
    let put = daemon.handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": x_id,
                "expectedRevision": x_rev1,
                "item": {
                    "type": "login", "name": "X", "username": "local-race",
                    "password": "p1", "uris": [], "custom": []
                }
            }),
        ),
        // M2.97 写门：与授权无关的竞争写走 desktop 直调豁免（GUI 同路径）
        &PeerInfo::desktop(),
    );
    let put_result = rpc_result(&put);
    assert!(
        put_result["item"]["id"].as_str().is_some(),
        "命令更新在同步网络 I/O 中被阻塞或被拒绝：{put}"
    );

    rx.recv_timeout(FRAME_WAIT).unwrap();

    let summary = round.join().unwrap().unwrap();
    assert_eq!(summary.pulled, 0, "应用复核跳过旧快照导入");
    assert_eq!(summary.pushed, 1, "Y 已推送");
    // M2.9 值披露：socket 读值经裁决（本测试与授权无关）→ desktop 直调
    // 受信豁免读取，验证数据不被轮次覆盖
    let x = rpc_result(&daemon.handle(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": x_id })),
        &PeerInfo::desktop(),
    ));
    assert_eq!(
        x["username"].as_str().unwrap(),
        "local-race",
        "同步期间命令的更新不被轮次覆盖"
    );
    let status = rpc_result(&daemon.handle(
        &rpc_line(M_VAULT_STATUS, None, json!({})),
        &PeerInfo::unknown(),
    ));
    assert!(status["syncWatermark"].as_str().is_some());
}

// ------------------------------------------------------------------
// M2：授权门（三层短路 / 审批 / G1）/ 规则库 / 推送通道 / 审计
// ------------------------------------------------------------------
