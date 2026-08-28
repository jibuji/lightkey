//! 值披露裁决集成测试（M2.9 值披露，value-disclosure.md §3 判定矩阵 / §10.2）。
//!
//! seam：`router.rs strategy_of` 策略表 + daemon 装配（route 主缝 / handle 直调）；
//! 审批三态经进程内桌面订阅（`push.subscribe(true)`）+ `approval.result`
//! 直调回传（#78 方案 A 语义）。

use super::*;

/// 种一个 file 条目（附件经 fileData base64 上传），返回条目 id。
fn put_file_item(state: &Arc<Mutex<Daemon>>, token: &str, name: &str, data: &[u8]) -> String {
    use base64::Engine as _;
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(token),
            json!({ "item": {
                "type": "file", "name": name, "note": "",
                "fileType": "application/octet-stream", "attachment": name,
                "fileData": base64::engine::general_purpose::STANDARD.encode(data),
            } }),
        ),
        &PeerInfo::unknown(),
    );
    rpc_result(&resp)["item"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("file 条目应创建成功：{resp}"))
        .to_string()
}

/// 审计中的值披露事件（command 恰为 `item.get` / `item.export`；spec §8）。
fn disclosure_audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    audit_events(dir)
        .into_iter()
        .filter(|e| e.command == "item.get" || e.command == "item.export")
        .collect()
}

/// 策略表：`item.get` / `item.export` 升为 ApprovalDeferred（spec §5.1）。
#[test]
fn disclosure_strategies_are_approval_deferred() {
    assert_eq!(
        crate::strategy_of(M_ITEM_GET),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    assert_eq!(
        crate::strategy_of(M_ITEM_EXPORT),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    // 其余 item 方法维持 Inline（元数据不裁决，spec §3）
    assert_eq!(
        crate::strategy_of(M_ITEM_LIST),
        crate::ExecutionStrategy::Inline
    );
    assert_eq!(
        crate::strategy_of(M_ITEM_PUT),
        crate::ExecutionStrategy::Inline
    );
}

/// 桌面内嵌直调 get/export：受信豁免直返值，不登记审批；审计 allowed
/// （channel=desktop，target=条目名；spec §3 第 1 行 / §8）。
#[test]
fn desktop_direct_get_and_export_exempt_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let file_id = put_file_item(&state, &token, "report.bin", b"file-bytes");
    // 经 item.put 返回值拿 secret 条目 id（m2_daemon 内部 seed 未回传）
    let secret_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "APIKey2", "value": "sk-2",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let pending_before = _shared.approvals.pending_count();
    // desktop 直调 get（PeerOrigin::Desktop，无 IPC 对端）
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": secret_id })),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["result"]["value"], "sk-2",
        "desktop 直调应直接返回值：{resp}"
    );
    // desktop 直调 export
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_EXPORT, Some(&token), json!({ "id": file_id })),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["result"]["name"], "report.bin",
        "desktop 直调 export 直返：{resp}"
    );
    assert_eq!(
        _shared.approvals.pending_count(),
        pending_before,
        "豁免路径不登记审批"
    );
    // 审计：allowed / channel=desktop / target=条目名（spec §8）
    let evs = disclosure_audit_events(dir.path());
    let get_ev = evs.iter().find(|e| e.command == "item.get").unwrap();
    assert_eq!(get_ev.result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(get_ev.channel, lk_core::audit::AuditChannel::Desktop);
    assert_eq!(get_ev.target, "APIKey2");
    let ex_ev = evs.iter().find(|e| e.command == "item.export").unwrap();
    assert_eq!(ex_ev.result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(ex_ev.channel, lk_core::audit::AuditChannel::Desktop);
    assert_eq!(ex_ev.target, "report.bin");
}

/// socket + 读规则命中（capability=read，projectDir 祖先 + keys 含条目名）
/// → 静默放行 + 审计 allowed（channel=cli；不弹窗、不登记审批）。
#[test]
fn socket_get_with_matching_read_rule_allowed_silently() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "read-config",
                    "command": "", "capability": "read", "keys": ["APIKey"],
                    "channel": "cli" }),
        ),
        &PeerInfo::unknown(),
    );
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "APIKey", "value": "sk-1",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1", "读规则命中应静默放行：{resp}");
    assert_eq!(shared.approvals.pending_count(), 0, "规则命中不弹窗");
    // 审计 allowed（channel=cli）
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::Cli);
    assert_eq!(evs[0].target, "APIKey");
}

/// socket 无读规则 + 无桌面订阅 → `authz.denied`(-32017) + 审计 denied。
#[test]
fn socket_get_without_rule_or_ui_denied_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        // 由 item.list 拿 id（最小索引含 id/name）
        let items = rpc_result(&resp)["items"].as_array().unwrap().clone();
        items.iter().find(|i| i["name"] == "APIKey").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "无规则无 UI 应拒绝：{resp}"
    );
    assert_eq!(v["error"]["message"], MSG_AUTHZ_DENIED);
    assert!(v.get("result").is_none(), "拒绝不返回值");
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1, "拒绝写审计");
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[0].target, "APIKey");
}

/// socket 无读规则 + 桌面订阅在场 → 弹窗三态（allow / deny / timeout）+ 审计。
#[test]
fn socket_get_without_rule_approval_allow_deny_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "APIKey", "value": "sk-1",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));

    // -- allow：桌面订阅收帧（kind=read，含 challenge）→ approval.result 放行
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert_eq!(
        fv["params"]["kind"], "read",
        "读审批帧 kind=read（spec §6）"
    );
    assert_eq!(fv["params"]["command"], "item.get");
    assert_eq!(fv["params"]["keys"][0], "APIKey", "keys=单元素条目名");
    assert!(!frame.contains("sk-1"), "审批帧不含值");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1", "弹窗批准后返回值：{resp}");
    // finalize 审计 allowed（channel=approval 与 inject 同口径，spec §8）
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::Approval);

    // -- deny
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "denied", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "拒绝 → authz.denied：{resp}"
    );
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[1].result, lk_core::audit::AuditResult::Denied);

    // -- timeout（approval_timeout_secs=1；不回传等超时默认拒绝）
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let _frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED, "超时默认拒绝：{resp}");
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 3);
    assert_eq!(
        evs[2].result,
        lk_core::audit::AuditResult::Denied,
        "超时统一记 denied（spec §8）"
    );
}

/// export 恒弹窗：读规则命中条目名也不豁免；无 UI → 拒绝（spec §3）。
#[test]
fn socket_export_always_prompts_even_with_read_rule() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "read-all",
                    "command": "", "capability": "read", "keys": ["report.bin"],
                    "channel": "cli" }),
        ),
        &PeerInfo::unknown(),
    );
    let file_id = put_file_item(&state, &token, "report.bin", b"payload");
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(M_ITEM_EXPORT, Some(&token), json!({ "id": file_id })),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "读规则命中 export 仍拒绝（无 UI）：{resp}"
    );
    assert_eq!(v["error"]["message"], MSG_AUTHZ_DENIED);
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[0].command, "item.export");
}

/// export 弹窗批准 → 返回数据包（name/mime/size/data base64）+ 审计 allowed；
/// 审批帧携带数据包规模元信息（spec §6）。
#[test]
fn socket_export_allowed_via_approval_returns_bundle() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let file_id = put_file_item(&state, &token, "report.bin", b"payload-bytes");
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(M_ITEM_EXPORT, Some(&token), json!({ "id": file_id }));
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["params"]["kind"], "export", "导出审批帧 kind=export");
    assert_eq!(
        fv["params"]["exportMeta"]["name"], "report.bin",
        "帧含数据包规模（spec §6）"
    );
    assert_eq!(fv["params"]["exportMeta"]["size"], 13);
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["name"], "report.bin");
    let data = v["result"]["data"].as_str().unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap(),
        b"payload-bytes"
    );
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::Approval);
}

/// 启动者未知（对端 PID 不可得）→ 第 1 层 fail-closed 拒绝，不弹窗、
/// 不留内容（spec §3；与 inject 同口径）。
#[test]
fn disclosure_unknown_starter_fail_closed_no_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let items = rpc_result(&resp)["items"].as_array().unwrap().clone();
        items.iter().find(|i| i["name"] == "APIKey").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &PeerInfo::unknown(), // pid=0 → starter=unknown
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED);
    assert_eq!(shared.approvals.pending_count(), 0, "fail-closed 不弹窗");
    let evs = disclosure_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
}

/// #78 回归（disclosure 场景）：socket 来源提交 `approval.result` →
/// `channel.forbidden`，读值弹窗只能由桌面回传批准。
#[test]
fn disclosure_socket_cannot_self_approve() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "APIKey", "value": "sk-1",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    // socket 连接提交审批回传 → 专用错误码（#78）
    let resp = handler(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_CHANNEL_FORBIDDEN);
    // 等待者按超时拒绝（默认拒绝，不因伪回传放行）
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED);
}

/// 等待期间锁定（桌面手动/自动锁定）→ 审批 allowed 也无法披露：vault 与
/// K_audit 已擦除 → 保守 `session.invalid`（不 panic；与 authz_finalize
/// resolve_env 失败同口径，G1 回归类）。
#[test]
fn disclosure_allowed_but_locked_during_wait_returns_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "APIKey", "value": "sk-1",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    // 等待期锁定复现（锁屏线程时序）：① 命令锁内审批回传解析（accepted，
    // 等待线程被唤醒但阻塞在命令锁上）；② 仍持命令锁时直接锁定 vault——
    // `lock_with_reason`（锁屏线程等价路径）只取 vault 写锁、不经过命令锁，
    // 正是生产中的竞态窗口：审批已放行但披露前 vault 被锁屏/手动锁定擦除
    let mut guard = state.lock().unwrap();
    let resp = guard.handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    guard.lock_with_reason(LockReason::Manual);
    drop(guard);
    // ③ 等待线程获得命令锁 → finalize Allowed + vault 已锁 → session.invalid
    // （保守，不 panic、不披露）
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "等待期锁定后批准 → session.invalid：{resp}"
    );
}

/// 锁定态读值 → `session.invalid`（spec §3：require_session 先失败；
/// 本项不做读通道的解锁一体化，spec §12）。
#[test]
fn disclosure_locked_vault_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), Some(("APIKey", "sk-1")));
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let items = rpc_result(&resp)["items"].as_array().unwrap().clone();
        items.iter().find(|i| i["name"] == "APIKey").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // 锁定（桌面来源直调）
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::desktop(),
    );
    let handler = make_handler(&state, &_shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "锁定态 session.invalid：{resp}"
    );
}

/// WSL 跨子系统（spec §9）：`wsl://` 规范形读规则 + bridge 侧归一化 cwd
/// 命中 → 静默放行；cwd 归一化两侧同函数（cross-subsystem.md §7.4）。
#[test]
fn socket_get_matches_wsl_read_rule() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("WSLKEY", "sk-wsl")));
    state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": "wsl://Debian/home/u/p", "name": "wsl-read",
                    "command": "", "capability": "read", "keys": ["WSLKEY"],
                    "channel": "cli" }),
        ),
        &PeerInfo::unknown(),
    );
    let item_id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": "WSLKEY", "value": "sk-wsl",
                    "purpose": "", "expiresAt": null } }),
            ),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["item"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let handler = make_handler(&state, &shared);
    // bridge 进程真实 cwd（UNC 变体）→ 守护进程归一化为 wsl://Debian/home/u/p
    let mut peer = test_peer(None);
    peer.cwd = Some(r"\\wsl.localhost\DEBIAN\home\u\p\sub".to_string());
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["result"]["value"], "sk-wsl",
        "wsl:// 读规则应命中：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0);
}

/// 条目不存在 → `item.not_found`（现状语义，spec §5.2 步骤 2），不弹窗。
#[test]
fn disclosure_missing_item_reports_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": ghost })),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_ITEM_NOT_FOUND, "{resp}");
    assert_eq!(shared.approvals.pending_count(), 0);
}
