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
        // 读规则预插走 desktop 直调豁免（补充拍板 #22）
        &PeerInfo::desktop(),
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
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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

    // -- timeout（显式收窄审批窗口到 1s——夹具为生产默认 30s，#92；
    //    不回传等超时默认拒绝；本测试前两相位需要回传落地，须宽窗口）
    shared.config.write().unwrap().approval_timeout_secs = 1;
    let line = rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let _frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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
        &PeerInfo::desktop(),
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
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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
    // 纯超时收尾测试（socket 伪回传被拒后等待者按超时默认拒绝）：显式
    // 收窄窗口到 1s（夹具为生产默认 30s，#92），短窗口只是让用例跑得快
    shared.config.write().unwrap().approval_timeout_secs = 1;
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
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
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

/// 锁定态 + 无桌面订阅（纯 headless）读值 → `session.invalid`（补充拍板
/// #23：一体化解锁弹窗只在**桌面 UI 在场**时提供；headless 维持 fail-closed，
/// 与 spec §3 原始语义一致——有 UI 的锁态一体化路径见下方 #23 用例组）。
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
    // 无桌面订阅（headless）→ session.invalid（#23 维持 fail-closed）
    let handler = make_handler(&state, &_shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": item_id })),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "锁定态 headless session.invalid：{resp}"
    );
}

// -------------------------------------------------------------------------
// #23 读通道一体化解锁（锁定态 + 桌面 UI 在场 → 主密码 + 解锁并允许窗；
// issue #105 / docs/decisions.md #23）
// -------------------------------------------------------------------------

/// 锁态夹具中按名称取条目 id：临时解锁 → list → 锁回（夹具语义；锁态下
/// 无法读加密索引）。断言回到锁态。
fn locked_item_id(state: &Arc<Mutex<Daemon>>, name: &str) -> String {
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    let token = rpc_result(&resp)["token"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let items = rpc_result(&resp)["items"].as_array().unwrap().clone();
    let id = items.iter().find(|i| i["name"] == name).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    id
}

/// 锁态两种子的 dominant flow helper：往锁态库种一个条目（临时解锁 →
/// 种 → 锁回），返回条目 id。
fn locked_seed_item(state: &Arc<Mutex<Daemon>>, item: Value) -> String {
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    let token = rpc_result(&resp)["token"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_PUT, Some(&token), item),
        &PeerInfo::unknown(),
    );
    let id = rpc_result(&resp)["item"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    id
}

/// 锁态 get 全流程：登记 Pending{needs_unlock:true} + 广播 authz.request
/// (needsUnlock=true, kind=read) → approval.result(allowed + masterPassword)
/// → 临时解锁 → 在临时 vault 披露值 + 审计；**临时 vault 无痕**（shared
/// vault 仍锁定、session.token 不存在、vault.status 仍 locked）——即
/// #23「单次披露即毁」+ #65 边界。
#[test]
fn locked_disclosure_get_unified_unlock_returns_value_trace_free() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("APIKey", "sk-1")), None);
    // 锁态自检：vault 未解锁、令牌文件不存在
    assert!(!shared.vault.read().unwrap().is_some());
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());

    // 锁态下取条目 id（临时解锁 → list → 锁回，夹具语义）
    let item_id = locked_item_id(&state, "APIKey");
    assert!(!shared.vault.read().unwrap().is_some(), "夹具应回到锁态");

    // 桌面订阅在场 → has_ui=true
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let audit_before = audit_events(dir.path()).len();
    // 线程内发起 get（锁态、无 token——一体化流程应放行到审批等待）
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_GET, None, json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    // 广播帧：kind=read + needsUnlock=true + command=item.get
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert_eq!(fv["params"]["kind"], "read", "读通道一体化帧 kind=read");
    assert_eq!(
        fv["params"]["needsUnlock"], true,
        "锁态读帧必须标注 needsUnlock：{frame}"
    );
    assert_eq!(fv["params"]["command"], "item.get");
    assert!(!frame.contains("sk-1"), "审批帧不含值");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 审批回传：desktop + allowed + masterPassword（锁态无会话令牌，跳过
    // require_session 由 needs_unlock 待审保证）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    // get 返回放行 + 值
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1", "锁态一体化应放行：{resp}");
    // 关键约束（#23/#65）：临时 vault 即用即毁——无 session.token、
    // shared vault 仍锁定、vault.status 仍 locked
    assert!(
        shared.vault.read().unwrap().is_none(),
        "临时解锁不得改写共享 vault（须保持锁定）"
    );
    assert!(
        !dir.path().join(crate::SESSION_TOKEN_FILE).exists(),
        "临时解锁不得写 session.token"
    );
    let status = state.lock().unwrap().handle(
        &rpc_line(M_VAULT_STATUS, None, json!({})),
        &PeerInfo::unknown(),
    );
    let sv: Value = serde_json::from_str(&status).unwrap();
    assert_eq!(sv["result"]["unlocked"], false, "vault.status 仍 locked");
    assert_eq!(sv["result"]["initialized"], true);
    // 审计两条：#23 —— vault.unlock(desktop) + item.get(allowed, approval,
    // target=条目名——finalize 在临时 vault 上解析)
    let flow_events = &audit_events(dir.path())[audit_before..];
    let unlock_evs: Vec<_> = flow_events
        .iter()
        .filter(|e| e.command == "vault.unlock")
        .collect();
    assert_eq!(unlock_evs.len(), 1, "解锁事件须留痕");
    assert_eq!(unlock_evs[0].channel, lk_core::audit::AuditChannel::Desktop);
    let get_evs: Vec<_> = flow_events
        .iter()
        .filter(|e| e.command == "item.get")
        .collect();
    assert_eq!(get_evs.len(), 1);
    assert_eq!(get_evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(get_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    assert_eq!(get_evs[0].target, "APIKey");
}

/// 锁态 export 全流程：与 get 同机制（#23 范围：get/export 都做）——
/// kind=export 一体化帧 → 解锁 + 允许 → 返回数据包；临时 vault 无痕。
#[test]
fn locked_disclosure_export_unified_unlock_returns_bundle() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    // 锁态库种 file 条目（临时解锁 → 种 → 锁回；夹具语义）
    let file_id = {
        let (state, _shared) = locked_daemon(dir.path(), None, None);
        locked_seed_item(
            &state,
            json!({ "item": {
                "type": "file", "name": "report.bin", "note": "",
                "fileType": "application/octet-stream", "attachment": "report.bin",
                "fileData": base64::engine::general_purpose::STANDARD
                    .encode(b"payload-bytes"),
            } }),
        )
    };
    let (state, shared) = {
        // 复用同一数据目录的新守护实例（锁定态）
        let daemon = Daemon::start(dir.path()).unwrap();
        let shared = daemon.shared();
        let state = Arc::new(std::sync::Mutex::new(daemon));
        (state, shared)
    };
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_EXPORT, None, json!({ "id": file_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert_eq!(fv["params"]["kind"], "export");
    assert_eq!(fv["params"]["needsUnlock"], true);
    assert_eq!(fv["params"]["command"], "item.export");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
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
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(v["result"]["data"].as_str().unwrap())
            .unwrap(),
        b"payload-bytes"
    );
    // 临时 vault 无痕
    assert!(!shared.vault.read().unwrap().is_some());
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());
}

/// 锁态必弹窗：即使该条目已有 read 规则命中（capability=read、projectDir/
/// keys 匹配）也必弹一体化窗——规则在加密库内无法预载（与 #67 inject 同款
/// 妥协，补充拍板 #23）。批准后放行。
#[test]
fn locked_disclosure_with_matching_read_rule_still_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(
        dir.path(),
        Some(("APIKey", "sk-1")),
        Some((proj.path(), "APIKey")),
    );
    // 锁态下取条目 id（临时解锁 → list → 锁回，夹具语义）
    let item_id = locked_item_id(&state, "APIKey");
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_GET, None, json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    // 锁态 read 规则命中仍必弹窗：needsUnlock=true 一体化帧，不是静默放行
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert_eq!(fv["params"]["kind"], "read");
    assert_eq!(fv["params"]["needsUnlock"], true);
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1");
}

/// 密码错重试：错误主密码 → `vault.invalid` 统一文案（防探测）+ 条目保留
/// （弹窗可重试）→ 正确密码 → 放行；期间 vault 保持锁定、无令牌。
#[test]
fn locked_disclosure_wrong_password_keeps_pending_then_retry() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("APIKey", "sk-1")), None);
    let item_id = locked_item_id(&state, "APIKey");
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_GET, None, json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // 错误主密码：vault.invalid 统一文案（不区分原因防探测）、条目未消费
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "WRONG-PW" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_VAULT_INVALID, "{resp}");
    assert_eq!(v["error"]["message"], MSG_VAULT_INVALID);
    assert_eq!(shared.approvals.pending_count(), 1, "错误密码不得消费条目");

    // 弹窗内重试：正确密码 → 放行
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1", "重试成功应放行：{resp}");
    assert!(!shared.vault.read().unwrap().is_some());
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());
}

/// 等待期整库被解锁 → finalize 走**常态路径**（共享 vault 披露 + 共享
/// K_audit 审计）：用户绕开弹窗直接解锁（GUI 解锁页）后放行照常成功。
#[test]
fn locked_disclosure_unlocked_during_wait_finalize_normal_path() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("APIKey", "sk-1")), None);
    let item_id = locked_item_id(&state, "APIKey");
    assert!(!shared.vault.read().unwrap().is_some());
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_GET, None, json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // 等待期间整库被解锁（GUI 解锁页路径：命令行锁 handle 等价）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    assert!(rpc_result(&resp)["token"].as_str().is_some(), "{resp}");
    assert!(shared.vault.read().unwrap().is_some(), "整库已被解锁");

    // 弹窗允许（带主密码；临时 unlock 冗余但无害）→ finalize 走常态路径
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
        ),
        &PeerInfo::desktop(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["result"]["accepted"],
        true
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["value"], "sk-1", "常态路径放行：{resp}");
    // 整库确实保持解锁（finalize 走常态路径后不额外锁定）
    assert!(shared.vault.read().unwrap().is_some());
}

/// 未初始化的库（initialized=false）+ 有桌面 UI：锁态不弹解锁窗、维持
/// fail-closed（补充拍板 #23——空库无从解锁，一体化解锁无意义）。
#[test]
fn uninitialized_locked_disclosure_fail_closed_even_with_ui() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).unwrap();
    let shared = daemon.shared();
    // 桌面订阅在场（UI 就绪）
    let (_sid, _rx) = shared.push.subscribe(true);
    let state = Arc::new(std::sync::Mutex::new(daemon));
    // 库未初始化；locked（vault=None）
    assert!(!shared.vault.read().unwrap().is_some());
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(M_ITEM_GET, None, json!({ "id": uuid::Uuid::new_v4() })),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "未初始化库锁态 fail-closed session.invalid：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0, "不弹窗、不登记");
}

/// 锁态一体化拒绝：denied（无需主密码）→ authz.denied + 不解锁 + 无审计
/// （锁态无 K_audit，拒绝不留内容，与 #67 注入拒绝同口径）。
#[test]
fn locked_disclosure_denied_fails_closed_without_audit() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("APIKey", "sk-1")), None);
    let item_id = locked_item_id(&state, "APIKey");
    let audit_before = audit_events(dir.path()).len();
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(M_ITEM_GET, None, json!({ "id": item_id }));
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
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
        "拒绝→authz.denied：{resp}"
    );
    assert!(!shared.vault.read().unwrap().is_some(), "拒绝不触发解锁");
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());
    let flow_events = &audit_events(dir.path())[audit_before..];
    assert!(
        !flow_events.iter().any(|e| e.command == "vault.unlock"),
        "拒绝不得产生解锁事件"
    );
    assert!(!flow_events.iter().any(|e| e.command == "item.get"));
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
        &PeerInfo::desktop(),
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
