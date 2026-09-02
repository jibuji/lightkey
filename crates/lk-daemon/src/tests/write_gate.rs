//! 写入授权门集成测试（M2.97 补充拍板 #24；write-gate.md §3 判定矩阵 /
//! §5 执行计划 / §8 审计 / §10.2 集成测试计划，issue #113）。
//!
//! seam：`router.rs strategy_of` 策略表 + daemon 装配（route 主缝 / handle
//! 直调）；审批三态经进程内桌面订阅（`push.subscribe(true)`）+
//! `approval.result` 直调回传（#78 方案 A 语义）。写规则种子不走 `rule.add`
//! RPC（校验层尚未放行 capability=write——PR C 随 `--write` 贯通），直接经
//! vault 写锁 `put_rule` 落库（与桌面规则页同一条唯一写入路径）。

use super::*;

/// 审计中的写门事件（command 以 item.create / item.update / item.delete
/// 开头；write-gate.md §8——daemon 侧按 action 派生，值不明文）。
fn write_audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    audit_events(dir)
        .into_iter()
        .filter(|e| {
            e.command.starts_with("item.create")
                || e.command.starts_with("item.update")
                || e.command.starts_with("item.delete")
        })
        .collect()
}

/// 取下一帧 `authz.request`（跳过写落盘/规则落库广播的 `item.changed`
/// 等无关帧——推送通道按序投递，测试按方法名过滤）。
fn next_authz_frame(rx: &mpsc::Receiver<String>) -> Value {
    loop {
        let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        if fv["method"] == "authz.request" {
            return fv;
        }
    }
}

/// 直接经 vault 写锁种一条写规则（capability=write；`rule.add` RPC 校验层
/// 尚未放行 write 能力，PR C 贯通——测试种子与桌面规则页同走 `put_rule`）。
fn seed_write_rule(
    shared: &Arc<SharedDaemon>,
    project_dir: &std::path::Path,
    keys: &[&str],
    actions: &[&str],
) {
    let canonical = lk_core::path_ns::canonical_project_dir(
        &std::fs::canonicalize(project_dir)
            .unwrap()
            .to_string_lossy(),
    );
    let mut guard = shared.vault.write().unwrap();
    guard
        .as_mut()
        .unwrap()
        .put_rule(
            lk_core::model::RuleDraft {
                project_dir: canonical,
                name: "write-seed".into(),
                command: String::new(),
                keys: keys.iter().map(|s| s.to_string()).collect(),
                capability: lk_core::model::RULE_CAPABILITY_WRITE.into(),
                actions: actions.iter().map(|s| s.to_string()).collect(),
                fingerprint: None,
            },
            None,
        )
        .unwrap();
}

/// desktop 直调种一个 secret 条目，返回（id, revision）。
fn seed_secret(
    state: &Arc<Mutex<Daemon>>,
    token: &str,
    name: &str,
    value: &str,
) -> (String, String) {
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(token),
            json!({ "item": {
                "type": "secret", "name": name, "value": value,
                "purpose": "", "expiresAt": null
            } }),
        ),
        &PeerInfo::desktop(),
    );
    let v = rpc_result(&resp);
    (
        v["item"]["id"].as_str().unwrap().to_string(),
        v["item"]["revision"].as_str().unwrap().to_string(),
    )
}

/// socket 发起写请求（写门主缝 route；线程内等待审批）。
fn spawn_write(
    handler: &transport::Handler,
    peer: &PeerInfo,
    method: &str,
    token: &str,
    params: Value,
) -> std::thread::JoinHandle<String> {
    let handler = handler.clone();
    let peer = peer.clone();
    let line = rpc_line(method, Some(token), params);
    std::thread::spawn(move || handler(&line, &peer))
}

/// 策略表：`item.put` / `item.delete` 升为 ApprovalDeferred（write-gate.md
/// §5.1）；`item.list` 维持 Inline（元数据令牌门，不裁决）。
#[test]
fn write_gate_strategies() {
    assert_eq!(
        crate::strategy_of(M_ITEM_PUT),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    assert_eq!(
        crate::strategy_of(M_ITEM_DELETE),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    assert_eq!(
        crate::strategy_of(M_ITEM_LIST),
        crate::ExecutionStrategy::Inline
    );
}

/// desktop 内嵌直调 put（create/update）/ delete：受信豁免直执行，不登记
/// 审批（spec §3 第 1 行）；审计 allowed、channel=desktop、command 按
/// action 派生、target=条目名（§8）。
#[test]
fn write_gate_desktop_direct_exempt_without_pending() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let pending_before = shared.approvals.pending_count();
    // create
    let (id, _rev) = seed_secret(&state, &token, "cfg", "v1");
    // update（整条替换）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": id,
                "expectedRevision": _rev,
                "item": {
                    "type": "secret", "name": "cfg", "value": "v2",
                    "purpose": "", "expiresAt": null
                }
            }),
        ),
        &PeerInfo::desktop(),
    );
    assert!(
        rpc_result(&resp)["item"]["id"].is_string(),
        "desktop 直调 update 直执行：{resp}"
    );
    // delete
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_DELETE, Some(&token), json!({ "id": id })),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(v["error"].is_null(), "desktop 直调 delete 直执行：{resp}");
    assert_eq!(
        shared.approvals.pending_count(),
        pending_before,
        "豁免路径不登记审批"
    );
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 3, "create/update/delete 全留痕：{:?}", evs);
    assert_eq!(evs[0].command, "item.create cfg");
    assert_eq!(evs[1].command, "item.update cfg");
    assert_eq!(evs[2].command, "item.delete cfg");
    assert!(evs
        .iter()
        .all(|e| e.result == lk_core::audit::AuditResult::Allowed
            && e.channel == lk_core::audit::AuditChannel::Desktop
            && e.target == "cfg"));
    assert!(
        !serde_json::to_string(&evs).unwrap().contains("v1v2"),
        "审计不明文记值"
    );
}

/// socket + 写规则命中 → 静默放行 + 审计 allowed（channel=cli）：create
/// 按草稿名命中；update 需存储名 ∧ 草稿名都在 keys（改名逃生/植毒不命中）。
#[test]
fn write_gate_socket_write_rule_hit_allows_silently() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    seed_write_rule(&shared, proj.path(), &["config.ini"], &["create", "update"]);
    // 对照组（不在 keys）：update 改名逃生用。种子 create 自身（desktop
    // 豁免）已留审计，断言从基线起算
    let (other_id, other_rev) = seed_secret(&state, &token, "other.ini", "x");
    let base = write_audit_events(dir.path()).len();
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));

    // create：草稿名命中 → 静默放行
    let resp = handler(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "secret", "name": "config.ini", "value": "v",
                "purpose": "", "expiresAt": null } }),
        ),
        &peer,
    );
    let created = rpc_result(&resp);
    assert!(
        created["item"]["id"].is_string(),
        "写规则命中 create 静默放行：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0, "规则命中不弹窗");
    let id = created["item"]["id"].as_str().unwrap().to_string();
    let rev = created["item"]["revision"].as_str().unwrap().to_string();

    // update：存储名 ∧ 草稿名都在 keys → 静默放行
    let resp = handler(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": id,
                "expectedRevision": rev,
                "item": {
                    "type": "secret", "name": "config.ini", "value": "v2",
                    "purpose": "", "expiresAt": null
                }
            }),
        ),
        &peer,
    );
    assert!(
        rpc_result(&resp)["item"]["id"].is_string(),
        "写规则命中 update 静默放行：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0);

    // 改名植毒：草稿名不在 keys → 不命中 → headless 拒绝
    let resp = handler(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": id,
                "expectedRevision": rpc_result(&resp)["item"]["revision"],
                "item": {
                    "type": "secret", "name": "poison.ini", "value": "p",
                    "purpose": "", "expiresAt": null
                }
            }),
        ),
        &peer,
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["error"]["code"],
        ERR_AUTHZ_DENIED,
        "草稿名不在 keys 不得静默放行：{resp}"
    );

    // 改名逃生：存储名不在 keys → 不命中 → 拒绝
    let resp = handler(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": other_id,
                "expectedRevision": other_rev,
                "item": {
                    "type": "secret", "name": "config.ini", "value": "hijack",
                    "purpose": "", "expiresAt": null
                }
            }),
        ),
        &peer,
    );
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["error"]["code"],
        ERR_AUTHZ_DENIED,
        "存储名不在 keys 不得静默放行：{resp}"
    );

    // 审计：两条 allowed（create/update，channel=cli）+ 两条 denied
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), base + 4);
    assert_eq!(evs[base].command, "item.create config.ini");
    assert_eq!(evs[base].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[base].channel, lk_core::audit::AuditChannel::Cli);
    assert_eq!(evs[base + 1].command, "item.update config.ini");
    assert_eq!(evs[base + 1].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[base + 2].command, "item.update poison.ini");
    assert_eq!(evs[base + 2].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[base + 3].command, "item.update config.ini");
    assert_eq!(evs[base + 3].result, lk_core::audit::AuditResult::Denied);
}

/// socket 无规则 + 桌面订阅在场 → 弹窗三态（allow / deny / timeout）+ 审计；
/// 审批帧 kind=write、command=`item.put <name>`（展示用）、keys=单元素、
/// projectDir=cwd、needsUnlock=false、不含值（write-gate.md §5.3 步骤 7）。
#[test]
fn write_gate_socket_no_rule_allow_deny_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let (_sid, rx) = shared.push.subscribe(true);

    // -- allow
    let h = spawn_write(
        &handler,
        &peer,
        M_ITEM_PUT,
        &token,
        json!({ "item": {
            "type": "secret", "name": "cfg", "value": "sekrit",
            "purpose": "", "expiresAt": null } }),
    );
    let fv = next_authz_frame(&rx);
    assert_eq!(fv["params"]["kind"], "write", "写审批帧 kind=write：{fv}");
    assert_eq!(fv["params"]["command"], "item.put cfg", "展示用 command");
    assert_eq!(fv["params"]["keys"][0], "cfg", "keys=单元素目标条目名");
    assert_eq!(fv["params"]["needsUnlock"], false);
    assert!(!fv.to_string().contains("sekrit"), "审批帧不含值：{fv}");
    let canonical_proj = lk_core::path_ns::canonical_project_dir(
        &std::fs::canonicalize(proj.path())
            .unwrap()
            .to_string_lossy(),
    );
    assert_eq!(fv["params"]["projectDir"], canonical_proj);
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
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
    assert!(v["result"]["item"]["id"].is_string(), "批准后落库：{resp}");
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].command, "item.create cfg");
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::Approval);

    // -- deny
    let id = {
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        rpc_result(&resp)["items"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let h = spawn_write(
        &handler,
        &peer,
        M_ITEM_PUT,
        &token,
        json!({
            "id": id,
            "item": {
                "type": "secret", "name": "cfg", "value": "evil",
                "purpose": "", "expiresAt": null
            }
        }),
    );
    let fv = next_authz_frame(&rx);
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
    assert_eq!(v["error"]["message"], MSG_AUTHZ_DENIED);
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[1].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[1].channel, lk_core::audit::AuditChannel::Approval);

    // -- timeout（显式收窄审批窗口到 1s——夹具为生产默认 30s，#92；
    //    不回传等超时默认拒绝）
    shared.config.write().unwrap().approval_timeout_secs = 1;
    let h = spawn_write(
        &handler,
        &peer,
        M_ITEM_PUT,
        &token,
        json!({
            "id": id,
            "item": {
                "type": "secret", "name": "cfg", "value": "evil",
                "purpose": "", "expiresAt": null
            }
        }),
    );
    let _fv = next_authz_frame(&rx);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED, "超时默认拒绝：{resp}");
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 3);
    assert_eq!(
        evs[2].result,
        lk_core::audit::AuditResult::Denied,
        "超时统一记 denied（write-gate.md §8）"
    );
}

/// socket 无规则 + 无桌面订阅（headless）→ `authz.denied`(-32017) + 审计
/// denied，不登记审批（spec §3）。
#[test]
fn write_gate_socket_no_rule_no_ui_denied_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "secret", "name": "cfg", "value": "v",
                "purpose": "", "expiresAt": null } }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "无规则无 UI 应拒绝：{resp}"
    );
    assert_eq!(v["error"]["message"], MSG_AUTHZ_DENIED);
    assert_eq!(shared.approvals.pending_count(), 0, "无 UI 不登记审批");
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 1, "拒绝写审计");
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[0].command, "item.create cfg");
    assert_eq!(evs[0].target, "cfg");
}

/// delete 恒弹窗：写规则 actions 防御性含 delete 也不豁免——有 UI 时照常
/// 弹窗（帧 command=`item.delete <name>`）；无 UI → 拒绝（spec §3/§5.3 步骤 5）。
#[test]
fn write_gate_delete_always_prompts_despite_write_rule() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    seed_write_rule(
        &shared,
        proj.path(),
        &["cfg"],
        &["create", "update", "delete"],
    );
    let (id, _rev) = seed_secret(&state, &token, "cfg", "v");
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));

    // 无 UI：规则含 delete 也直接拒绝（不静默放行）。种子 create 自身
    // （desktop 豁免）已留 1 条审计，拒绝事件从基线起算
    let base = write_audit_events(dir.path()).len();
    let resp = handler(
        &rpc_line(M_ITEM_DELETE, Some(&token), json!({ "id": id })),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "delete 恒弹窗：规则不豁免，无 UI 拒绝：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0);
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), base + 1);
    assert_eq!(evs[base].command, "item.delete cfg");
    assert_eq!(evs[base].result, lk_core::audit::AuditResult::Denied);

    // 有 UI：照常弹窗（帧证明「弹」而非「规则放行」），批准后删除生效
    let (_sid, rx) = shared.push.subscribe(true);
    let h = spawn_write(&handler, &peer, M_ITEM_DELETE, &token, json!({ "id": id }));
    let fv = next_authz_frame(&rx);
    assert_eq!(fv["params"]["kind"], "write");
    assert_eq!(
        fv["params"]["command"], "item.delete cfg",
        "delete 审批帧按展示形态广播"
    );
    assert_eq!(fv["params"]["keys"][0], "cfg");
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
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
    assert!(v["error"].is_null(), "批准后删除生效：{resp}");
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), base + 2);
    assert_eq!(evs[base + 1].command, "item.delete cfg");
    assert_eq!(evs[base + 1].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(
        evs[base + 1].channel,
        lk_core::audit::AuditChannel::Approval
    );
}

/// 启动者未知（对端 PID 不可得）→ 第 1 层 fail-closed 拒绝，不弹窗、
/// 不登记（put / delete 同口径；spec §3）。
#[test]
fn write_gate_unknown_starter_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let (id, _rev) = seed_secret(&state, &token, "cfg", "v");
    let handler = make_handler(&state, &shared);
    for method in [M_ITEM_PUT, M_ITEM_DELETE] {
        let params = if method == M_ITEM_PUT {
            json!({ "item": {
                "type": "secret", "name": "cfg", "value": "v",
                "purpose": "", "expiresAt": null } })
        } else {
            json!({ "id": id })
        };
        let resp = handler(
            &rpc_line(method, Some(&token), params),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED, "{method}: {resp}");
    }
    assert_eq!(shared.approvals.pending_count(), 0, "fail-closed 不登记");
    let evs = write_audit_events(dir.path());
    assert_eq!(
        evs.len(),
        3,
        "put/delete 失败路径全审计（含种子 create 1 条）"
    );
    assert!(evs[1..]
        .iter()
        .all(|e| e.result == lk_core::audit::AuditResult::Denied && e.starter == "unknown"));
}

/// 锁定态 → `session.invalid` 先行（不弹窗；未初始化库同口径——空库无从
/// 解锁，spec §3）。
#[test]
fn write_gate_locked_or_uninitialized_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::desktop(),
    );
    let handler = make_handler(&state, &shared);
    let put_line = rpc_line(
        M_ITEM_PUT,
        Some(&token),
        json!({ "item": {
            "type": "secret", "name": "cfg", "value": "v",
            "purpose": "", "expiresAt": null } }),
    );
    let resp = handler(&put_line, &test_peer(None));
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "锁定态 session.invalid：{resp}"
    );
    // 未初始化库：vault 不存在且未解锁 → 同口径 fail-closed
    let dir2 = tempfile::tempdir().unwrap();
    let daemon2 = Daemon::start(dir2.path()).unwrap();
    let shared2 = daemon2.shared();
    let state2 = Arc::new(Mutex::new(daemon2));
    let handler2 = make_handler(&state2, &shared2);
    let resp = handler2(
        &rpc_line(
            M_ITEM_PUT,
            None,
            json!({ "item": {
                "type": "secret", "name": "cfg", "value": "v",
                "purpose": "", "expiresAt": null } }),
        ),
        &test_peer(None),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "未初始化库同口径：{resp}"
    );
    assert_eq!(shared2.approvals.pending_count(), 0);
}

/// TOCTOU①：等待期整库被锁定 → 批准也无法落盘：vault 与 K_audit 已擦除 →
/// 保守 `session.invalid`（与披露/规则门 finalize 同口径）。
#[test]
fn write_gate_allowed_but_locked_during_wait_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let h = spawn_write(
        &handler,
        &peer,
        M_ITEM_PUT,
        &token,
        json!({ "item": {
            "type": "secret", "name": "cfg", "value": "v",
            "purpose": "", "expiresAt": null } }),
    );
    let fv = next_authz_frame(&rx);
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    // 命令锁内审批回传解析后、等待线程获得命令锁前锁定（锁屏线程时序）
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
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "等待期锁定 → session.invalid：{resp}"
    );
}

/// TOCTOU②：等待期 delete 目标已消失（被并发桌面直调删除）→ 批准也拒绝
/// 并审计（重验按**未删除**口径——`read_item_file` 含墓碑、幂等 delete
/// 静默成功，不能用作重验；write-gate.md §5.4）。
#[test]
fn write_gate_delete_target_deleted_during_wait_denied() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let (id, _rev) = seed_secret(&state, &token, "cfg", "v");
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let h = spawn_write(&handler, &peer, M_ITEM_DELETE, &token, json!({ "id": id }));
    let fv = next_authz_frame(&rx);
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    // 等待窗内：desktop 直调（GUI 日常操作）先删了同一条目（幂等 delete
    // 语义：条目置 deleted + 墓碑，文件仍在——按未删除口径重验必须识破）
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_DELETE, Some(&token), json!({ "id": id })),
        &PeerInfo::desktop(),
    );
    assert!(
        serde_json::from_str::<Value>(&resp).unwrap()["error"].is_null(),
        "桌面直调删除应成功：{resp}"
    );
    // 批准到达 → finalize 锁内重验目标已删除 → 拒绝 + 审计
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
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "目标已删除 → 批准也拒绝（TOCTOU 重校验）：{resp}"
    );
    let evs = write_audit_events(dir.path());
    let last = evs.last().unwrap();
    assert_eq!(last.command, "item.delete cfg");
    assert_eq!(last.result, lk_core::audit::AuditResult::Denied);
    assert_eq!(last.channel, lk_core::audit::AuditChannel::Approval);
    // 条目保持已删除（批准未造成二次写；item.list 含已删除条目，按
    // deleted 标志断言）
    let list = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    assert!(
        rpc_result(&list)["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["name"] == "cfg" || i["deleted"] != true),
        "已删条目不得复活（不得出现 deleted=false 的 cfg）：{list}"
    );
}

/// #78 回归（write 门场景）：socket 连接提交 `approval.result` →
/// `channel.forbidden`，写审批只能由桌面回传批准；等待者按超时默认拒绝。
#[test]
fn write_gate_socket_cannot_self_approve() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    // 纯超时收尾测试（socket 伪回传被拒后等待者按超时默认拒绝）：显式
    // 收窄窗口到 1s（夹具为生产默认 30s，#92）
    shared.config.write().unwrap().approval_timeout_secs = 1;
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let h = spawn_write(
        &handler,
        &peer,
        M_ITEM_PUT,
        &token,
        json!({ "item": {
            "type": "secret", "name": "cfg", "value": "v",
            "purpose": "", "expiresAt": null } }),
    );
    let fv = next_authz_frame(&rx);
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
    // 伪回传未造成写入
    let evs = write_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
}
