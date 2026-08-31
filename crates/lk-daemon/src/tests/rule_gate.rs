//! 规则管理审批门集成测试（补充拍板 #22；authorization-gate.md §9）。
//!
//! seam：`router.rs strategy_of` 策略表 + daemon 装配（route 主缝 / handle
//! 直调）。审批三态经进程内桌面订阅（`push.subscribe(true)`）+ `approval.result`
//! 直调回传（#78 方案 A 语义）；E2E 自动批准经 `start_with_rule_auto` 显式
//! 装配（不读进程 env，避免并行测试竞争）。

use super::*;

/// 审计中的规则门事件（command 以 rule.add / rule.remove 开头）。
fn rule_gate_audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    audit_events(dir)
        .into_iter()
        .filter(|e| e.command.starts_with("rule.add") || e.command.starts_with("rule.remove"))
        .collect()
}

/// 取下一帧 `authz.request`（跳过 rule.add 落盘后广播的 `item.changed`
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

/// 策略表：`rule.add` / `rule.remove` 升为 ApprovalDeferred（补充拍板 #22）；
/// `rule.list` 维持 Inline（只读元数据，M2.9 同口径）。
#[test]
fn rule_gate_strategies() {
    assert_eq!(
        crate::strategy_of(M_RULE_ADD),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    assert_eq!(
        crate::strategy_of(M_RULE_REMOVE),
        crate::ExecutionStrategy::ApprovalDeferred
    );
    assert_eq!(
        crate::strategy_of(M_RULE_LIST),
        crate::ExecutionStrategy::Inline
    );
}

/// desktop 内嵌直调：受信豁免直执行（GUI 设置页 / 读值弹窗「允许并记住」
/// 内部的 ruleAdd），审计 channel=desktop（现状语义回归）。
#[test]
fn rule_gate_desktop_direct_exempt() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    let id = v["result"]["rule"]["id"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id })),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(v["error"].is_null(), "desktop 直调豁免：{resp}");
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 2);
    assert!(evs
        .iter()
        .all(|e| e.channel == lk_core::audit::AuditChannel::Desktop));
}

/// socket 无 UI（headless）→ fail-closed 立即拒绝（-32017 authz.denied，
/// 复用值披露错误码，协议零新增）+ 失败路径审计 Denied；bridge 通道
/// （channel=wsl-bridge 标注）同样受门且归因如实。
#[test]
fn rule_gate_headless_no_ui_denied_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &_shared);
    let resp = handler(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_AUTHZ_DENIED,
        "无 UI headless 拒绝：{resp}"
    );
    assert_eq!(v["error"]["message"], MSG_AUTHZ_DENIED);
    // 失败路径审计（现状仅成功路径写）：denied + wsl-bridge 归因
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 1, "拒绝写审计");
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[0].command, "rule.add pub");
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::WslBridge);
}

/// 启动者未知（对端 PID 不可得）→ fail-closed 拒绝，不弹窗（与 inject/披露
/// 同口径）。
#[test]
fn rule_gate_unknown_starter_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let _ = shared; // 无桌面订阅（无 UI 分支先行也须拒绝）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &PeerInfo::unknown(), // pid=0 → starter=unknown
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED);
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[0].starter, "unknown");
}

/// socket + 桌面订阅在场：弹窗三态（allow → 落规则 / deny / timeout）+
/// 审计（allowed=channel=approval；denied/timeout=失败路径审计）。审批帧
/// kind=rule、command=`rule.add <name>`、keys/项目目录如实展示。
#[test]
fn rule_gate_pending_allow_deny_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let (_sid, rx) = shared.push.subscribe(true);

    // -- allow：批准 → 落规则 + 审计 channel=approval
    let line = rpc_line(
        M_RULE_ADD,
        Some(&token),
        json!({ "projectDir": proj.path(), "name": "pub",
                "command": "npm *", "keys": ["NPM_TOKEN"] }),
    );
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let fv = next_authz_frame(&rx);
    assert_eq!(
        fv["params"]["kind"], "rule",
        "规则审批帧 kind=rule（补充拍板 #22）"
    );
    assert_eq!(
        fv["params"]["command"], "rule.add pub",
        "单一 kind + command 承载操作"
    );
    assert_eq!(fv["params"]["keys"][0], "NPM_TOKEN");
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
    assert!(
        v["result"]["rule"]["id"].is_string(),
        "批准后落规则：{resp}"
    );
    // 规则确实入库
    let list = state.lock().unwrap().handle(
        &rpc_line(M_RULE_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    assert_eq!(rpc_result(&list)["rules"].as_array().unwrap().len(), 1);
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::Approval);
    assert_eq!(evs[0].command, "rule.add pub");

    // -- deny：拒绝 → authz.denied + 失败路径审计
    let line = rpc_line(
        M_RULE_ADD,
        Some(&token),
        json!({ "projectDir": proj.path(), "name": "deploy",
                "command": "yarn *", "keys": ["NPM_TOKEN"] }),
    );
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
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
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[1].result, lk_core::audit::AuditResult::Denied);
    // 拒绝不落规则
    let list = state.lock().unwrap().handle(
        &rpc_line(M_RULE_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    assert_eq!(rpc_result(&list)["rules"].as_array().unwrap().len(), 1);

    // -- timeout（显式收窄审批窗口到 1s——夹具为生产默认 30s，#92；不回传
    //    等超时默认拒绝）
    shared.config.write().unwrap().approval_timeout_secs = 1;
    let line = rpc_line(
        M_RULE_ADD,
        Some(&token),
        json!({ "projectDir": proj.path(), "name": "shell",
                "command": "sh *", "keys": ["NPM_TOKEN"] }),
    );
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let _fv = next_authz_frame(&rx);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_AUTHZ_DENIED, "超时默认拒绝：{resp}");
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[2].result, lk_core::audit::AuditResult::Timeout);
}

/// remove 门：审批帧展示 id→规则解析出的名称 / keys / projectDir（daemon
/// 侧补全，补充拍板 #22）；批准后删除生效 + 审计。
#[test]
fn rule_gate_remove_popup_shows_resolved_rule() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    // 预插规则走 desktop 豁免
    let add = rpc_result(&state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "publish",
                    "command": "npm *", "keys": ["NPM_TOKEN", "GH_TOKEN"] }),
        ),
        &PeerInfo::desktop(),
    ));
    let id = add["rule"]["id"].as_str().unwrap().to_string();
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id }));
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["params"]["kind"], "rule");
    assert_eq!(
        fv["params"]["command"], "rule.remove publish",
        "弹窗按名称展示被删规则（id→规则解析补全）：{frame}"
    );
    let keys: Vec<&str> = fv["params"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert!(
        keys.contains(&"NPM_TOKEN") && keys.contains(&"GH_TOKEN"),
        "keys 展示既有规则授权"
    );
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
    assert!(v["error"].is_null(), "批准后删除生效：{resp}");
    let list = state.lock().unwrap().handle(
        &rpc_line(M_RULE_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    assert_eq!(rpc_result(&list)["rules"].as_array().unwrap().len(), 0);
    let evs = rule_gate_audit_events(dir.path());
    assert!(evs.iter().any(|e| e.command.starts_with("rule.remove")
        && e.result == lk_core::audit::AuditResult::Allowed
        && e.channel == lk_core::audit::AuditChannel::Approval));
}

/// 锁定态：`session.invalid` 先行（规则在加密库内；不弹解锁窗——锁态规则
/// 管理一体化在规格 Out of Scope）。
#[test]
fn rule_gate_locked_vault_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
        &PeerInfo::desktop(),
    );
    let handler = make_handler(&state, &_shared);
    let resp = handler(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "锁态 session.invalid：{resp}"
    );
}

/// 等待期锁定 → 批准也无法落盘：vault 与 K_audit 已擦除 → 保守
/// `session.invalid`（与披露 finalize 同口径）。
#[test]
fn rule_gate_locked_during_wait_session_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let line = rpc_line(
        M_RULE_ADD,
        Some(&token),
        json!({ "projectDir": proj.path(), "name": "pub",
                "command": "npm *", "keys": ["NPM_TOKEN"] }),
    );
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
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

/// finalize 锁内重校验（TOCTOU）：30s 等待窗内目标规则被并发改变（另一
/// desktop 直调删除）→ 批准也拒绝并落审计（不产生基于过期快照的写入）。
#[test]
fn rule_gate_remove_race_rule_changed_during_wait() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    let add = rpc_result(&state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "publish",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &PeerInfo::desktop(),
    ));
    let id = add["rule"]["id"].as_str().unwrap().to_string();
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    // socket 发起 remove → 登记 pending（等待桌面决策）
    let line = rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id }));
    let peer = test_peer(Some(proj.path()));
    let h = {
        let handler = handler.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let fv = next_authz_frame(&rx);
    let (request_id, challenge) = (
        fv["params"]["requestId"].as_str().unwrap().to_string(),
        fv["params"]["challenge"].as_str().unwrap().to_string(),
    );
    // 等待窗内：desktop 直调（GUI 日常管理）先删了同一条规则
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id })),
        &PeerInfo::desktop(),
    );
    assert!(serde_json::from_str::<Value>(&resp).unwrap()["error"].is_null());
    // 批准到达 → finalize 锁内重验规则存在性：已消失 → 拒绝 + 审计
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
        "规则已消失 → 批准也拒绝（TOCTOU 重校验）：{resp}"
    );
    let evs = rule_gate_audit_events(dir.path());
    // 第一条：desktop 豁免预插（allowed）；第二条：desktop 直调删除（allowed）；
    // 第三条：socket 门内 TOCTOU 拒绝（denied）
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[2].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(evs[2].channel, lk_core::audit::AuditChannel::Approval);
}

/// E2E 自动批准（env 门控）：无 UI 时规则审批立即 Allowed——审计
/// channel=auto-approve 且 command 含 requestId 与规则内容；inject 审批
/// **不受影响**（无规则 + 无 UI 照旧立即拒绝，不等待）。
#[test]
fn rule_gate_auto_approve_allows_rule_only() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon_with(dir.path(), Some(("NPM_TOKEN", "sekrit")), true);
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    // 无桌面订阅（headless）+ 自动批准门开启 → 规则落盘成功
    let resp = handler(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert!(
        v["result"]["rule"]["id"].is_string(),
        "自动批准 → 落规则：{resp}"
    );
    assert_eq!(shared.approvals.pending_count(), 0, "即时决策不留 pending");
    let evs = rule_gate_audit_events(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].channel, lk_core::audit::AuditChannel::AutoApprove);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert!(
        evs[0].command.starts_with("rule.add pub [auto-approve "),
        "command 含规则内容与 requestId（绝不静默）：{}",
        evs[0].command
    );
    // 对照：inject 未命中规则 + 无 UI → 照旧立即拒绝（自动批准不碰 inject）
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "cargo publish", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false, "{resp}");
    assert_eq!(v["result"]["reason"], "no_ui", "inject 审批不受 E2E 门影响");
}
