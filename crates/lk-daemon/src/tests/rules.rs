//! rules 域测试（自原 lib.rs tests 模块拆出；助手见 `super`）。

use super::*;

/// 规则入库形态与运行时 cwd 判定同基准（§7.4 两侧同函数）：rule.add 的
/// canonicalize 产物再过 canonical_project_dir 入库；Windows 上该归一化
/// 剥离 verbatim 前缀，否则与 evaluate 侧归一化 cwd 不匹配（回归门：
/// Windows CI 下此断言直接捕捉存储形态漂移）。
#[test]
fn rule_add_stores_normalized_project_dir() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // desktop 直调豁免（补充拍板 #22：socket 通道 rule.add 走审批门；
    // 本用例测存储归一化形态，不测门）
    let add = rpc_result(&state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "p",
                    "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "cli" }),
        ),
        &PeerInfo::desktop(),
    ));
    let stored = add["rule"]["projectDir"]
        .as_str()
        .expect("规则应入库")
        .to_string();
    let canonical = lk_core::path_ns::canonical_project_dir(
        &std::fs::canonicalize(proj.path())
            .unwrap()
            .to_string_lossy(),
    );
    assert_eq!(stored, canonical);
    // 归一化后的存储形态与 evaluate 侧归一化 cwd 祖先匹配命中
    let handler = make_handler(&state, &_shared);
    let peer = test_peer(Some(proj.path()));
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "规则命中应放行：{resp}");
}

/// 规则 CRUD（IPC）+ 审计（channel 区分）+ `item.changed(kind="rule")` 广播。
#[test]
fn rule_crud_audits_and_broadcasts() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), None);
    // 监听 item.changed 帧（推送通道）
    let (_sid, rx) = shared.push.subscribe(true); // 桌面壳模拟（#72/#78 起订阅带来源标签）
                                                  // add
    let add = state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "pub",
                    "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "desktop" }),
        ),
        // desktop 直调豁免（补充拍板 #22；socket 通道的规则门覆盖见
        // tests/rule_gate.rs）
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&add).unwrap();
    let rule = &v["result"]["rule"];
    let id = rule["id"].as_str().unwrap().to_string();
    assert_eq!(rule["name"], "pub");
    assert_eq!(rule["command"], "npm publish");
    // projectDir 以 canonical 形态入库（§7.4 两侧同函数：canonicalize 产物
    // 再过 canonical_project_dir，Windows 下剥离 verbatim \\?\ 前缀）
    let canonical_proj = lk_core::path_ns::canonical_project_dir(
        &std::fs::canonicalize(proj.path())
            .unwrap()
            .to_string_lossy(),
    );
    assert_eq!(rule["projectDir"], canonical_proj);
    // 广播 item.changed(kind=rule, deleted=false)（决策 #6）
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "item.changed");
    assert_eq!(fv["params"]["type"], "rule");
    assert_eq!(fv["params"]["deleted"], false);
    assert_eq!(fv["params"]["itemId"], id);
    // list
    let list = state.lock().unwrap().handle(
        &rpc_line(M_RULE_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&list).unwrap();
    assert_eq!(v["result"]["rules"].as_array().unwrap().len(), 1);
    // remove → 广播 deleted=true
    state.lock().unwrap().handle(
        &rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id })),
        &PeerInfo::desktop(),
    );
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["params"]["type"], "rule");
    assert_eq!(fv["params"]["deleted"], true);
    // list 不再包含
    let list = state.lock().unwrap().handle(
        &rpc_line(M_RULE_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&list).unwrap();
    assert_eq!(v["result"]["rules"].as_array().unwrap().len(), 0);
    // 审计：add（desktop）/ list ×2（cli）/ remove（cli）四条留痕
    let events = audit_events(dir.path());
    let rule_evs: Vec<_> = events
        .iter()
        .filter(|e| e.command.starts_with("rule."))
        .collect();
    assert_eq!(rule_evs.len(), 4);
    assert_eq!(rule_evs[0].command, "rule.add pub");
    assert_eq!(rule_evs[0].channel, lk_core::audit::AuditChannel::Desktop);
    assert_eq!(
        rule_evs.iter().filter(|e| e.command == "rule.list").count(),
        2
    );
    assert!(rule_evs
        .iter()
        .any(|e| e.command.starts_with("rule.remove")));
}

/// rule.add 校验：超长/非法 projectDir、非法 key 名 → 拒绝不入库（#19）。
#[test]
fn rule_add_rejects_invalid_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    // desktop 直调豁免下的校验路径（补充拍板 #22：字段校验先于通道判定，
    // socket 通道同样先报 invalid params）
    let handle = |params: Value| -> Value {
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_RULE_ADD, Some(&token), params),
            &PeerInfo::desktop(),
        );
        serde_json::from_str(&resp).unwrap()
    };
    // 相对路径
    assert!(handle(
        json!({ "projectDir": "relative/path", "name": "n", "command": "c", "keys": ["K"] })
    )["error"]
        .is_object());
    // 不存在的绝对路径
    assert!(handle(json!({ "projectDir": "/definitely/not/exists-xyz", "name": "n", "command": "c", "keys": ["K"] }))["error"].is_object());
    // 非法 key 名
    assert!(handle(json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": ["BAD-KEY!"] }))["error"].is_object());
    // 超长 command
    let long = "x".repeat(1025);
    assert!(handle(
        json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": long, "keys": ["K"] })
    )["error"]
        .is_object());
    // 空 keys
    assert!(handle(
        json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": [] })
    )["error"]
        .is_object());
    // 合法 → 入库
    assert!(handle(
        json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": ["K"] })
    )["result"]["rule"]["id"]
        .is_string());
}

/// 跨命名空间归一化（cross-subsystem.md §7.4/§10）：rule.add 收 UNC WSL
/// 路径 → 以 `wsl://<distro>/<rest>` 规范形入库；运行时对端 cwd 为伪造
/// 写法变体（大写 distro / 尾斜杠）→ 归一化后与规则一致匹配放行；
/// `channel=wsl-bridge` 如实审计。
#[test]
fn rule_add_and_authz_normalize_wsl_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 规则入库：UNC 形态（守护进程侧归一化为规范形）
    let raw = state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": r"\\wsl.localhost\Debian\home\u\p", "name": "wsl",
                    "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
        ),
        // desktop 直调豁免（补充拍板 #22）；channel=wsl-bridge 标注照旧入审计
        &PeerInfo::desktop(),
    );
    let add = rpc_result(&raw);
    assert_eq!(
        add["rule"]["projectDir"], "wsl://Debian/home/u/p",
        "UNC 应归一为 wsl:// 规范形入库：{add}"
    );
    // 运行时：对端 cwd 为伪造写法变体（大写 distro + 尾斜杠）→ 命中同一规则
    let handler = make_handler(&state, &shared);
    let peer = PeerInfo {
        pid: std::process::id(),
        cwd: Some(r"\\wsl.localhost\DEBIAN\home\u\p\".to_string()),
        origin: PeerOrigin::Socket,
    };
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "归一化后应命中规则：{resp}");
    // 审计如实记录 channel=wsl-bridge
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(
        authz_evs[0].channel,
        lk_core::audit::AuditChannel::WslBridge
    );
}

/// 路由表完整性：全部 `M_*` 方法常量经 handle()（直调形态查同一张策略
/// 表）均可命中——未解锁态下预期 session.invalid / invalid params 等，
/// 但绝不 method-not-found。防「加方法忘登记」退回静默 not-found。
#[test]
fn routing_table_covers_all_methods() {
    let dir = tempfile::tempdir().unwrap();
    let mut daemon = Daemon::start(dir.path()).unwrap();
    let all_methods = [
        M_VAULT_STATUS,
        M_VAULT_INIT,
        M_VAULT_UNLOCK,
        M_VAULT_LOCK,
        M_VAULT_RECOVER,
        M_ITEM_LIST,
        M_ITEM_GET,
        M_ITEM_PUT,
        M_ITEM_DELETE,
        M_ITEM_EXPORT,
        M_AUDIT_LIST,
        M_AUDIT_VERIFY,
        M_SYNC_TRIGGER,
        M_SYNC_POLL,
        M_AUTHZ_EVALUATE,
        M_APPROVAL_RESULT,
        M_RULE_ADD,
        M_RULE_LIST,
        M_RULE_REMOVE,
        M_SUBSCRIBE,
    ];
    for method in all_methods {
        let resp =
            rpc_json(&daemon.handle(&rpc_line(method, None, json!({})), &PeerInfo::unknown()));
        let err = &resp["error"];
        if !err.is_null() {
            assert_ne!(
                err["code"], ERR_METHOD_NOT_FOUND,
                "{method} 未在执行计划路由登记（strategy_of 缺臂）"
            );
        }
    }
    // 对照：未知方法仍然 method-not-found（表完整性断言本身有效）
    let unknown = rpc_json(&daemon.handle(
        &rpc_line("nonexistent.method", None, json!({})),
        &PeerInfo::unknown(),
    ));
    assert_eq!(unknown["error"]["code"], ERR_METHOD_NOT_FOUND);
}
