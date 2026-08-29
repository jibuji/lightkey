//! authz 域测试（自原 lib.rs tests 模块拆出；助手见 `super`）。

use super::*;

/// 规则命中（第 2 层）：env 只含被授权 key 的值；审计 allowed（channel=cli）。
#[test]
fn authz_rule_hit_injects_env_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 规则：proj 下 npm * 授权 NPM_TOKEN
    let add = rpc_result(&state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "publish",
                    "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "cli" }),
        ),
        &PeerInfo::unknown(),
    ));
    assert!(add["rule"]["id"].as_str().is_some());

    let handler = make_handler(&state, &shared);
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
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");
    assert!(
        v["result"]["env"].get("GH_TOKEN").is_none(),
        "未授权 key 不可见"
    );
    // 审计：allowed（channel=cli；starter 为真实进程链回溯，非 unknown）
    let events = audit_events(dir.path());
    let authz_evs: Vec<_> = events
        .iter()
        .filter(|e| e.command.starts_with("lk inject"))
        .collect();
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Cli);
    assert_ne!(authz_evs[0].starter, lk_core::starter::UNKNOWN_STARTER);
    assert_eq!(authz_evs[0].target, "npm");
    assert!(
        !serde_json::to_string(authz_evs[0])
            .unwrap()
            .contains("sekrit"),
        "审计不含密钥值"
    );
}

/// 第 1 层：启动者未知（对端 PID 不可得）→ 拒绝 + 审计；不弹窗。
#[test]
fn authz_denies_unknown_starter_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
        ),
        &PeerInfo::unknown(), // pid=0 → starter=unknown
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false);
    assert_eq!(v["result"]["reason"], "unknown_starter");
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Denied);
}

/// 伪造 cwd（客户端自报参数）→ 守护进程以对端真实 cwd 判定：
/// 参数指向有规则的项目目录、真实 cwd 在别处 → 拒绝（testing.md #2）。
#[test]
fn authz_ignores_client_cwd_and_uses_peer_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "p",
                    "command": "npm *", "keys": ["NPM_TOKEN"] }),
        ),
        &PeerInfo::unknown(),
    );
    let handler = make_handler(&state, &shared);
    // 客户端自报 cwd = 项目目录（伪造）；真实 cwd = other → 必须拒绝
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"],
                    "cwd": proj.path() }),
        ),
        &test_peer(Some(other.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false, "伪造 cwd 不得放行：{resp}");
    // 真实 cwd = 项目目录 → 放行
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true);
}

/// 无审批界面（无订阅连接）+ 未命中规则 → 立即拒绝（不阻塞），
/// 原因 no_ui + 审计 denied（testing.md #7）。
#[test]
fn authz_denies_without_ui_fast() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    assert_eq!(shared.push.subscriber_count(), 0);
    let t0 = Instant::now();
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(Some(proj.path())),
    );
    // 阈值语义：粗上界，只防「误入审批等待」（m2_daemon 审批窗口=生产默认
    // 30s，误等任一都会超此界）；不是延迟 SLA。更紧的常数在并行测试负载下
    // 不可靠：Windows 启动者进程链回溯（Toolhelp+PEB）单机实测 ~440ms、
    // 满载 >1s，3× 过载下 begin 段整体 >5s（#92），故上界与 FRAME_WAIT 同阶。
    // 功能面由下方 reason=no_ui 断言锁定：走审批等待的结果是 timeout 而非
    // no_ui，时间上界只是兜底哨兵。
    assert!(t0.elapsed() < FRAME_WAIT, "无界面必须立即拒绝");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false);
    assert_eq!(v["result"]["reason"], "no_ui");
}

/// 第 3 层完整闭环：桌面订阅连接存在 → evaluate 阻塞等审批 →
/// 广播 authz.request 帧（含一次性 challenge，仅投桌面订阅者）→
/// approval.result（桌面直调 + 原样回带挑战）→ 放行 + 审计(Approval)。
#[test]
fn authz_approval_roundtrip_via_push_and_result() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    // 订阅连接（桌面壳模拟：进程内登记 = desktop 来源）
    let (_sid, rx) = shared.push.subscribe(true);
    assert_eq!(shared.push.subscriber_count(), 1);
    // 线程内发起 evaluate（阻塞至审批回传）
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"], "channel": "desktop" }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    // 推送通道收到 authz.request 帧（含 requestId + challenge；无密钥值）
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert!(fv.get("id").is_none());
    // projectDir 以对端 cwd 归一化形态广播（§7.4 两侧同函数：canonicalize
    // 产物再过 canonical_project_dir，Windows 下剥离 verbatim \\?\ 前缀）
    assert_eq!(
        fv["params"]["projectDir"],
        lk_core::path_ns::canonical_project_dir(
            &std::fs::canonicalize(proj.path())
                .unwrap()
                .to_string_lossy()
        )
    );
    assert_eq!(fv["params"]["command"], "yarn publish");
    assert_eq!(fv["params"]["keys"][0], "NPM_TOKEN");
    assert!(
        fv["params"]["challenge"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "authz.request 必须携带一次性挑战（#78 方案 B）：{fv}"
    );
    assert!(!frame.contains("sekrit"), "authz.request 不含密钥值");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 审批回传（approval.result）：仅桌面内嵌直调可提交（#78 方案 A）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    // evaluate 返回放行 + env
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true);
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");
    // 审计：channel=Approval（第 3 层结果）
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);
}

/// #49 回归：决策产生于一条连接（`approval.result`），必须写回**发起**
/// `authz.evaluate` 的那条连接。走真实 UDS 传输层（bind + serve +
/// `transport::request`），而非仅 `make_handler` 直调——覆盖「响应写回
/// 发起连接」投递段（#49 断点所在：finalize 已生成响应却未达客户端）。
#[cfg(unix)]
#[test]
fn authz_response_returns_on_initiating_connection_over_real_transport() {
    let _lock = transport_test_lock();
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);

    // 桌面壳订阅（进程内）：available()=true → 第 3 层走审批而非 no_ui
    let (_sid, rx) = shared.push.subscribe(true);

    // 真实 UDS 服务端（与生产 serve 主循环同一条路径）
    let listener = transport::bind_server(dir.path()).unwrap();
    global_shutdown().store(false, std::sync::atomic::Ordering::Relaxed);
    let hub = Some(Arc::clone(&shared.push));
    let serve_thread = std::thread::spawn(move || {
        let _ = transport::serve(listener, handler, hub, global_shutdown());
    });

    let ep = transport::read_endpoint(dir.path()).expect("bind 后应写入 daemon.json");
    wait_transport_ready(&ep);

    // 发起连接：authz.evaluate（阻塞至审批回传；channel=wsl-bridge 覆盖）
    let eval_line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
    );
    let eval_thread = std::thread::spawn({
        let ep = ep.clone();
        move || transport::request(&ep, &eval_line)
    });

    // 订阅通道收到 authz.request 帧 → 取 requestId/challenge（桌面壳视角）
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // 审批回传经桌面内嵌直调（#78 方案 A：socket 不再是合法提交面）——
    // 决策产生在与发起连接不同的线程，响应仍必须写回发起的 socket 连接
    let approve_resp = rpc_json(&state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    ));
    assert_eq!(approve_resp["result"]["accepted"], true);

    // 发起连接收到写回的响应：allowed + env
    let resp = eval_thread.join().unwrap().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "响应应写回发起连接：{resp}");
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");

    // 审计：channel=Approval（第 3 层结果；与生产一致）
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);

    // 收尾：置位 shutdown 让 serve 循环退出后 join（tempdir 再回收 socket）
    global_shutdown().store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = serve_thread.join();
}

/// #49 回归（Windows named pipe 形态）：与上方 UDS 版同构——决策产生于
/// 一条连接（`approval.result`），必须写回**发起** `authz.evaluate` 的那条
/// 真实 named pipe 连接（生产 WSL bridge 路径即此形态）。
#[cfg(windows)]
#[test]
fn authz_response_returns_on_initiating_connection_over_named_pipe() {
    let _lock = transport_test_lock();
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 审批窗口=夹具生产默认 30s：本测试锁定「投递」段而非超时边界，
    // 宽窗口避免负载/慢机把健康路径误判为 timeout（#92）
    let handler = make_handler(&state, &shared);

    // 桌面壳订阅（进程内）：available()=true → 第 3 层走审批而非 no_ui
    let (_sid, rx) = shared.push.subscribe(true);

    // 真实 named pipe 服务端（与生产 serve 主循环同一条路径）
    transport::bind_server(dir.path()).unwrap();
    global_shutdown().store(false, std::sync::atomic::Ordering::Relaxed);
    let hub = Some(Arc::clone(&shared.push));
    let serve_dir = dir.path().to_path_buf();
    let serve_thread = std::thread::spawn(move || {
        let _ = transport::serve(&serve_dir, handler, hub, global_shutdown());
    });

    let ep = transport::read_endpoint(dir.path()).expect("bind 后应写入 daemon.json");
    // serve 线程创建首个监听实例前 connect 报 FILE_NOT_FOUND（瞬态重试
    // 总窗口 ~200ms 满载下不够，#92）→ 先等就绪再发起真实请求
    wait_transport_ready(&ep);

    // 发起连接：authz.evaluate（阻塞至审批回传；channel=wsl-bridge 覆盖）
    let eval_line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
    );
    let eval_thread = std::thread::spawn({
        let ep = ep.clone();
        move || transport::request(&ep, &eval_line)
    });

    // 订阅通道收到 authz.request 帧 → 取 requestId/challenge（桌面壳视角）
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // 审批回传经桌面内嵌直调（#78 方案 A：socket 不再是合法提交面）——
    // 决策产生在与发起连接不同的线程，响应仍必须写回发起的 pipe 连接
    let approve_resp = rpc_json(&state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    ));
    assert_eq!(approve_resp["result"]["accepted"], true);

    // 发起连接收到写回的响应：allowed + env
    let resp = eval_thread.join().unwrap().expect("evaluate 应收到响应行");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "响应应写回发起连接：{resp}");
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");

    // 审计：channel=Approval（第 3 层结果；与生产一致）
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);

    // 收尾：置位 shutdown；serve 主循环可能阻塞在 ConnectNamedPipe
    // （Windows 无非阻塞轮询，与生产「进程退出即回收」语义一致），不 join
    global_shutdown().store(true, std::sync::atomic::Ordering::Relaxed);
    drop(serve_thread);
}

/// Windows named pipe 推送路径验证：真实 serve + 外部订阅连接（
/// transport::connect）应能收到 subscribe 响应与后续 notification 帧
/// （桌面壳进程内订阅不走此路径，外部订阅者唯一入口）。#49 排障发现的
/// 真实缺陷：旧实现「主线程阻塞 ReadFile + 复制句柄 WriteFile」在同步
/// named pipe 上把 writer 的写串行化在挂起读之后，帧全部滞留、订阅者
/// 饿死——本测试锁定回归。
#[cfg(windows)]
#[test]
fn push_stream_delivers_frames_over_real_named_pipe() {
    let _lock = transport_test_lock();
    let dir = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    transport::bind_server(dir.path()).unwrap();
    global_shutdown().store(false, std::sync::atomic::Ordering::Relaxed);
    let hub = Some(Arc::clone(&shared.push));
    let serve_dir = dir.path().to_path_buf();
    let serve_thread = std::thread::spawn(move || {
        let _ = transport::serve(&serve_dir, handler, hub, global_shutdown());
    });
    let ep = transport::read_endpoint(dir.path()).unwrap();
    // serve 线程创建首个监听实例前 connect 报 FILE_NOT_FOUND（瞬态重试
    // 总窗口 ~200ms 满载下不够，#92）→ 先等就绪再建订阅连接
    wait_transport_ready(&ep);

    // 订阅连接：subscribe → ok 响应 → 转流模式等通知帧
    let mut sub = transport::connect(&ep).unwrap();
    transport::write_line(
        &mut sub,
        &rpc_line(M_SUBSCRIBE, None, json!({ "token": token })),
    )
    .unwrap();
    let sub_resp = transport::read_line(&mut sub).unwrap().unwrap();
    let v: Value = serde_json::from_str(&sub_resp).unwrap();
    assert!(v.get("error").is_none(), "subscribe 应成功：{sub_resp}");

    // 触发 item.changed 事件（另一条连接的常规命令）
    let _ = transport::request(
        &ep,
        &rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "secret", "name": "PUSH_TEST", "value": "v",
                "purpose": "", "expiresAt": null
            } }),
        ),
    )
    .unwrap();

    // 订阅连接必须收到 item.changed 通知帧（修复前：永远收不到）
    let frame = transport::read_line(&mut sub)
        .unwrap()
        .expect("订阅连接应收到通知帧");
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "item.changed", "got: {frame}");

    global_shutdown().store(true, std::sync::atomic::Ordering::Relaxed);
    // serve 主循环可能阻塞在 ConnectNamedPipe，不 join（测试进程退出即回收）
    drop(serve_thread);
}

#[test]
fn authz_approval_timeout_denies_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 纯超时边界测试：显式收窄窗口到 1s（夹具已回到生产默认 30s，#92）——
    // 本测试不回传，超时拒绝与「回传落地」无关，短窗口只是让用例跑得快
    shared.config.write().unwrap().approval_timeout_secs = 1;
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 不回传 → 1s 后超时默认拒绝
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false);
    assert_eq!(v["result"]["reason"], "timeout");
    // 超时后回传（桌面直调 + 帧内挑战）→ 忽略（条目已清理）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], false);
    let authz_evs = inject_audit_events(dir.path());
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Timeout);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    // 失败提交的独立审计（#78：审批提交行为可归因；不计入 inject 事件）
    let submissions: Vec<_> = audit_events(dir.path())
        .into_iter()
        .filter(|e| e.command == "approval.result")
        .collect();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].result, lk_core::audit::AuditResult::Denied);
}

/// G1 回归：authz.evaluate 在第 3 层等待审批期间，其他命令不被阻塞
/// （30s 等待不持命令锁）。
#[test]
fn authz_wait_does_not_block_other_commands() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    // 发起 evaluate（阻塞等待审批）
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
    );
    let peer = test_peer(Some(proj.path()));
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 等待期间：其他命令必须及时返回（命令锁未被 30s 等待占用）。
    // 上界取 5s：健康路径是毫秒级命令，若回归成「等待持命令锁」则阻塞
    // 整个审批窗口（30s）必然超界；更紧的常数在并行满载下被调度延迟
    // 挤爆（#92 同类）。
    let t0 = Instant::now();
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
        &PeerInfo::unknown(),
    );
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "审批等待期间命令被阻塞 {elapsed:?}"
    );
    assert!(rpc_result(&resp)["items"].as_array().is_some());
    // 回传 → evaluate 完成
    shared.approvals.resolve(
        uuid::Uuid::parse_str(&request_id).unwrap(),
        ApprovalDecision::Allowed,
        &challenge,
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true);
}

/// 审批回传校验矩阵（#17/#72/#78）：伪造 requestId → 忽略（accepted=false）；
/// 无令牌 → session.invalid；socket 来源 → channel.forbidden；
/// 缺 challenge 参数 → invalid params。
#[test]
fn approval_result_rejects_forged_and_unauthenticated() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, token) = m2_daemon(dir.path(), None);
    // 伪造 requestId（桌面直调语义下走完整校验链 → resolve 忽略）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": uuid::Uuid::new_v4(), "decision": "allowed",
                    "challenge": "whatever" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], false);
    // 无令牌
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": uuid::Uuid::new_v4(), "decision": "allowed",
                    "challenge": "whatever" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["message"], MSG_SESSION_INVALID);
    // 非法 decision
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": uuid::Uuid::new_v4(), "decision": "maybe",
                    "challenge": "whatever" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_INVALID_PARAMS);
    // 缺 challenge 字段 → invalid params（#78：挑战必填）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": uuid::Uuid::new_v4(), "decision": "allowed" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], ERR_INVALID_PARAMS);
}

/// #78 方案 A（对抗性回归）：持有效令牌的 **socket** 进程即使拿到正确的
/// requestId/challenge，提交审批也必须被专用错误码拒绝，且不得消耗/清掉
/// 真实的待审批条目——随后真正的桌面回传照常生效。被拒提交写审计
/// （command=approval.result，对端归因）。
#[test]
fn approval_result_rejected_from_socket_origin_keeps_pending_entry() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // socket 进程（ PeerInfo::unknown()）+ 完整正确参数 → 仍必须拒绝
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::unknown(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_CHANNEL_FORBIDDEN,
        "socket 提交审批必须 channel.forbidden：{resp}"
    );

    // 被拒提交写审计（#78：尝试自我批准的 socket 进程可归因——
    // starter 为对端回溯结果，unknown 对端如实记 unknown）
    let submissions: Vec<_> = audit_events(dir.path())
        .into_iter()
        .filter(|e| e.command == "approval.result")
        .collect();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].result, lk_core::audit::AuditResult::Denied);
    assert_eq!(submissions[0].starter, "unknown");
    assert_eq!(submissions[0].channel, lk_core::audit::AuditChannel::Cli);

    // 待审批条目未被消耗：真正的桌面回传照常放行
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true);
}

/// #78 方案 B（对抗性回归）：挑战值不符 → 忽略且条目保留（伪回传不能
/// 打掉真用户的待审批请求），失败提交写审计；随后原样回带 → 放行。
#[test]
fn approval_result_with_wrong_challenge_is_ignored_but_request_survives() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();

    // 挑战不符 → accepted=false（错挑战不是超时竞态）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": "forged" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], false);
    // 失败提交审计（命令名 approval.result）
    let submissions: Vec<_> = audit_events(dir.path())
        .into_iter()
        .filter(|e| e.command == "approval.result")
        .collect();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].result, lk_core::audit::AuditResult::Denied);

    // 条目保留：原样回带挑战 → 放行
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true);
}

/// #78 方案 A（订阅面）：仅有 socket 订阅者时不算「有界面」（no_ui 立即拒绝，
/// 与旧语义 subscriber_count>0 的差异点）；有桌面订阅者并存时——authz.request
/// 帧**只投桌面**通道，socket 订阅者拿不到帧（也就拿不到 challenge）。
#[test]
fn socket_subscribers_are_not_ui_and_receive_no_authz_frames() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);

    // 场景 1：只有 socket 订阅者（模拟持令牌攻击进程自行 subscribe）→
    // has_ui 仍为 false → 第 3 层立即 fail-closed
    let (_sock_sid, sock_rx) = shared.push.subscribe(false);
    assert_eq!(shared.push.subscriber_count(), 1);
    assert_eq!(shared.push.desktop_subscriber_count(), 0);
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["reason"], "no_ui");
    // socket 订阅者也收不到被拒请求的任何帧
    assert!(sock_rx.recv_timeout(Duration::from_millis(200)).is_err());

    // 场景 2：socket + 桌面订阅者并存 → 帧只达桌面；审批后两者自然结束
    let (desk_sid, desk_rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "cargo publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    // 桌面通道收到帧（含挑战）
    let frame = desk_rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert!(fv["params"]["challenge"].as_str().is_some());
    // socket 通道无帧投递
    assert!(
        sock_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "authz.request 帧绝不能投给 socket 订阅者"
    );
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "denied", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["reason"], "rejected");
    drop(desk_rx);
    shared.push.unsubscribe(desk_sid);
}

/// 请求的 key 无法解析（不存在）→ 第 1 层拒绝（missing_keys；不弹窗）。
#[test]
fn authz_denies_unresolvable_requested_keys() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "npm publish", "keys": ["GHOST_KEY"] }),
        ),
        &test_peer(Some(proj.path())),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false);
    assert_eq!(v["result"]["reason"], "missing_keys");
}

/// interface 即测试面：两阶段策略（OutsideLock / ApprovalDeferred）的
/// 直调形态与生产主缝（make_handler → route）请求/响应逐字一致。
/// 选取无副作用场景（同步未配置 / 无审批界面 fail-closed）以便双路径对跑。
#[test]
fn special_strategies_direct_call_matches_production_route() {
    let dir = tempfile::tempdir().unwrap();
    let mut audit = AuditLog::open(dir.path()).unwrap();
    init_vault_with_params(
        dir.path(),
        "pw123456",
        false,
        &mut audit,
        &test_kdf_params(),
    )
    .unwrap();
    let mut daemon = Daemon::start(dir.path()).unwrap();
    daemon
        .shared()
        .config
        .write()
        .unwrap()
        .approval_timeout_secs = 1;
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();

    let state = Arc::new(std::sync::Mutex::new(daemon));
    let shared = state.lock().unwrap().shared();
    let handler = make_handler(&state, &shared);
    let peer = test_peer(None);

    for (method, params) in [
        // OutsideLock：同步未配置 → ERR_SYNC_NOT_CONFIGURED
        (M_SYNC_TRIGGER, json!({ "token": token })),
        // ApprovalDeferred：无订阅者 = 无审批界面 → fail-closed 立即拒绝
        (
            M_AUTHZ_EVALUATE,
            json!({
                "token": token,
                "command": "npm run build",
                "keys": ["NPM_TOKEN"],
            }),
        ),
    ] {
        let line = rpc_line(method, Some(&token), params);
        let via_handle = rpc_json(&state.lock().unwrap().handle(&line, &peer));
        let via_route = rpc_json(&handler(&line, &peer));
        assert_eq!(via_handle, via_route, "{method} 直调与生产主缝行为不一致");
    }
    // 具体语义抽查：同步未配置的错误码（错误响应走完整对象而非 result）
    let sync_resp = rpc_json(&handler(
        &rpc_line(M_SYNC_TRIGGER, Some(&token), json!({ "token": token })),
        &peer,
    ));
    assert_eq!(sync_resp["error"]["code"], ERR_SYNC_NOT_CONFIGURED);
}

/// 跨缝等价回归：ApprovalDeferred 阶段①的会话预检在两条缝上都生效——
/// 无效 token + 第 2 层规则可命中时，直调与生产主缝都必须 session.invalid，
/// 绝不放行或泄露注入值。
#[test]
fn authz_deferred_invalid_token_session_gated_on_both_seams() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 规则：proj 下 npm * 授权 NPM_TOKEN（保证第 2 层对有效会话可命中）
    let add = rpc_result(&state.lock().unwrap().handle(
        &rpc_line(
            M_RULE_ADD,
            Some(&token),
            json!({ "projectDir": proj.path(), "name": "publish",
                    "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "cli" }),
        ),
        &PeerInfo::unknown(),
    ));
    assert!(add["rule"]["id"].as_str().is_some());

    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some("bogus-token"),
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" }),
    );
    let via_handle = rpc_json(&state.lock().unwrap().handle(&line, &peer));
    let via_route = rpc_json(&handler(&line, &peer));
    for (seam, resp) in [("handle", via_handle), ("route", via_route)] {
        assert_eq!(
            resp["error"]["code"], ERR_SESSION_INVALID,
            "{seam}: 无效 token 必须 session.invalid: {resp}"
        );
        assert!(
            resp.to_string().find("sekrit").is_none(),
            "{seam}: 不得泄露注入值"
        );
    }
    // 对照组：同一场景换成有效 token → 第 2 层放行且 env 可见
    // （证明上面的 session.invalid 来自预检而非规则未命中）。
    let ok_line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" }),
    );
    let ok = rpc_json(&handler(&ok_line, &peer));
    assert_eq!(ok["result"]["allowed"], true);
    assert_eq!(ok["result"]["env"]["NPM_TOKEN"], "sekrit");
}

// -------------------------------------------------------------------------
// #67 锁定态一体化（临时解锁 + 本次授权一次交互）
// -------------------------------------------------------------------------

/// 锁定态夹具：初始化 + 建条目后**锁定**（无会话令牌、vault=None），
/// 模拟「库存在但未解锁、GUI 已运行」场景。返回（命令锁, 共享态）。
fn locked_daemon_with_secret(
    dir: &std::path::Path,
    secret: Option<(&str, &str)>,
) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>) {
    {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }
    let mut daemon = Daemon::start(dir).unwrap();
    // 审批窗口维持生产默认 30s（同 m2_daemon，#92）
    // 解锁建条目，再锁定（回到锁态）
    let unlock = rpc_result(&daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    ));
    let token = unlock["token"].as_str().unwrap().to_string();
    if let Some((name, value)) = secret {
        daemon.handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "secret", "name": name, "value": value,
                    "purpose": "", "expiresAt": null
                } }),
            ),
            &PeerInfo::unknown(),
        );
    }
    daemon.handle(
        &rpc_line(M_VAULT_LOCK, None, json!({})),
        &PeerInfo::unknown(),
    );
    let shared = daemon.shared();
    let state = Arc::new(Mutex::new(daemon));
    (state, shared)
}

/// 锁定态 + 桌面订阅：authz.evaluate → 广播 authz.request(needsUnlock=true)
/// → approval.result(desktop, masterPassword) → 临时解锁放行 env；
/// **不签发会话令牌**（vault 仍锁定、session.token 未写、item.* 不可用）——
/// 即 #67 关键约束 + #65 注入通道不再产生全量能力。
#[test]
fn authz_locked_inject_unified_unlock_approval_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon_with_secret(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    // 锁态自检：vault 未解锁、令牌文件不存在（锁定时已删）
    assert!(!shared.vault.read().unwrap().is_some());
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());

    let handler = make_handler(&state, &shared);
    // 桌面壳订阅（进程内登记 = desktop 来源）→ has_ui=true
    let (_sid, rx) = shared.push.subscribe(true);
    assert_eq!(shared.push.subscriber_count(), 1);
    // 记录流程前审计水位（夹具 unlock/lock 各写一条；只断言本次流程新增）
    let audit_before = audit_events(dir.path()).len();

    // 线程内发起 evaluate（锁态、无 token —— 一体化流程应放行到审批等待）
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        None,
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    // 广播帧：needsUnlock=true + challenge
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    assert_eq!(fv["params"]["needsUnlock"], true, "锁态一体化帧须标注");
    assert_eq!(fv["params"]["command"], "npm publish");
    assert_eq!(fv["params"]["keys"][0], "NPM_TOKEN");
    assert!(!frame.contains("sekrit"));
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 审批回传：desktop 直调 + allowed + masterPassword + challenge（
    // 锁态无会话令牌——跳过 require_session 由 needs_unlock 待审保证）
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "allowed",
                    "challenge": challenge, "masterPassword": "pw123456" }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    // evaluate 返回放行 + env
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "锁态一体化应放行：{resp}");
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");
    // 关键约束（#67 #2 / #65）：临时解锁不产生 item.* 全量能力
    assert!(
        shared.vault.read().unwrap().is_none(),
        "临时解锁不得改写共享 vault（须保持锁定）"
    );
    assert!(
        !dir.path().join(crate::SESSION_TOKEN_FILE).exists(),
        "临时解锁不得写 session.token"
    );
    // 审计两条：#67 一体化 —— vault.unlock(desktop) + inject allowed(Approval)
    let events = audit_events(dir.path());
    let flow_events = &events[audit_before..];
    let unlock_evs: Vec<_> = flow_events
        .iter()
        .filter(|e| e.command == "vault.unlock")
        .collect();
    assert_eq!(unlock_evs.len(), 1, "解锁事件须留痕（via=inject-gui）");
    assert_eq!(unlock_evs[0].channel, lk_core::audit::AuditChannel::Desktop);
    let authz_evs: Vec<_> = flow_events
        .iter()
        .filter(|e| e.command.starts_with("lk inject"))
        .collect();
    assert_eq!(authz_evs.len(), 1);
    assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);
    assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
}

/// 锁定态一体化：错误主密码 → approval.result 错误响应（accepted != true，
/// 条目保留不回传）→ CLI 侧最终超时默认拒绝；AuthGuard 记失败。
/// 弹窗在此错误上停留（UI 侧），倒计时内可重试——守护进程侧只保证不
/// 解锁、不 resolve。
#[test]
fn authz_locked_inject_wrong_password_keeps_pending_and_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon_with_secret(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let (_sid, rx) = shared.push.subscribe(true);
    // 流程前审计水位（夹具 unlock 写过 vault.unlock，只断言本次流程新增）
    let audit_before = audit_events(dir.path()).len();
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        None,
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
    );
    // 线程内发起 evaluate（dispatch 直调在同线程会阻塞在审批等待上，
    // 挡住后续 approval.result 的命令锁——须用主缝 handler 线程）
    let h = std::thread::spawn({
        let handler = handler.clone();
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    // 广播帧
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(fv["method"], "authz.request");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 错误主密码：错误响应（vault.invalid 统一文案），条目未消费
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
    assert_eq!(
        v["error"]["code"], ERR_VAULT_INVALID,
        "主密码错误须报错：{resp}"
    );
    assert_eq!(
        shared.approvals.pending_count(),
        1,
        "错误密码不得 resolve（条目保留，弹窗可重试）"
    );
    // CLI 侧（等待线程）超时默认拒绝：审批窗口为夹具生产默认 30s，
    // 「回传落地」与「到期拒绝」两段都不与真实时钟赛跑——测试钩子把
    // 待审条目即时到期，到期判定/清理/默认拒绝仍走 await_decision
    // 既有语义（#92）
    shared.approvals.expire_all_for_tests();
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false, "超时默认拒绝：{resp}");
    assert_eq!(v["result"]["reason"], "timeout");
    // vault 仍锁定、无令牌
    assert!(shared.vault.read().unwrap().is_none());
    assert!(!dir.path().join(crate::SESSION_TOKEN_FILE).exists());
    // 审计：未解锁 → 本次流程无 vault.unlock；无 inject 事件（超时拒绝
    // 在锁态无 K_audit，与 v0 锁态拒绝同口径不审计）
    let flow_events = &audit_events(dir.path())[audit_before..];
    assert!(
        !flow_events.iter().any(|e| e.command == "vault.unlock"),
        "错误密码不得产生解锁事件"
    );
    assert!(!flow_events
        .iter()
        .any(|e| e.command.starts_with("lk inject")));
}

/// 锁定态一体化：用户拒绝 → 回传 denied（无需主密码）→ CLI 侧拒绝；
/// vault 不解锁。
#[test]
fn authz_locked_inject_denied_without_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon_with_secret(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        None,
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
    );
    let h = std::thread::spawn({
        let handler = make_handler(&state, &shared);
        let peer = peer.clone();
        move || handler(&line, &peer)
    });
    let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
    let fv: Value = serde_json::from_str(&frame).unwrap();
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // denied：无需主密码
    let resp = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            None,
            json!({ "requestId": request_id, "decision": "denied", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["accepted"], true);
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], false);
    assert_eq!(v["result"]["reason"], "rejected");
    assert!(shared.vault.read().unwrap().is_none(), "拒绝不触发解锁");
}

/// 锁定态 + 无桌面订阅（纯 headless）：维持 v0 fail-closed——session.invalid，
/// 不阻塞、不静默回落（issue #67「GUI 不在运行维持现状」）。
#[test]
fn authz_locked_inject_headless_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon_with_secret(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    assert_eq!(shared.push.subscriber_count(), 0, "无桌面订阅");
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        None,
        json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
    );
    let resp = state.lock().unwrap().handle(&line, &peer);
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "headless 锁态必须 fail-closed session.invalid：{resp}"
    );
    assert!(shared.vault.read().unwrap().is_none());
}
