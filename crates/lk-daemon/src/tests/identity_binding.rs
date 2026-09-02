//! 规则程序指纹绑定集成测试（M2.98，identity-binding.md §10.2，issue #124）。
//!
//! seam：daemon 装配（`authz_begin` 绑定裁决折叠 + notifier 审批帧 +
//! `rules` finalize 侧重算指纹）+ 对端 env PATH 经 `set_peer_env` 注入
//! （信 daemon 不信客户端）；绑定规则经 `shared.vault.put_rule` 直接落库
//! （与规则管理页同一唯一写入面）。
//!
//! 各 AC 对应测试：
//! - 绑定命中 → 静默放行 + 审计（比对序各步均达）：`binding_hit_silently_allows`
//! - 失配 → NeedsApproval + 审批帧「指纹不符」主题：`binding_mismatch_folds_to_approval`
//! - headless 失配 → `authz.denied` 同码：`headless_mismatch_denied_same_code`
//! - 重新授权 → 规则门批准 → 落盘重算指纹 + 审计 rule.add：`reauthorize_via_rule_gate`
//! - 缓存元信息一致复用（stat 计数断言）：`cache_meta_unchanged_reuses_hash`
//! - 改内容 + mtime 变 → 重算 → 失配：`content_change_recomputes_and_mismatches`
//! - macOS env 读取失败 → fail-closed（cfg 门）：`macos_env_read_failure_fail_closed`
//! - 锁态 → `session.invalid`（回归）：`locked_session_invalid_regression`
//! - 启动者未知 → 第 1 层拒绝（先于指纹比对，回归）：`unknown_starter_denied_first`

use super::*;
use crate::identity::PeerEnv;
use lk_core::fingerprint;
use lk_core::model::{ProgramFingerprint, RuleDraft, RULE_CAPABILITY_INJECT};
use std::path::{Path, PathBuf};

/// 假对端 env：返回指定 bin 目录（PATH 单目录，测试确定性解析）。
#[derive(Clone)]
struct FakePeerEnv {
    path: String,
}
impl PeerEnv for FakePeerEnv {
    fn peer_path(&self, _pid: u32) -> Option<String> {
        Some(self.path.clone())
    }
}

/// 注入假对端 env 到守护进程（替换平台真实读取）。
fn inject_fake_env(state: &Arc<Mutex<Daemon>>, bin_dir: &Path) {
    state.lock().unwrap().set_peer_env(Arc::new(FakePeerEnv {
        path: bin_dir.to_string_lossy().into_owned(),
    }));
}

/// 建一个伪装可执行文件（内容 → 真实指纹 + canonical 路径）。
fn make_exe(dir: &Path, name: &str, content: &[u8]) -> (PathBuf, ProgramFingerprint) {
    let raw = dir.join(name);
    std::fs::write(&raw, content).unwrap();
    let canonical = std::fs::canonicalize(&raw).unwrap();
    let fp = ProgramFingerprint {
        exe_path: canonical.to_string_lossy().into_owned(),
        sha256: fingerprint::file_sha256(&canonical).unwrap(),
        size: std::fs::metadata(&canonical).unwrap().len(),
    };
    (raw, fp)
}

/// 直接经 vault 写锁种一条绑定 inject 规则（command 精确 = 注入命令形态；
/// project_dir = 注入对端 cwd 的祖先，rule_matches 才命中）。
fn seed_bound_rule(
    shared: &Arc<SharedDaemon>,
    project_dir: &Path,
    exe_fp: &ProgramFingerprint,
    command: &str,
    keys: &[&str],
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
            RuleDraft {
                project_dir: canonical,
                name: "inject-bound".into(),
                command: command.into(),
                keys: keys.iter().map(|s| s.to_string()).collect(),
                capability: RULE_CAPABILITY_INJECT.into(),
                actions: lk_core::model::default_rule_actions(),
                fingerprint: Some(exe_fp.clone()),
            },
            None,
        )
        .unwrap();
}

/// 审计中的注入裁决事件（command 以 `lk inject` 开头）。
fn inject_audit(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
    inject_audit_events(dir)
}

/// 取下一帧 `authz.request`（跳过无关帧）。
fn next_authz_frame(rx: &mpsc::Receiver<String>) -> Value {
    loop {
        let frame = rx.recv_timeout(FRAME_WAIT).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        if fv["method"] == "authz.request" {
            return fv;
        }
    }
}

/// 绑定命中：绑定规则的 canonical 路径 + size + SHA-256 全部一致 → 静默放行
/// + 审计 Allowed（比对序各步均达：先比路径、次比 size、最后哈希）。
#[test]
fn binding_hit_silently_allows() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (_exe, fp) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho hi\n");
    // 绑定 inject 规则（command 形态 = bind/dev 的前缀）
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp, "pgm deploy", &["NPM_TOKEN"]);
    inject_fake_env(&state, bin.path());

    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "绑定命中应静默放行：{resp}");
    assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit", "放行注入值");
    assert!(
        shared.approvals.pending_count() == 0,
        "绑定命中不弹窗（无审批登记）"
    );
    // 审计：比对序全部通过 → allowed
    let evs = inject_audit(dir.path());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].result, lk_core::audit::AuditResult::Allowed);
}

/// 绑定失配（改内容 → 哈希失配，同路径）→ 视同未命中 → 转审批（GUI 在场）；
/// 审批帧携带 `fingerprintMismatch`（当前解析路径 + 8 位哈希摘要，不含完整值）。
#[test]
fn binding_mismatch_folds_to_approval() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (pgm_path, fp_v1) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp_v1, "pgm deploy", &["NPM_TOKEN"]);
    inject_fake_env(&state, bin.path());
    // 内容被改（提升 mtime）→ 现哈希 ≠ 规则记录的 fp_v1.sha256
    std::fs::write(&pgm_path, b"#!/bin/sh\necho v2-xxxx\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));

    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let line = rpc_line(
        M_AUTHZ_EVALUATE,
        Some(&token),
        json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
    );
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    // 审批帧：指纹不符主题（resolvedExePath + sha256Short 摘要）
    let fv = next_authz_frame(&rx);
    assert_eq!(fv["params"]["kind"], "inject");
    let mm = &fv["params"]["fingerprintMismatch"];
    assert!(
        mm.is_object(),
        "指纹失配审批帧须携带 fingerprintMismatch：{fv}"
    );
    let resolved = PathBuf::from(mm["resolvedExePath"].as_str().unwrap());
    assert_eq!(
        std::fs::canonicalize(&pgm_path).unwrap(),
        resolved,
        "展示当前解析路径"
    );
    let short = mm["sha256Short"].as_str().unwrap();
    assert_eq!(short.len(), 8, "仅展示 8 位哈希摘要，非完整值");
    // 完整 64 位哈希不得出现在帧里
    assert!(
        !serde_json::to_string(&fv)
            .unwrap()
            .contains(fp_v1.sha256.as_str())
            || fp_v1.sha256.len() == 8,
        "审批帧不得携带完整哈希"
    );
    // 审批批准 → 本次放行（失配仍走审批给"本次允许"）
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
    let _ = serde_json::from_str::<Value>(&resp).unwrap();
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["allowed"], true, "审批批准后放行：{resp}");
}

/// headless 失配 → **与未命中共用同一条 headless 拒绝路径**（防探测、不打
/// 新错误码）：`allowed:false, reason=no_ui`（不引入指纹专属码，与普通
/// 「无规则命中 → 无审批界面」的响应完全一致）。
#[test]
fn headless_mismatch_denied_same_code() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (pgm_path, fp_v1) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp_v1, "pgm deploy", &["NPM_TOKEN"]);
    inject_fake_env(&state, bin.path());
    // 制造失配：改内容（mtime 变）→ 现哈希 ≠ 规则记录
    std::fs::write(&pgm_path, b"#!/bin/sh\necho v2-other\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    // 无桌面订阅（headless）→ 失配也统一走 headless 拒绝
    assert_eq!(shared.push.subscriber_count(), 0);
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["result"]["allowed"], false,
        "headless 失配 → 拒绝：{resp}"
    );
    assert_eq!(
        v["result"]["reason"].as_str(),
        Some("no_ui"),
        "与未命中共用 headless no_ui 拒绝（不新增错误码/不泄露指纹差异）：{resp}"
    );
    assert!(
        v["error"].is_null(),
        "headless 拒绝走 result（allowed:false reason=no_ui），不打 RPC 错误码：{resp}"
    );
}

/// 「以新指纹重新授权」：`rule.add`（携带被要求的绑定 exe）走规则审批门 →
/// 批准 → finalize 侧重算指纹（不信任客户端上报）落盘 + 审计 command 以
/// `rule.add` 开头。
#[test]
fn reauthorize_via_rule_gate_persists_recomputed_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (pgm_path, _fp) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    inject_fake_env(&state, bin.path());

    let handler = make_handler(&state, &shared);
    let (_sid, rx) = shared.push.subscribe(true);
    let peer = test_peer(Some(proj.path()));
    let canonical = std::fs::canonicalize(&pgm_path).unwrap();
    // 客户端上报：仅声明"绑哪个 exe"（sha/size 故意给假值——daemon 不得信任）
    let line = rpc_line(
        M_RULE_ADD,
        Some(&token),
        json!({ "projectDir": proj.path(), "name": "re-auth", "command": "pgm deploy",
                "capability": "inject", "keys": ["NPM_TOKEN"],
                "fingerprint": { "exePath": canonical.to_string_lossy(), "sha256": "x".repeat(64), "size": 0 },
                "channel": "cli" }),
    );
    let h = {
        let handler = handler.clone();
        let peer = peer.clone();
        std::thread::spawn(move || handler(&line, &peer))
    };
    let fv = next_authz_frame(&rx);
    assert_eq!(fv["params"]["kind"], "rule", "规则门弹窗：{fv}");
    let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
    let challenge = fv["params"]["challenge"].as_str().unwrap().to_string();
    // 批准
    let _ = state.lock().unwrap().handle(
        &rpc_line(
            M_APPROVAL_RESULT,
            Some(&token),
            json!({ "requestId": request_id, "decision": "allowed", "challenge": challenge }),
        ),
        &PeerInfo::desktop(),
    );
    let resp = h.join().unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    let rule = &v["result"]["rule"];
    // 落盘指纹 = daemon 侧重算（真实 hash/size，非客户端假值）
    let stored = rule["fingerprint"].clone();
    assert_eq!(
        stored["size"],
        std::fs::metadata(&canonical).unwrap().len(),
        "size 为 daemon 侧重算值"
    );
    assert!(
        stored["sha256"].as_str().unwrap().len() == 64
            && stored["sha256"]
                != "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "sha256 为 daemon 侧重算的真实值"
    );
    // 审计 command 以 rule.add 开头
    let evs = audit_events(dir.path());
    assert!(
        evs.iter().any(|e| e.command.starts_with("rule.add")),
        "重新授权审计 command 以 rule.add 开头：{evs:?}"
    );
}

/// 缓存：元信息一致 → 复用哈希（只 stat 不重算；hash 计数不增）。
#[test]
fn cache_meta_unchanged_reuses_hash() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (_exe, fp) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp, "pgm deploy", &["NPM_TOKEN"]);
    inject_fake_env(&state, bin.path());
    let handler = make_handler(&state, &shared);
    let peer = test_peer(Some(proj.path()));

    let run = || {
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
            ),
            &peer,
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true);
    };
    run(); // 冷态：stat + hash
    let hash_after_first = state.lock().unwrap().fingerprint_hash_calls();
    run(); // 元信息一致 → 只 stat，复用缓存哈希
    assert_eq!(
        state.lock().unwrap().fingerprint_hash_calls(),
        hash_after_first,
        "元信息一致应复用，不重复哈希"
    );
    assert_eq!(
        state.lock().unwrap().fingerprint_stat_calls(),
        2, // 每次裁决先 stat 一次
    );
}

/// 缓存 + 决策：改内容 + mtime 变 → 重算 → 失配（同径同长覆盖也重算）。
#[test]
fn content_change_recomputes_and_mismatches() {
    for content in [
        b"#!/bin/sh\necho v2-longer\n".as_slice(),
        b"#!/bin/sh\necho v2\n".as_slice(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let (pgm_path, fp_v1) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        seed_bound_rule(&shared, proj.path(), &fp_v1, "pgm deploy", &["NPM_TOKEN"]);
        inject_fake_env(&state, bin.path());
        // 改内容（mtime 变）→ 重算 → 哈希失配 → 转审批
        std::fs::write(&pgm_path, content).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let handler = make_handler(&state, &shared);
        let peer = test_peer(Some(proj.path()));
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
            ),
            &peer,
        );
        // 无订阅 → headless 失配 → 拒绝（allowd:false reason=no_ui；决策已
        // 重算并失配，与未命中共用拒绝路径）
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            v["result"]["allowed"],
            false,
            "内容改后应重算并失配：{resp}（content len={}）",
            content.len()
        );
        assert_eq!(
            v["result"]["reason"].as_str(),
            Some("no_ui"),
            "失配 headless 拒绝 reason=no_ui：{resp}"
        );
        assert!(
            state.lock().unwrap().fingerprint_hash_calls() >= 1,
            "内容改触发重算"
        );
    }
}

/// 锁态回归：绑定规则存在 + 锁定 → `session.invalid` 先行（规则在加密库内）。
#[test]
fn locked_session_invalid_regression() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (_exe, fp) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    // 建 daemon → 建规则 → 锁定
    let proj_canon = std::fs::canonicalize(proj.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp, "pgm deploy", &["NPM_TOKEN"]);
    state.lock().unwrap().handle(
        &rpc_line(M_VAULT_LOCK, None, json!({})),
        &PeerInfo::unknown(),
    );
    inject_fake_env(&state, bin.path());
    let handler = make_handler(&state, &shared);
    let peer = PeerInfo {
        pid: std::process::id(),
        cwd: Some(proj_canon),
        origin: PeerOrigin::Socket,
    };
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["error"]["code"], ERR_SESSION_INVALID,
        "锁态 → session.invalid：{resp}"
    );
}

/// 启动者未知 → 第 1 层 fail-closed 拒绝（先于指纹比对；绑定规则也不豁免）。
#[test]
fn unknown_starter_denied_first() {
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let (_exe, fp) = make_exe(bin.path(), "pgm", b"#!/bin/sh\necho v1\n");
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    seed_bound_rule(&shared, proj.path(), &fp, "pgm deploy", &["NPM_TOKEN"]);
    inject_fake_env(&state, bin.path());
    let handler = make_handler(&state, &shared);
    // 桌面订阅在场（有审批界面）——但启动者未知仍第 1 层拒绝，不进指纹/审批
    let (_sid, _rx) = shared.push.subscribe(true);
    // pid=0（未知启动者）+ 有效 cwd
    let peer = PeerInfo {
        pid: 0,
        cwd: Some(
            std::fs::canonicalize(proj.path())
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ),
        origin: PeerOrigin::Socket,
    };
    let resp = handler(
        &rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "pgm deploy", "keys": ["NPM_TOKEN"] }),
        ),
        &peer,
    );
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        v["result"]["allowed"], false,
        "未知启动者第 1 层拒绝：{resp}"
    );
    assert_eq!(
        v["result"]["reason"].as_str(),
        Some(lk_core::authz::DenyReason::UnknownStarter.as_str()),
        "reason=unknown starter"
    );
}

/// macOS：对端 env 读取失败 → fail-closed（None）——与 resolve_peer_cwd 同
/// 口径（不可行则该平台绑定规则按未命中处理）。cfg 门：仅 macOS 编译运行。
#[cfg(target_os = "macos")]
#[test]
fn macos_env_read_failure_fail_closed() {
    let env = crate::identity::PlatformPeerEnv;
    // 不存在的 pid / 超限 pid → 读取失败 → None（fail-closed）
    assert!(
        env.peer_path(999_999).is_none(),
        "macOS env 读取失败须 fail-closed"
    );
}
