//! 逐门 × 逐状态响应字节 golden 表（issue #167 / 拍板 #28 候选 3）。
//!
//! 钉住的安全不变量（architecture-deepening.md §1.6）：同一 reason
//! （no_ui / unknown_starter）跨门、跨锁态的 fail-closed 响应字节**不压缩**——
//! 六类 spec 钉死的码逐门保留：
//!
//! 1. inject × 解锁 × no_ui → `ok{allowed:false,reason:"no_ui"}`
//!    （authorization-gate §5）；
//! 2. inject × 解锁 × unknown_starter → `ok{allowed:false,reason:"unknown_starter"}`；
//! 3. inject × 锁定 × no_ui（headless）→ `session.invalid`(-32002)——会话
//!    前置失败（编排器预检层），非裁决拒绝；
//! 4. disclosure（item.get / item.export）× 任意拒绝 → `authz.denied`
//!    (-32017)（value-disclosure §5.4，不区分原因防探测）；
//! 5. write（item.put / item.delete）× 任意拒绝 → `authz.denied`(-32017)
//!    （write-gate §5.5）；锁定 → `session.invalid`（预检先行，§5.3）；
//! 6. rules（rule.add / rule.remove）× 任意拒绝 → `authz.denied`(-32017)
//!    （补充拍板 #22）；锁定 → `session.invalid`（预检先行）。
//!
//! 注册表完整性测试（router.rs `flow_registry_matches_strategy_table`）
//! 只钉 rependable / unlock_supported 布尔，不钉字节——本表补字节面。
//! 断言用**完整响应行**（rpc_line 固定 id=1，序列化确定性由结构体字段序
//! 保证），不是仅 code——防「码对形不对」的漂移。

use serde_json::{json, Value};

use lk_core::ipc::*;

use super::{locked_daemon, m2_daemon, make_handler, rpc_line, test_peer};
use crate::daemon::gate_kit::GateDeny;
use crate::PeerInfo;
use std::sync::Arc;

/// golden 常量（完整行；rpc_line 固定 id=1）。
const OK_NO_UI: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"allowed":false,"reason":"no_ui"}}"#;
const OK_UNKNOWN_STARTER: &str =
    r#"{"jsonrpc":"2.0","id":1,"result":{"allowed":false,"reason":"unknown_starter"}}"#;
const ERR_SESSION_INVALID: &str =
    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"session.invalid"}}"#;
const ERR_AUTHZ_DENIED: &str =
    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32017,"message":"authz.denied"}}"#;

/// 发起 `authz.evaluate`（触发 no_ui 用真实 starter + 无订阅；触发
/// unknown_starter 用 pid=0 对端）。
fn inject_line(keys: &str) -> Value {
    json!({ "command": "yarn publish", "keys": [keys] })
}

/// 逐门 × 逐状态响应字节 golden 表：同一 reason 跨门跨锁态字节不压缩
/// （六类 fail-closed 码逐门钉住，见模块文档）。
#[test]
fn gate_fail_closed_bytes_golden_table() {
    // ---- 解锁态（有会话令牌）----
    let dir = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
    let handler = make_handler(&state, &shared);
    assert_eq!(shared.push.subscriber_count(), 0, "无订阅 = headless");

    // 门 1·inject：解锁 × no_ui → ok{allowed:false,reason:"no_ui"}（非错误码！）
    let resp = handler(
        &rpc_line(M_AUTHZ_EVALUATE, Some(&token), inject_line("NPM_TOKEN")),
        &test_peer(Some(proj.path())),
    );
    assert_eq!(resp, OK_NO_UI, "inject 解锁 no_ui 码不得压平");
    // 门 1·inject：解锁 × unknown_starter → ok{reason:"unknown_starter"}
    //（第 1 层检查先于 no_ui：pid=0 对端即拒绝，无需订阅面）
    let resp = handler(
        &rpc_line(M_AUTHZ_EVALUATE, Some(&token), inject_line("NPM_TOKEN")),
        &PeerInfo::unknown(),
    );
    assert_eq!(
        resp, OK_UNKNOWN_STARTER,
        "inject unknown_starter 码不得压平"
    );

    // 门 4·disclosure：解锁 × no_ui / unknown_starter → authz.denied(-32017)
    let secret_id = secret_id_of(&state, &token);
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": secret_id })),
        &test_peer(Some(proj.path())),
    );
    assert_eq!(resp, ERR_AUTHZ_DENIED, "disclosure 解锁 no_ui 码不得压平");
    let resp = handler(
        &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": secret_id })),
        &PeerInfo::unknown(),
    );
    assert_eq!(
        resp, ERR_AUTHZ_DENIED,
        "disclosure unknown_starter 与 no_ui 同码（防探测）"
    );

    // 门 6·write：解锁 × no_ui / unknown_starter → authz.denied(-32017)
    let put = json!({ "item": { "type": "secret", "name": "g-put", "value": "v",
                                "purpose": "", "expiresAt": null } });
    let resp = handler(
        &rpc_line(M_ITEM_PUT, Some(&token), put.clone()),
        &test_peer(Some(proj.path())),
    );
    assert_eq!(resp, ERR_AUTHZ_DENIED, "write 解锁 no_ui 码不得压平");
    let resp = handler(
        &rpc_line(M_ITEM_PUT, Some(&token), put),
        &PeerInfo::unknown(),
    );
    assert_eq!(
        resp, ERR_AUTHZ_DENIED,
        "write unknown_starter 与 no_ui 同码（防探测）"
    );

    // 门 6·rules：解锁 × no_ui / unknown_starter → authz.denied(-32017)
    //（m2_daemon 缺省 rule_auto=false——E2E 自动批准不参与）
    let rule = json!({ "projectDir": proj.path(), "name": "g1",
                       "command": "yarn *", "keys": ["NPM_TOKEN"] });
    let resp = handler(
        &rpc_line(M_RULE_ADD, Some(&token), rule.clone()),
        &test_peer(Some(proj.path())),
    );
    assert_eq!(resp, ERR_AUTHZ_DENIED, "rules 解锁 no_ui 码不得压平");
    let resp = handler(
        &rpc_line(M_RULE_ADD, Some(&token), rule),
        &PeerInfo::unknown(),
    );
    assert_eq!(
        resp, ERR_AUTHZ_DENIED,
        "rules unknown_starter 与 no_ui 同码（防探测）"
    );

    // ---- 锁定态（无令牌；vault=None）----
    let dir = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")), None);
    let handler = make_handler(&state, &shared);
    assert_eq!(shared.push.subscriber_count(), 0, "无订阅 = headless");

    // 门 3·inject：锁定 × no_ui（headless）→ session.invalid（会话前置失败，
    // 预检层——非 ok{no_ui}！这是「同一 reason 跨锁态字节不同」的钉子）
    let resp = handler(
        &rpc_line(M_AUTHZ_EVALUATE, None, inject_line("NPM_TOKEN")),
        &test_peer(None),
    );
    assert_eq!(
        resp, ERR_SESSION_INVALID,
        "inject 锁定 headless 必须 session.invalid"
    );

    // 门 4·disclosure / 门 5·write / 门 6·rules：锁定（无论界面在场与否）
    // → 预检 session.invalid 先行
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = handler(
        &rpc_line(M_ITEM_GET, None, json!({ "id": ghost })),
        &test_peer(None),
    );
    assert_eq!(resp, ERR_SESSION_INVALID, "disclosure 锁定预检先行");
    let put = json!({ "item": { "type": "secret", "name": "g-put2", "value": "v",
                                "purpose": "", "expiresAt": null } });
    let resp = handler(&rpc_line(M_ITEM_PUT, None, put), &test_peer(None));
    assert_eq!(resp, ERR_SESSION_INVALID, "write 锁定预检先行（无解锁窗）");
    let resp = handler(
        &rpc_line(
            M_RULE_ADD,
            None,
            json!({ "projectDir": dir.path(), "name": "g2",
                    "command": "yarn *", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(None),
    );
    assert_eq!(resp, ERR_SESSION_INVALID, "rules 锁定预检先行");

    // ---- 锁定态 + 桌面界面在场（一体化门 vs 无解锁门的分野）----
    let dir = tempfile::tempdir().unwrap();
    let (state, shared) = locked_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")), None);
    let handler = make_handler(&state, &shared);
    let _sub = shared.push.subscribe(true); // 桌面订阅 = 审批界面在场

    // 门 1·inject：锁定 × UI 在场 × unknown_starter → 仍 ok{reason}（第 1 层
    // 拒绝先于一体化弹窗，锁态同码）
    let resp = handler(
        &rpc_line(M_AUTHZ_EVALUATE, None, inject_line("NPM_TOKEN")),
        &PeerInfo::unknown(),
    );
    assert_eq!(
        resp, OK_UNKNOWN_STARTER,
        "inject 锁定 unknown_starter 与解锁同码（第 1 层先于弹窗）"
    );
    // 门 4·disclosure：锁定 × UI 在场 × unknown_starter → authz.denied
    //（锁态 begin 拒绝；与解锁同码——disclosure 的码不随锁态变）
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = handler(
        &rpc_line(M_ITEM_GET, None, json!({ "id": ghost })),
        &PeerInfo::unknown(),
    );
    assert_eq!(resp, ERR_AUTHZ_DENIED, "disclosure 锁定 begin 拒绝同码");
    // 门 5·write / 门 6·rules：锁定即使 UI 在场 → session.invalid（无解锁窗）
    let put = json!({ "item": { "type": "secret", "name": "g-put3", "value": "v",
                                "purpose": "", "expiresAt": null } });
    let resp = handler(&rpc_line(M_ITEM_PUT, None, put), &test_peer(None));
    assert_eq!(
        resp, ERR_SESSION_INVALID,
        "write 锁定 = session.invalid（UI 在场也不弹）"
    );
    let resp = handler(
        &rpc_line(
            M_RULE_ADD,
            None,
            json!({ "projectDir": dir.path(), "name": "g3",
                    "command": "yarn *", "keys": ["NPM_TOKEN"] }),
        ),
        &test_peer(None),
    );
    assert_eq!(
        resp, ERR_SESSION_INVALID,
        "rules 锁定 = session.invalid（UI 在场也不弹）"
    );

    // 锁定 + UI 在场的合法 inject 会进入一体化弹窗（Pending），不在此表
    // 断言（由 #67 一体化集成测试覆盖）——本表只钉 fail-closed 码。
}

/// 门声明渲染器字节（分层裁决结果的唯一渲染点，issue #167）：直接驱动
/// 各门渲染器钉「(门 × reason) → 字节」映射，与路由级 golden 表互补——
/// 路由表钉端到端，本测试钉渲染器本身（含锁态 daemon 上下文入参）。
#[test]
fn gate_renderer_bytes_per_gate() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _shared, _token) = m2_daemon(dir.path(), None);
    let g = state.lock().unwrap();
    // inject 渲染器：任何 reason（含 NoUi）→ ok{allowed:false,reason}——
    // 锁态 headless 的 session.invalid 不出自渲染器（会话前置失败在编排器
    // 预检 / begin 锁态分支，分层见 GateBegin 类型文档；本断言把这条分层
    // 钉死：渲染器对锁态 daemon 也不吐 session.invalid）。
    let inject = &crate::daemon::authz::AUTHZ_GATE;
    assert_eq!((inject.render_deny)(&g, json!(1), GateDeny::NoUi), OK_NO_UI);
    assert_eq!(
        (inject.render_deny)(&g, json!(1), GateDeny::UnknownStarter),
        OK_UNKNOWN_STARTER
    );
    assert_eq!(
        (inject.render_deny)(&g, json!(1), GateDeny::Rejected),
        r#"{"jsonrpc":"2.0","id":1,"result":{"allowed":false,"reason":"rejected"}}"#
    );
    assert_eq!(
        (inject.render_deny)(&g, json!(1), GateDeny::Timeout),
        r#"{"jsonrpc":"2.0","id":1,"result":{"allowed":false,"reason":"timeout"}}"#
    );
    // 其余三门渲染器：任何 reason → authz.denied(-32017)（防探测统一码）
    for gate in [
        &crate::daemon::disclosure::DISCLOSURE_GATE,
        &crate::daemon::write::WRITE_GATE,
        &crate::daemon::rules::RULE_GATE,
    ] {
        for deny in [
            GateDeny::NoUi,
            GateDeny::UnknownStarter,
            GateDeny::Rejected,
            GateDeny::Timeout,
        ] {
            assert_eq!(
                (gate.render_deny)(&g, json!(1), deny),
                ERR_AUTHZ_DENIED,
                "{} 渲染器对 {} 必须统一 authz.denied",
                gate.name,
                deny.as_str()
            );
        }
    }
}

/// 取 seed 条目 id（item.list，desktop 直调豁免）。
fn secret_id_of(state: &Arc<std::sync::Mutex<crate::Daemon>>, token: &str) -> String {
    let resp = state.lock().unwrap().handle(
        &rpc_line(M_ITEM_LIST, Some(token), json!({})),
        &PeerInfo::desktop(),
    );
    super::rpc_result(&resp)["items"].as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string()
}
