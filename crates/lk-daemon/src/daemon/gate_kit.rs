//! gate-kit（issue #148）：四个授权门模块（authz / disclosure / rules /
//! write）各自重抄的「五件套」中可下沉部分的唯一出处——纯下沉，零行为变更。
//!
//! - [`GateBegin`]：begin 阶段统一结果类型（四门各一个同构枚举合一）；
//! - [`PendingGates`] / [`GateEntry`] / [`GateKind`]：**统一待审批注册表**
//!   （四张 pending 表合一；key = 请求 id，payload = 门枚举）——审批解锁
//!   辅助（needs_unlock 判定 / 临时 vault 存取）表无关，未来任何门带
//!   needs_unlock 自动被看见（#67/#23 类特性不再逐门特判）；
//! - [`Daemon::open_gate_approval`]：审批请求（id / challenge / 超时）单点
//!   铸造并经 `ApprovalChannel::open` 登记广播（challenge 一次性等不变量
//!   只有一处实现，#78）；
//! - [`Daemon::audit_gate`] + [`ActingVault`]：四门合一的审计辅助——事件
//!   字段由门提供，K_audit 按「本次执行所用 vault」签名（调用方决定共享
//!   vault 还是临时 vault，为审批工作区衔接预留，T4）；
//! - 参数解析辅助（[`parse_gate_params`] / [`invalid_params`]）。
//!
//! 预检（precheck）与 finalize 编排仍属各门 / 路由（T3 通用 deferred 编排器
//! 在此之上收敛）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::disclosure::PendingDisclosure;
use super::rules::PendingRuleChange;
use super::write::PendingWrite;
use super::*;

/// begin 阶段统一结果类型（issue #148）：最终响应（不阻塞）或待审批
/// （等待移出命令锁，G1）。到期时刻以登记值为准（审批注册表侧超时默认
/// 拒绝），此处不重复携带。取代 authz / disclosure / rules / write 四个
/// 同构枚举（`AuthzBegin` 等，已删除）。
pub(crate) enum GateBegin {
    Final(String),
    Pending { request_id: uuid::Uuid },
}

/// 统一待审批注册表条目（key = 请求 id，由外层 map 承担）。needs_unlock
/// 与临时 vault 是条目级一等字段（issue #148）：审批解锁辅助表无关，且为
/// 审批工作区（T4：临时解锁材料成为注册表条目内的一等对象）预留位置。
pub(crate) struct GateEntry {
    /// 锁定态一体化标志（#67 inject / #23 读通道）：审批需先临时解锁；
    /// `authz.request` 帧的 `needsUnlock` 与本值同源（单点铸造保证）。
    pub needs_unlock: bool,
    /// 临时解锁 vault（审批工作区预留位）：由 `approval.result`（正确主
    /// 密码 + allowed）填充，finalize 消费后随条目销毁——**不签发会话
    /// 令牌 / 不写 session.token / 不置 shared vault**（#67 关键约束）。
    /// 正常路径恒空，仅一体化解锁路径填充。
    pub temp_vault: Option<UnlockedVault>,
    /// 门负载（各门 begin 期已解析的产物）。
    pub kind: GateKind,
}

/// 统一注册表条目的门负载（issue #148：payload = 门枚举）。
pub(crate) enum GateKind {
    /// 授权判定第 3 层待办（daemon/authz.rs）。
    Authz(PendingAuthz),
    /// 值披露第 3 层待办（daemon/disclosure.rs）。
    Disclosure(PendingDisclosure),
    /// 规则管理审批门待办（daemon/rules.rs）。
    Rule(PendingRuleChange),
    /// 条目写入审批门待办（daemon/write.rs）。
    Write(PendingWrite),
}

/// 统一待审批注册表（issue #148：四张 pending 表并成一张；key = 请求 id）。
///
/// 命令线程登记 / finalize 消费，`approval.result` 回传线程写入（needs_unlock
/// 判定与临时 vault 存取经 [`Self::needs_unlock`] / [`Self::store_temp_vault`]
/// ——表无关，不感知具体门）。
#[derive(Default)]
pub(crate) struct PendingGates {
    entries: HashMap<uuid::Uuid, GateEntry>,
}

impl PendingGates {
    /// 登记待审条目（begin 阶段，命令锁内）。
    pub(crate) fn insert(&mut self, request_id: uuid::Uuid, entry: GateEntry) {
        self.entries.insert(request_id, entry);
    }

    /// 消费待审条目（finalize 阶段，重取命令锁后）。条目已被消费（极端
    /// 竞态 / 超时清理）→ `None`，调用方保守拒绝。按引用借取：调用方
    /// （规则门 auto-approve 审计）finalize 后段还要用请求 id。
    pub(crate) fn remove(&mut self, request_id: &uuid::Uuid) -> Option<GateEntry> {
        self.entries.remove(request_id)
    }

    /// 待审条目是否带锁定态一体化标志（审批解锁辅助，表无关）：请求 id
    /// 不在册或条目为常规（解锁态）审批 → false。
    pub(crate) fn needs_unlock(&self, request_id: uuid::Uuid) -> bool {
        self.entries
            .get(&request_id)
            .map(|e| e.needs_unlock)
            .unwrap_or(false)
    }

    /// 把临时解锁 vault 存入待审条目（`approval.result` 的 allowed 决策，
    /// 主密码临时解锁成功后）。返回条目是否存在（true = 已存储）；条目已
    /// 被 finalize 消费（超时竞态）→ false，vault 随调用方作用域 drop。
    pub(crate) fn store_temp_vault(
        &mut self,
        request_id: uuid::Uuid,
        vault: UnlockedVault,
    ) -> bool {
        match self.entries.get_mut(&request_id) {
            Some(entry) => {
                entry.temp_vault = Some(vault);
                true
            }
            None => false,
        }
    }
}

/// 审批请求草稿（issue #148 单点铸造的入参）：id / challenge / 超时不在
/// 其中——由 [`Daemon::open_gate_approval`] 唯一铸造；展示字段由各门自带。
pub(crate) struct ApprovalDraft {
    pub starter: String,
    pub project_dir: String,
    pub command: String,
    /// 审批帧 keys（仅 key 名/条目名；弹窗展示用）。
    pub keys: Vec<String>,
    pub kind: lk_core::authz::ApprovalKind,
    /// #147：审批子类型事实（rule.add / rule.remove / item.put /
    /// item.delete 随帧回带 subKind；read/export/inject 恒 None）。
    pub sub_kind: Option<lk_core::authz::ApprovalSubKind>,
    /// #137：写审批的权威派生动作（随帧回带 writeAction）；非写审批 None。
    pub write_action: Option<lk_core::authz::WriteAction>,
    /// export 审批的数据包规模元信息；其余门 None。
    pub export_meta: Option<lk_core::authz::ExportMeta>,
    /// M2.98 指纹失配展示信息（identity-binding.md §7）；其余路径 None。
    pub fingerprint_mismatch: Option<lk_core::authz::FingerprintMismatch>,
}

impl Daemon {
    /// 审批请求单点铸造 + 登记广播 + 统一注册表登记（issue #148）：
    /// request_id / challenge / 超时在此**唯一铸造**（challenge 一次性等
    /// 不变量单点实现，#78）；广播经 `ApprovalChannel::open`（仅投桌面
    /// 订阅者）；待审条目随后入统一注册表。帧 `needsUnlock` 与条目
    /// `needs_unlock` 同源（同一 [`GateEntry`] 承载，不会漂移）。
    /// 返回请求 id（等待方据此 `await_decision`）。
    pub(crate) fn open_gate_approval(
        &mut self,
        draft: ApprovalDraft,
        pending: GateEntry,
    ) -> uuid::Uuid {
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let areq = ApprovalRequest {
            request_id,
            starter: draft.starter,
            project_dir: draft.project_dir,
            command: draft.command,
            keys: draft.keys,
            challenge,
            needs_unlock: pending.needs_unlock,
            kind: draft.kind,
            write_action: draft.write_action,
            export_meta: draft.export_meta,
            fingerprint_mismatch: draft.fingerprint_mismatch,
            sub_kind: draft.sub_kind,
        };
        self.gate.approval().open(&areq, expires_at);
        self.pending_gates
            .lock()
            .unwrap()
            .insert(request_id, pending);
        request_id
    }

    /// 四门合一的审计辅助（issue #148）：事件字段（starter/target/command/
    /// channel/result）由调用方提供，K_audit 按**本次执行所用 vault**
    /// （[`ActingVault`]）签名——调用方决定传共享 vault 还是临时 vault。
    /// 共享 vault 已锁定（K_audit 已擦除）→ 跳过审计（fail-closed 不留
    /// 审计内容，与既有口径一致）。
    pub(crate) fn audit_gate(
        &self,
        acting: ActingVault<'_>,
        starter: &str,
        target: &str,
        command: &str,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        let keys = match acting {
            ActingVault::Shared => {
                let vault = self.shared.vault.read().unwrap();
                let Some(v) = vault.as_ref() else {
                    return; // 已锁定 → 无法签名（K_audit 已擦除）
                };
                v.keys().clone()
            }
            ActingVault::Temporary(v) => v.keys().clone(),
        };
        let _ = self.audit.append(
            &keys,
            &EventInput {
                starter: starter.to_string(),
                target: target.to_string(),
                command: command.to_string(),
                result,
                channel,
                old_key_id: None,
                new_key_id: None,
            },
        );
    }
}

/// 本次执行所用 vault（acting vault；审计签名 / 执行的 K_audit 来源）。
/// 调用方决定传共享 vault 还是临时 vault（取走即空、drop 即毁，#67）。
pub(crate) enum ActingVault<'a> {
    /// 共享 vault（解锁态常态路径）；已锁定 → 审计辅助跳过（K_audit 擦除）。
    Shared,
    /// 锁定态一体化的临时 vault（#67/#23）：单次披露/注入即毁，K_audit
    /// 在内存可用。
    Temporary(&'a UnlockedVault),
}

/// 门参数解析辅助（issue #148）：解析失败 → `invalid params` 响应行
/// （`Err`）。`id` 语义照旧由调用方决定（authz/disclosure 传请求 id，
/// rules/write 的解析错误现状为 null id——零行为变更）。
pub(crate) fn parse_gate_params<T: serde::de::DeserializeOwned>(
    id: &Value,
    params: Value,
) -> std::result::Result<T, String> {
    serde_json::from_value(params).map_err(|_| invalid_params(id.clone(), None))
}

/// `invalid params` 错误响应行（门参数校验失败路径共用；`detail` 为可选
/// 人读说明，进 error.data.detail）。
pub(crate) fn invalid_params(id: Value, detail: Option<String>) -> String {
    rpc_string(RpcResponse::err(
        id,
        ERR_INVALID_PARAMS,
        "invalid params",
        detail.map(|d| json!({ "detail": d })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::crypto::test_kdf_params;
    use lk_core::vault::init_vault_with_params;

    /// 构造一个 disclosure 门条目（字段全为简单值；GateKind 选哪个门不影响
    /// 条目级行为——这正是「表无关」的断言点）。
    fn disclosure_entry(needs_unlock: bool) -> GateEntry {
        GateEntry {
            needs_unlock,
            temp_vault: None,
            kind: GateKind::Disclosure(PendingDisclosure {
                method: lk_core::ipc::M_ITEM_GET.to_string(),
                item_id: uuid::Uuid::new_v4(),
                item_name: Some("item".to_string()),
                starter: "test".to_string(),
            }),
        }
    }

    /// 初始化临时 vault（审批工作区预留位需要真实的 UnlockedVault 值；
    /// test KDF 参数下开销可忽略。UnlockedVault 不可 Clone，每次取用重新
    /// 解锁）。
    fn init_vault(dir: &std::path::Path) {
        let mut audit = lk_core::audit::AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }

    fn unlock_vault(dir: &std::path::Path) -> UnlockedVault {
        UnlockedVault::unlock(dir, "pw123456").unwrap()
    }

    #[test]
    fn unknown_request_is_not_needs_unlock() {
        let registry = PendingGates::default();
        assert!(!registry.needs_unlock(uuid::Uuid::new_v4()));
    }

    /// 表无关（issue #148 验收 1）：条目带 needs_unlock 即被审批解锁辅助
    /// 看见，不感知具体门；常规条目不误报。
    #[test]
    fn needs_unlock_is_seen_for_any_gate_entry() {
        let mut registry = PendingGates::default();
        let unified = uuid::Uuid::new_v4();
        let plain = uuid::Uuid::new_v4();
        registry.insert(unified, disclosure_entry(true));
        registry.insert(plain, disclosure_entry(false));
        assert!(registry.needs_unlock(unified));
        assert!(!registry.needs_unlock(plain));
    }

    /// 临时 vault 生命周期与条目严格一致（审批工作区衔接预留）：在册条目
    /// 存储成功、随 remove 返回；条目已被消费（超时竞态）→ false。
    #[test]
    fn temp_vault_storage_follows_entry_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let mut registry = PendingGates::default();
        // 条目不在册 → 放弃存储（调用方作用域 drop）
        assert!(!registry.store_temp_vault(uuid::Uuid::new_v4(), unlock_vault(dir.path())));
        let id = uuid::Uuid::new_v4();
        registry.insert(id, disclosure_entry(true));
        assert!(registry.store_temp_vault(id, unlock_vault(dir.path())));
        let entry = registry.remove(&id).expect("条目在册");
        assert!(entry.temp_vault.is_some());
        // 消费后再存 → false（一次性语义）
        assert!(!registry.store_temp_vault(id, unlock_vault(dir.path())));
    }

    /// 参数解析辅助：成功路径原样解析；失败路径 = `invalid params` 行
    /// （id 原样回带——rules/write 传 null、authz/disclosure 传请求 id 的
    /// 既有语义由调用方决定）。
    #[test]
    fn parse_gate_params_ok_and_err() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct P {
            id: uuid::Uuid,
        }
        let p: P = parse_gate_params(
            &json!(7),
            json!({ "id": "00000000-0000-0000-0000-000000000001" }),
        )
        .unwrap();
        assert_eq!(p.id, uuid::Uuid::from_u128(1));
        let line = parse_gate_params::<P>(&json!(7), json!({ "nope": 1 })).unwrap_err();
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["id"], json!(7));
        assert_eq!(parsed["error"]["code"], json!(ERR_INVALID_PARAMS));
        assert_eq!(parsed["error"]["message"], json!("invalid params"));
        assert_eq!(parsed["error"]["data"], Value::Null);
    }
}
