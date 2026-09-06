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
//! - [`Daemon::audit_gate`] + [`ActingVault`] + [`Daemon::with_acting_vault`]：
//!   四门合一的审计辅助——事件字段由门提供，K_audit 按「本次执行所用
//!   vault」签名（执行/审计入口统一收 ActingVault，issue #150 起无
//!   `_from` 变体对）；
//! - [`ApprovalWorkspace`]：审批工作区（issue #150）——临时解锁材料与
//!   单次裁决状态的条目内一等对象；「单次即毁 / 不签令牌 / 不置共享
//!   vault / 指纹裁决单发」不变量的**单点出处**（类型文档即权威）；
//! - 参数解析辅助（[`parse_gate_params`] / [`invalid_params`]）；
//! - [`DeferredOutcome`]：finalize 阶段统一结果类型（RePended 由通用
//!   deferred 编排器内建循环消费）。
//!
//! 预检（precheck）/ begin / finalize 由各门声明为流程（issue #149），锁
//! 编排收敛于 router.rs 的通用 deferred 编排器。

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

/// finalize 阶段统一结果类型（issue #149）：最终响应，或锁定态一体化指纹
/// 失配转**二次审批**（issue #140）——RePended 循环内建于通用 deferred 编排器
/// （router.rs `run_deferred`），finalize 返回 [`DeferredOutcome::RePended`]
/// 即回到锁外等待；注入裁决不再是编排特例。取代 authz 特有的
/// `AuthzFinalize`（已删除）。
pub(crate) enum DeferredOutcome {
    Done(String),
    RePended { request_id: uuid::Uuid },
}

/// 审批工作区（issue #150）：注册表条目内的**一等对象**——临时解锁材料与
/// 单次裁决状态的唯一承载。正常路径恒不存在（条目字段恒 `None`），仅锁定态
/// 一体化解锁路径（#67 inject / #23 读通道）由 `approval.result`（正确主
/// 密码 + allowed）填充。
///
/// 生命周期与条目**严格一致**：工作区只存在于 [`GateEntry`] 内，finalize
/// 消费即随条目销毁；超时竞态（条目已被 finalize 取走）下 `store_workspace`
/// 失败、工作区随调用方作用域整体 drop。由此**由构造与生命周期承载**的
/// 不变量（取代既往散布各门 finalize / 审批回传路径的注释纪律）：
///
/// - **单次即毁**：vault 字段私有、只出不进借用（[`Self::vault`]），
///   所有权无法离开工作区——不存在把临时 vault 移入 `shared.vault`（共享
///   解锁态）的代码路径；
/// - **不签发会话令牌 / 不写 session.token**：会话签发代码对工作区无任何
///   访问面（无持有主密码、无 vault 所有权可移交）；
/// - **指纹裁决单发**（issue #140）：裁决一次性状态随工作区走
///   （[`Self::fingerprint_adjudicated`] / [`Self::mark_fingerprint_adjudicated`]），
///   二次审批条目携带已裁决工作区——防「裁决 → 审批 → 裁决」死循环由
///   结构承载，#140 类竞态不可复发。
pub(crate) struct ApprovalWorkspace {
    /// 临时解锁 vault（私有：仅借出引用，无所有权出口）。
    vault: UnlockedVault,
    /// 指纹裁决单发状态（issue #140）：false = 本次审批尚未做过指纹裁决
    /// （锁定态一体化 begin 无法裁决）；true = 已裁决（解锁态 begin 侧或
    /// 二次审批条目），finalize 不得重复裁决。
    fp_adjudicated: bool,
}

impl ApprovalWorkspace {
    /// 由临时解锁产物构造（`approval.result` 解锁成功路径，session.rs）。
    /// 初始未裁决（锁定态一体化 begin 无法预裁决）。
    pub(crate) fn new(vault: UnlockedVault) -> Self {
        Self {
            vault,
            fp_adjudicated: false,
        }
    }

    /// 临时 vault 借用（K_audit / 规则 / 密文在此内存态可用；finalize 在
    /// 其上执行裁决、读值与审计签名）。
    pub(crate) fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// 指纹裁决是否已执行（单发状态读取）。
    pub(crate) fn fingerprint_adjudicated(&self) -> bool {
        self.fp_adjudicated
    }

    /// 标记指纹裁决已执行（转二次审批时随工作区移入新条目——新条目的
    /// finalize 不再裁决）。
    pub(crate) fn mark_fingerprint_adjudicated(&mut self) {
        self.fp_adjudicated = true;
    }
}

/// 统一待审批注册表条目（key = 请求 id，由外层 map 承担）。needs_unlock 与
/// 审批工作区是条目级一等字段（issue #148/#150）：审批解锁辅助表无关。
pub(crate) struct GateEntry {
    /// 锁定态一体化标志（#67 inject / #23 读通道）：审批需先临时解锁；
    /// `authz.request` 帧的 `needsUnlock` 与本值同源（单点铸造保证）。
    /// 规则门/写门恒 false——由 [`GateEntry::approval`] 构造器与各门流程
    /// 声明（`DeferredFlow::unlock_supported`）显式承载（issue #150）。
    pub needs_unlock: bool,
    /// 审批工作区（issue #150，见 [`ApprovalWorkspace`] 类型文档——不变量
    /// 「单次即毁 / 不签令牌 / 不置共享 vault」的单点出处）。正常路径恒
    /// `None`，仅一体化解锁路径由审批回传填充。
    pub workspace: Option<ApprovalWorkspace>,
    /// 门负载（各门 begin 期已解析的产物）。
    pub kind: GateKind,
}

impl GateEntry {
    /// 常规审批条目（解锁态；**显式声明无需一体化解锁**——规则门/写门等）。
    pub(crate) fn approval(kind: GateKind) -> Self {
        Self {
            needs_unlock: false,
            workspace: None,
            kind,
        }
    }

    /// 一体化解锁审批条目（锁定态 #67/#23：审批回传以主密码临时解锁后
    /// 由 [`PendingGates::store_workspace`] 填充工作区）。
    pub(crate) fn unified_unlock(kind: GateKind) -> Self {
        Self {
            needs_unlock: true,
            workspace: None,
            kind,
        }
    }
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
/// 判定与工作区存取经 [`Self::needs_unlock`] / [`Self::store_workspace`]
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

    /// 把审批工作区存入待审条目（`approval.result` 的 allowed 决策，主密码
    /// 临时解锁成功后；issue #150）。返回条目是否存在（true = 已存储）；
    /// 条目已被 finalize 消费（超时竞态）→ false，工作区随调用方作用域
    /// 整体 drop（生命周期与条目严格一致）。
    ///
    /// 条目已带工作区（#140 二次审批条目）时**替换解锁材料、保留单次裁决
    /// 状态**：指纹单发状态属于条目侧裁决流程而非某一份解锁材料——重解锁
    /// 不得重置「已裁决」标记，否则失配二次审批将再次裁决、再次失配，形成
    /// 裁决死循环（#140 类竞态由结构排除）。
    pub(crate) fn store_workspace(
        &mut self,
        request_id: uuid::Uuid,
        mut ws: ApprovalWorkspace,
    ) -> bool {
        match self.entries.get_mut(&request_id) {
            Some(entry) => {
                if let Some(prev) = entry.workspace.take() {
                    if prev.fingerprint_adjudicated() {
                        ws.mark_fingerprint_adjudicated();
                    }
                }
                entry.workspace = Some(ws);
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

    /// 「本次执行所用 vault」统一取用原语（issue #150）：执行/审计入口收
    /// [`ActingVault`]——Shared = 共享 vault 读锁内取（`None` = 已锁定，
    /// K_audit 已擦除，语义由调用方决定：审计跳过 / 执行保守报错）；
    /// Temporary = 锁定态一体化的临时 vault 借用（审批工作区，见
    /// [`ApprovalWorkspace::vault`]）。执行与审计的 `_from` 变体对由此
    /// 全消（环境解析 / 读值执行 / 导出执行 / 审计同一入口）。
    pub(crate) fn with_acting_vault<R>(
        &self,
        acting: ActingVault<'_>,
        f: impl FnOnce(Option<&UnlockedVault>) -> R,
    ) -> R {
        match acting {
            ActingVault::Shared => {
                let guard = self.shared.vault.read().unwrap();
                f(guard.as_ref())
            }
            ActingVault::Temporary(v) => f(Some(v)),
        }
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
        let keys = match self.with_acting_vault(acting, |v| v.map(|v| v.keys().clone())) {
            // 共享 vault 已锁定 → K_audit 已擦除，跳过审计（既有口径）
            Some(keys) => keys,
            None => return,
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

/// 本次执行所用 vault（acting vault；执行与审计的 K_audit 来源）。执行/
/// 审计入口统一收本枚举（issue #150：`with_acting_vault` 单点取用）——
/// 调用方决定传共享 vault 还是临时 vault；临时形态的 vault 由审批工作区
/// 持有（借用，生命周期不变量见 [`ApprovalWorkspace`]）。
pub(crate) enum ActingVault<'a> {
    /// 共享 vault（解锁态常态路径）；已锁定（`None`）→ 语义由调用方决定
    /// （审计跳过 / 执行保守报错）。
    Shared,
    /// 锁定态一体化的临时 vault（#67/#23；审批工作区借用）。
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
        let kind = GateKind::Disclosure(PendingDisclosure {
            method: lk_core::ipc::M_ITEM_GET.to_string(),
            item_id: uuid::Uuid::new_v4(),
            item_name: Some("item".to_string()),
            starter: "test".to_string(),
        });
        if needs_unlock {
            GateEntry::unified_unlock(kind)
        } else {
            GateEntry::approval(kind)
        }
    }

    /// 初始化临时 vault（审批工作区需要真实的 UnlockedVault 值；test KDF
    /// 参数下开销可忽略。UnlockedVault 不可 Clone，每次取用重新解锁）。
    fn init_vault(dir: &std::path::Path) {
        let mut audit = lk_core::audit::AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }

    /// 构造填充态审批工作区（临时解锁 vault 由测试主密码解锁）。
    fn workspace(dir: &std::path::Path) -> ApprovalWorkspace {
        ApprovalWorkspace::new(UnlockedVault::unlock(dir, "pw123456").unwrap())
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

    /// 审批工作区生命周期与条目严格一致（issue #150）：在册条目存储成功、
    /// 随 remove 返回（finalize 消费）；条目已被消费（超时竞态）→ false，
    /// 工作区随调用方作用域整体 drop。
    #[test]
    fn workspace_storage_follows_entry_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let mut registry = PendingGates::default();
        // 条目不在册 → 放弃存储（调用方作用域 drop）
        assert!(!registry.store_workspace(uuid::Uuid::new_v4(), workspace(dir.path())));
        let id = uuid::Uuid::new_v4();
        registry.insert(id, disclosure_entry(true));
        assert!(registry.store_workspace(id, workspace(dir.path())));
        let entry = registry.remove(&id).expect("条目在册");
        assert!(entry.workspace.is_some());
        // 消费后再存 → false（一次性语义）
        assert!(!registry.store_workspace(id, workspace(dir.path())));
    }

    /// 单次裁决状态属于条目而非解锁材料（issue #150，#140 回归钉）：二次
    /// 审批条目已带「已裁决」工作区时，`approval.result` 重解锁存入**新的**
    /// 解锁材料——替换 vault 但不得重置已裁决标记，否则失配二次审批将再次
    /// 裁决、再次失配，形成裁决死循环。
    #[test]
    fn store_workspace_preserves_single_shot_state_of_repend_entry() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let mut registry = PendingGates::default();
        let id = uuid::Uuid::new_v4();
        // 模拟二次审批条目：工作区已裁决（finalize reopen 侧标记）
        registry.insert(id, disclosure_entry(true));
        let mut ws = workspace(dir.path());
        ws.mark_fingerprint_adjudicated();
        registry.store_workspace(id, ws);
        // 回传重解锁：全新解锁材料替换既有工作区
        assert!(registry.store_workspace(id, workspace(dir.path())));
        let entry = registry.remove(&id).expect("条目在册");
        let ws = entry.workspace.expect("工作区在册");
        assert!(
            ws.fingerprint_adjudicated(),
            "重解锁不得重置单次裁决状态（#140 裁决死循环由结构排除）"
        );
    }

    /// 工作区 = 临时解锁材料 + 单次裁决状态的一等对象（issue #150）：
    /// vault 只能借用（K_audit 在内存可用）；指纹裁决单发状态默认 false、
    /// 标记后 true（防裁决 → 审批 → 裁决死循环由结构承载，issue #140）。
    #[test]
    fn workspace_borrows_vault_and_carries_single_shot_state() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let mut ws = workspace(dir.path());
        // 临时 vault 可借用：K_audit 在内存（审计可签名）
        let _ = ws.vault().keys();
        // 单次裁决状态：默认未裁决
        assert!(!ws.fingerprint_adjudicated());
        ws.mark_fingerprint_adjudicated();
        assert!(ws.fingerprint_adjudicated());
    }

    /// 条目构造器即声明（issue #150）：`GateEntry::approval` = 常规审批
    /// （needs_unlock=false，规则门/写门显式声明无需一体化解锁）；
    /// `GateEntry::unified_unlock` = 一体化解锁审批（needs_unlock=true，
    /// #67/#23）；工作区在两条路径上初始恒空。
    #[test]
    fn entry_constructors_declare_unlock_gate() {
        let plain = disclosure_entry(false);
        assert!(!plain.needs_unlock);
        assert!(plain.workspace.is_none());
        let unified = disclosure_entry(true);
        assert!(unified.needs_unlock);
        assert!(unified.workspace.is_none());
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
