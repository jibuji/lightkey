//! Agent 授权门（规格：`docs/authorization-gate.md`；M2 落地）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - 三层模型作为**硬编码确定性流程**（`waterfall` 语义，命中即短路，
//!   不数据化，plugin-architecture.md §5.4）：① 默认拒绝 → ② 规则白名单
//!   （vault 内加密、按项目目录绑定）→ ③ 弹窗审批（30s 超时默认拒绝）。
//! - 启动者判定（[`crate::starter`]）由**守护进程**从 IPC 对端 PID 回溯，
//!   客户端自报 `starter/cwd` 一律视为不可信输入。
//! - 规则匹配：`projectDir` 祖先匹配（canonical 形态）+ `command` glob
//!   （`*`/`?`，大小写敏感）；多规则命中取 **keys 并集**；注入集合 =
//!   规则 keys ∩ 请求 keys（agent 只能看到被授权的 key 名）。
//! - 第 3 层审批的**编排**（登记 / `authz.request` 广播 / 锁外等待 /
//!   收尾）住在守护进程侧——daemon 审批注册表（单表承载 challenge/expires/
//!   decision + needs_unlock/workspace/kind）+ 通用 deferred 编排器；本模块
//!   只承载三层判定与规则匹配纯函数（拍板 #28 候选 2：`ApprovalChannel`
//!   通道抽象已删除，core 不再持有待审批状态）。
//! - 授权门三层是 Rust 内部确定性流程；`authz.request`（[`bus::VaultEvent`]）
//!   只是「需要用户决策」的通知，决策权始终在 Rust 侧（§5.3）。
//! - **G1 并发约束**：第 3 层的 30s 等待不得持有守护进程命令锁——实现为
//!   三阶段（begin 命令锁内 → 锁外等待 → 重取锁收尾），编排见 `lk-daemon`
//!   的 router.rs 通用 deferred 编排器。
//! - fail-closed：启动者未知 / 规则库损坏（解密失败）/ 无审批界面 /
//!   请求 key 无法解析 → 一律拒绝，不弹窗、不留内容，仅审计拒绝事件。

use std::collections::HashSet;

use crate::model::Rule;
use crate::Result;

/// 审批超时默认值（第 3 层弹窗 30s 超时默认拒绝；守护进程配置可调，默认 30）。
pub const APPROVAL_TIMEOUT_DEFAULT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// 请求 / 决策类型
// ---------------------------------------------------------------------------

/// 授权判定请求（**全部由守护进程侧派生/核对**，不信任客户端自报字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzRequest {
    /// 启动者（进程链回溯结果；`unknown` = fail-closed 拒绝）。
    pub starter: String,
    /// 对端进程真实 cwd（canonical 形态）。
    pub cwd: String,
    /// 具名命令（如 `npm publish`；匹配规则 command glob）。
    pub command: String,
    /// 请求注入的 key 名集合（值不可见、名可指名，决策 #1）。
    pub keys: Vec<String>,
}

/// 三层判定的中间/最终结果（`evaluate_layers` 为非阻塞的第 1/2 层短路）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerResult {
    /// 第 2 层规则命中：注入 `keys`（规则 keys ∩ 请求 keys）。
    Allowed { keys: Vec<String> },
    /// 第 1 层拒绝（fail-closed；不弹窗、不留内容）。
    Denied { reason: DenyReason },
    /// 未命中规则 → 进入第 3 层弹窗审批。
    NeedsApproval,
}

/// 拒绝原因（审计与 CLI 文案映射用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// 启动者未知（进程链回溯失败/跨会话）→ fail-closed。
    UnknownStarter,
    /// 对端 cwd 不可得（回溯失败）→ fail-closed（规则按项目目录绑定）。
    NoCwd,
    /// 请求的 key 无法在库中解析（不存在/非 secret 类型）→ 无法满足请求。
    MissingKeys,
    /// 规则库损坏（解密失败）→ fail-closed。
    RuleCorrupt,
    /// 无审批界面（无推送订阅连接）→ 第 3 层立即拒绝，不阻塞。
    NoUi,
    /// 用户拒绝。
    Rejected,
    /// 审批超时（默认拒绝）。
    Timeout,
}

impl DenyReason {
    /// 协议面字符串（`authz.evaluate` 响应的 `reason` 字段）。
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::UnknownStarter => "unknown_starter",
            DenyReason::NoCwd => "no_cwd",
            DenyReason::MissingKeys => "missing_keys",
            DenyReason::RuleCorrupt => "rule_corrupt",
            DenyReason::NoUi => "no_ui",
            DenyReason::Rejected => "rejected",
            DenyReason::Timeout => "timeout",
        }
    }
}

/// 审批通道决策（第 3 层结果三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Allowed,
    Denied,
    Timeout,
}

/// 审批请求类型（M2.9 值披露；弹窗按 kind 选形态，value-disclosure.md §6；
/// 补充拍板 #22 增 `Rule`，#24 增 `Write`）。加性变更，不升协议版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalKind {
    /// 命令注入（既有 inject 语义）。
    Inject,
    /// 读条目值（`item.get`；读规则命中则不产生审批）。
    Read,
    /// 导出条目数据包（`item.export`；恒弹窗，规则不豁免）。
    Export,
    /// 规则管理（`rule.add` / `rule.remove`；补充拍板 #22）。单一 kind +
    /// `command` 字段承载操作（`rule.add <name>` / `rule.remove <name>`），
    /// 不拆两个 kind——remove 由 daemon 解析 id→规则补全 name/keys/projectDir
    /// 供弹窗展示。
    Rule,
    /// 写入门（补充拍板 #24，M2.97，write-gate.md §6）。单一 kind + `command`
    /// 字段承载动作（`item.put <name>` / `item.delete <name>`）；keys = 单元素
    /// [目标条目名]；export_meta 恒 None。
    Write,
}

/// 审批子类型（issue #147：审批帧携带门事实）。规则门/写门的子类型事实
/// ——daemon 权威派生并随 `authz.request` 帧回带 `subKind`（serde 值 =
/// RPC 方法名 `rule.add` / `rule.remove` / `item.put` / `item.delete`，
/// 常量在 [`crate::ipc::SUB_KIND_*`]）；read/export/inject 审批不带
/// （`None`）。前端据此渲染门语义并纯派生「记住」可记性
/// （rememberable 不进协议——派生值进帧即同一真相存两处），取代弹窗的
/// command 前缀匹配启发式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApprovalSubKind {
    #[serde(rename = "rule.add")]
    RuleAdd,
    #[serde(rename = "rule.remove")]
    RuleRemove,
    #[serde(rename = "item.put")]
    ItemPut,
    #[serde(rename = "item.delete")]
    ItemDelete,
}

impl ApprovalSubKind {
    /// 协议面字符串（`authz.request` 帧 `subKind` 字段；常量单一来源
    /// `crate::ipc::SUB_KIND_*`，TS 镜像 `APPROVAL_SUB_KINDS`）。
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalSubKind::RuleAdd => crate::ipc::SUB_KIND_RULE_ADD,
            ApprovalSubKind::RuleRemove => crate::ipc::SUB_KIND_RULE_REMOVE,
            ApprovalSubKind::ItemPut => crate::ipc::SUB_KIND_ITEM_PUT,
            ApprovalSubKind::ItemDelete => crate::ipc::SUB_KIND_ITEM_DELETE,
        }
    }
}

/// export 审批的数据包元信息（弹窗展示规模用；不含数据本身）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportMeta {
    pub name: String,
    pub mime: String,
    pub size: u64,
}

/// 程序指纹失配信息（M2.98，identity-binding.md §7）：绑定注入规则命中
/// 命令形态但指纹不符时随 `authz.request` 帧携带（弹窗据此显示「指纹不符」
/// 主题 + 当前解析路径、8 位哈希摘要并给「以新指纹重新授权」入口）；未失配
/// 为 `None`（常规审批）。**不含完整哈希、任何值或错误码差异化**（失配视同
/// 未命中，headless 统一 `authz.denied`，防探测）。审批帧的其余展示字段
/// （starter / projectDir / command / keys / kind / writeAction / exportMeta /
/// subKind / needsUnlock / challenge）由 [`crate::bus::VaultEvent::AuthzRequest`]
/// 直接承载；一次性挑战值的登记与校验在 daemon 审批注册表（#78 方案 B）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintMismatch {
    /// 当前解析到的 canonical 绝对路径（daemon 侧重算；展示用，非安全依据）。
    pub resolved_exe_path: String,
    /// 8 位 SHA-256 前缀摘要（hex 小写；不展示完整值）。
    pub sha256_short: String,
}

// ---------------------------------------------------------------------------
// 规则库视图（授权门对 vault 的最小读取面；测试注入假实现）
// ---------------------------------------------------------------------------

/// 授权门需要的 vault 视图：解密态规则 + 按名解析 secret 值。
pub trait RuleVault: Send + Sync {
    /// 全部解密态规则（含已删除的？——**不含**：删除规则不参与匹配）。
    /// 解密失败 → `Err`（规则库损坏 → fail-closed）。
    fn rules(&self) -> Result<Vec<Rule>>;
    /// 按 key 名解析 secret 条目值（不存在/非 secret/已删除 → `Ok(None)`）。
    fn secret_value(&self, key_name: &str) -> Result<Option<String>>;
}

// ---------------------------------------------------------------------------
// 授权门（三层模型，硬编码确定性流程）
// ---------------------------------------------------------------------------

/// B 层 **authz-gate** 插件（`docs/plugin-architecture.md` §3.2；注入
/// session + audit + vault-store）。承载三层模型的第 1/2 层非阻塞短路
/// （waterfall，命中即短路）；第 3 层审批编排（登记 / `authz.request` 广播 /
/// 锁外等待 / 收尾）在守护进程侧的审批注册表与通用 deferred 编排器
/// （拍板 #28 候选 2：`ApprovalChannel` 通道抽象已删除，本类型不再持有
/// 审批状态或通道字段）。
#[derive(Default)]
pub struct AuthzGate;

impl AuthzGate {
    pub fn new() -> AuthzGate {
        AuthzGate
    }

    /// 第 1/2 层（**非阻塞**；守护进程命令锁内调用）：
    ///
    /// 1. 默认拒绝：启动者未知 / cwd 不可得 / 请求 key 无法解析 /
    ///    规则库损坏 → [`LayerResult::Denied`]（fail-closed，不弹窗）；
    /// 2. 规则白名单：`(projectDir, command)` 匹配（祖先 + glob）→ 命中
    ///    取多规则 keys **并集 ∩ 请求 keys** → [`LayerResult::Allowed`]；
    /// 3. 未命中 → [`LayerResult::NeedsApproval`]（进入弹窗审批）。
    pub fn evaluate_layers(&self, req: &AuthzRequest, vault: &dyn RuleVault) -> LayerResult {
        // 第 1 层：fail-closed 检查
        if req.starter == crate::starter::UNKNOWN_STARTER {
            return LayerResult::Denied {
                reason: DenyReason::UnknownStarter,
            };
        }
        if req.cwd.is_empty() {
            return LayerResult::Denied {
                reason: DenyReason::NoCwd,
            };
        }
        // 规则库损坏（解密失败）优先于 key 解析失败（更根本的故障）
        let rules = match vault.rules() {
            Ok(r) => r,
            Err(_) => {
                return LayerResult::Denied {
                    reason: DenyReason::RuleCorrupt,
                }
            }
        };
        if !all_keys_resolvable(req, vault) {
            return LayerResult::Denied {
                reason: DenyReason::MissingKeys,
            };
        }
        // 第 2 层：规则白名单
        let mut granted: HashSet<&str> = HashSet::new();
        for rule in &rules {
            if rule_matches(rule, &req.cwd, &req.command) {
                for k in &rule.keys {
                    granted.insert(k.as_str());
                }
            }
        }
        let keys: Vec<String> = req
            .keys
            .iter()
            .filter(|k| granted.contains(k.as_str()))
            .cloned()
            .collect();
        if keys.is_empty() {
            LayerResult::NeedsApproval
        } else {
            LayerResult::Allowed { keys }
        }
    }
}

/// 规则是否匹配 `(cwd, command)`（注入路径）：**capability=inject**（能力
/// 不互授，read 规则不授权注入）+ projectDir 祖先匹配（canonical 形态，
/// 相等或为前缀 + `/`）+ command 形态（`*`/`?`，大小写敏感）：
///
/// - **未绑定指纹（None）**：`glob_match(rule.command, command)` 整串匹配
///   （现状语义零变化，identity-binding.md §4）；
/// - **指纹绑定（Some）**：按 `command[0]` 的**可执行名**（basename，去
///   目录；可执行后缀剥离按 stem 等价比较，issue #133）与 `rule.command`
///   glob 匹配（identity-binding.md §2 目标 2：注入规则绑定被注入命令的
///   可执行文件）——CLI 以 exe basename 落库（`/usr/bin/npm` → `"npm"`，
///   Windows `npm.cmd` → `"npm.cmd"`），注入请求 command 是完整命令串
///   （`lk inject -- npm publish` → `"npm publish"`），整串匹配必失配
///   （issue #132）；Windows 无扩展名键入与带后缀落库由 stem 等价桥接
///   （issue #133）。命令为空/纯空白 → 形式不成立（fail-closed）。
pub fn rule_matches(rule: &Rule, canonical_cwd: &str, command: &str) -> bool {
    rule.capability == crate::model::RULE_CAPABILITY_INJECT
        && project_dir_matches(&rule.project_dir, canonical_cwd)
        && inject_command_form_matches(rule, command)
}

/// 注入命令形态匹配：绑定规则按 `command[0]` 的可执行名（basename）比较，
/// 未绑定规则维持整串 glob（issue #132 契约，见 [`rule_matches`]）。
fn inject_command_form_matches(rule: &Rule, command: &str) -> bool {
    match &rule.fingerprint {
        None => glob_match(&rule.command, command),
        Some(_) => command0_exe_name(command)
            .is_some_and(|name| bound_command_matches(&rule.command, &name)),
    }
}

/// 绑定规则命令形态匹配（issue #133）：规则 `command`（CLI 由 --fingerprint
/// 的可执行文件 basename 推导，Windows 常带 `.cmd`/`.exe`——`npm.cmd`）与
/// 注入 `command[0]` 可执行名（Windows 用户实际输入常**无扩展名**——`npm`）
/// 按 **stem 等价** 比较：双方都剥离可执行后缀
/// （[`crate::fingerprint::EXEC_EXTENSIONS`]）后再 glob——`"npm.cmd" ↔
/// "npm"`、`"fptool.exe" ↔ "fptool.exe"` 均命中；无可剥离后缀时退化回
/// #132 的 basename glob（零变化）。形式层只负责**收集候选规则**；安全由
/// 解析 + 指纹门承载（解析到不同文件/不可解析 → 审批 fail-closed，
/// identity-binding.md §5）。
fn bound_command_matches(rule_pattern: &str, typed_name: &str) -> bool {
    glob_match(
        strip_exec_suffix(rule_pattern),
        strip_exec_suffix(typed_name),
    )
}

/// 剥离可执行文件后缀（[`crate::fingerprint::EXEC_EXTENSIONS`]，大小写不
/// 敏感；`npm.cmd` → `npm`，`NPM.CMD` → `NPM`）；无已知后缀 / 剥离后为空
/// （`".cmd"` 自身）→ 原样返回。
fn strip_exec_suffix(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    crate::fingerprint::EXEC_EXTENSIONS
        .iter()
        .find_map(|ext| {
            (lower.ends_with(ext) && name.len() > ext.len())
                .then(|| &name[..name.len() - ext.len()])
        })
        .unwrap_or(name)
}

/// `command[0]` 的可执行名（basename，去目录）：「npm publish」→「npm」；
/// 「/usr/bin/npm publish」→「npm」；空/纯空白 → `None`。daemon 规则门
/// finalize 落库侧用同一函数做绑定规则 command 规范化（issue #136：与匹配
/// 层共用一处契约实现，两侧永不漂移）。
pub fn command0_exe_name(command: &str) -> Option<String> {
    let c0 = crate::fingerprint::command0(command)?;
    Some(
        std::path::Path::new(c0)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| c0.to_string()),
    )
}

/// 读规则是否匹配 `(cwd, 条目名)`（值披露读路径，value-disclosure.md §4）：
/// **capability=read**（inject 规则不授权读）+ projectDir 祖先匹配（与
/// inject 同一套归一化/祖先匹配，WSL 侧两侧同函数）+ keys **精确包含**
/// 条目名（不做 key 通配，与 inject 的 keys 语义一致）。
pub fn read_rule_matches(rule: &Rule, canonical_cwd: &str, item_name: &str) -> bool {
    rule.capability == crate::model::RULE_CAPABILITY_READ
        && project_dir_matches(&rule.project_dir, canonical_cwd)
        && rule.keys.iter().any(|k| k == item_name)
}

/// 写动作（M2.97 写入门，write-gate.md §4/§5.2）：守护进程从
/// `ItemPutParams.id: Option<Uuid>` **权威派生**（None = create，Some =
/// update），不信任客户端自报。**无 Delete 变体**——delete 恒弹窗由协议
/// 保证（§3），根本不进规则匹配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    /// 新建（id=None）：keys 精确包含草稿名。
    Create,
    /// 整条替换（id=Some）：keys 同时包含存储名与草稿名（双向名约束）。
    Update,
}

impl WriteAction {
    /// 协议面字符串（`authz.request` 帧的 `writeAction` 字段；#137 最小
    /// 授权修复——前端「记住」按帧内 action 生成 `actions=[当前动作]`）。
    pub fn as_str(self) -> &'static str {
        match self {
            WriteAction::Create => "create",
            WriteAction::Update => "update",
        }
    }
}

/// 写规则是否匹配 `(cwd, action, 存储名?, 草稿名)`（写门路径，write-gate.md
/// §4）：**capability=write**（三能力两两不互授）+ projectDir 祖先匹配（与
/// inject/read 同一套归一化/祖先匹配，`wsl://` 规范形两侧同函数）+ 按动作：
///
/// - [`WriteAction::Create`]：actions 含 `create` 且 keys **精确包含草稿名**；
/// - [`WriteAction::Update`]：actions 含 `update` 且 keys **同时包含存储名
///   与草稿名**——改名不得「进出」授权名集合（堵改名逃生 / 改名植毒，§4）；
///   存储名未知（`None`）→ 不命中（fail-closed）。
///
/// 重名语义「名字即身份」：keys 按名匹配，覆盖全部同名条目（与读规则同构）。
pub fn write_rule_matches(
    rule: &Rule,
    canonical_cwd: &str,
    action: WriteAction,
    stored_name: Option<&str>,
    draft_name: &str,
) -> bool {
    if rule.capability != crate::model::RULE_CAPABILITY_WRITE {
        return false;
    }
    if !project_dir_matches(&rule.project_dir, canonical_cwd) {
        return false;
    }
    match action {
        WriteAction::Create => {
            rule.actions
                .iter()
                .any(|a| a == crate::model::RULE_ACTION_CREATE)
                && rule.keys.iter().any(|k| k == draft_name)
        }
        WriteAction::Update => {
            rule.actions
                .iter()
                .any(|a| a == crate::model::RULE_ACTION_UPDATE)
                && stored_name.is_some_and(|s| rule.keys.iter().any(|k| k == s))
                && rule.keys.iter().any(|k| k == draft_name)
        }
    }
}

/// projectDir 祖先匹配：`cwd` 等于 `project_dir`，或 `cwd` 是 `project_dir`
/// 的路径前缀（**按路径组件**比较——目录边界 `/a/b/cd` 不匹配 `/a/b/c`；
/// 分隔符随平台，Windows `C:\\a\\b` 与 `/` 写法均正确）。
///
/// 两侧先过 [`crate::path_ns::canonical_project_dir`] 归一化再比较（§7.4
/// 两侧同函数，幂等）：规则侧历史/同步入库的 verbatim 前缀形态
/// （`\\?\C:\…`）剥离为常规绝对路径；cwd 侧同样归一化——Windows 上
/// `fs::canonicalize` 产物本身即 verbatim 形态，未归一化将无法与规则侧命中
/// （守护进程边界已归一化时此步无副作用，属纵深防御：客户端自报 cwd 不得
/// 因写法变体绕过或漏配）。`wsl://<distro>/<rest>` 规范形保留原样。
/// 两侧均为 wsl:// 规范形时改用 wsl 形态匹配：大小写不敏感（NTFS 默认
/// 语义）、按 `/` 目录边界（cross-subsystem.md §7.4——distro 名保留原样
/// 但匹配不区分大小写，防伪造 cwd 大小写变体绕过或漏配）。
pub fn project_dir_matches(project_dir: &str, canonical_cwd: &str) -> bool {
    let dir_norm = crate::path_ns::canonical_project_dir(project_dir);
    let cwd_norm = crate::path_ns::canonical_project_dir(canonical_cwd);
    if crate::path_ns::is_wsl_canonical(&dir_norm) && crate::path_ns::is_wsl_canonical(&cwd_norm) {
        return crate::path_ns::wsl_ancestor_matches(&dir_norm, &cwd_norm);
    }
    let dir = std::path::Path::new(&dir_norm);
    let cwd = std::path::Path::new(&cwd_norm);
    cwd == dir || cwd.starts_with(dir)
}

/// 命令 glob 匹配（`*` = 任意长度、`?` = 单字符；其余字面量，大小写敏感）。
/// 双指针迭代实现（无递归/回溯爆炸）。
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            star_ti = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 请求的 key 是否全部可在库中解析（不存在 → 第 1 层拒绝，不进审批：
/// 弹窗不为无法满足的请求打扰用户；不泄露库内有哪些 key——只反馈「无法满足」）。
fn all_keys_resolvable(req: &AuthzRequest, vault: &dyn RuleVault) -> bool {
    req.keys
        .iter()
        .all(|k| vault.secret_value(k).ok().flatten().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use uuid::Uuid;

    fn rule(project_dir: &str, command: &str, keys: &[&str]) -> Rule {
        Rule {
            id: Uuid::new_v4(),
            project_dir: project_dir.into(),
            name: "t".into(),
            command: command.into(),
            keys: keys.iter().map(|s| s.to_string()).collect(),
            capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            actions: crate::model::default_rule_actions(),
            fingerprint: None,
            created: "2026-01-01T00:00:00.000000Z".into(),
        }
    }

    /// 假规则库（测试注入）。
    struct FakeVault {
        rules: Vec<Rule>,
        secrets: std::collections::HashMap<String, String>,
    }

    impl FakeVault {
        fn new(rules: Vec<Rule>, secrets: &[(&str, &str)]) -> FakeVault {
            FakeVault {
                rules,
                secrets: secrets
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    impl RuleVault for FakeVault {
        fn rules(&self) -> Result<Vec<Rule>> {
            Ok(self.rules.clone())
        }
        fn secret_value(&self, key_name: &str) -> Result<Option<String>> {
            Ok(self.secrets.get(key_name).cloned())
        }
    }

    /// 损坏规则库（解密失败 → fail-closed）。
    struct CorruptVault;

    impl RuleVault for CorruptVault {
        fn rules(&self) -> Result<Vec<Rule>> {
            Err(Error::Decrypt)
        }
        fn secret_value(&self, _key_name: &str) -> Result<Option<String>> {
            Ok(None)
        }
    }

    fn req(starter: &str, cwd: &str, command: &str, keys: &[&str]) -> AuthzRequest {
        AuthzRequest {
            starter: starter.into(),
            cwd: cwd.into(),
            command: command.into(),
            keys: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 第 1 层短路：未知启动者 → 拒绝（不看规则）。
    #[test]
    fn layer1_denies_unknown_starter_before_rules() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new();
        let r = gate.evaluate_layers(&req("unknown", "/proj", "npm publish", &["A"]), &vault);
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::UnknownStarter
            }
        );
    }

    /// 第 1 层：cwd 不可得 → 拒绝。
    #[test]
    fn layer1_denies_missing_cwd() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new();
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "", "npm publish", &["A"]), &vault),
            LayerResult::Denied {
                reason: DenyReason::NoCwd
            }
        );
    }

    /// 第 1 层：请求 key 无法解析 → 拒绝（不弹窗）。
    #[test]
    fn layer1_denies_unresolvable_keys() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new();
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["GHOST"]), &vault);
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::MissingKeys
            }
        );
    }

    /// 第 1 层：规则库损坏 → fail-closed 拒绝。
    #[test]
    fn layer1_denies_corrupt_rule_vault() {
        let gate = AuthzGate::new();
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A"]),
            &CorruptVault,
        );
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::RuleCorrupt
            }
        );
    }

    /// 第 2 层：规则命中 → 注入 = 规则 keys ∩ 请求 keys。
    #[test]
    fn layer2_allowed_intersects_rule_keys() {
        let vault = FakeVault::new(
            vec![rule("/proj", "npm *", &["A", "B"])],
            &[("A", "a"), ("B", "b")],
        );
        let gate = AuthzGate::new();
        // 请求 [A] → 注入 [A]（B 未请求，不注入——不泄漏未请求的值）
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["A"]), &vault);
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 请求 [A, B] → 注入 [A, B]
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A", "B"]),
            &vault,
        );
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into(), "B".into()]
            }
        );
    }

    /// 多规则命中取 keys 并集；请求的 key 未被任何规则授权 → 进第 3 层。
    #[test]
    fn layer2_union_across_rules_and_fallback() {
        let vault = FakeVault::new(
            vec![
                rule("/proj", "npm *", &["A"]),
                rule("/proj", "npm publish", &["B"]),
            ],
            &[("A", "a"), ("B", "b"), ("C", "c")],
        );
        let gate = AuthzGate::new();
        // 两条规则都命中 → 并集 {A, B}
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A", "B"]),
            &vault,
        );
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into(), "B".into()]
            }
        );
        // 请求 [C]：无规则授权 → NeedsApproval
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["C"]), &vault);
        assert_eq!(r, LayerResult::NeedsApproval);
    }

    /// 规则匹配矩阵：祖先/目录边界/glob。
    #[test]
    fn rule_matching_matrix() {
        // projectDir 祖先：相等 / 子目录 / 非子目录 / 前缀欺骗
        assert!(project_dir_matches("/a/b", "/a/b"));
        assert!(project_dir_matches("/a/b", "/a/b/c"));
        assert!(project_dir_matches("/a/b", "/a/b/c/d"));
        assert!(!project_dir_matches("/a/b", "/a/bc"));
        assert!(!project_dir_matches("/a/b", "/x/y"));
        assert!(!project_dir_matches("/a/b", "/a"));
        // 尾斜杠归一化
        assert!(project_dir_matches("/a/b/", "/a/b"));
        // command glob：精确 / 通配 / 不匹配
        assert!(glob_match("npm publish", "npm publish"));
        assert!(glob_match("npm *", "npm publish"));
        assert!(!glob_match("npm *", "npm")); // 空格为字面量（标准 glob 语义）
        assert!(glob_match("*publish", "npm publish"));
        assert!(glob_match("npm p?blish", "npm publish"));
        assert!(!glob_match("npm p?blish", "npm publish x"));
        assert!(!glob_match("npm *", "yarn publish"));
        assert!(!glob_match("npm publish", "npm publish --tag"));
        assert!(!glob_match("NPM *", "npm publish")); // 大小写敏感
                                                      // 组合
        let r = rule("/proj", "npm *", &["A"]);
        assert!(rule_matches(&r, "/proj/sub", "npm publish"));
        assert!(!rule_matches(&r, "/proj-other", "npm publish"));
        assert!(!rule_matches(&r, "/proj/sub", "yarn publish"));
    }

    /// 跨命名空间（cross-subsystem.md §7.4/§10）：规则录 `wsl://` 规范形，
    /// 伪造 UNC cwd 变体（大写 distro / 别名 / 尾斜杠）经守护进程侧
    /// [`crate::path_ns::canonical_project_dir`] 归一化后必须命中同一规则
    /// （不得绕过、也不得漏配）。
    #[test]
    fn wsl_namespace_rule_matches_normalized_cwd() {
        let vault = FakeVault::new(
            vec![rule("wsl://Debian/home/u/p", "*", &["A"])],
            &[("A", "a")],
        );
        let gate = AuthzGate::new();
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\");
        assert_eq!(
            gate.evaluate_layers(&req("starter", &cwd, "npm publish", &["A"]), &vault),
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 目录边界外（p2）不得命中
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert_eq!(
            gate.evaluate_layers(&req("starter", &cwd2, "npm publish", &["A"]), &vault),
            LayerResult::NeedsApproval
        );
    }

    /// 符号链接目录：cwd 已 canonicalize → 与 canonical 规则目录匹配
    /// （真实 fs：临时目录 + symlink，canonicalize 后比较）。
    #[test]
    fn rule_matching_resolves_symlink_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-proj");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&real, &link).unwrap();
        let canonical_real = std::fs::canonicalize(&real).unwrap();
        let canonical_link = std::fs::canonicalize(&link).unwrap();
        // 规则绑定真实路径；cwd 经符号链接进入（canonical 后 = 真实路径）
        let r = rule(&canonical_real.to_string_lossy(), "*", &["A"]);
        assert!(rule_matches(
            &r,
            &canonical_link.join("sub").to_string_lossy(),
            "x"
        ));
        assert!(rule_matches(&r, &canonical_link.to_string_lossy(), "x"));
    }

    /// 完整三层短路：规则命中 → Allowed；未命中 → NeedsApproval
    /// （守护进程再判 UI 在场谓词 → 拒绝）。
    #[test]
    fn three_layer_short_circuit() {
        let vault = FakeVault::new(vec![rule("/proj", "npm *", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new();
        // 第 1 层：未知启动者
        assert!(matches!(
            gate.evaluate_layers(&req("unknown", "/proj", "npm publish", &["A"]), &vault),
            LayerResult::Denied { .. }
        ));
        // 第 2 层：命中
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["A"]), &vault),
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 未命中 → 第 3 层
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "/proj", "yarn publish", &["A"]), &vault),
            LayerResult::NeedsApproval
        );
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("", ""));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "aXbYcZ"));
        assert!(glob_match("?", "x"));
        assert!(!glob_match("?", ""));
        assert!(glob_match("a?", "ab"));
        assert!(!glob_match("a?", "a"));
        // 全星号
        assert!(glob_match("***", "xyz"));
        // 长文本性能冒烟（双指针，无回溯爆炸）
        let long = "x".repeat(10_000);
        assert!(glob_match(&format!("{}*", "x".repeat(9_999)), &long));
        assert!(!glob_match(&format!("{}y", "x".repeat(9_999)), &long));
    }

    // -- M2.9 值披露（补充拍板 #20）：读规则匹配 + ApprovalKind ------------

    /// 读规则（capability=read）的 helper：command 恒空串（spec §4）。
    fn read_rule(project_dir: &str, keys: &[&str]) -> Rule {
        let mut r = rule(project_dir, "", keys);
        r.capability = crate::model::RULE_CAPABILITY_READ.into();
        r
    }

    /// 读规则匹配矩阵：capability 过滤 + projectDir 祖先 + keys 精确名。
    #[test]
    fn read_rule_matching_matrix() {
        let r = read_rule("/proj", &["A", "B"]);
        // 条目名精确包含 + cwd 祖先
        assert!(read_rule_matches(&r, "/proj", "A"));
        assert!(read_rule_matches(&r, "/proj/sub", "B"));
        assert!(!read_rule_matches(&r, "/proj", "C"), "keys 未包含 → 不命中");
        assert!(!read_rule_matches(&r, "/other", "A"), "cwd 不匹配 → 不命中");
        assert!(!read_rule_matches(&r, "/projc", "A"), "目录边界不匹配");
        // 能力不互授：inject 规则不授权读
        let inject = rule("/proj", "*", &["A"]);
        assert!(!read_rule_matches(&inject, "/proj", "A"));
        // read 规则不授权注入（inject 匹配路径按 capability 过滤）
        assert!(!rule_matches(&r, "/proj", "x"), "read 规则不得命中注入");
        // 带伪造 command 的 read 规则同样不得命中注入
        let mut rogue = r.clone();
        rogue.command = "npm *".into();
        assert!(!rule_matches(&rogue, "/proj", "npm publish"));
    }

    /// 读规则跨命名空间：`wsl://` 规范形规则命中归一化后的 WSL cwd
    /// （与 inject 同一套 project_dir_matches，两侧同函数）。
    #[test]
    fn read_rule_matches_wsl_normalized_cwd() {
        let r = read_rule("wsl://Debian/home/u/p", &["A"]);
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\sub");
        assert!(read_rule_matches(&r, &cwd, "A"));
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert!(!read_rule_matches(&r, &cwd2, "A"));
    }

    /// inject 规则（capability 缺省）照常命中注入路径（回归：legacy 规则
    /// 反序列化为 inject 后三层语义不变）。
    #[test]
    fn inject_rule_still_matches_after_capability_default() {
        let mut r = rule("/proj", "npm *", &["A"]);
        r.capability = crate::model::RULE_CAPABILITY_INJECT.into();
        assert!(rule_matches(&r, "/proj/sub", "npm publish"));
    }

    // -- M2.97 写入门（补充拍板 #24）：写规则匹配矩阵（write-gate.md §4/§10.1）-

    /// 写规则 helper：capability=write；command 恒空串（spec §4），keys =
    /// 条目名（精确，不做通配），actions = 写动作子集。
    fn write_rule(project_dir: &str, keys: &[&str], actions: &[&str]) -> Rule {
        let mut r = rule(project_dir, "", keys);
        r.capability = crate::model::RULE_CAPABILITY_WRITE.into();
        r.actions = actions.iter().map(|s| s.to_string()).collect();
        r
    }

    /// create：keys 精确包含草稿名 + projectDir 祖先匹配。
    #[test]
    fn write_rule_create_matches_draft_name() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Create,
            None,
            "config.ini"
        ));
        assert!(write_rule_matches(
            &r,
            "/proj/sub",
            WriteAction::Create,
            None,
            "config.ini"
        ));
        assert!(
            !write_rule_matches(&r, "/proj", WriteAction::Create, None, "other.ini"),
            "keys 未包含草稿名 → 不命中"
        );
        assert!(
            !write_rule_matches(&r, "/other", WriteAction::Create, None, "config.ini"),
            "cwd 不匹配 → 不命中"
        );
        assert!(
            !write_rule_matches(&r, "/projc", WriteAction::Create, None, "config.ini"),
            "目录边界不匹配"
        );
    }

    /// update：keys 同时包含存储名与草稿名（双向名约束）。
    #[test]
    fn write_rule_update_requires_both_names() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "config.ini"
        ));
        // 同目录改名（两名字都在授权集）：命中
        let multi = write_rule("/proj", &["old.ini", "new.ini"], &["update"]);
        assert!(write_rule_matches(
            &multi,
            "/proj",
            WriteAction::Update,
            Some("old.ini"),
            "new.ini"
        ));
    }

    /// 改名逃生：存储名不在 keys → 不命中（把授权条目改名出集合）。
    #[test]
    fn write_rule_rename_escape_denied() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("secret.ini"),
            "config.ini"
        ));
    }

    /// 改名植毒：草稿名不在 keys → 不命中（把非授权条目改名进集合）。
    #[test]
    fn write_rule_rename_poisoning_denied() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "poison.ini"
        ));
    }

    /// 重名语义「名字即身份」：规则按名覆盖全部同名条目（data-model.md
    /// 无名称唯一约束，重名允许）。匹配函数签名只收（存储名, 草稿名）
    /// 字符串、不收条目 id——同名条目无论 id 均命中同一规则，本用例把
    /// 该 API 形态钉住。
    #[test]
    fn write_rule_covers_all_same_named_items() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "config.ini"
        ));
    }

    /// actions 子集语义：create-only 不授 update，update-only 不授 create。
    #[test]
    fn write_rule_actions_are_per_action() {
        let create_only = write_rule("/proj", &["a.ini"], &["create"]);
        assert!(write_rule_matches(
            &create_only,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(!write_rule_matches(
            &create_only,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        let update_only = write_rule("/proj", &["a.ini"], &["update"]);
        assert!(!write_rule_matches(
            &update_only,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(write_rule_matches(
            &update_only,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
    }

    /// delete 不参与匹配（write-gate.md §3 恒弹窗）：即使规则 actions 防御性
    /// 含 "delete"，也不产生任何放行面——写门匹配只服务 create/update；
    /// `WriteAction` 无 Delete 变体（delete 根本不进规则匹配，daemon 直开弹窗）。
    #[test]
    fn delete_never_participates_in_rule_matching() {
        let r = write_rule("/proj", &["a.ini"], &["delete"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        // actions 含 delete + create：delete 部分无效果，create 照常
        let mixed = write_rule("/proj", &["a.ini"], &["create", "delete"]);
        assert!(write_rule_matches(
            &mixed,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// 跨命名空间：`wsl://` 规范形规则命中归一化后的 WSL cwd（与 inject/read
    /// 同一套 project_dir_matches，两侧同函数）。
    #[test]
    fn write_rule_matches_wsl_normalized_cwd() {
        let r = write_rule("wsl://Debian/home/u/p", &["a.ini"], &["create", "update"]);
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\sub");
        assert!(write_rule_matches(
            &r,
            &cwd,
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(write_rule_matches(
            &r,
            &cwd,
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert!(!write_rule_matches(
            &r,
            &cwd2,
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// 三能力两两不互授（双向）：write 不授权读/注入；read/inject 不授权写。
    #[test]
    fn write_capability_does_not_grant_read_or_inject() {
        let w = write_rule("/proj", &["A"], &["create", "update"]);
        // write 规则不命中注入 / 读路径
        assert!(!rule_matches(&w, "/proj", "npm publish"));
        assert!(!read_rule_matches(&w, "/proj", "A"));
        // read / inject 规则不命中写路径
        let rd = read_rule("/proj", &["A"]);
        assert!(!write_rule_matches(
            &rd,
            "/proj",
            WriteAction::Create,
            None,
            "A"
        ));
        assert!(!write_rule_matches(
            &rd,
            "/proj",
            WriteAction::Update,
            Some("A"),
            "A"
        ));
        let inj = rule("/proj", "*", &["A"]);
        assert!(!write_rule_matches(
            &inj,
            "/proj",
            WriteAction::Create,
            None,
            "A"
        ));
        // 带伪造 command 的 write 规则同样不得命中注入（capability 过滤在前）
        let mut rogue = w.clone();
        rogue.command = "npm *".into();
        assert!(!rule_matches(&rogue, "/proj", "npm publish"));
    }

    /// ApprovalKind 协议面序列化（serde camelCase 单词 → 小写）。
    #[test]
    fn approval_kind_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ApprovalKind::Inject).unwrap(),
            serde_json::json!("inject")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::Read).unwrap(),
            serde_json::json!("read")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::Export).unwrap(),
            serde_json::json!("export")
        );
        // 规则管理审批门（补充拍板 #22）：kind=rule，加性变更不升协议版本
        assert_eq!(
            serde_json::to_value(ApprovalKind::Rule).unwrap(),
            serde_json::json!("rule")
        );
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("rule")).unwrap();
        assert_eq!(back, ApprovalKind::Rule);
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("read")).unwrap();
        assert_eq!(back, ApprovalKind::Read);
    }

    /// 写入门审批 kind（补充拍板 #24，write-gate.md §6）：kind=write，
    /// serde 往返，加性变更不升协议版本。
    #[test]
    fn approval_kind_write_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ApprovalKind::Write).unwrap(),
            serde_json::json!("write")
        );
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("write")).unwrap();
        assert_eq!(back, ApprovalKind::Write);
    }

    /// WriteAction 协议面字符串（`authz.request` 帧的 `writeAction` 字段；
    /// #137 最小授权——前端「记住」按帧内 action 生成 `actions=[当前动作]`）。
    #[test]
    fn write_action_as_str_contract() {
        assert_eq!(WriteAction::Create.as_str(), "create");
        assert_eq!(WriteAction::Update.as_str(), "update");
    }

    /// ApprovalSubKind 协议面序列化（serde rename = RPC 方法名字符串；
    /// 常量单一来源 `crate::ipc::SUB_KIND_*`，TS 镜像 `APPROVAL_SUB_KINDS`）。
    #[test]
    fn approval_sub_kind_serde_contract() {
        for (v, s) in [
            (ApprovalSubKind::RuleAdd, crate::ipc::SUB_KIND_RULE_ADD),
            (
                ApprovalSubKind::RuleRemove,
                crate::ipc::SUB_KIND_RULE_REMOVE,
            ),
            (ApprovalSubKind::ItemPut, crate::ipc::SUB_KIND_ITEM_PUT),
            (
                ApprovalSubKind::ItemDelete,
                crate::ipc::SUB_KIND_ITEM_DELETE,
            ),
        ] {
            assert_eq!(v.as_str(), s);
            assert_eq!(serde_json::to_value(v).unwrap(), serde_json::json!(s));
            let back: ApprovalSubKind = serde_json::from_value(serde_json::json!(s)).unwrap();
            assert_eq!(back, v);
        }
    }

    // -- M2.98 规则程序指纹（补充拍板 #25）：未绑定匹配路径零变化回归 ---------

    /// 指纹不改变 **read/write** 匹配路径，且**未绑定（None）**的注入规则
    /// 保持与绑定前完全一致的整串 glob 语义——fingerprint=None = 现状语义
    /// （identity-binding.md §4「匹配函数行为零变化」）。绑定**注入**规则
    /// 的命令形态按 `command[0]` 可执行名匹配（issue #132，见
    /// [`fingerprint_bound_inject_rule_matches_command0`]）；本测试的注入分支
    /// 用 glob 形态 `"npm*"`（绑定按可执行名 `"npm"`、未绑定按整串
    /// `"npm publish"` 都命中），两端结果一致，钉住的是「未绑定路径不因指纹
    /// 存在与否而变化」。
    #[test]
    fn fingerprint_does_not_change_base_matcher_behavior() {
        use crate::model::ProgramFingerprint;

        // 注：read/write 分支的匹配结果与有无指纹无关，恒由 capability/cwd/keys
        // 决定；注入分支的差异面（绑定 → command[0] 可执行名）由
        // fingerprint_bound_inject_rule_matches_command0 单独钉住。
        let fp_some = Some(ProgramFingerprint {
            exe_path: "/usr/bin/node".into(),
            sha256: "a".repeat(64),
            size: 100,
        });

        // inject 规则（glob 形态 "npm*"：绑定按 command[0] 可执行名 "npm"、
        // 未绑定按整串 "npm publish"，两端都命中，钉「未绑定零变化」）
        let mut inj = rule("/proj", "npm*", &["A"]);
        let inj_unbound = rule("/proj", "npm*", &["A"]);
        inj.fingerprint = fp_some.clone();
        assert_eq!(
            rule_matches(&inj, "/proj/sub", "npm publish"),
            rule_matches(&inj_unbound, "/proj/sub", "npm publish"),
        );
        assert!(rule_matches(&inj_unbound, "/proj/sub", "npm publish"));

        // read 规则
        let mut rd = read_rule("/proj", &["A"]);
        let rd_unbound = read_rule("/proj", &["A"]);
        rd.fingerprint = fp_some.clone();
        assert_eq!(
            read_rule_matches(&rd, "/proj", "A"),
            read_rule_matches(&rd_unbound, "/proj", "A"),
        );
        assert!(read_rule_matches(&rd_unbound, "/proj", "A"));

        // write 规则（create）
        let mut wr = write_rule("/proj", &["a.ini"], &["create", "update"]);
        let wr_unbound = write_rule("/proj", &["a.ini"], &["create", "update"]);
        wr.fingerprint = fp_some;
        assert_eq!(
            write_rule_matches(&wr, "/proj", WriteAction::Create, None, "a.ini"),
            write_rule_matches(&wr_unbound, "/proj", WriteAction::Create, None, "a.ini"),
        );
        assert!(write_rule_matches(
            &wr_unbound,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// issue #132（bug 修复契约）：指纹绑定注入规则的命令形态按 `command[0]`
    /// 的**可执行名**（basename，去目录）与规则 command 做 glob 匹配。CLI 以
    /// exe basename 落库（`/usr/bin/npm` → `"npm"`，lk-cli `cmd_rule_add_inner`），
    /// 而注入请求 command 是**完整命令串**（`lk inject -- npm publish` → `"npm
    /// publish"`）——整串 glob 匹配必失配，绑定规则永不命中、指纹门不可达
    /// （identity-binding.md §2 目标 2：注入规则绑定 `command[0]` 的可执行文件）。
    /// 未绑定（None）规则维持整串 glob 语义（§4 零变化）。
    #[test]
    fn fingerprint_bound_inject_rule_matches_command0() {
        use crate::model::ProgramFingerprint;

        let fp = |exe: &str| {
            Some(ProgramFingerprint {
                exe_path: exe.into(),
                sha256: "a".repeat(64),
                size: 100,
            })
        };

        // 绑定规则：command = CLI 推导的可执行 basename（真实产品形态）
        let mut bound = rule("/proj", "npm", &["A"]);
        bound.fingerprint = fp("/usr/bin/npm");
        // 带参命令：整串 ≠ basename，但 command[0] 可执行名 = "npm" → 命中
        assert!(rule_matches(&bound, "/proj/sub", "npm publish"));
        assert!(rule_matches(&bound, "/proj", "npm"));
        // 绝对路径可执行 + 参数 → 仍按可执行名 basename 命中
        assert!(rule_matches(&bound, "/proj", "/usr/bin/npm publish"));
        // 不同可执行名 → 不命中（fail-closed：形式不成立，指纹门不介入）
        assert!(!rule_matches(&bound, "/proj", "npx foo"));
        assert!(!rule_matches(&bound, "/proj", "npm-publish"));

        // 绑定规则的 glob basename 形态（如按前缀命名再通配）
        let mut glob = rule("/proj", "npm*", &["A"]);
        glob.fingerprint = fp("/usr/bin/npm");
        assert!(rule_matches(&glob, "/proj", "npm publish"));

        // 未绑定（None）：整串 glob 语义零变化——basename 精确串不因加参命中
        let unbound = rule("/proj", "npm", &["A"]);
        assert!(rule_matches(&unbound, "/proj", "npm"));
        assert!(!rule_matches(&unbound, "/proj", "npm publish"));
        assert!(!rule_matches(&unbound, "/proj", "/usr/bin/npm publish"));
    }

    /// 绑定规则命令的 **stem 等价**（issue #133）：CLI 落库 basename 带
    /// Windows 可执行后缀（`--fingerprint C:\bin\npm.cmd` → command
    /// `"npm.cmd"`），而注入请求 command[0] 无扩展名（`npm publish` →
    /// `"npm"`）——两者是同一可执行文件的两种拼写，须都命中绑定规则；
    /// 带扩展名键入（`npm.cmd`）亦须命中；无后缀规则（`pgm`）语义零变化。
    #[test]
    fn fingerprint_bound_rule_stem_matches_windows_extensions() {
        use crate::model::ProgramFingerprint;

        let fp = || {
            Some(ProgramFingerprint {
                exe_path: "C:\\bin\\npm.cmd".into(),
                sha256: "a".repeat(64),
                size: 100,
            })
        };

        // CLI 落库形态：--fingerprint ...\npm.cmd → command = "npm.cmd"
        let mut bound = rule("/proj", "npm.cmd", &["A"]);
        bound.fingerprint = fp();
        // Windows 用户实际输入无扩展名 → 命中（issue #133 主线）
        assert!(rule_matches(&bound, "/proj", "npm publish"));
        assert!(rule_matches(&bound, "/proj", "npm"));
        // 带扩展名键入 → 同样命中（与解析层 PATHEXT 探测同向）
        assert!(rule_matches(&bound, "/proj", "npm.cmd publish"));
        // 不同可执行名 / 同名前缀 → 不命中（fail-closed）
        assert!(!rule_matches(&bound, "/proj", "yarn publish"));
        assert!(!rule_matches(&bound, "/proj", "npm-publish"));

        // --fingerprint ...\fptool.exe → command = "fptool.exe"
        let mut b2 = rule("/proj", "fptool.exe", &["A"]);
        b2.fingerprint = fp();
        assert!(rule_matches(&b2, "/proj", "fptool /user"));
        assert!(rule_matches(&b2, "/proj", "fptool.exe /user"));

        // 无后缀规则（Linux /usr/bin/npm 形态）：stem 等价不引入新语义
        let mut b3 = rule("/proj", "pgm", &["A"]);
        b3.fingerprint = fp();
        assert!(rule_matches(&b3, "/proj", "pgm deploy"));
        assert!(!rule_matches(&b3, "/proj", "pgm2 deploy"));
        // 镜像对称：规则 "pgm"（无后缀）↔ 键入 "pgm.cmd"——stem 等价同样命中；
        // 形式层只负责「收集候选规则」，安全落在解析+指纹门（解析到不同文件
        // 或不可解析 → 审批 fail-closed，见 issue #133 集成断言）
        assert!(rule_matches(&b3, "/proj", "pgm.cmd deploy"));
    }

    /// 绑定规则与未绑定规则占据同一片授权空间，指纹门不改变未命中语义：
    /// 匹配器继续负责 capability/cwd/keys，未绑定的始终未命中时与现状一致。
    #[test]
    fn unbound_rule_matchers_unchanged_for_miss_cases() {
        // read 规则未命中 cases（现状语义原样）
        let rd = read_rule("/proj", &["A"]);
        assert!(!read_rule_matches(&rd, "/proj", "B"));
        assert!(!read_rule_matches(&rd, "/other", "A"));
        // inject 未命中：cwd 不匹配 / command glob 不匹配
        let inj = rule("/proj", "npm *", &["A"]);
        assert!(!rule_matches(&inj, "/other", "npm publish"));
        assert!(!rule_matches(&inj, "/proj", "yarn publish"));
    }
}
