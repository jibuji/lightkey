//! 审计锚点（issue #75：截断可证明 / truncation is provable）。
//!
//! 审计日志是本地 0600 追加式文件，本身没有**文件外可信锚点**——同用户
//! 攻击者可截尾抹掉近期事件、或删掉整个文件让守护进程重建空链，截断后的
//! 链仍能通过「第一条到最后一条」的 HMAC 校验。设计取向：同用户总能写
//! 数据目录，目标是**截断可证明**（chain 比锚点短 → 报截断），不是截断可预防。
//!
//! 锚点语义：在**密钥轮换 / 锁定 / 解锁 / 守护进程干净关闭**（及后台异步
//! flush）时，把链的「最后一条事件 HMAC + ordinal」持久化到平台安全存储
//! （Windows Credential Manager / macOS Keychain / Linux secret-service、
//! kutils 等，经 [`keyring`] 抽象——由 lk-daemon 提供实现）。本模块**不依赖
//! keyring**，只定义抽象与降级侧写；平台 store 由上层注入。
//!
//! - 降级原则（接受标准）：平台 keychain 不可用 → **fail-open**，给出明确
//!   「锚点不可用、防篡改能力减弱」警告，降级到签名独立的侧写文件（比没有强，
//!   但文档标注更弱），**绝不阻断 vault 解锁**。
//! - 锚点写入**非阻塞**：不在热路径（同步触发、密钥轮换、审批）上同步阻塞；
//!   后台异步 flush + 低频点（轮换/锁定/解锁/干净关闭）同步写可接受。
//! - anchor 写入**无需 K_audit**：锚点值只含链尾 ordinal 与最后一条事件的
//!   `hmac`（均从日志文件直接读取），因此锁定态/未解锁态也能写锚点。
//!
//! 校验语义（[`check_anchor`]）：锚点代表「可信的链延伸上界」。链与锚点
//! 逐一对比：
//!
//! - 链 `ordinal <` 锚点 `ordinal` → **截断（tail 被抹）**，definite；
//! - 链与锚点 ordinal 相等但 last_hmac 不同 → **锚定事件被换/伪造**；
//! - 锚点缺失（平台与侧写都没有）→ 既可能是从未建立（新库）也可能是被
//!   删光，按截断证明语义报「锚点缺失」；
//! - 链 `ordinal >` 锚点 `ordinal` → 锚点落后于链尾（锚点后追加的事件），
//!   不是截断；HMAC 链自身已校验，报「锚点未覆盖尾部 N 条」弱提示。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 审计锚点（平台安全存储 / 降级侧写共用的值）。
///
/// - `ordinal`：锚点建立时链的事件总数（等价于最后一条事件的从 1 起的序号）。
/// - `last_hmac`：锚点建立时最后一条事件的 `hmac`（base64；`ordinal == 0`
///   时空串）。取值直接来自日志文件，无需 K_audit。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorValue {
    pub ordinal: u64,
    #[serde(default)]
    pub last_hmac: String,
}

/// 锚点存储错误：区分「平台不可用（可降级 / fail-open）」与「存储层 I/O」。
#[derive(Debug, Clone)]
pub enum AuditAnchorError {
    /// 平台安全存储不可用（无可访问的 secret-service / keyutils / 未配置）。
    Unavailable(String),
    /// store 本身可达但持久化失败。
    Io(String),
}

impl std::fmt::Display for AuditAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAnchorError::Unavailable(m) => write!(f, "平台安全存储不可用：{m}"),
            AuditAnchorError::Io(m) => write!(f, "锚点持久化失败：{m}"),
        }
    }
}

impl std::error::Error for AuditAnchorError {}

/// 锚点存储抽象。平台实现由上层（lk-daemon）用 [`keyring`] 注入；本模块只
/// 提供降级侧写与测试用 fake。`read` 返回 `Ok(None)` = store 可达但没有锚点；
/// `Err(Unavailable)` = store 本身不可用（触发 fail-open 降级）。
pub trait AuditAnchorStore: Send + Sync {
    /// 人类可读的名称（诊断 / `vault.status` 文案用）。
    fn name(&self) -> &'static str;

    /// 读取锚点。`Ok(None)` = 可达但无锚点；`Err(_)` = 不可用 / 读失败。
    fn read(&self) -> std::result::Result<Option<AuditAnchorValue>, AuditAnchorError>;

    /// 覆盖写入锚点（幂等：同值再写无副作用）。
    fn write(&self, value: &AuditAnchorValue) -> std::result::Result<(), AuditAnchorError>;
}

/// 锚点校验结果（纯函数，无 K_audit 依赖，可独立单测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorCheck {
    /// 锚点覆盖当前链尾（`ordinal == 锚点 ordinal` 且 last_hmac 一致）。
    Ok,
    /// 锚点落后于链尾 N 条（不是截断；HMAC 链仍自洽，但锚点未覆盖更早/更晚尾部）。
    /// 携带落后的条数。
    AnchorBehind(u64),
    /// **截断**：链比可信锚点短（`链 ordinal < 锚点 ordinal`）。
    Truncated {
        chain_ordinal: u64,
        anchor_ordinal: u64,
    },
    /// 链与锚点 ordinal 相同但 last_hmac 不一致 → 锚定事件被替换/伪造。
    TamperedAnchoredEvent { chain_ordinal: u64 },
    /// 锚点缺失（平台与侧写都没有锚点）。
    AnchorMissing,
}

/// 把给定链（ordinal + last_hmac）与锚点交叉核对。锚点 `None` = 缺失。
pub fn check_anchor(
    chain_ordinal: u64,
    last_hmac: &str,
    anchor: Option<&AuditAnchorValue>,
) -> AnchorCheck {
    let Some(anchor) = anchor else {
        return AnchorCheck::AnchorMissing;
    };
    if chain_ordinal < anchor.ordinal {
        return AnchorCheck::Truncated {
            chain_ordinal,
            anchor_ordinal: anchor.ordinal,
        };
    }
    if chain_ordinal > anchor.ordinal {
        return AnchorCheck::AnchorBehind(chain_ordinal - anchor.ordinal);
    }
    // ordinal 相等：锚定的最后一条事件必须与链尾一致
    if anchor.last_hmac.is_empty() {
        // ordinal>0 但 last_hmac 缺失 = 损坏的锚点，视作未锚定 → 缺失
        return AnchorCheck::AnchorMissing;
    }
    if anchor.last_hmac == last_hmac {
        AnchorCheck::Ok
    } else {
        AnchorCheck::TamperedAnchoredEvent { chain_ordinal }
    }
}

/// 降级侧写文件路径名（用户数据目录）。
pub const AUDIT_ANCHOR_SIDECAR: &str = "audit.anchor";

/// 文件侧写锚点（0600，原子写）。作为平台 keychain 不可用时的**降级**锚点
/// ——比没有强（可证明「链被整体重写/截尾到某条数」，且 blast radius 收窄），
/// 但同用户可改写文件本身，属最弱档（文档标注）。
#[derive(Debug, Clone)]
pub struct FileAnchorSidecar {
    path: PathBuf,
}

impl FileAnchorSidecar {
    /// 在用户数据目录下打开/创建侧写锚点。
    pub fn new(dir: &Path) -> FileAnchorSidecar {
        FileAnchorSidecar {
            path: dir.join(AUDIT_ANCHOR_SIDECAR),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditAnchorStore for FileAnchorSidecar {
    fn name(&self) -> &'static str {
        "file-sidecar (degraded)"
    }

    fn read(&self) -> std::result::Result<Option<AuditAnchorValue>, AuditAnchorError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AuditAnchorError::Io(e.to_string())),
        };
        match serde_json::from_slice::<AuditAnchorValue>(&bytes) {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(AuditAnchorError::Io(format!("侧写锚点格式损坏：{e}"))),
        }
    }

    fn write(&self, value: &AuditAnchorValue) -> std::result::Result<(), AuditAnchorError> {
        let bytes = match serde_json::to_vec(value) {
            Ok(b) => b,
            Err(e) => return Err(AuditAnchorError::Io(e.to_string())),
        };
        let tmp = self.path.with_extension("tmp");
        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
        {
            Ok(mut f) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                }
                if let Err(e) = f.write_all(&bytes).and_then(|_| f.sync_all()) {
                    return Err(AuditAnchorError::Io(e.to_string()));
                }
            }
            Err(e) => return Err(AuditAnchorError::Io(e.to_string())),
        }
        fs::rename(&tmp, &self.path).map_err(|e| AuditAnchorError::Io(e.to_string()))
    }
}

/// 组合锚点：平台安全存储（+ 降级侧写）。写入时优先平台；平台不可用 →
/// fail-open 降级到侧写并暴露「degraded」状态（调用方可据此告警，但不阻断
/// 解锁）。`read` 优先平台，其次侧写。
///
/// `platform` 为 `Err`（某次写入探测）或 `None`（从未配置平台）时走侧写。
/// degraded 状态用原子位跟踪（跨线程：守卫进程命令线程 / 后台 flush 线程）。
pub struct CompositeAuditAnchor {
    /// 平台 store（lk-daemon 注入 `keyring` 实现）；`None` = 未配置平台。
    platform: Option<Box<dyn AuditAnchorStore>>,
    sidecar: FileAnchorSidecar,
    /// 最近一次写入命中的档位：false = 平台，true = 已降级到侧写。
    degraded: std::sync::atomic::AtomicBool,
    /// 最近一次读取是否找到锚点。
    anchored: std::sync::atomic::AtomicBool,
}

impl CompositeAuditAnchor {
    /// 平台可以为 `None`（测试 / 未配置时纯侧写）。`sidecar` 恒存在（降级兜底）。
    pub fn new(
        platform: Option<Box<dyn AuditAnchorStore>>,
        sidecar: FileAnchorSidecar,
    ) -> CompositeAuditAnchor {
        CompositeAuditAnchor {
            platform,
            sidecar,
            degraded: std::sync::atomic::AtomicBool::new(false),
            anchored: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// 组合读取：优先平台；平台不可用/无锚点 → 侧写。返回 (值, 是否降级)。
    pub fn load(&self) -> std::result::Result<Option<AuditAnchorValue>, AuditAnchorError> {
        if let Some(platform) = &self.platform {
            match platform.read() {
                Ok(Some(v)) => {
                    self.degraded
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    self.anchored
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(Some(v));
                }
                Ok(None) => {
                    // 平台可达但无锚点 → 试侧写
                }
                Err(_) => {
                    self.degraded
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let v = self.sidecar.read()?;
        if v.is_some() {
            self.anchored
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(v)
    }

    /// 组合写入：优先平台；平台不可用 → 侧写（fail-open），标记 degraded。
    /// 返回 `degraded`（true = 落到侧写，防篡改能力减弱）。
    pub fn store(&self, value: &AuditAnchorValue) -> std::result::Result<bool, AuditAnchorError> {
        if let Some(platform) = &self.platform {
            match platform.write(value) {
                Ok(()) => {
                    self.degraded
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    self.anchored
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(false); // 平台命中
                }
                Err(e) => {
                    self.degraded
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = &e; // 平台不可用：fail-open 走侧写
                }
            }
        }
        self.sidecar.write(value)?;
        self.anchored
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(true) // 降级
    }

    /// 当前是否降级到侧写（平台不可用）。
    pub fn degraded(&self) -> bool {
        self.degraded.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 是否已建立过锚点（平台或侧写任一 reads 命中过）。
    pub fn anchored(&self) -> bool {
        self.anchored.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 平台 store 是否存在（诊断用）。
    pub fn has_platform(&self) -> bool {
        self.platform.is_some()
    }
}

/// 从当前链（事件列表）派生锚点值。
pub fn anchor_from_chain(events: &[crate::audit::AuditEvent]) -> AuditAnchorValue {
    let ordinal = events.len() as u64;
    let last_hmac = events.last().map(|e| e.hmac.clone()).unwrap_or_default();
    AuditAnchorValue { ordinal, last_hmac }
}

/// 内存 fake 锚点（单测：fake log + fake anchor 不匹配场景）。
#[derive(Debug, Default)]
pub struct FakeAnchorStore(pub std::sync::Mutex<Option<AuditAnchorValue>>);

impl FakeAnchorStore {
    pub fn new() -> FakeAnchorStore {
        FakeAnchorStore(std::sync::Mutex::new(None))
    }
    /// 直接设置锚点（模拟「平台已建立锚点 N」）。
    pub fn set(&self, v: AuditAnchorValue) {
        *self.0.lock().unwrap() = Some(v);
    }
}

impl AuditAnchorStore for FakeAnchorStore {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn read(&self) -> std::result::Result<Option<AuditAnchorValue>, AuditAnchorError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn write(&self, value: &AuditAnchorValue) -> std::result::Result<(), AuditAnchorError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
}

/// 永不成功写/读的平台 store（模拟 keychain 不可用 → 触发 fail-open 降级）。
#[derive(Debug, Default)]
pub struct UnavailablePlatformStore(pub String);

impl AuditAnchorStore for UnavailablePlatformStore {
    fn name(&self) -> &'static str {
        "unavailable-platform"
    }
    fn read(&self) -> std::result::Result<Option<AuditAnchorValue>, AuditAnchorError> {
        Err(AuditAnchorError::Unavailable(self.0.clone()))
    }
    fn write(&self, _: &AuditAnchorValue) -> std::result::Result<(), AuditAnchorError> {
        Err(AuditAnchorError::Unavailable(self.0.clone()))
    }
}

/// 便捷：构造一个组合锚点 = 仅侧写写路径（成功 / 降级）。
pub fn sidecar_only(dir: &Path) -> CompositeAuditAnchor {
    CompositeAuditAnchor::new(None, FileAnchorSidecar::new(dir))
}

/// 便捷：注入 fake 平台的组合锚点（核心测试）。
pub fn fake_composite(dir: &Path, fake: FakeAnchorStore) -> CompositeAuditAnchor {
    CompositeAuditAnchor::new(Some(Box::new(fake)), FileAnchorSidecar::new(dir))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditResult, EventInput};
    use crate::crypto::test_kdf_params;

    /// 构造 N 条事件并返回链（fake log 用：直接用 `AuditLog::append`，但锚点
    /// 校验只需要链尾 ordinal/hmac，这里用真实 HMAC 链保证语义一致）。
    fn chain_with(n: usize) -> (tempfile::TempDir, Vec<AuditEvent>, crate::audit::AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = crate::audit::AuditLog::open(dir.path()).unwrap();
        let keys = test_kdf_params()
            .derive_master_key("pw")
            .unwrap()
            .derive_keys();
        let mut events = Vec::new();
        for i in 0..n {
            let cmd = format!("op{i}");
            let e = log
                .append(&keys, &EventInput::new("lk", &cmd, AuditResult::Allowed))
                .unwrap();
            events.push(e);
        }
        (dir, events, log)
    }

    fn anchor(events: &[AuditEvent]) -> AuditAnchorValue {
        anchor_from_chain(events)
    }

    #[test]
    fn check_anchor_ok_when_chain_matches() {
        let (_d, events, _log) = chain_with(3);
        let a = anchor(&events);
        assert_eq!(check_anchor(3, &events[2].hmac, Some(&a)), AnchorCheck::Ok);
    }

    #[test]
    fn truncation_detected_when_tail_trimmed() {
        let (_d, events, _log) = chain_with(6);
        // 锚点建立在 6 条时；攻击者删掉尾部 3 条 → 链只剩 3 条
        let a = anchor(&events);
        assert_eq!(
            check_anchor(3, &events[2].hmac, Some(&a)),
            AnchorCheck::Truncated {
                chain_ordinal: 3,
                anchor_ordinal: 6,
            }
        );
    }

    #[test]
    fn tampered_anchor_event_detected_when_same_ordinal_diff_hmac() {
        let (_d, events, _log) = chain_with(4);
        let a = anchor(&events);
        // 同 ordinal 4 但 last_hmac 换成伪造值
        let mut forged = a.clone();
        forged.last_hmac = format!("forge{}", forged.last_hmac);
        assert_eq!(
            check_anchor(4, &events[3].hmac, Some(&forged)),
            AnchorCheck::TamperedAnchoredEvent { chain_ordinal: 4 }
        );
    }

    #[test]
    fn anchor_missing_reported() {
        let (_d, events, _log) = chain_with(2);
        assert_eq!(
            check_anchor(2, &events[1].hmac, None),
            AnchorCheck::AnchorMissing
        );
    }

    #[test]
    fn anchor_behind_chain_is_not_truncation() {
        let (_d, events, _log) = chain_with(5);
        // 锚点建于 3 条时，之后又追加 2 条
        let a = anchor(&events[..3]);
        assert_eq!(
            check_anchor(5, &events[4].hmac, Some(&a)),
            AnchorCheck::AnchorBehind(2)
        );
    }

    #[test]
    fn sidecar_roundtrip_0600() {
        let dir = tempfile::tempdir().unwrap();
        let sc = FileAnchorSidecar::new(dir.path());
        let v = AuditAnchorValue {
            ordinal: 7,
            last_hmac: "abc".to_string(),
        };
        sc.write(&v).unwrap();
        assert_eq!(sc.read().unwrap(), Some(v.clone()));
        let v2 = AuditAnchorValue {
            ordinal: 8,
            last_hmac: "def".to_string(),
        };
        sc.write(&v2).unwrap();
        assert_eq!(sc.read().unwrap(), Some(v2));
    }

    #[test]
    fn composite_fails_open_to_sidecar_when_platform_down() {
        let dir = tempfile::tempdir().unwrap();
        let platform = UnavailablePlatformStore("no keyring in test".to_string());
        let comp =
            CompositeAuditAnchor::new(Some(Box::new(platform)), FileAnchorSidecar::new(dir.path()));
        let v = AuditAnchorValue {
            ordinal: 2,
            last_hmac: "x".to_string(),
        };
        // 平台不可用 → 落到侧写（fail-open），返回 degraded=true
        assert!(comp.store(&v).unwrap());
        assert!(comp.degraded());
        // fake log + fake anchor 不匹配场景：侧写里读到锚点，可通过组合读取
        assert_eq!(comp.load().unwrap(), Some(v));
    }

    #[test]
    fn composite_hits_platform_when_available() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeAnchorStore::new();
        let comp = fake_composite(dir.path(), fake);
        let v = AuditAnchorValue {
            ordinal: 1,
            last_hmac: "h".to_string(),
        };
        assert!(!comp.store(&v).unwrap()); // 平台命中
        assert!(!comp.degraded());
        assert_eq!(comp.load().unwrap(), Some(v));
    }

    #[test]
    fn fake_anchor_and_log_mismatch_verify_fails() {
        // 集成语义：fake log（6 条）+ 锚点建立在 6 条 → 截尾 3 条 → check 报截断
        let (_d, events, _log) = chain_with(6);
        // 攻击者截掉尾部 3 条（events 只剩前 3 条是链里余下的）
        let surviving = &events[..3];
        let a = anchor(&events);
        let res = check_anchor(
            surviving.len() as u64,
            &surviving.last().unwrap().hmac,
            Some(&a),
        );
        assert!(matches!(res, AnchorCheck::Truncated { .. }));
    }
}
