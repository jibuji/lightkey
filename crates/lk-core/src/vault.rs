//! 落盘存储层与生命周期编排（规格：`docs/data-model.md`、`docs/recovery.md`）。
//!
//! - 布局：`vault.json`（头）· `index.lk`（加密索引）· `{uuid}.item.lk`（条目）
//!   · `{uuid}.tomb.lk`（墓碑）· `{uuid}.attach.lk` + `{uuid}.{i}.chunk.lk`
//!   （附件）· `recovery.envelope`（恢复信封）。
//! - 条目 CRUD、乐观并发 CAS（base revision == 当前 revision）、软删除墓碑
//!   （30 天延迟硬删）、加密索引（损坏 → 全量重建）、附件分块（1 MiB，
//!   每附件独立 K_attach）。
//! - 生命周期编排：`init_vault`（建库 + 恢复码/信封）、`unlock`、
//!   `recover_vault`（恢复码 + 新主密码：重派生 → 重加密 → 审计密钥轮换链 →
//!   新信封）。
//! - 时间戳统一 ISO-8601 UTC；写入原子（tmp + rename）；文件 0600。

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::audit::{AuditLog, AuditResult, EventInput};
use crate::bus::{EventBus, VaultEvent};
use crate::crypto::{
    self, bump_iso, now_iso, open, parse_iso, random_array, random_uuid, seal, KdfCost, KdfParams,
    Keys, SealType, VaultHeader,
};
use crate::model::{
    AttachmentBundle, AttachmentMeta, IndexEntry, Item, ItemDraft, ItemKind, ItemSummary,
    ObjectKind, Rule, RuleDraft, Tombstone, CHUNK_BYTES, MAX_FILE_BYTES, TOMBSTONE_GRACE,
};
use crate::recovery::{RecoveryCode, RecoveryEnvelope};
use crate::{Error, Result};

/// vault 头文件名。
pub const VAULT_HEADER_FILE: &str = "vault.json";
/// 加密索引文件名。
pub const INDEX_FILE: &str = "index.lk";
/// 恢复信封文件名。
pub const ENVELOPE_FILE: &str = "recovery.envelope";

/// 主密码最小长度（建库/恢复设置新主密码时校验；与原型设计一致：至少 8 位）。
pub const MIN_MASTER_PASSWORD_LEN: usize = 8;

/// 主密码校验：不满足最小长度 → [`Error::WeakPassword`]。
/// 所有「设置新主密码」的入口（建库/恢复）必须先行调用（安全核心留 Rust）。
pub fn validate_master_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LEN {
        return Err(Error::WeakPassword);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 文件路径
// ---------------------------------------------------------------------------

fn item_file(dir: &Path, id: uuid::Uuid) -> PathBuf {
    dir.join(format!("{id}.item.lk"))
}
fn rule_file(dir: &Path, id: uuid::Uuid) -> PathBuf {
    dir.join(format!("{id}.rule.lk"))
}
fn tomb_file(dir: &Path, id: uuid::Uuid) -> PathBuf {
    dir.join(format!("{id}.tomb.lk"))
}
fn attach_meta_file(dir: &Path, attach_id: uuid::Uuid) -> PathBuf {
    dir.join(format!("{attach_id}.attach.lk"))
}
fn chunk_file(dir: &Path, attach_id: uuid::Uuid, i: u32) -> PathBuf {
    dir.join(format!("{attach_id}.{i}.chunk.lk"))
}
fn header_file(dir: &Path) -> PathBuf {
    dir.join(VAULT_HEADER_FILE)
}
fn index_file(dir: &Path) -> PathBuf {
    dir.join(INDEX_FILE)
}
fn envelope_file(dir: &Path) -> PathBuf {
    dir.join(ENVELOPE_FILE)
}

/// 原子写入：tmp + rename（目录 0700 / 文件 0600 由调用方保证）。
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", hex::encode(random_array::<4>())));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// 确保目录存在（unix 0700）。
fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 头部 / 存在性
// ---------------------------------------------------------------------------

pub fn vault_exists(dir: &Path) -> bool {
    header_file(dir).exists()
}

pub fn load_header(dir: &Path) -> Result<VaultHeader> {
    let bytes = fs::read(header_file(dir)).map_err(|_| Error::NotInitialized)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// 建库（`lk init`）：主密码 → MK；生成恢复码（仅展示一次）与恢复信封。
///
/// `reset=true` 时先清空旧 vault 数据（旧数据不可解，调用方须明示）。
/// 返回恢复码与 keys 引用无关的头部信息；审计事件由调用方传入的日志追加。
pub fn init_vault(
    dir: &Path,
    password: &str,
    reset: bool,
    audit: &mut AuditLog,
) -> Result<(VaultHeader, RecoveryCode)> {
    init_vault_with_params(dir, password, reset, audit, &crypto::default_kdf_params())
}

/// 建库（`lk init`），KDF 参数可注入（生产用 [`init_vault`]；测试注入低代价参数）。
pub fn init_vault_with_params(
    dir: &Path,
    password: &str,
    reset: bool,
    audit: &mut AuditLog,
    params: &KdfParams,
) -> Result<(VaultHeader, RecoveryCode)> {
    // 主密码策略校验先于一切（含已存在判定；弱密码/已存在库统一由上层拒
    // 绝，防探测不区分——ipc.md §3 语义在 UI 的体现）
    validate_master_password(password)?;
    if vault_exists(dir) {
        if !reset {
            return Err(Error::VaultExists);
        }
        wipe_vault_files(dir)?;
    }
    ensure_dir(dir)?;

    let mk = params.derive_master_key(password)?;
    let keys = mk.derive_keys();

    // 恢复信封：信封内独立随机 salt（m/t/p 同主 KDF，可演进）
    let code = RecoveryCode::generate();
    let mut envelope_kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        m: params.m,
        t: params.t,
        p: params.p,
        salt: random_array(),
    };
    envelope_kdf.salt = random_array();
    let envelope = RecoveryEnvelope::build(&code, &mk, envelope_kdf, KdfCost::from(params))?;
    write_atomic(&envelope_file(dir), &envelope.to_bytes()?)?;

    let header = VaultHeader::new(params.clone(), keys.k_data.as_ref());
    write_atomic(&header_file(dir), &serde_json::to_vec(&header)?)?;

    // 空索引
    let empty: Vec<IndexEntry> = Vec::new();
    let sealed_index = seal(
        keys.k_data.as_ref(),
        SealType::Index,
        INDEX_FILE,
        &serde_json::to_vec(&empty)?,
    );
    write_atomic(&index_file(dir), &sealed_index)?;

    audit.append(
        &keys,
        &EventInput::new("lk", "vault.init", AuditResult::Allowed),
    )?;

    Ok((header, code))
}

/// 重置：删除全部 vault 数据文件（保留 audit.log 与 config.json）。
fn wipe_vault_files(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_vault_file = name == VAULT_HEADER_FILE
            || name == INDEX_FILE
            || name == ENVELOPE_FILE
            || name.ends_with(".item.lk")
            || name.ends_with(".rule.lk")
            || name.ends_with(".tomb.lk")
            || name.ends_with(".attach.lk")
            || name.ends_with(".chunk.lk");
        if is_vault_file {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 解锁态 vault
// ---------------------------------------------------------------------------

/// 解锁态 vault：密钥 + 内存索引缓存（锁定即整体丢弃，密钥经 Zeroizing 擦除）。
///
/// A 层 **vault-store** 插件边界（`docs/plugin-architecture.md` §3.1）：
/// 条目/索引/墓碑/附件 CRUD、CAS、30 天延迟硬删；可挂事件总线，
/// 写操作成功后广播 `item.changed`（fire-and-forget；未挂总线 = 零行为差异）。
pub struct UnlockedVault {
    dir: PathBuf,
    keys: Keys,
    index: HashMap<uuid::Uuid, IndexEntry>,
    /// 本会话已签发的最大 revision（保证严格递增）。
    last_revision: Option<String>,
    /// 事件总线（C 层宿主装配；缺省 = 不广播）。
    bus: Option<Arc<EventBus>>,
}

impl UnlockedVault {
    /// 解锁：主密码 → MK → K_data/K_audit；加载加密索引（缺失/损坏 → 全量重建）。
    ///
    /// 密钥正确性验证：若索引为空但存在条目密文（全部无法解密），判定
    /// 密钥错误（统一 [`Error::Decrypt`]）——避免「错误密码解锁出空库」。
    pub fn unlock(dir: &Path, password: &str) -> Result<UnlockedVault> {
        let header = load_header(dir)?;
        let mk = header.kdf.derive_master_key(password)?;
        let keys = mk.derive_keys();
        // 密钥校验值（KCV）：主密码正确性验证（空库也有效，防「错误密码解锁出空库」）
        let kcv_ok = header.key_check.is_some() && header.verify_key(keys.k_data.as_ref());
        if !kcv_ok {
            return Err(Error::Decrypt);
        }
        let index = Self::load_index(dir, &keys)?;
        let last_revision = index
            .values()
            .map(|e| e.revision.clone())
            .max()
            .or_else(|| {
                fs::read_dir(dir).ok().and_then(|it| {
                    it.filter_map(|e| e.ok())
                        .filter(|e| e.file_name().to_string_lossy().ends_with(".tomb.lk"))
                        .filter_map(|e| {
                            Self::read_tomb(dir, &keys, &e.file_name().to_string_lossy()).ok()
                        })
                        .map(|t| t.revision)
                        .max()
                })
            });
        Ok(UnlockedVault {
            dir: dir.to_path_buf(),
            keys,
            index,
            last_revision,
            bus: None,
        })
    }

    /// 挂载事件总线（C 层宿主在解锁后装配；`item.changed` 广播）。
    pub fn attach_bus(&mut self, bus: Arc<EventBus>) {
        self.bus = Some(bus);
    }

    /// `item.changed` 观察广播（fire-and-forget；订阅者须非阻塞，见 [`EventBus`]）。
    fn emit_item_changed(&self, item: &Item, deleted: bool) {
        if let Some(bus) = &self.bus {
            bus.emit(&VaultEvent::ItemChanged {
                item_id: item.id(),
                revision_date: item.revision().to_string(),
                kind: item.kind().as_str().to_string(),
                deleted,
            });
        }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    // -- 同步引擎接口（M1；密文 blob 原样导入/导出，revision 不 bump）-----
    // 只读方法（`pub`）供守护进程的 [`VaultRead`](crate::sync::VaultRead) 视图
    // 按需短锁读取；写入方法仅供同步引擎在应用阶段（守护进程持写锁）调用。

    /// 索引快照（同步引擎对比用；含 kind=Rule 的透传条目）。
    pub fn index_snapshot(&self) -> Vec<IndexEntry> {
        let mut v: Vec<IndexEntry> = self.index.values().cloned().collect();
        v.sort_by_key(|e| e.id);
        v
    }

    /// 条目密文原文（同步上传用，不重加密）。
    pub fn item_blob(&self, id: uuid::Uuid) -> Result<Vec<u8>> {
        let path = item_file(&self.dir, id);
        std::fs::read(&path).map_err(|_| Error::ItemNotFound(id))
    }

    /// 规则密文原文（同步上传用，不重加密）。
    pub fn rule_blob(&self, id: uuid::Uuid) -> Result<Vec<u8>> {
        let path = rule_file(&self.dir, id);
        std::fs::read(&path).map_err(|_| Error::ItemNotFound(id))
    }

    /// 墓碑密文原文（可能不存在——远端墓碑缺失时由引擎合成）。
    pub fn tomb_blob(&self, id: uuid::Uuid) -> Result<Vec<u8>> {
        let path = tomb_file(&self.dir, id);
        std::fs::read(&path).map_err(|_| Error::ItemNotFound(id))
    }

    /// 附件元数据密文原文。
    pub fn attach_meta_blob(&self, attach_id: uuid::Uuid) -> Result<Vec<u8>> {
        let path = attach_meta_file(&self.dir, attach_id);
        std::fs::read(&path).map_err(|_| Error::ItemNotFound(attach_id))
    }

    /// 附件分块密文原文。
    pub fn chunk_blob(&self, attach_id: uuid::Uuid, i: u32) -> Result<Vec<u8>> {
        let path = chunk_file(&self.dir, attach_id, i);
        std::fs::read(&path).map_err(|_| Error::ItemNotFound(attach_id))
    }

    /// 拉取条目落盘：**原样写远程密文 blob**（不重加密）+ 更新内存索引。
    /// revision 不 bump；`last_revision` 提升到导入值（本地后续写入保持严格递增）。
    pub(crate) fn import_item(&mut self, blob: &[u8], item: &Item) -> Result<()> {
        let id = item.id();
        write_atomic(&item_file(&self.dir, id), blob)?;
        self.index.insert(
            id,
            IndexEntry {
                id,
                revision: item.revision().to_string(),
                kind: ObjectKind::Item,
                deleted: item.deleted(),
            },
        );
        if let Some(last) = &self.last_revision {
            if item.revision() > last.as_str() {
                self.last_revision = Some(item.revision().to_string());
            }
        } else {
            self.last_revision = Some(item.revision().to_string());
        }
        // 立即持久化索引：守护进程重启后从磁盘解锁，索引必须反映导入
        // （否则重启后拉取条目不可见，直到下一次同步——S1 同款语义）
        self.save_index()
    }

    /// 拉取规则落盘（原样密文；revision/deleted 以远端索引为准——规则体无
    /// revision 字段，修订号只在索引内）。
    pub(crate) fn import_rule(
        &mut self,
        blob: &[u8],
        rule: &Rule,
        revision: &str,
        deleted: bool,
    ) -> Result<()> {
        let id = rule.id;
        write_atomic(&rule_file(&self.dir, id), blob)?;
        self.index.insert(
            id,
            IndexEntry {
                id,
                revision: revision.to_string(),
                kind: ObjectKind::Rule,
                deleted,
            },
        );
        if let Some(last) = &self.last_revision {
            if revision > last.as_str() {
                self.last_revision = Some(revision.to_string());
            }
        } else {
            self.last_revision = Some(revision.to_string());
        }
        self.save_index()
    }

    /// 拉取墓碑落盘（原样密文）。
    pub(crate) fn import_tomb(&self, blob: &[u8], tomb: &Tombstone) -> Result<()> {
        write_atomic(&tomb_file(&self.dir, tomb.id), blob)
    }

    /// 拉取附件落盘（元数据 + 全部分块，原样密文）。
    pub(crate) fn import_attachment(
        &self,
        meta_blob: &[u8],
        meta: &AttachmentMeta,
        chunks: &[(u32, Vec<u8>)],
    ) -> Result<()> {
        write_atomic(&attach_meta_file(&self.dir, meta.id), meta_blob)?;
        for (i, blob) in chunks {
            write_atomic(&chunk_file(&self.dir, meta.id, *i), blob)?;
        }
        Ok(())
    }

    /// 硬删（同步确认后）：条目/规则 + 墓碑 + 附件密文 + 索引条目。
    /// 不做 30 天检查（由同步引擎按「已同步确认」语义裁决后调用）。
    pub(crate) fn hard_delete(&mut self, id: uuid::Uuid) -> Result<()> {
        // 先读条目取附件 id（file 条目）：删掉 `.item.lk` 后即无从获取（G1 同款顺序）
        let attach_id = self.read_item_file(id).ok().and_then(|i| i.attach_id());
        fs::remove_file(item_file(&self.dir, id)).ok();
        fs::remove_file(rule_file(&self.dir, id)).ok();
        fs::remove_file(tomb_file(&self.dir, id)).ok();
        self.remove_attachment(attach_id)?;
        self.index.remove(&id);
        self.save_index()
    }

    /// 全部本地墓碑（id + 载荷；同步引擎 30 天/确认裁决用）。
    pub fn tombstones(&self) -> Vec<(uuid::Uuid, Tombstone)> {
        let mut v = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return v;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".tomb.lk") {
                continue;
            }
            if let Ok(t) = Self::read_tomb(&self.dir, &self.keys, &name) {
                v.push((t.id, t));
            }
        }
        v
    }

    /// 附件元数据（解密态）。
    pub fn attachment_meta(&self, attach_id: uuid::Uuid) -> Result<AttachmentMeta> {
        self.read_attachment_meta(attach_id)
    }

    /// 附件远端文件键列表（{attach_id}.attach.lk + {attach_id}.{i}.chunk.lk）。
    pub fn attachment_keys(&self, attach_id: uuid::Uuid) -> Vec<String> {
        let mut keys = vec![format!("{attach_id}.attach.lk")];
        if let Ok(meta) = self.read_attachment_meta(attach_id) {
            for i in 0..meta.chunks {
                keys.push(format!("{attach_id}.{i}.chunk.lk"));
            }
        }
        keys
    }

    /// 索引加载；`index.lk` 缺失或损坏 → 全量重建（不阻塞解锁）。
    fn load_index(dir: &Path, keys: &Keys) -> Result<HashMap<uuid::Uuid, IndexEntry>> {
        let path = index_file(dir);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            // 缺失与损坏同语义（data-model.md §6「索引损坏 → 全量重建」）：
            // 否则恢复/解锁会以空索引密封，条目对用户不可见（S1 缺失子场景）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self::rebuild_index(dir, keys);
            }
            Err(e) => return Err(e.into()),
        };
        match open(keys.k_data.as_ref(), SealType::Index, INDEX_FILE, &bytes)
            .and_then(|pt| Ok(serde_json::from_slice::<Vec<IndexEntry>>(&pt)?))
        {
            Ok(entries) => Ok(entries.into_iter().map(|e| (e.id, e)).collect()),
            Err(_) => Self::rebuild_index(dir, keys),
        }
    }

    /// 全量重建：扫描本地条目密文重建索引（不阻塞解锁）。
    fn rebuild_index(dir: &Path, keys: &Keys) -> Result<HashMap<uuid::Uuid, IndexEntry>> {
        let mut index = HashMap::new();
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".item.lk") {
                let bytes = fs::read(entry.path())?;
                let item: Item = match open(keys.k_data.as_ref(), SealType::Item, &name, &bytes)
                    .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
                {
                    Ok(item) => item,
                    Err(_) => continue, // 单条损坏跳过（与索引损坏同语义：不阻塞解锁）
                };
                let e = IndexEntry {
                    id: item.id(),
                    revision: item.revision().to_string(),
                    kind: ObjectKind::Item,
                    deleted: item.deleted(),
                };
                index.insert(e.id, e.clone());
                entries.push(e);
            } else if name.ends_with(".rule.lk") {
                // 规则随同一索引重建（data-model.md §6；损坏跳过，不阻塞解锁）。
                // 规则体无 deleted 字段：软删状态从墓碑恢复（revision 同源）。
                let bytes = fs::read(entry.path())?;
                let rule: Rule = match open(keys.k_data.as_ref(), SealType::Rule, &name, &bytes)
                    .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
                {
                    Ok(rule) => rule,
                    Err(_) => continue,
                };
                let tomb_state = Self::read_tomb(dir, keys, &format!("{}.tomb.lk", rule.id))
                    .ok()
                    .map(|t| (t.revision, true));
                let (revision, deleted) = tomb_state.unwrap_or_else(|| (now_iso(), false));
                let e = IndexEntry {
                    id: rule.id,
                    revision,
                    kind: ObjectKind::Rule,
                    deleted,
                };
                index.insert(e.id, e.clone());
                entries.push(e);
            }
        }
        entries.sort_by_key(|e| e.id);
        let sealed = seal(
            keys.k_data.as_ref(),
            SealType::Index,
            INDEX_FILE,
            &serde_json::to_vec(&entries)?,
        );
        write_atomic(&index_file(dir), &sealed)?;
        Ok(index)
    }

    fn save_index(&self) -> Result<()> {
        let mut entries: Vec<IndexEntry> = self.index.values().cloned().collect();
        entries.sort_by_key(|e| e.id);
        let sealed = seal(
            self.keys.k_data.as_ref(),
            SealType::Index,
            INDEX_FILE,
            &serde_json::to_vec(&entries)?,
        );
        write_atomic(&index_file(self.dir()), &sealed)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 下一个 revision：ISO-8601 UTC，且严格大于本会话已签发值。
    fn next_revision(&mut self) -> String {
        let mut rev = now_iso();
        if let Some(last) = &self.last_revision {
            if rev <= *last {
                rev = bump_iso(last);
            }
        }
        self.last_revision = Some(rev.clone());
        rev
    }

    fn read_item_file(&self, id: uuid::Uuid) -> Result<Item> {
        let path = item_file(&self.dir, id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let bytes = fs::read(&path).map_err(|_| Error::ItemNotFound(id))?;
        let pt = open(self.keys.k_data.as_ref(), SealType::Item, &name, &bytes)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    fn write_item_file(&self, item: &Item) -> Result<()> {
        let path = item_file(&self.dir, item.id());
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let blob = seal(
            self.keys.k_data.as_ref(),
            SealType::Item,
            &name,
            &item.to_plaintext()?,
        );
        write_atomic(&path, &blob)
    }

    fn read_tomb(dir: &Path, keys: &Keys, file_name: &str) -> Result<Tombstone> {
        let bytes = fs::read(dir.join(file_name))?;
        let pt = open(keys.k_data.as_ref(), SealType::Tombstone, file_name, &bytes)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    // -- 查询 --------------------------------------------------------------

    /// 条目最小索引（解密态；含已删除条目，供列表/恢复判断）。
    pub fn list(&mut self) -> Result<Vec<ItemSummary>> {
        let mut out = Vec::new();
        let mut ids: Vec<uuid::Uuid> = self.index.keys().copied().collect();
        ids.sort();
        // 文件缺失的条目：自愈（从索引剔除）
        let missing: Vec<uuid::Uuid> = ids
            .iter()
            .copied()
            .filter(|id| !item_file(&self.dir, *id).exists())
            .collect();
        for id in &missing {
            self.index.remove(id);
        }
        if !missing.is_empty() {
            self.save_index()?;
        }
        for id in ids {
            if let Ok(item) = self.read_item_file(id) {
                out.push(ItemSummary::from(&item));
            }
        }
        Ok(out)
    }

    /// 取单条（完整解密字段）。
    pub fn get(&self, id: uuid::Uuid) -> Result<Item> {
        self.read_item_file(id)
    }

    // -- 写入 --------------------------------------------------------------

    /// 新建/整条替换（CAS）。新建：`id=None`；更新：`id` + `expected_revision`
    /// 必须等于存储端当前 revision，否则 [`Error::Conflict`]（last-write-wins
    /// 语义：更新者刷新后重试）。
    pub fn put(
        &mut self,
        id: Option<uuid::Uuid>,
        draft: ItemDraft,
        expected_revision: Option<String>,
    ) -> Result<Item> {
        // 更新路径先做 CAS 检查（不匹配 → Conflict，不做任何写入）
        let existing = match id {
            Some(id) => {
                let existing = self.read_item_file(id)?;
                match expected_revision.as_deref() {
                    Some(base) if base == existing.revision() => {}
                    Some(_) => return Err(Error::Conflict),
                    None => {
                        return Err(Error::Other("更新必须携带 expectedRevision（CAS）".into()))
                    }
                }
                Some(existing)
            }
            None => None,
        };

        // 附件（若有 fileData）：CAS 通过后才存储，避免冲突时残留孤儿附件
        let file_data = draft.file_data()?;
        let (new_attach, new_size) = match file_data {
            Some(bytes) => {
                let (name, mime) = match &draft {
                    ItemDraft::File {
                        attachment,
                        file_type,
                        ..
                    } => (attachment.clone(), file_type.clone()),
                    _ => unreachable!("非 file 草稿不带 fileData"),
                };
                let meta = self.store_attachment(&name, &mime, &bytes)?;
                (Some(meta.id), Some(meta.size))
            }
            None => (None, None),
        };

        let id = id.unwrap_or_else(random_uuid);
        let mut item = Item::from_draft(draft, id, self.next_revision());
        // file 条目：新建带附件 → 填入 attach_id/size；编辑保留附件关联
        if let Item::File {
            attach_id: a,
            size: s,
            ..
        } = &mut item
        {
            match (new_attach, new_size) {
                (Some(a_id), Some(a_size)) => {
                    if let Some(old) = existing.as_ref().and_then(Item::attach_id) {
                        self.remove_attachment(Some(old))?;
                    }
                    *a = Some(a_id);
                    *s = a_size;
                }
                _ => {
                    if let Some(existing) = &existing {
                        if a.is_none() {
                            *a = existing.attach_id();
                        }
                        // 元数据编辑：大小以存储的附件为准
                        *s = existing_size(existing);
                    }
                }
            }
        }

        let id = item.id();
        self.write_item_file(&item)?;
        self.index.insert(
            id,
            IndexEntry {
                id,
                revision: item.revision().to_string(),
                kind: ObjectKind::Item,
                deleted: false,
            },
        );
        self.save_index()?;
        self.emit_item_changed(&item, false);
        Ok(item)
    }

    /// 软删除：条目置 deleted + 新 revision，写墓碑（30 天延迟硬删）。
    pub fn delete(&mut self, id: uuid::Uuid) -> Result<Tombstone> {
        let existing = self.read_item_file(id)?;
        if existing.deleted() {
            // 幂等：已删除 → 返回既有墓碑
            let path = tomb_file(&self.dir, id);
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            return match fs::read(&path) {
                Ok(bytes) => {
                    let pt = open(
                        self.keys.k_data.as_ref(),
                        SealType::Tombstone,
                        &name,
                        &bytes,
                    )?;
                    Ok(serde_json::from_slice(&pt)?)
                }
                Err(_) => Ok(Tombstone {
                    id,
                    deleted_at: now_iso(),
                    revision: existing.revision().to_string(),
                }),
            };
        }
        let mut item = existing;
        item.set_deleted(true);
        let rev = self.next_revision();
        item.set_revision(rev.clone());
        self.write_item_file(&item)?;

        let tomb = Tombstone {
            id,
            deleted_at: now_iso(),
            revision: rev.clone(),
        };
        let path = tomb_file(&self.dir, id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let blob = seal(
            self.keys.k_data.as_ref(),
            SealType::Tombstone,
            &name,
            &serde_json::to_vec(&tomb)?,
        );
        write_atomic(&path, &blob)?;

        if let Some(e) = self.index.get_mut(&id) {
            e.deleted = true;
            e.revision = rev;
        }
        self.save_index()?;
        self.emit_item_changed(&item, true);
        Ok(tomb)
    }

    // -- 规则（M2；`docs/authorization-gate.md` §4）--------------------------
    // 规则 = vault 内加密对象（`{uuid}.rule.lk`，K_data 密封），与条目同一
    // 索引/轮询路径同步（data-model.md §6）。唯一写入路径：`lk rule add` +
    // 桌面规则页；不开放手动改加密文件；规则变更写审计 + 广播
    // `item.changed(kind="rule")`（决策 #6）。软删/墓碑/30 天硬删与条目同路径
    // （删除在多端传播）。

    /// `item.changed(kind="rule")` 观察广播（决策 #6：规则变更复用该事件）。
    fn emit_rule_changed(&self, rule_id: uuid::Uuid, revision: &str, deleted: bool) {
        if let Some(bus) = &self.bus {
            bus.emit(&VaultEvent::ItemChanged {
                item_id: rule_id,
                revision_date: revision.to_string(),
                kind: "rule".to_string(),
                deleted,
            });
        }
    }

    fn read_rule_file(&self, id: uuid::Uuid) -> Result<Rule> {
        let path = rule_file(&self.dir, id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let bytes = fs::read(&path).map_err(|_| Error::ItemNotFound(id))?;
        let pt = open(self.keys.k_data.as_ref(), SealType::Rule, &name, &bytes)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    fn write_rule_file(&self, rule: &Rule) -> Result<()> {
        let path = rule_file(&self.dir, rule.id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let blob = seal(
            self.keys.k_data.as_ref(),
            SealType::Rule,
            &name,
            &rule.to_plaintext()?,
        );
        write_atomic(&path, &blob)
    }

    /// 新建/替换规则（`id=None` = 新建；`Some` = 替换，保留 created）。
    /// 规则体无 revision（规格字段集），修订号在索引内（`next_revision`）。
    pub fn put_rule(&mut self, draft: RuleDraft, id: Option<uuid::Uuid>) -> Result<Rule> {
        // 绝对路径校验；合法的 `wsl://<distro>[/<rest>]` 跨命名空间规范形例外
        // （非本机 fs 路径，cross-subsystem.md §7.4，入库前已归一化；畸形
        // wsl:// 形态——缺 distro 段等——同样拒绝）。
        if !crate::path_ns::is_valid_wsl_canonical(&draft.project_dir)
            && !std::path::Path::new(&draft.project_dir).is_absolute()
        {
            return Err(Error::Other("projectDir 必须是绝对路径".into()));
        }
        let existing = match id {
            Some(id) => Some(self.read_rule_file(id)?),
            None => None,
        };
        let rule = Rule {
            id: id.unwrap_or_else(random_uuid),
            project_dir: draft.project_dir,
            name: draft.name,
            command: draft.command,
            keys: draft.keys,
            capability: draft.capability,
            created: existing.map(|r| r.created).unwrap_or_else(now_iso),
        };
        let rev = self.next_revision();
        self.write_rule_file(&rule)?;
        // 复活/替换规则：清理陈旧墓碑（软删后同 id 重建 → 墓碑已失效；否则
        // 非同步模式的 purge_expired 会把活跃规则连同墓碑一并误删）。
        fs::remove_file(tomb_file(&self.dir, rule.id)).ok();
        self.index.insert(
            rule.id,
            IndexEntry {
                id: rule.id,
                revision: rev.clone(),
                kind: ObjectKind::Rule,
                deleted: false,
            },
        );
        self.save_index()?;
        self.emit_rule_changed(rule.id, &rev, false);
        Ok(rule)
    }

    /// 全部解密态规则（**不含已删除**；解密失败 → `Err`——规则库损坏
    /// fail-closed，授权门第 1 层据此拒绝）。
    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        let mut out = Vec::new();
        let mut ids: Vec<uuid::Uuid> = self
            .index
            .iter()
            .filter(|(_, e)| e.kind == ObjectKind::Rule && !e.deleted)
            .map(|(id, _)| *id)
            .collect();
        ids.sort();
        for id in ids {
            out.push(self.read_rule_file(id)?);
        }
        Ok(out)
    }

    /// 单条规则（含已删除——`rule.get`/同步 LWW 复核用）。
    pub fn get_rule(&self, id: uuid::Uuid) -> Result<Rule> {
        self.read_rule_file(id)
    }

    /// 按 key 名解析 secret 条目值（授权门用）：未删除的 secret 条目按
    /// 名称精确匹配；不存在/非 secret/已删除 → `Ok(None)`。
    /// 文件缺失的条目跳过（list() 自愈剔除；授权门按「无法解析」处理）。
    pub fn find_secret_by_name(&self, name: &str) -> Result<Option<String>> {
        Ok(self.secret_values()?.remove(name))
    }

    /// 全部未删除 secret 条目（name → value；单次扫描，授权门批量解析用）。
    /// 文件缺失的条目跳过。
    pub fn secret_values(&self) -> Result<std::collections::HashMap<String, String>> {
        let mut ids: Vec<uuid::Uuid> = self
            .index
            .iter()
            .filter(|(_, e)| e.kind == ObjectKind::Item && !e.deleted)
            .map(|(id, _)| *id)
            .collect();
        ids.sort();
        let mut out = std::collections::HashMap::new();
        for id in ids {
            let Ok(item) = self.read_item_file(id) else {
                continue;
            };
            if item.kind() == ItemKind::Secret {
                if let Item::Secret { name, value, .. } = item {
                    out.insert(name, value);
                }
            }
        }
        Ok(out)
    }

    /// 规则当前修订号（索引内；不存在 → `None`）。
    pub fn rule_revision(&self, id: uuid::Uuid) -> Option<String> {
        self.index.get(&id).map(|e| e.revision.clone())
    }

    /// 软删除规则（墓碑；30 天延迟硬删；删除随同步传播——与条目同路径）。
    pub fn delete_rule(&mut self, id: uuid::Uuid) -> Result<Tombstone> {
        self.read_rule_file(id)?; // 不存在 → ItemNotFound
        if self.index.get(&id).map(|e| e.deleted).unwrap_or(false) {
            // 幂等：已删除 → 返回既有墓碑
            let path = tomb_file(&self.dir, id);
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            return match fs::read(&path) {
                Ok(bytes) => {
                    let pt = open(
                        self.keys.k_data.as_ref(),
                        SealType::Tombstone,
                        &name,
                        &bytes,
                    )?;
                    Ok(serde_json::from_slice(&pt)?)
                }
                Err(_) => Ok(Tombstone {
                    id,
                    deleted_at: now_iso(),
                    revision: self
                        .index
                        .get(&id)
                        .map(|e| e.revision.clone())
                        .unwrap_or_else(now_iso),
                }),
            };
        }
        let rev = self.next_revision();
        if let Some(e) = self.index.get_mut(&id) {
            e.deleted = true;
            e.revision = rev.clone();
        }
        let tomb = Tombstone {
            id,
            deleted_at: now_iso(),
            revision: rev.clone(),
        };
        let path = tomb_file(&self.dir, id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let blob = seal(
            self.keys.k_data.as_ref(),
            SealType::Tombstone,
            &name,
            &serde_json::to_vec(&tomb)?,
        );
        write_atomic(&path, &blob)?;
        self.save_index()?;
        self.emit_rule_changed(id, &rev, true);
        Ok(tomb)
    }

    /// 30 天延迟硬删：删除条目/规则 + 墓碑 + 附件密文（同步确认口留给 M1）。
    pub fn purge_expired(&mut self, now: &str) -> Result<usize> {
        let now = parse_iso(now).unwrap_or_else(time::OffsetDateTime::now_utc);
        let mut purged = 0usize;
        let tombstones: Vec<(uuid::Uuid, Tombstone)> = {
            let mut v = Vec::new();
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".tomb.lk") {
                    continue;
                }
                if let Ok(t) = Self::read_tomb(&self.dir, &self.keys, &name) {
                    v.push((t.id, t));
                }
            }
            v
        };
        for (id, tomb) in tombstones {
            let expired = parse_iso(&tomb.deleted_at)
                .map(|t| t + TOMBSTONE_GRACE <= now)
                .unwrap_or(false);
            if !expired {
                continue;
            }
            // 先读条目取附件 id（file 条目）：attach_id 只能从条目密文得知，
            // 删掉 `.item.lk` 后即无从获取——顺序不可颠倒（G1）。
            let attach_id = self.read_item_file(id).ok().and_then(|i| i.attach_id());
            fs::remove_file(item_file(&self.dir, id)).ok();
            fs::remove_file(rule_file(&self.dir, id)).ok();
            fs::remove_file(tomb_file(&self.dir, id)).ok();
            self.remove_attachment(attach_id)?;
            self.index.remove(&id);
            purged += 1;
        }
        if purged > 0 {
            self.save_index()?;
        }
        Ok(purged)
    }

    // -- 附件 --------------------------------------------------------------

    /// 存附件：每附件独立 K_attach + 1 MiB 分块；元数据 attach.lk（K_data 密封，
    /// 内含加密的 K_attach）。附件密文绝不复用条目密钥。
    pub fn store_attachment(&self, name: &str, mime: &str, data: &[u8]) -> Result<AttachmentMeta> {
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(Error::Limit(format!(
                "附件 {} 字节超过 50MB 上限",
                data.len()
            )));
        }
        let attach_id = random_uuid();
        let k_attach = Zeroizing::new(random_array::<32>());
        let chunks = ((data.len() as u64).div_ceil(CHUNK_BYTES)).max(1) as u32;
        for i in 0..chunks {
            let start = (i as u64 * CHUNK_BYTES) as usize;
            let end = ((start as u64 + CHUNK_BYTES).min(data.len() as u64)) as usize;
            let chunk_pt = &data[start..end];
            // 对象 id = 分块文件名（与导出/重建路径一致，AAD 稳定）
            let object_id = format!("{attach_id}.{i}.chunk.lk");
            let blob = seal(k_attach.as_ref(), SealType::Chunk, &object_id, chunk_pt);
            write_atomic(&chunk_file(&self.dir, attach_id, i), &blob)?;
        }
        let sealed_key = seal(
            self.keys.k_data.as_ref(),
            SealType::Attach,
            &attach_id.to_string(),
            k_attach.as_ref(),
        );
        let meta = AttachmentMeta {
            id: attach_id,
            name: name.to_string(),
            mime: mime.to_string(),
            size: data.len() as u64,
            chunks,
            sealed_key,
            created: now_iso(),
        };
        // 对象 id = 附件元数据文件名（与读取路径一致，AAD 稳定）
        let meta_name = format!("{attach_id}.attach.lk");
        let blob = seal(
            self.keys.k_data.as_ref(),
            SealType::Attach,
            &meta_name,
            &serde_json::to_vec(&meta)?,
        );
        write_atomic(&attach_meta_file(&self.dir, attach_id), &blob)?;
        Ok(meta)
    }

    fn read_attachment_meta(&self, attach_id: uuid::Uuid) -> Result<AttachmentMeta> {
        let path = attach_meta_file(&self.dir, attach_id);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let bytes = fs::read(&path)?;
        let pt = open(self.keys.k_data.as_ref(), SealType::Attach, &name, &bytes)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    /// 删除附件（元数据 + 全部分块）。
    pub(crate) fn remove_attachment(&self, attach_id: Option<uuid::Uuid>) -> Result<()> {
        let Some(attach_id) = attach_id else {
            return Ok(());
        };
        if let Ok(meta) = self.read_attachment_meta(attach_id) {
            for i in 0..meta.chunks {
                fs::remove_file(chunk_file(&self.dir, attach_id, i)).ok();
            }
        }
        fs::remove_file(attach_meta_file(&self.dir, attach_id)).ok();
        Ok(())
    }

    /// 附件整包下载（M0 单机整包；V1 桌面同款语义）。
    pub fn export(&self, id: uuid::Uuid) -> Result<AttachmentBundle> {
        let item = self.read_item_file(id)?;
        let Item::File { attach_id, .. } = &item else {
            return Err(Error::Other("条目不是 file 类型".into()));
        };
        let Some(attach_id) = attach_id else {
            return Err(Error::Other("file 条目没有附件".into()));
        };
        let meta = self.read_attachment_meta(*attach_id)?;
        let k_attach = open(
            self.keys.k_data.as_ref(),
            SealType::Attach,
            &attach_id.to_string(),
            &meta.sealed_key,
        )?;
        let mut data = Vec::with_capacity(meta.size as usize);
        for i in 0..meta.chunks {
            let path = chunk_file(&self.dir, *attach_id, i);
            let fname = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let bytes = fs::read(&path)?;
            let pt = open(k_attach.as_ref(), SealType::Chunk, &fname, &bytes)?;
            data.extend_from_slice(&pt);
        }
        if data.len() as u64 != meta.size {
            return Err(Error::Other("附件大小与元数据不符（可能被篡改）".into()));
        }
        Ok(AttachmentBundle {
            name: meta.name.clone(),
            mime: meta.mime.clone(),
            size: meta.size,
            data,
        })
    }
}

fn existing_size(item: &Item) -> u64 {
    match item {
        Item::File { size, .. } => *size,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// 恢复流程编排
// ---------------------------------------------------------------------------

/// 恢复：恢复码 + 新主密码。
///
/// 1. 恢复码派生信封密钥 → 解信封取回旧 MK；
/// 2. 新 salt 重派生 MK'（K_data' / K_audit'）；
/// 3. 先用旧 K_audit 追加「审计密钥轮换」事件（验证链），再重加密全部
///    条目/索引/附件元数据（附件分块用独立 K_attach，不受影响）；
/// 4. 新恢复码 + 新信封（旧信封作废）；vault 头更新 KDF 参数。
///
/// 返回新恢复码（仅展示一次）。
pub fn recover_vault(
    dir: &Path,
    code: &RecoveryCode,
    new_password: &str,
    audit: &mut AuditLog,
) -> Result<RecoveryCode> {
    recover_vault_with_params(
        dir,
        code,
        new_password,
        audit,
        &crypto::default_kdf_params(),
    )
}

/// 恢复流程（KDF 参数可注入；生产用 [`recover_vault`]）。
pub fn recover_vault_with_params(
    dir: &Path,
    code: &RecoveryCode,
    new_password: &str,
    audit: &mut AuditLog,
    new_params: &KdfParams,
) -> Result<RecoveryCode> {
    // 恢复 = 重设主密码：同样执行最小长度策略（recovery.md §3 流程）
    validate_master_password(new_password)?;
    let header = load_header(dir)?;
    let envelope = RecoveryEnvelope::from_bytes(&fs::read(envelope_file(dir))?)?;

    let old_mk = envelope.open(code)?; // 错误恢复码 → 统一 Decrypt
    let old_keys = old_mk.derive_keys();

    // 新 KDF 参数（新 salt）+ 新 MK'
    let new_mk = new_params.derive_master_key(new_password)?;
    let new_keys = new_mk.derive_keys();

    // 审计密钥轮换事件：旧钥签名（先于任何新钥事件）
    audit.append(
        &old_keys,
        &EventInput::rotation(&old_keys.audit_key_id(), &new_keys.audit_key_id()),
    )?;

    // 索引先于重加密循环处理：以旧钥加载（缺失/损坏 → 用旧钥重建）。
    // 顺序不可颠倒——若先重加密条目，索引损坏时按旧钥重建会全部解密失败，
    // 产出空索引并以新钥密封，下次解锁不再触发重建，条目将从 list() 消失（S1）。
    let index_entries: Vec<IndexEntry> = {
        let idx = UnlockedVault::load_index(dir, &old_keys)?;
        let mut v: Vec<IndexEntry> = idx.values().cloned().collect();
        v.sort_by_key(|e| e.id);
        v
    };

    // 重加密：条目 / 墓碑 / 附件元数据（分块不动——K_attach 未变）
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let kind = if name.ends_with(".item.lk") {
            SealType::Item
        } else if name.ends_with(".rule.lk") {
            SealType::Rule
        } else if name.ends_with(".tomb.lk") {
            SealType::Tombstone
        } else if name.ends_with(".attach.lk") {
            SealType::Attach
        } else {
            continue;
        };
        let bytes = fs::read(&path)?;
        let pt = open(old_keys.k_data.as_ref(), kind, &name, &bytes)?;
        let new_pt = if kind == SealType::Attach {
            // 附件元数据内还嵌着一层「K_attach 密封体」（用 K_data 密封）——
            // 需一并换钥重密封，否则恢复后附件无法解密
            let mut meta: AttachmentMeta = serde_json::from_slice(&pt)?;
            meta.sealed_key = seal(
                new_keys.k_data.as_ref(),
                SealType::Attach,
                &meta.id.to_string(),
                &open(
                    old_keys.k_data.as_ref(),
                    SealType::Attach,
                    &meta.id.to_string(),
                    &meta.sealed_key,
                )?,
            );
            serde_json::to_vec(&meta)?
        } else {
            pt
        };
        let new_blob = seal(new_keys.k_data.as_ref(), kind, &name, &new_pt);
        write_atomic(&path, &new_blob)?;
    }

    // 索引重密封（重建结果可能已由 load_index 以旧钥写盘，此处统一换新钥）
    let sealed = seal(
        new_keys.k_data.as_ref(),
        SealType::Index,
        INDEX_FILE,
        &serde_json::to_vec(&index_entries)?,
    );
    write_atomic(&index_file(dir), &sealed)?;

    // 新恢复码 + 新信封（旧信封作废）
    let new_code = RecoveryCode::generate();
    let mut envelope_kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        m: new_params.m,
        t: new_params.t,
        p: new_params.p,
        salt: random_array(),
    };
    envelope_kdf.salt = random_array();
    let envelope =
        RecoveryEnvelope::build(&new_code, &new_mk, envelope_kdf, KdfCost::from(new_params))?;
    write_atomic(&envelope_file(dir), &envelope.to_bytes()?)?;

    // vault 头更新 KDF 参数（新 salt）+ 重建 KCV
    let mut header = header;
    header.kdf = new_params.clone();
    header.refresh_key_check(new_keys.k_data.as_ref());
    write_atomic(&header_file(dir), &serde_json::to_vec(&header)?)?;

    audit.append(
        &new_keys,
        &EventInput::new("lk", "vault.recover", AuditResult::Allowed),
    )?;

    Ok(new_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::crypto::MK_LEN;
    use crate::model::ItemKind;
    use base64::Engine as _;

    fn temp_vault(_name: &str) -> (tempfile::TempDir, AuditLog, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();
        let (_h, code) = init_vault_with_params(
            dir.path(),
            "pw123456",
            false,
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        (dir, audit, code.display())
    }

    fn unlock_vault(dir: &Path, password: &str) -> crate::Result<UnlockedVault> {
        UnlockedVault::unlock(dir, password)
    }

    fn login_draft(name: &str) -> ItemDraft {
        ItemDraft::Login {
            name: name.into(),
            username: "u".into(),
            password: "p".into(),
            uris: vec!["https://example.com".into()],
            custom: vec![],
        }
    }

    /// M2.5 主密码策略：<8 位拒绝（WeakPassword）；≥8 位通过；恢复的新主
    /// 密码同策略（recovery.md §3 重设主密码）。
    #[test]
    fn master_password_policy_enforced_on_init_and_recover() {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();

        // 弱密码（<8 位）→ 不建库
        assert!(matches!(
            init_vault_with_params(
                dir.path(),
                "short",
                false,
                &mut audit,
                &crypto::test_kdf_params()
            ),
            Err(Error::WeakPassword)
        ));
        assert!(!vault_exists(dir.path()));

        // ≥8 位 → 建库
        let (_, code) = init_vault_with_params(
            dir.path(),
            "pw123456",
            false,
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();

        // 恢复设置新主密码同样校验（recovery.md §3 重设主密码）
        assert!(matches!(
            recover_vault_with_params(
                dir.path(),
                &RecoveryCode::parse(&code.display()).unwrap(),
                "new",
                &mut audit,
                &crypto::test_kdf_params()
            ),
            Err(Error::WeakPassword)
        ));
    }

    #[test]
    fn init_creates_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();
        let (header, code) = init_vault_with_params(
            dir.path(),
            "pw123456",
            false,
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert!(vault_exists(dir.path()));
        assert_eq!(header.format, "lightkey.vault");
        assert_eq!(header.kdf.m, 8);
        assert!(dir.path().join(VAULT_HEADER_FILE).exists());
        assert!(dir.path().join(ENVELOPE_FILE).exists());
        assert!(dir.path().join(INDEX_FILE).exists());
        assert_eq!(code.display().len(), 5 * 8 + 4);
        // 重复 init 报 VaultExists
        assert!(matches!(
            init_vault_with_params(
                dir.path(),
                "pw123456",
                false,
                &mut audit,
                &crypto::test_kdf_params()
            ),
            Err(Error::VaultExists)
        ));
    }

    #[test]
    fn crud_and_cas() {
        let (dir, audit, _code) = temp_vault("crud");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        assert_eq!(v.list().unwrap().len(), 0);

        // create
        let item = v.put(None, login_draft("GitHub"), None).unwrap();
        let id = item.id();
        assert!(!item.revision().is_empty());
        assert_eq!(v.list().unwrap().len(), 1);

        // get
        let got = v.get(id).unwrap();
        assert_eq!(got.name(), "GitHub");
        assert_eq!(got.kind(), ItemKind::Login);

        // update with wrong base → Conflict
        assert!(matches!(
            v.put(Some(id), login_draft("GitHub2"), Some("stale-rev".into())),
            Err(Error::Conflict)
        ));
        // update with missing base → error
        assert!(v.put(Some(id), login_draft("GitHub2"), None).is_err());
        // update with correct base → ok, revision bumped, LWW 收敛（新值生效）
        let updated = v
            .put(
                Some(id),
                login_draft("GitHub2"),
                Some(item.revision().into()),
            )
            .unwrap();
        assert!(updated.revision() > item.revision());
        assert_eq!(v.get(id).unwrap().name(), "GitHub2");

        // delete → 墓碑 + deleted 标记
        let tomb = v.delete(id).unwrap();
        assert_eq!(tomb.id, id);
        let after = v.get(id).unwrap();
        assert!(after.deleted());
        // 幂等删除
        assert_eq!(v.delete(id).unwrap().id, id);
        // 索引仍列出（deleted=true）
        let summaries = v.list().unwrap();
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].deleted);

        // 不存在条目
        assert!(matches!(
            v.get(uuid::Uuid::new_v4()),
            Err(Error::ItemNotFound(_))
        ));
        drop(v);
        drop(audit);
    }

    #[test]
    fn revision_monotonic_across_restarts() {
        let (dir, _audit, _code) = temp_vault("mono");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let i1 = v.put(None, login_draft("a"), None).unwrap();
        let i2 = v.put(None, login_draft("b"), None).unwrap();
        assert!(i2.revision() > i1.revision());
        drop(v);
        // 重启（重新解锁）：索引里最大 revision 作为起点，仍严格递增
        let mut v2 = unlock_vault(dir.path(), "pw123456").unwrap();
        let i3 = v2.put(None, login_draft("c"), None).unwrap();
        assert!(i3.revision() > i2.revision());
    }

    #[test]
    fn corrupted_index_rebuilds() {
        let (dir, _audit, _code) = temp_vault("idx");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("a"), None).unwrap();
        drop(v);
        // 破坏 index.lk
        let idx = dir.path().join(INDEX_FILE);
        let mut bytes = std::fs::read(&idx).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&idx, &bytes).unwrap();
        // 解锁不阻塞，索引重建
        let mut v2 = unlock_vault(dir.path(), "pw123456").unwrap();
        assert_eq!(v2.list().unwrap().len(), 1);
        assert_eq!(v2.get(item.id()).unwrap().name(), "a");
    }

    #[test]
    fn purge_expired_after_grace() {
        let (dir, _audit, _code) = temp_vault("purge");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("old"), None).unwrap();
        v.delete(item.id()).unwrap();
        // 未到期 → 不 purge
        assert_eq!(v.purge_expired(&now_iso()).unwrap(), 0);
        // 已过期（now = 删除后 31 天）→ 硬删
        let future = (time::OffsetDateTime::now_utc() + time::Duration::days(31))
            .format(&time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))
            .unwrap();
        assert_eq!(v.purge_expired(&future).unwrap(), 1);
        assert!(matches!(v.get(item.id()), Err(Error::ItemNotFound(_))));
        assert!(!dir.path().join(format!("{}.tomb.lk", item.id())).exists());
    }

    /// G1 回归：file 条目删除 + 过期 → 附件元数据与全部分块必须一并删除。
    #[test]
    fn purge_removes_file_attachment() {
        let (dir, _audit, _code) = temp_vault("purge-attach");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        // 1 MiB + 123 B → 2 块
        let data: Vec<u8> = (0..(CHUNK_BYTES as usize + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let item = v
            .put(
                None,
                ItemDraft::File {
                    name: "f.bin".into(),
                    note: String::new(),
                    size: 0,
                    file_type: "application/octet-stream".into(),
                    attachment: "f.bin".into(),
                    attach_id: None,
                    file_data: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
                },
                None,
            )
            .unwrap();
        let Item::File { attach_id, .. } = &item else {
            panic!("file")
        };
        let attach_id = attach_id.unwrap();
        assert_ne!(attach_id, item.id(), "附件 id 与条目 id 独立");
        assert!(dir.path().join(format!("{attach_id}.attach.lk")).exists());
        assert!(dir.path().join(format!("{attach_id}.0.chunk.lk")).exists());
        assert!(dir.path().join(format!("{attach_id}.1.chunk.lk")).exists());
        v.delete(item.id()).unwrap();
        // 已过期（now = 删除后 31 天）→ 硬删条目 + 墓碑 + 附件密文
        let future = (time::OffsetDateTime::now_utc() + time::Duration::days(31))
            .format(&time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))
            .unwrap();
        assert_eq!(v.purge_expired(&future).unwrap(), 1);
        assert!(
            !dir.path().join(format!("{attach_id}.attach.lk")).exists(),
            "附件元数据应随硬删删除"
        );
        assert!(
            !dir.path().join(format!("{attach_id}.0.chunk.lk")).exists(),
            "附件分块应随硬删删除"
        );
        assert!(
            !dir.path().join(format!("{attach_id}.1.chunk.lk")).exists(),
            "附件分块应随硬删删除"
        );
    }

    #[test]
    fn attachment_chunking_and_export() {
        let (dir, _audit, _code) = temp_vault("attach");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        // 2.5 MiB（3 块）
        let data: Vec<u8> = (0..(2 * 1024 * 1024 + 512 * 1024))
            .map(|i| (i % 251) as u8)
            .collect();
        let draft = ItemDraft::File {
            name: "blob.bin".into(),
            note: "测试附件".into(),
            size: 0,
            file_type: "application/octet-stream".into(),
            attachment: "blob.bin".into(),
            attach_id: None,
            file_data: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
        };
        let item = v.put(None, draft, None).unwrap();
        let Item::File {
            size, attach_id, ..
        } = &item
        else {
            panic!("file")
        };
        assert_eq!(*size, data.len() as u64);
        let attach_id = attach_id.unwrap();
        assert!(dir.path().join(format!("{attach_id}.0.chunk.lk")).exists());
        assert!(dir.path().join(format!("{attach_id}.2.chunk.lk")).exists());
        assert!(!dir.path().join(format!("{attach_id}.3.chunk.lk")).exists());
        // 分块密文 ≠ 明文
        let chunk0 = std::fs::read(dir.path().join(format!("{attach_id}.0.chunk.lk"))).unwrap();
        assert_ne!(&chunk0[..], &data[..chunk0.len().min(data.len())]);
        // 导出整包 == 原数据
        let bundle = v.export(item.id()).unwrap();
        assert_eq!(bundle.data, data);
        assert_eq!(bundle.size, data.len() as u64);
        assert_eq!(bundle.name, "blob.bin");
        // 元数据编辑保留附件
        let edited = v
            .put(
                Some(item.id()),
                ItemDraft::File {
                    name: "blob2.bin".into(),
                    note: "改备注".into(),
                    size: 0,
                    file_type: "application/octet-stream".into(),
                    attachment: "blob.bin".into(),
                    attach_id: Some(attach_id),
                    file_data: None,
                },
                Some(item.revision().into()),
            )
            .unwrap();
        assert_eq!(edited.attach_id(), Some(attach_id));
        assert_eq!(v.export(edited.id()).unwrap().data, data);
        // 替换附件
        let new_data = b"replacement".to_vec();
        let replaced = v
            .put(
                Some(edited.id()),
                ItemDraft::File {
                    name: "blob2.bin".into(),
                    note: "替换".into(),
                    size: 0,
                    file_type: "text/plain".into(),
                    attachment: "b.txt".into(),
                    attach_id: Some(attach_id),
                    file_data: Some(base64::engine::general_purpose::STANDARD.encode(&new_data)),
                },
                Some(edited.revision().into()),
            )
            .unwrap();
        assert_eq!(v.export(replaced.id()).unwrap().data, new_data);
        // 超过 50MB 拒绝
        let too_big = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
        assert!(v.store_attachment("big", "x", &too_big).is_err());
    }

    #[test]
    fn recover_flow_rotates_everything() {
        let (dir, mut audit, code) = temp_vault("recover");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("keep-me"), None).unwrap();
        let data = b"attachment-data".to_vec();
        let fitem = v
            .put(
                None,
                ItemDraft::File {
                    name: "f".into(),
                    note: String::new(),
                    size: 0,
                    file_type: "text/plain".into(),
                    attachment: "f.txt".into(),
                    attach_id: None,
                    file_data: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
                },
                None,
            )
            .unwrap();
        v.delete(item.id()).unwrap();
        drop(v);

        let old_keys = {
            let mk = load_header(dir.path())
                .unwrap()
                .kdf
                .derive_master_key("pw123456")
                .unwrap();
            mk.derive_keys()
        };

        // 错误恢复码 → 统一失败
        let bad_code = RecoveryCode::generate();
        assert!(recover_vault_with_params(
            dir.path(),
            &bad_code,
            "newpw123",
            &mut audit,
            &crypto::test_kdf_params()
        )
        .is_err());

        // 正确恢复码 + 新主密码
        let new_code = recover_vault_with_params(
            dir.path(),
            &RecoveryCode::parse(&code).unwrap(),
            "newpw123",
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert_ne!(new_code.display(), code, "恢复码轮换");

        // 旧密码不可解锁，新密码可
        assert!(unlock_vault(dir.path(), "pw123456").is_err());
        let mut v2 = unlock_vault(dir.path(), "newpw123").unwrap();
        // 条目可读（重加密成功）
        assert_eq!(v2.get(item.id()).unwrap().name(), "keep-me");
        assert!(v2.get(item.id()).unwrap().deleted());
        assert_eq!(v2.export(fitem.id()).unwrap().data, data);
        // 新库继续可写
        let fresh = v2.put(None, login_draft("after"), None).unwrap();
        assert_eq!(v2.get(fresh.id()).unwrap().name(), "after");

        // 旧密钥不可解新数据：新条目密文用旧钥打开失败
        let new_item_blob = std::fs::read(item_file(dir.path(), fresh.id())).unwrap();
        let fname = format!("{}.item.lk", fresh.id());
        assert!(open(
            old_keys.k_data.as_ref(),
            SealType::Item,
            &fname,
            &new_item_blob
        )
        .is_err());
        // 旧信封已作废：旧恢复码开新信封失败
        let envelope =
            RecoveryEnvelope::from_bytes(&std::fs::read(envelope_file(dir.path())).unwrap())
                .unwrap();
        assert!(envelope.open(&RecoveryCode::parse(&code).unwrap()).is_err());
        // 新恢复码可开新信封
        let mk_roundtrip = envelope
            .open(&RecoveryCode::parse(&new_code.display()).unwrap())
            .unwrap();
        let new_params = load_header(dir.path()).unwrap().kdf;
        assert!(
            new_params.derive_master_key("newpw123").unwrap().as_bytes() == mk_roundtrip.as_bytes()
        );

        // 审计链：轮换事件在旧钥下可验，轮换后事件在新钥下可验
        let log = AuditLog::open(dir.path()).unwrap();
        let new_id = v2.keys().audit_key_id();
        let new_k = *v2.keys().k_audit;
        let resolve = move |id: &str| -> Option<Zeroizing<[u8; MK_LEN]>> {
            if id == new_id {
                Some(Zeroizing::new(new_k))
            } else {
                None
            }
        };
        let verified = log.verify(&old_keys, &resolve).unwrap();
        assert!(verified >= 3, "init + 轮换 + recover + ... 至少 3 条");
    }

    /// S1 回归：恢复 + index.lk 损坏 → 索引须以旧钥重建，条目数与恢复前一致。
    #[test]
    fn recover_with_corrupt_index_keeps_items() {
        let (dir, mut audit, code) = temp_vault("recover-idx");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("keep-me"), None).unwrap();
        v.put(
            None,
            ItemDraft::File {
                name: "f.bin".into(),
                note: String::new(),
                size: 0,
                file_type: "application/octet-stream".into(),
                attachment: "f.bin".into(),
                attach_id: None,
                file_data: Some(
                    base64::engine::general_purpose::STANDARD.encode(b"attachment-data"),
                ),
            },
            None,
        )
        .unwrap();
        let n_before = v.list().unwrap().len();
        assert_eq!(n_before, 2);
        drop(v);
        // 破坏 index.lk（同 corrupted_index_rebuilds 手法）
        let idx = dir.path().join(INDEX_FILE);
        let mut bytes = std::fs::read(&idx).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&idx, &bytes).unwrap();
        // 恢复：索引损坏时必须以旧钥重建（此刻条目密文仍是旧钥），
        // 不能产出空索引
        let new_code = recover_vault_with_params(
            dir.path(),
            &RecoveryCode::parse(&code).unwrap(),
            "newpw123",
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert_ne!(new_code.display(), code);
        // 新密码解锁：条目数与恢复前一致，条目可读
        let mut v2 = unlock_vault(dir.path(), "newpw123").unwrap();
        assert_eq!(
            v2.list().unwrap().len(),
            n_before,
            "恢复后索引不得为空（S1）"
        );
        assert_eq!(v2.get(item.id()).unwrap().name(), "keep-me");
        // 二次解锁不重建（索引合法），条目仍可见
        drop(v2);
        let mut v3 = unlock_vault(dir.path(), "newpw123").unwrap();
        assert_eq!(v3.list().unwrap().len(), n_before);
    }

    /// S1 回归（缺失子场景）：恢复 + index.lk 缺失 → 与损坏同语义全量重建，
    /// 条目数与恢复前一致（缺失时恢复若产出空索引，用户视角数据丢失）。
    #[test]
    fn recover_with_missing_index_keeps_items() {
        let (dir, mut audit, code) = temp_vault("recover-idx-missing");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("keep-me"), None).unwrap();
        let n_before = v.list().unwrap().len();
        assert_eq!(n_before, 1);
        drop(v);
        // 删除 index.lk（磁盘/同步损坏、手动删除）
        std::fs::remove_file(dir.path().join(INDEX_FILE)).unwrap();
        // 恢复：索引缺失时必须重建（此刻条目密文仍是旧钥），不能产出空索引
        let new_code = recover_vault_with_params(
            dir.path(),
            &RecoveryCode::parse(&code).unwrap(),
            "newpw123",
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert_ne!(new_code.display(), code);
        // 新密码解锁：条目数与恢复前一致，条目可读
        let mut v2 = unlock_vault(dir.path(), "newpw123").unwrap();
        assert_eq!(
            v2.list().unwrap().len(),
            n_before,
            "恢复后索引不得为空（S1 缺失子场景）"
        );
        assert_eq!(v2.get(item.id()).unwrap().name(), "keep-me");
    }

    /// S1 回归（缺失子场景，正常解锁路径）：index.lk 缺失 → 条目仍可见。
    #[test]
    fn unlock_with_missing_index_keeps_items() {
        let (dir, _audit, _code) = temp_vault("unlock-idx-missing");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let item = v.put(None, login_draft("keep-me"), None).unwrap();
        let n_before = v.list().unwrap().len();
        assert_eq!(n_before, 1);
        drop(v);
        // 删除 index.lk 后正常解锁：不得出现空列表
        std::fs::remove_file(dir.path().join(INDEX_FILE)).unwrap();
        let mut v2 = unlock_vault(dir.path(), "pw123456").unwrap();
        assert_eq!(
            v2.list().unwrap().len(),
            n_before,
            "解锁后索引不得为空（S1 缺失子场景）"
        );
        assert_eq!(v2.get(item.id()).unwrap().name(), "keep-me");
        // 重建的索引已落盘：再次解锁不重建，条目仍可见
        assert!(
            dir.path().join(INDEX_FILE).exists(),
            "解锁后应重建并落盘索引"
        );
        drop(v2);
        let mut v3 = unlock_vault(dir.path(), "pw123456").unwrap();
        assert_eq!(v3.list().unwrap().len(), n_before);
    }

    /// M2：规则 CRUD——落盘形态（{uuid}.rule.lk 密封）、索引 kind=Rule、
    /// 广播 item.changed(kind="rule")、软删墓碑、恢复重加密、索引重建保留。
    #[test]
    fn rule_crud_seal_recover_and_rebuild() {
        let (dir, audit, code) = temp_vault("rules");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        // 新建
        let proj = std::env::temp_dir()
            .join("lk-test-proj")
            .to_string_lossy()
            .to_string();
        let rule = v
            .put_rule(
                RuleDraft {
                    project_dir: proj.clone(),
                    name: "publish".into(),
                    command: "npm publish".into(),
                    keys: vec!["NPM_TOKEN".into()],
                    capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                },
                None,
            )
            .unwrap();
        assert_eq!(rule.name, "publish");
        // 落盘：{uuid}.rule.lk 且为密文（非明文 JSON）
        let path = dir.path().join(format!("{}.rule.lk", rule.id));
        assert!(path.exists());
        let blob = std::fs::read(&path).unwrap();
        assert!(!blob
            .windows(b"npm publish".len())
            .any(|w| w == b"npm publish"));
        // 索引含 kind=Rule
        assert!(v
            .index_snapshot()
            .iter()
            .any(|e| e.id == rule.id && e.kind == ObjectKind::Rule));
        // 列表/取值
        assert_eq!(v.list_rules().unwrap().len(), 1);
        assert_eq!(v.get_rule(rule.id).unwrap().name, "publish");
        // 广播 item.changed(kind="rule")（决策 #6）
        let bus = Arc::new(crate::bus::EventBus::new());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        bus.subscribe(Arc::new(crate::bus::FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone());
        })));
        v.attach_bus(bus);
        v.put_rule(
            RuleDraft {
                project_dir: proj,
                name: "publish2".into(),
                command: "npm *".into(),
                keys: vec!["A".into(), "B".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            },
            Some(rule.id),
        )
        .unwrap();
        v.delete_rule(rule.id).unwrap();
        let seen = events.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        match &seen[0] {
            crate::bus::VaultEvent::ItemChanged { kind, deleted, .. } => {
                assert_eq!(kind, "rule");
                assert!(!deleted);
            }
            other => panic!("应广播 item.changed(kind=rule)：{other:?}"),
        }
        match &seen[1] {
            crate::bus::VaultEvent::ItemChanged { kind, deleted, .. } => {
                assert_eq!(kind, "rule");
                assert!(deleted, "软删广播 deleted=true");
            }
            other => panic!("应广播 item.changed(kind=rule, deleted)：{other:?}"),
        }
        // 软删：墓碑 + 列表不再含
        assert!(dir.path().join(format!("{}.tomb.lk", rule.id)).exists());
        assert_eq!(v.list_rules().unwrap().len(), 0);
        // 索引重建保留规则（含已删除标记由重建语义决定：重建不含 deleted 信息）
        drop(v);
        let idx = dir.path().join(INDEX_FILE);
        let mut bytes = std::fs::read(&idx).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&idx, &bytes).unwrap();
        let v2 = unlock_vault(dir.path(), "pw123456").unwrap();
        assert!(v2
            .index_snapshot()
            .iter()
            .any(|e| e.id == rule.id && e.kind == ObjectKind::Rule));
        drop(v2);
        // 恢复：规则密文随重加密换钥（旧钥打不开新密文）
        drop(audit);
        let new_code = recover_vault_with_params(
            dir.path(),
            &RecoveryCode::parse(&code).unwrap(),
            "newpw123",
            &mut AuditLog::open(dir.path()).unwrap(),
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert_ne!(new_code.display(), code);
        let v3 = unlock_vault(dir.path(), "newpw123").unwrap();
        let rules = v3.list_rules().unwrap();
        assert_eq!(rules.len(), 0, "恢复后软删规则仍删除");
        assert!(v3
            .index_snapshot()
            .iter()
            .any(|e| e.id == rule.id && e.kind == ObjectKind::Rule));
        // 旧钥打不开新规则密文（已换钥）
        let blob = std::fs::read(dir.path().join(format!("{}.rule.lk", rule.id))).unwrap();
        let old_keys = {
            let mk = load_header(dir.path())
                .unwrap()
                .kdf
                .derive_master_key("pw123456")
                .unwrap();
            mk.derive_keys()
        };
        assert!(open(
            old_keys.k_data.as_ref(),
            SealType::Rule,
            &format!("{}.rule.lk", rule.id),
            &blob,
        )
        .is_err());
    }

    /// M2：软删后同 id 复活规则 → 陈旧墓碑必须清理，否则非同步模式的
    /// `purge_expired` 会把活跃规则误删。
    #[test]
    fn put_rule_clears_stale_tombstone_on_revive() {
        let (dir, _audit, _code) = temp_vault("rule-revive");
        let mut v = unlock_vault(dir.path(), "pw123456").unwrap();
        let proj = std::env::temp_dir()
            .join("lk-test-proj")
            .to_string_lossy()
            .to_string();
        let rule = v
            .put_rule(
                RuleDraft {
                    project_dir: proj.clone(),
                    name: "publish".into(),
                    command: "npm publish".into(),
                    keys: vec!["NPM_TOKEN".into()],
                    capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                },
                None,
            )
            .unwrap();
        v.delete_rule(rule.id).unwrap();
        assert!(dir.path().join(format!("{}.tomb.lk", rule.id)).exists());
        // 同 id 复活（替换）：陈旧墓碑应被清理
        v.put_rule(
            RuleDraft {
                project_dir: proj,
                name: "publish2".into(),
                command: "npm *".into(),
                keys: vec!["A".into(), "B".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            },
            Some(rule.id),
        )
        .unwrap();
        assert!(
            !dir.path().join(format!("{}.tomb.lk", rule.id)).exists(),
            "复活规则应清理陈旧墓碑"
        );
        assert_eq!(v.list_rules().unwrap().len(), 1);
        // 过期清理不得删除活跃规则
        let future = (time::OffsetDateTime::now_utc() + time::Duration::days(31))
            .format(&time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))
            .unwrap();
        assert_eq!(v.purge_expired(&future).unwrap(), 0);
        assert_eq!(v.list_rules().unwrap().len(), 1, "活跃规则不被过期清理误删");
        assert!(v.get_rule(rule.id).is_ok());
    }

    #[test]
    fn reset_keeps_audit_log() {
        let (dir, mut audit, _code) = temp_vault("reset");
        let n_before = audit.count().unwrap();
        let (header, _new_code) = init_vault_with_params(
            dir.path(),
            "pw222222",
            true,
            &mut audit,
            &crypto::test_kdf_params(),
        )
        .unwrap();
        assert!(header.kdf.salt != [0u8; 16]);
        let n_after = audit.count().unwrap();
        assert_eq!(n_after, n_before + 1, "重置后审计继续追加（不删除）");
        assert!(vault_exists(dir.path()));
    }
}
