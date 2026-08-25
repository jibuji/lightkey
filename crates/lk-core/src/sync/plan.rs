//! 一轮同步的本地侧应用计划、LWW 裁决与索引 diff / 合并（纯函数）。
//!
//! 计划类型与裁决/合并逻辑同模块：`fetch_round` 产出 [`SyncPlan`]，
//! `apply_round` 消费；字段对本 crate 内的引擎可见（`pub(crate)`，
//! 非对外接口）。

use std::cmp::Ordering;
use std::collections::HashMap;

use sha2::Digest;
use uuid::Uuid;

use crate::model::{AttachmentMeta, IndexEntry, Item, ObjectKind, Rule, Tombstone};

use super::config::SyncSummary;

/// last-write-wins 裁决结果。
pub(crate) enum Lww {
    Local,
    Remote,
    Tie,
}

/// 整条目 last-write-wins：revisionDate 更晚者胜；同 revision 按内容
/// SHA-256 确定性决胜（两端同规则 → 收敛）；内容相同 → Tie。
pub(crate) fn lww(local: &Item, remote: &Item) -> Lww {
    match local.revision().cmp(remote.revision()) {
        Ordering::Greater => Lww::Local,
        Ordering::Less => Lww::Remote,
        Ordering::Equal => {
            let lh = item_content_hash(local);
            let rh = item_content_hash(remote);
            match lh.cmp(&rh) {
                Ordering::Greater => Lww::Local,
                Ordering::Less => Lww::Remote,
                Ordering::Equal => Lww::Tie,
            }
        }
    }
}

pub(crate) fn item_content_hash(item: &Item) -> [u8; 32] {
    // 条目明文序列化失败视为内容不同（防御性；正常路径不会发生）
    item.to_plaintext()
        .map(|pt| sha2::Sha256::digest(&pt).into())
        .unwrap_or([0u8; 32])
}

/// 一轮同步的本地侧应用计划（`fetch_round` 产物；`apply_round` 消费）。
pub struct SyncPlan {
    /// 摘要（pulled/purged 由应用阶段按实际应用计数回填）。
    pub summary: SyncSummary,
    /// 待导入的远端条目（密文原样缓冲；抓取阶段已解密校验，应用阶段复核）。
    pub(crate) imports: Vec<PendingImport>,
    /// 待本地硬删的条目（id + 裁决时的墓碑 revision；应用阶段复核）。
    pub(crate) hard_delete: Vec<(Uuid, String)>,
}

impl SyncPlan {
    /// 按 id upsert 待导入条目：同一条目在 CAS 重试间被再次缓冲（远端
    /// revision 前进）时，以最新缓冲替换旧缓冲——保证合并索引（`pending`）
    /// 与抓取阶段看到的远端 revision 恒一致，旧快照不得覆盖更新版本。
    pub(crate) fn upsert_import(&mut self, imp: PendingImport) {
        self.imports.retain(|i| i.id != imp.id);
        self.imports.push(imp);
    }
}

/// 待导入的远端对象（条目或规则；M2 起规则与条目同路径同步）。
pub(crate) enum PendingObject {
    Item(Item),
    Rule(Rule),
}

/// 待导入的远端对象。
pub(crate) struct PendingImport {
    pub(crate) id: Uuid,
    /// 对象类型（密文文件名与索引 kind 同源）。
    pub(crate) kind: ObjectKind,
    /// 远端索引修订号（规则体无 revision，以索引为准；条目与体内一致）。
    pub(crate) revision: String,
    /// 远端索引 deleted 标记（规则删除状态在索引内）。
    pub(crate) deleted: bool,
    /// 对象密文（原样落盘）。
    pub(crate) blob: Vec<u8>,
    /// 已解密对象（校验 + 应用阶段 LWW 复核）。
    pub(crate) object: PendingObject,
    /// (密文, 已解密)；远端墓碑缺失 → 引擎合成。
    pub(crate) tomb: Option<(Vec<u8>, Tombstone)>,
    pub(crate) attachments: Vec<PendingAttachment>,
}

/// 待导入的附件（元数据密文 + 已解密元数据 + 分块密文）。
pub(crate) struct PendingAttachment {
    pub(crate) meta_blob: Vec<u8>,
    pub(crate) meta: AttachmentMeta,
    pub(crate) chunks: Vec<(u32, Vec<u8>)>,
}

/// 推送结果。
pub(crate) enum PushResult {
    /// 已推送（远端已反映该条目的快照状态）。
    Pushed,
    /// 快照一致性守卫：条目在 diff 后被并发更新（或本地缺失）→ 本轮跳过
    /// （合并索引恢复远端原状/剔除；下轮再推）。
    Skipped,
    /// CAS 冲突后采纳远端（已缓冲到计划；合并索引以其远端版本为准）。
    Adopted,
}

// ---------------------------------------------------------------------------
// 差异 / 合并
// ---------------------------------------------------------------------------

/// 对比本地与远端索引：返回 (需拉取 ids, 需推送 ids)。
///
/// - 远端 revision 更大（或本地缺失）→ 拉取；
/// - 本地 revision 更大（或远端缺失）→ 推送；
/// - 同 revision 但 deleted 标记不一致 → 拉取（内容哈希决胜兜底）。
/// - 条目与规则同路径（M2：规则软删/墓碑经同一 diff 传播）。
pub(crate) fn diff(
    local: &[IndexEntry],
    remote: &HashMap<Uuid, IndexEntry>,
) -> (Vec<Uuid>, Vec<Uuid>) {
    let local_map: HashMap<Uuid, &IndexEntry> = local.iter().map(|e| (e.id, e)).collect();
    let mut pull = Vec::new();
    let mut push = Vec::new();
    for e in remote.values() {
        match local_map.get(&e.id) {
            None => pull.push(e.id),
            Some(le) => {
                if le.revision < e.revision
                    || (le.revision == e.revision && le.deleted != e.deleted)
                {
                    pull.push(e.id);
                } else if le.revision > e.revision {
                    push.push(e.id);
                }
            }
        }
    }
    for le in local {
        if !remote.contains_key(&le.id) {
            // 已删除对象远端缺失 → 不推送：远端要么从未有（无需传播），
            // 要么已硬删（再推送会让对端把墓碑拉回，形成复活循环）。
            // 本地清理由 purge_phase 按「≥30 天」裁决。
            if !le.deleted {
                push.push(le.id);
            }
        }
    }
    (pull, push)
}

/// 合并索引：远端为底；**本轮已缓冲的拉取条目以其远端版本为准**（密文已
/// 在远端就位）；本地较新者覆盖（其密文本轮已推送，见推送快照守卫）；
/// 跳过（对象缺失 / 推送被并发更新跳过）的条目恢复远端原状（无远端条目
/// 则剔除）；硬删条目剔除；rule 条目透传。返回排序后的索引向量。
pub(crate) fn merge_indexes(
    remote: &HashMap<Uuid, IndexEntry>,
    local: &[IndexEntry],
    pending: &[IndexEntry],
    skipped: &[Uuid],
    skipped_push: &[Uuid],
    purged: &[Uuid],
) -> Vec<IndexEntry> {
    let mut m: HashMap<Uuid, IndexEntry> = remote.clone();
    // 本轮已缓冲的拉取条目：以远端版本为准（本地快照的旧 revision 不得覆盖）
    for e in pending {
        m.insert(e.id, e.clone());
    }
    for e in local {
        if pending.iter().any(|p| p.id == e.id) {
            continue;
        }
        match m.get(&e.id) {
            None => {
                m.insert(e.id, e.clone());
            }
            Some(re) => {
                if e.revision > re.revision {
                    m.insert(e.id, e.clone());
                }
            }
        }
    }
    for id in skipped {
        // 拉取侧对象缺失 → 自愈：剔除（远端索引不再引用缺失的密文）
        m.remove(id);
    }
    for id in skipped_push {
        // 推送被并发更新跳过 → 本地旧快照条目不写入远端：恢复远端原状 / 剔除
        match remote.get(id) {
            Some(e) => {
                m.insert(*id, e.clone());
            }
            None => {
                m.remove(id);
            }
        }
    }
    for id in purged {
        m.remove(id);
    }
    let mut v: Vec<IndexEntry> = m.into_values().collect();
    v.sort_by_key(|e| e.id);
    v
}
