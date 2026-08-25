//! 同步引擎的本地 vault 只读视图。
//!
//! 守护进程侧实现：每次方法调用独立获取**短读锁**（仅本地内存/磁盘访问，
//! 不跨网络），网络 I/O 期间不持任何锁；测试直接以 [`UnlockedVault`] 实现。

use uuid::Uuid;

use crate::crypto::Keys;
use crate::model::{AttachmentMeta, IndexEntry, Item, Rule, Tombstone};
use crate::vault::UnlockedVault;
use crate::Result;

/// 附件抓取/推送的成组数据（元数据密文 + 已解密元数据 + 分块密文）。
pub type AttachmentBlobs = (AttachmentMeta, Vec<u8>, Vec<(u32, Vec<u8>)>);

/// 同步引擎的本地 vault 只读视图（阶段 1 用）。
///
/// 守护进程侧实现：每次方法调用独立获取**短读锁**（仅本地内存/磁盘访问，
/// 不跨网络），网络 I/O 期间不持任何锁；测试直接以 [`UnlockedVault`] 实现。
pub trait VaultRead {
    /// 密钥快照（抓取阶段解密/加密；应用阶段复核其仍与解锁态一致）。
    fn keys(&self) -> Keys;

    /// 索引快照（diff/合并的一致性基点；每次 CAS 重试取新快照）。
    fn index_snapshot(&self) -> Result<Vec<IndexEntry>>;

    /// 解密态条目（拉取 LWW 初筛）。
    fn item(&self, id: Uuid) -> Result<Item>;

    /// 条目 + 密文（**同一一致性点**读取；推送/冲突裁决用）。
    fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)>;

    /// 解密态规则（M2；拉取 LWW 初筛）。
    fn rule(&self, id: Uuid) -> Result<Rule>;

    /// 规则 + 密文（**同一一致性点**读取；推送用）。
    fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)>;

    /// 规则当前修订号（索引内——规则体无 revision 字段；LWW 初筛用）。
    fn rule_revision(&self, id: Uuid) -> Option<String>;

    /// 墓碑密文（可能不存在——远端墓碑缺失时由引擎合成）。
    fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>>;

    /// 附件元数据密文 + 全部分块密文（推送用；单次一致读取）。
    fn attachment_blobs(&self, attach_id: Uuid) -> Result<AttachmentBlobs>;

    /// 附件远端文件键列表（远端硬删用）。
    fn attachment_keys(&self, attach_id: Uuid) -> Vec<String>;

    /// 全部本地墓碑（硬删裁决）。
    fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>>;
}

impl VaultRead for UnlockedVault {
    fn keys(&self) -> Keys {
        self.keys().clone()
    }

    fn index_snapshot(&self) -> Result<Vec<IndexEntry>> {
        Ok(self.index_snapshot())
    }

    fn item(&self, id: Uuid) -> Result<Item> {
        self.get(id)
    }

    fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)> {
        let item = self.get(id)?;
        let blob = self.item_blob(id)?;
        Ok((item, blob))
    }

    fn rule(&self, id: Uuid) -> Result<Rule> {
        self.get_rule(id)
    }

    fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)> {
        let rule = self.get_rule(id)?;
        let blob = self.rule_blob(id)?;
        Ok((rule, blob))
    }

    fn rule_revision(&self, id: Uuid) -> Option<String> {
        self.rule_revision(id)
    }

    fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>> {
        self.tomb_blob(id)
    }

    fn attachment_blobs(&self, attach_id: Uuid) -> Result<AttachmentBlobs> {
        let meta = self.attachment_meta(attach_id)?;
        let meta_blob = self.attach_meta_blob(attach_id)?;
        let mut chunks = Vec::with_capacity(meta.chunks as usize);
        for i in 0..meta.chunks {
            chunks.push((i, self.chunk_blob(attach_id, i)?));
        }
        Ok((meta, meta_blob, chunks))
    }

    fn attachment_keys(&self, attach_id: Uuid) -> Vec<String> {
        self.attachment_keys(attach_id)
    }

    fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>> {
        Ok(self.tombstones())
    }
}
