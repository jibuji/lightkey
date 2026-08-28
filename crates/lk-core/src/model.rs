//! 数据模型（规格：`docs/data-model.md`，条目 schema 按 2026-08-15 存储类型
//! 定案 v2 更新为四类：login / note / secret / file）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **条目级密文 blob**（`{uuid}.item.lk`）+ 加密索引（`index.lk`），
//!   存储端只见密文文件与文件名时间戳。
//! - **四类 v2**：`login`（账号+密码+网址+自定义字段）、`note`（Markdown 内容）、
//!   `secret`（密钥值+用途+可选过期）、`file`（元数据+加密附件 ≤50MB）；
//!   全部真加密存储（零知识）；已砍「收藏 favorite」。
//! - `revisionDate`（IPC/前端字段名 `revision`）支持增量同步；软删除墓碑
//!   （30 天延迟硬删）。
//! - 乐观并发：CAS，整条目 last-write-wins。
//! - 附件：每附件独立密钥 K_attach + 1 MiB 流式分块。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// UUID 重导出（外部使用）。
pub type ItemUuid = Uuid;

use crate::{Error, Result};

/// 单文件附件上限：50MB（存储类型定案 v2）。
pub const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
/// 附件分块大小：1 MiB。
pub const CHUNK_BYTES: u64 = 1024 * 1024;
/// 墓碑延迟硬删窗口：30 天。
pub const TOMBSTONE_GRACE: time::Duration = time::Duration::days(30);

// ---------------------------------------------------------------------------
// 条目 schema（四类 v2）
// ---------------------------------------------------------------------------

/// 自定义字段（login 用；hidden 字段在 UI 中遮罩）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

/// 条目类型（四类 v2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Login,
    Note,
    Secret,
    File,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Login => "login",
            ItemKind::Note => "note",
            ItemKind::Secret => "secret",
            ItemKind::File => "file",
        }
    }
}

/// 条目（四类 v2，JSON-RPC 同款 serde；`type` 决定字段集）。
///
/// 字段约定：`revision` = revisionDate（ISO-8601 UTC，CAS 依据）；
/// IPC/前端字段名 `revision`、`expiresAt`、`fileType`、`attachmentId`（camelCase）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Item {
    /// 登录：账号 + 密码 + 网址（可多个）+ 自定义字段。
    #[serde(rename_all = "camelCase")]
    Login {
        id: Uuid,
        name: String,
        revision: String,
        #[serde(default)]
        deleted: bool,
        username: String,
        password: String,
        #[serde(default)]
        uris: Vec<String>,
        #[serde(default)]
        custom: Vec<CustomField>,
    },
    /// 笔记：Markdown 文本（轻量编辑 + 语法高亮，无预览）。
    #[serde(rename_all = "camelCase")]
    Note {
        id: Uuid,
        name: String,
        revision: String,
        #[serde(default)]
        deleted: bool,
        content: String,
    },
    /// 密钥：密钥值 + 用途/备注（可选）+ 过期时间（可选）。
    #[serde(rename_all = "camelCase")]
    Secret {
        id: Uuid,
        name: String,
        revision: String,
        #[serde(default)]
        deleted: bool,
        value: String,
        #[serde(default)]
        purpose: String,
        #[serde(default)]
        expires_at: Option<String>,
    },
    /// 文件：名称 + 备注 + 大小（字节）+ 类型 + 加密附件（≤50MB）。
    #[serde(rename_all = "camelCase")]
    File {
        id: Uuid,
        name: String,
        revision: String,
        #[serde(default)]
        deleted: bool,
        #[serde(default)]
        note: String,
        /// 附件大小（字节）。
        #[serde(default)]
        size: u64,
        /// MIME 类型。
        #[serde(default)]
        file_type: String,
        /// 附件文件名（展示用）。
        #[serde(default)]
        attachment: String,
        /// 附件 id（内部关联 `{attach_id}.attach.lk` 与分块）。
        #[serde(default, rename = "attachmentId")]
        attach_id: Option<Uuid>,
    },
}

impl Item {
    pub fn id(&self) -> Uuid {
        match self {
            Item::Login { id, .. }
            | Item::Note { id, .. }
            | Item::Secret { id, .. }
            | Item::File { id, .. } => *id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Item::Login { name, .. }
            | Item::Note { name, .. }
            | Item::Secret { name, .. }
            | Item::File { name, .. } => name,
        }
    }

    pub fn revision(&self) -> &str {
        match self {
            Item::Login { revision, .. }
            | Item::Note { revision, .. }
            | Item::Secret { revision, .. }
            | Item::File { revision, .. } => revision,
        }
    }

    pub fn deleted(&self) -> bool {
        match self {
            Item::Login { deleted, .. }
            | Item::Note { deleted, .. }
            | Item::Secret { deleted, .. }
            | Item::File { deleted, .. } => *deleted,
        }
    }

    pub fn kind(&self) -> ItemKind {
        match self {
            Item::Login { .. } => ItemKind::Login,
            Item::Note { .. } => ItemKind::Note,
            Item::Secret { .. } => ItemKind::Secret,
            Item::File { .. } => ItemKind::File,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Item::Login { name: n, .. }
            | Item::Note { name: n, .. }
            | Item::Secret { name: n, .. }
            | Item::File { name: n, .. } => *n = name,
        }
    }

    pub fn set_revision(&mut self, revision: String) {
        match self {
            Item::Login { revision: r, .. }
            | Item::Note { revision: r, .. }
            | Item::Secret { revision: r, .. }
            | Item::File { revision: r, .. } => *r = revision,
        }
    }

    pub fn set_deleted(&mut self, deleted: bool) {
        match self {
            Item::Login { deleted: d, .. }
            | Item::Note { deleted: d, .. }
            | Item::Secret { deleted: d, .. }
            | Item::File { deleted: d, .. } => *d = deleted,
        }
    }

    /// 条目密文 JSON（存入 `{uuid}.item.lk` 的载荷）。
    pub fn to_plaintext(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Item> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// 由草稿构造新条目（id/revision 由调用方注入）。
    pub fn from_draft(draft: ItemDraft, id: Uuid, revision: String) -> Item {
        match draft {
            ItemDraft::Login {
                name,
                username,
                password,
                uris,
                custom,
            } => Item::Login {
                id,
                name,
                revision,
                deleted: false,
                username,
                password,
                uris,
                custom,
            },
            ItemDraft::Note { name, content } => Item::Note {
                id,
                name,
                revision,
                deleted: false,
                content,
            },
            ItemDraft::Secret {
                name,
                value,
                purpose,
                expires_at,
            } => Item::Secret {
                id,
                name,
                revision,
                deleted: false,
                value,
                purpose,
                expires_at,
            },
            ItemDraft::File {
                name,
                note,
                size,
                file_type,
                attachment,
                attach_id,
                ..
            } => Item::File {
                id,
                name,
                revision,
                deleted: false,
                note,
                size,
                file_type,
                attachment,
                attach_id,
            },
        }
    }

    /// 条目 → 草稿（编辑表单回填用；file 保留附件关联）。
    pub fn into_draft(self) -> ItemDraft {
        match self {
            Item::Login {
                name,
                username,
                password,
                uris,
                custom,
                ..
            } => ItemDraft::Login {
                name,
                username,
                password,
                uris,
                custom,
            },
            Item::Note { name, content, .. } => ItemDraft::Note { name, content },
            Item::Secret {
                name,
                value,
                purpose,
                expires_at,
                ..
            } => ItemDraft::Secret {
                name,
                value,
                purpose,
                expires_at,
            },
            Item::File {
                name,
                note,
                size,
                file_type,
                attachment,
                attach_id,
                ..
            } => ItemDraft::File {
                name,
                note,
                size,
                file_type,
                attachment,
                attach_id,
                file_data: None,
            },
        }
    }

    /// 附件 id（file 类型）。
    pub fn attach_id(&self) -> Option<Uuid> {
        match self {
            Item::File { attach_id, .. } => *attach_id,
            _ => None,
        }
    }
}

/// 新建/编辑表单产出（除 id/revision/deleted 外的全部字段）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ItemDraft {
    Login {
        name: String,
        username: String,
        password: String,
        #[serde(default)]
        uris: Vec<String>,
        #[serde(default)]
        custom: Vec<CustomField>,
    },
    Note {
        name: String,
        content: String,
    },
    Secret {
        name: String,
        value: String,
        #[serde(default)]
        purpose: String,
        #[serde(default)]
        expires_at: Option<String>,
    },
    File {
        name: String,
        #[serde(default)]
        note: String,
        /// 附件大小（字节）；带 `file_data` 时由守护进程重新计算。
        #[serde(default)]
        size: u64,
        #[serde(default)]
        file_type: String,
        #[serde(default)]
        attachment: String,
        /// 附件 id（编辑时保留关联；新建时忽略）。
        #[serde(default, rename = "attachmentId")]
        attach_id: Option<Uuid>,
        /// 附件明文内容（base64，M0 单机整包上传 ≤50MB；M1 换分块协议）。
        #[serde(default, rename = "fileData")]
        file_data: Option<String>,
    },
}

impl ItemDraft {
    pub fn kind(&self) -> ItemKind {
        match self {
            ItemDraft::Login { .. } => ItemKind::Login,
            ItemDraft::Note { .. } => ItemKind::Note,
            ItemDraft::Secret { .. } => ItemKind::Secret,
            ItemDraft::File { .. } => ItemKind::File,
        }
    }

    /// file 草稿中的附件明文（base64 解码）。
    pub fn file_data(&self) -> Result<Option<Vec<u8>>> {
        use base64::Engine as _;
        match self {
            ItemDraft::File {
                file_data: None, ..
            } => Ok(None),
            ItemDraft::File {
                file_data: Some(b64),
                ..
            } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| Error::Other(format!("fileData base64 无效: {e}")))?;
                Ok(Some(bytes))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// 授权规则（M2；authorization-gate.md §4）
// ---------------------------------------------------------------------------

/// 规则能力类型：注入（默认；值披露裁决前的既有语义，spec value-disclosure §4）。
pub const RULE_CAPABILITY_INJECT: &str = "inject";
/// 规则能力类型：读值（M2.9 值披露；授权 socket 通道按名读条目）。
pub const RULE_CAPABILITY_READ: &str = "read";

/// 读规则 `capability` 的 serde 缺省（既有规则密文无该字段 → inject，无迁移）。
fn default_rule_capability() -> String {
    RULE_CAPABILITY_INJECT.to_string()
}

/// 授权门白名单规则（`docs/authorization-gate.md` §4，字段含 `name`——决策 #6）。
///
/// - 落盘：`{uuid}.rule.lk`，K_data 密封（[`SealType::Rule`](crate::crypto::SealType::Rule)）；
/// - 随库同步：经同一加密索引/轮询路径（[`ObjectKind::Rule`]，data-model.md §6）；
/// - 规则体内无 `revision`（规格字段集），修订号只在索引（[`IndexEntry`]）内；
/// - 唯一写入路径：`lk rule add`（CLI）+ 桌面规则管理页（M2 desktop）；
///   不开放手动改加密文件；规则变更写审计。
///
/// M2.9 值披露（value-disclosure.md §4）：`capability` 区分注入/读值，
/// **能力不互授**——inject 规则不授权读，read 规则不授权注入；带 serde
/// 缺省，既有规则密文反序列化不受影响。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: Uuid,
    /// 规范化绝对路径（`lk rule add` 时 canonicalize）。
    pub project_dir: String,
    /// 规则名（决策 #6；与前端 AuthRule.name 对齐）。
    pub name: String,
    /// 具名命令，可 glob（如 `npm publish` 精确、`npm *` 通配；大小写敏感）。
    /// capability=read 时为空串（读规则无命令绑定）。
    pub command: String,
    /// 授权注入的 key 名（最小集合）；capability=read 时语义为**可读条目名**
    /// （精确匹配，不做通配）。
    pub keys: Vec<String>,
    /// 规则能力类型：inject（注入，默认）| read（读值）。
    #[serde(default = "default_rule_capability")]
    pub capability: String,
    /// 创建时间（ISO-8601 UTC；替换时保留）。
    pub created: String,
}

/// 规则草稿（`rule.add` / 桌面规则页产出；id/created 由 vault 注入）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleDraft {
    pub project_dir: String,
    pub name: String,
    pub command: String,
    pub keys: Vec<String>,
    /// 规则能力类型（inject | read；缺省 inject，见 [`Rule::capability`] 语义）。
    #[serde(default = "default_rule_capability")]
    pub capability: String,
}

impl Rule {
    /// 规则密文 JSON（存入 `{uuid}.rule.lk` 的载荷）。
    pub fn to_plaintext(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Rule> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// 由草稿构造新规则（id/created 由调用方注入）。
    pub fn from_draft(draft: RuleDraft, id: Uuid, created: String) -> Rule {
        Rule {
            id,
            project_dir: draft.project_dir,
            name: draft.name,
            command: draft.command,
            keys: draft.keys,
            capability: draft.capability,
            created,
        }
    }
}

// ---------------------------------------------------------------------------
// 索引 / 墓碑 / 附件
// ---------------------------------------------------------------------------

/// vault 对象类型（索引覆盖条目与规则；M0 只产生条目；M2 起产生规则）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    Item,
    Rule,
}

/// 加密索引条目（`index.lk` 载荷元素；最小可索引字段，全部在密文内）。
/// 规则与条目同路径同步（data-model.md §6）：规则软删同样以 `deleted` 标记
/// + 墓碑传播（决策 #6：规则变更复用 `item.changed(kind="rule")`，含删除）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IndexEntry {
    pub id: Uuid,
    pub revision: String,
    #[serde(rename = "type")]
    pub kind: ObjectKind,
    #[serde(default)]
    pub deleted: bool,
}

/// 墓碑载荷（`{uuid}.tomb.lk`；软删除标记，含删除时间）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    pub id: Uuid,
    pub deleted_at: String,
    pub revision: String,
}

/// 附件元数据载荷（`{uuid}.attach.lk`；整体用 K_data 密封）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentMeta {
    /// 附件 id（与条目 id 独立；决定 attach.lk 与分块文件名）。
    pub id: Uuid,
    /// 文件名（展示用）。
    pub name: String,
    /// MIME 类型。
    pub mime: String,
    /// 大小（字节）。
    pub size: u64,
    /// 分块数（1 MiB/块）。
    pub chunks: u32,
    /// 加密的 K_attach（base64；K_data 密封，AAD=attach id）。
    #[serde(with = "crate::crypto::b64_fmt")]
    pub sealed_key: Vec<u8>,
    /// 创建时间（ISO-8601 UTC）。
    pub created: String,
}

/// 附件整包（导出/导入传输形态）。
pub struct AttachmentBundle {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub data: Vec<u8>,
}

/// 条目最小索引（`item.list` 响应元素，ipc.md §4）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ItemKind,
    pub revision: String,
    pub deleted: bool,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        ItemSummary {
            id: item.id(),
            name: item.name().to_string(),
            kind: item.kind(),
            revision: item.revision().to_string(),
            deleted: item.deleted(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev() -> String {
        crate::crypto::now_iso()
    }

    #[test]
    fn item_json_roundtrip_four_types() {
        let items = vec![
            Item::Login {
                id: Uuid::new_v4(),
                name: "GitHub".into(),
                revision: rev(),
                deleted: false,
                username: "octocat".into(),
                password: "s3cr3t".into(),
                uris: vec!["https://github.com".into()],
                custom: vec![CustomField {
                    name: "otp".into(),
                    value: "123456".into(),
                    hidden: true,
                }],
            },
            Item::Note {
                id: Uuid::new_v4(),
                name: "日记".into(),
                revision: rev(),
                deleted: false,
                content: "# 标题\n正文".into(),
            },
            Item::Secret {
                id: Uuid::new_v4(),
                name: "API key".into(),
                revision: rev(),
                deleted: false,
                value: "sk-xxx".into(),
                purpose: "生产".into(),
                expires_at: Some("2026-12-31".into()),
            },
            Item::File {
                id: Uuid::new_v4(),
                name: "合同.pdf".into(),
                revision: rev(),
                deleted: false,
                note: "扫描件".into(),
                size: 1024,
                file_type: "application/pdf".into(),
                attachment: "合同.pdf".into(),
                attach_id: Some(Uuid::new_v4()),
            },
        ];
        for item in items {
            let json = item.to_plaintext().unwrap();
            let back: Item = Item::from_plaintext(&json).unwrap();
            assert_eq!(back, item);
            // JSON 字段名符合前端约定
            let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(v["type"], serde_json::json!(item.kind().as_str()));
            assert!(v.get("revision").is_some());
            assert!(v.get("favorite").is_none(), "已砍收藏字段");
        }
    }

    #[test]
    fn draft_to_item_sets_invariants() {
        let draft = ItemDraft::Login {
            name: "x".into(),
            username: "u".into(),
            password: "p".into(),
            uris: vec![],
            custom: vec![],
        };
        let item = Item::from_draft(draft, Uuid::new_v4(), rev());
        assert!(!item.deleted());
        assert!(!item.revision().is_empty());
        let summary = ItemSummary::from(&item);
        assert_eq!(summary.kind, ItemKind::Login);
    }

    #[test]
    fn secret_edit_roundtrip_preserves_type() {
        let item = Item::Secret {
            id: Uuid::new_v4(),
            name: "k".into(),
            revision: rev(),
            deleted: false,
            value: "v".into(),
            purpose: "p".into(),
            expires_at: None,
        };
        let draft = item.clone().into_draft();
        let back = Item::from_draft(draft, item.id(), rev());
        assert_eq!(back.kind(), ItemKind::Secret);
        assert_eq!(back.name(), "k");
        assert_eq!(back.revision(), back.revision());
    }

    #[test]
    fn file_draft_carries_attachment_id_and_data() {
        let mut draft = ItemDraft::File {
            name: "f".into(),
            note: String::new(),
            size: 0,
            file_type: "text/plain".into(),
            attachment: "f.txt".into(),
            attach_id: Some(Uuid::new_v4()),
            file_data: Some("aGVsbG8=".into()),
        };
        assert_eq!(draft.file_data().unwrap().unwrap(), b"hello");
        if let ItemDraft::File { file_data, .. } = &mut draft {
            *file_data = None;
        }
        assert_eq!(draft.file_data().unwrap(), None);
    }

    #[test]
    fn attachment_meta_serialization() {
        use base64::Engine as _;
        let meta = AttachmentMeta {
            id: Uuid::new_v4(),
            name: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 42,
            chunks: 1,
            sealed_key: vec![7u8; 48],
            created: rev(),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(
            v["sealedKey"],
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(vec![7u8; 48]))
        );
        let back: AttachmentMeta = serde_json::from_value(v).unwrap();
        assert_eq!(back, meta);
    }

    // -- M2.9 值披露（补充拍板 #20）：Rule.capability ----------------------

    /// 既有规则密文（无 capability 字段）反序列化 → inject，无迁移。
    #[test]
    fn rule_legacy_json_without_capability_parses_as_inject() {
        let legacy = serde_json::json!({
            "id": Uuid::nil(),
            "projectDir": "/proj",
            "name": "publish",
            "command": "npm *",
            "keys": ["NPM_TOKEN"],
            "created": "2026-01-01T00:00:00.000000Z",
        });
        let rule: Rule = serde_json::from_value(legacy).unwrap();
        assert_eq!(rule.capability, RULE_CAPABILITY_INJECT);
    }

    /// capability 读写往返：read 规则密封/解密封后保持 read。
    #[test]
    fn rule_capability_roundtrip_through_plaintext() {
        let rule = Rule {
            id: Uuid::new_v4(),
            project_dir: "/proj".into(),
            name: "read-config".into(),
            command: String::new(),
            keys: vec!["DATABASE_URL".into()],
            capability: RULE_CAPABILITY_READ.into(),
            created: rev(),
        };
        let bytes = rule.to_plaintext().unwrap();
        let back = Rule::from_plaintext(&bytes).unwrap();
        assert_eq!(back, rule);
        assert_eq!(back.capability, RULE_CAPABILITY_READ);
    }
}
