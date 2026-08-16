//! 加密原语与密文格式（规格：`docs/crypto.md`）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **vault 头**：随机 16 字节 salt + KDF 参数（可演进字段）+ 密文格式类型/版本号。
//! - **主密钥派生**：Argon2id(m=64MiB, t=3, p=4)（由主密码）。
//! - **密钥分叉**：HKDF-SHA256 仅分叉两把互不复用的密钥——数据加密密钥
//!   K_data 与审计 HMAC 密钥 K_audit；恢复信封密钥 K_recovery 不在 MK
//!   分叉之内，由恢复码 + Argon2id 独立派生（见 docs/crypto.md 与
//!   docs/decisions.md 补充拍板 #1）。
//! - **原语**：AES-256-GCM，刻意不用 Bitwarden 的 CBC+HMAC 组合。
//! - **自描述密文**：`LKC1` magic + 版本 + 类型 + 随机 nonce 的密文容器，
//!   支持演进与迁移；AAD = 类型 + 对象 id，防换位。
//! - 解密失败统一「密文被篡改或密钥错误」，不区分错误类型（防 oracle）。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::BorrowedFormatItem;
use zeroize::Zeroizing;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// KDF 内存代价（Argon2 以 KiB 计）：64 MiB。
pub const KDF_M_KIB: u32 = 64 * 1024;
/// KDF 时间代价。
pub const KDF_T: u32 = 3;
/// KDF 并行度。
pub const KDF_P: u32 = 4;
/// KDF salt 长度：16 字节随机。
pub const KDF_SALT_LEN: usize = 16;
/// 主密钥长度：32 字节。
pub const MK_LEN: usize = 32;
/// AES-GCM nonce 长度：12 字节。
pub const NONCE_LEN: usize = 12;
/// 密文容器 magic："LKC1"。
pub const MAGIC: &[u8; 4] = b"LKC1";
/// 密文容器格式版本。
pub const FORMAT_VERSION: u8 = 1;

/// 生产 KDF 参数（Argon2id，64MiB/3/4，salt 随机 16B）。
pub fn default_kdf_params() -> KdfParams {
    KdfParams {
        algorithm: "argon2id".to_string(),
        m: KDF_M_KIB,
        t: KDF_T,
        p: KDF_P,
        salt: random_array(),
    }
}

/// 测试用低代价 KDF 参数（仅测试，避免 64MiB 拉慢属性测试）。
#[doc(hidden)]
pub fn test_kdf_params() -> KdfParams {
    KdfParams {
        algorithm: "argon2id".to_string(),
        m: 8,
        t: 1,
        p: 1,
        salt: random_array(),
    }
}

// ---------------------------------------------------------------------------
// serde 辅助：hex 编码的定长字节数组
// ---------------------------------------------------------------------------

/// hex 字符串形式的定长字节数组（salt / 密钥指纹等）。
pub mod hex_fmt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        v: &[u8; N],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> std::result::Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; N] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("hex 长度与期望不符"))?;
        Ok(arr)
    }
}

/// base64 字符串形式的字节串。
pub mod b64_fmt {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// KDF 参数与主密钥派生
// ---------------------------------------------------------------------------

/// KDF 参数（**可演进字段**，写入 vault 头；未来提升代价无需迁移数据）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// 算法名，固定 `"argon2id"`。
    pub algorithm: String,
    /// 内存代价（KiB）。
    pub m: u32,
    /// 时间代价。
    pub t: u32,
    /// 并行度。
    pub p: u32,
    /// 16 字节随机 salt（每个库唯一）。
    #[serde(with = "hex_fmt")]
    pub salt: [u8; KDF_SALT_LEN],
}

/// KDF 代价参数（不含 salt）——恢复信封内「主 KDF 参数引用」用。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfCost {
    pub algorithm: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl From<&KdfParams> for KdfCost {
    fn from(p: &KdfParams) -> Self {
        KdfCost {
            algorithm: p.algorithm.clone(),
            m: p.m,
            t: p.t,
            p: p.p,
        }
    }
}

impl KdfParams {
    /// 派生主密钥 MK（32B）。KDF 参数可演进：未来提升代价时旧库按头内参数派生。
    pub fn derive_master_key(&self, password: &str) -> Result<MasterKey> {
        if self.algorithm != "argon2id" {
            return Err(Error::Kdf(format!("不支持的算法: {}", self.algorithm)));
        }
        let params = Params::new(self.m, self.t, self.p, Some(MK_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; MK_LEN]);
        argon
            .hash_password_into(password.as_bytes(), &self.salt, out.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(MasterKey(out))
    }
}

/// 主密钥 MK（32B）。内存中 `Zeroizing` 包装，Drop 即擦除。
pub struct MasterKey(pub Zeroizing<[u8; MK_LEN]>);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; MK_LEN] {
        &self.0
    }

    /// HKDF-SHA256 分叉两把功能密钥：K_data（数据加密）与 K_audit（审计 HMAC）。
    pub fn derive_keys(&self) -> Keys {
        let hk = Hkdf::<Sha256>::new(None, self.0.as_ref());
        let mut k_data = Zeroizing::new([0u8; MK_LEN]);
        let mut k_audit = Zeroizing::new([0u8; MK_LEN]);
        // 各自独立 info 标签，互不复用（HKDF 提取一次、扩展两次）。
        hk.expand(b"lightkey:v1:k_data", k_data.as_mut())
            .expect("HKDF 输出长度 32B 在 SHA-256 限制内");
        hk.expand(b"lightkey:v1:k_audit", k_audit.as_mut())
            .expect("HKDF 输出长度 32B 在 SHA-256 限制内");
        Keys { k_data, k_audit }
    }
}

/// 两把功能密钥（K_data / K_audit），`Zeroizing` 内存擦除。
/// `Clone`：同步引擎阶段 1 以密钥快照工作（守护进程侧网络 I/O 不持锁）。
#[derive(Clone)]
pub struct Keys {
    pub k_data: Zeroizing<[u8; MK_LEN]>,
    pub k_audit: Zeroizing<[u8; MK_LEN]>,
}

impl Keys {
    /// 从 MK 派生（正常路径）。
    pub fn derive(mk: &MasterKey) -> Keys {
        mk.derive_keys()
    }

    /// 从显式字节构造（测试用）。
    pub fn from_raw(k_data: [u8; MK_LEN], k_audit: [u8; MK_LEN]) -> Keys {
        Keys {
            k_data: Zeroizing::new(k_data),
            k_audit: Zeroizing::new(k_audit),
        }
    }

    /// 审计密钥指纹：SHA-256(K_audit) 前 8 字节 hex（不含密钥材料）。
    pub fn audit_key_id(&self) -> String {
        key_id(self.k_audit.as_ref())
    }
}

/// 密钥指纹：SHA-256(key) 前 8 字节 hex（仅标识，不含密钥材料）。
pub fn key_id(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

// ---------------------------------------------------------------------------
// 自描述密文容器
// ---------------------------------------------------------------------------

/// 密文容器类型（1 字节，演进时增补；AAD 亦含类型，防换位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SealType {
    /// 条目 `{uuid}.item.lk`
    Item = 1,
    /// 加密索引 `index.lk`
    Index = 2,
    /// 附件元数据 `{uuid}.attach.lk`
    Attach = 3,
    /// 恢复信封 `recovery.envelope`
    Envelope = 4,
    /// 墓碑 `{uuid}.tomb.lk`
    Tombstone = 5,
    /// 附件分块 `{uuid}.{i}.chunk.lk`
    Chunk = 6,
    /// vault 头内密钥校验值（KCV）
    Check = 7,
    /// 规则 `{uuid}.rule.lk`（M2 新增；既有类型字节不变，零回归）
    Rule = 8,
}

impl SealType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<SealType> {
        match v {
            1 => Some(SealType::Item),
            2 => Some(SealType::Index),
            3 => Some(SealType::Attach),
            4 => Some(SealType::Envelope),
            5 => Some(SealType::Tombstone),
            6 => Some(SealType::Chunk),
            7 => Some(SealType::Check),
            8 => Some(SealType::Rule),
            _ => None,
        }
    }

    /// AAD 中的类型标签。
    pub fn as_str(self) -> &'static str {
        match self {
            SealType::Item => "item",
            SealType::Index => "index",
            SealType::Attach => "attach",
            SealType::Envelope => "env",
            SealType::Tombstone => "tomb",
            SealType::Chunk => "chunk",
            SealType::Check => "check",
            SealType::Rule => "rule",
        }
    }
}

/// 构建 AAD = `类型:对象 id`（防换位；附件分块为 `chunk:{attach_id}:{i}`）。
pub fn aad(kind: SealType, object_id: &str) -> Vec<u8> {
    format!("{}:{}", kind.as_str(), object_id).into_bytes()
}

/// 密封：随机 12B nonce + AES-256-GCM；容器 = magic(4) + ver(1) + type(1) + nonce(12) + ct+tag。
pub fn seal(key: &[u8], kind: SealType, object_id: &str, plaintext: &[u8]) -> Vec<u8> {
    let nonce = random_array::<NONCE_LEN>();
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let aad = aad(kind, object_id);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-256-GCM 加密不会因长度失败");
    let mut out = Vec::with_capacity(4 + 1 + 1 + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kind.as_u8());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// 打开密封容器。任何不符（magic/版本/类型/长度/认证失败）统一返回
/// [`Error::Decrypt`]（「密文被篡改或密钥错误」，防 oracle）。
pub fn open(key: &[u8], expected_kind: SealType, object_id: &str, blob: &[u8]) -> Result<Vec<u8>> {
    const HEADER: usize = 4 + 1 + 1 + NONCE_LEN;
    if blob.len() < HEADER + 16 || &blob[..4] != MAGIC {
        return Err(Error::Decrypt);
    }
    if blob[4] != FORMAT_VERSION {
        return Err(Error::Decrypt);
    }
    if blob[5] != expected_kind.as_u8() {
        return Err(Error::Decrypt);
    }
    let nonce = Nonce::from_slice(&blob[6..6 + NONCE_LEN]);
    let ct = &blob[HEADER..];
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let aad = aad(expected_kind, object_id);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| Error::Decrypt)
}

// ---------------------------------------------------------------------------
// Vault 头
// ---------------------------------------------------------------------------

/// 密文格式声明（vault 头内）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextFormat {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: u32,
}

/// Vault 头（`vault.json`，库级明文最小集：不含任何内容明文）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultHeader {
    /// 格式类型（magic 域名），固定 `"lightkey.vault"`。
    pub format: String,
    /// 格式版本号。
    pub version: u32,
    /// KDF 参数（可演进）。
    pub kdf: KdfParams,
    pub ciphertext_format: CiphertextFormat,
    /// 恢复信封文件名引用。
    pub recovery_envelope_ref: String,
    /// 密钥校验值（KCV）：用 K_data 密封的固定挑战，解锁时校验主密码。
    /// 只有密文，不泄漏任何密钥材料；空库也能正确拒绝错误密码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_check: Option<String>,
    /// 创建时间（ISO-8601 UTC）。
    pub created: String,
}

/// KCV 固定挑战明文与对象 id。
pub const KEY_CHECK_PLAINTEXT: &[u8] = b"lightkey:v1:key-check";
pub const KEY_CHECK_OBJECT_ID: &str = "vault.check";

impl VaultHeader {
    /// 新建 vault 头（随机 salt + 密钥校验值）。
    pub fn new(kdf: KdfParams, k_data: &[u8]) -> VaultHeader {
        use base64::Engine as _;
        let key_check = seal(
            k_data,
            SealType::Check,
            KEY_CHECK_OBJECT_ID,
            KEY_CHECK_PLAINTEXT,
        );
        VaultHeader {
            format: "lightkey.vault".to_string(),
            version: 1,
            kdf,
            ciphertext_format: CiphertextFormat {
                kind: "aes-256-gcm".to_string(),
                version: 1,
            },
            recovery_envelope_ref: "recovery.envelope".to_string(),
            key_check: Some(base64::engine::general_purpose::STANDARD.encode(key_check)),
            created: now_iso(),
        }
    }

    /// 校验 KCV：主密码派生出的 K_data 能否打开密钥校验值。
    pub fn verify_key(&self, k_data: &[u8]) -> bool {
        match &self.key_check {
            Some(b64) => {
                use base64::Engine as _;
                match base64::engine::general_purpose::STANDARD.decode(b64) {
                    Ok(blob) => open(k_data, SealType::Check, KEY_CHECK_OBJECT_ID, &blob).is_ok(),
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    /// 重建 KCV（恢复流程换钥后）。
    pub fn refresh_key_check(&mut self, k_data: &[u8]) {
        use base64::Engine as _;
        let key_check = seal(
            k_data,
            SealType::Check,
            KEY_CHECK_OBJECT_ID,
            KEY_CHECK_PLAINTEXT,
        );
        self.key_check = Some(base64::engine::general_purpose::STANDARD.encode(key_check));
    }
}

// ---------------------------------------------------------------------------
// 时间 / 随机
// ---------------------------------------------------------------------------

static ISO_FMT: std::sync::OnceLock<&'static [BorrowedFormatItem<'static>]> =
    std::sync::OnceLock::new();

fn iso_fmt() -> &'static [BorrowedFormatItem<'static>] {
    ISO_FMT.get_or_init(|| {
        time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
        )
    })
}

/// 当前时间 ISO-8601 UTC，固定微秒精度（`...123456Z`），字典序即时间序。
pub fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(iso_fmt())
        .expect("ISO 格式固定，不会失败")
}

/// 在 ISO 时间串上加 1 微秒（保证 revision 严格递增）。
pub fn bump_iso(iso: &str) -> String {
    let parsed = parse_iso(iso).unwrap_or_else(time::OffsetDateTime::now_utc);
    (parsed + time::Duration::microseconds(1))
        .format(iso_fmt())
        .expect("ISO 格式固定，不会失败")
}

/// 解析 ISO-8601 UTC 时间串（兼容 `...123456Z` 微秒格式；失败返回 None）。
pub fn parse_iso(iso: &str) -> Option<time::OffsetDateTime> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(iso, &Rfc3339).ok()
}

/// 测试注时用：以与 [`now_iso`] 相同的固定格式格式化时间（仅测试）。
#[doc(hidden)]
pub fn iso_fmt_for_tests() -> &'static [BorrowedFormatItem<'static>] {
    iso_fmt()
}

/// 随机 `N` 字节（CSPRNG）。
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// 随机字节串（CSPRNG）。
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// 随机 UUID v4（`Uuid::new_v4()` 设置 version/variant 位，符合 data-model.md）。
pub fn random_uuid() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_default_params_are_argon2id_64mib() {
        let p = default_kdf_params();
        assert_eq!(p.algorithm, "argon2id");
        assert_eq!(p.m, 64 * 1024);
        assert_eq!(p.t, 3);
        assert_eq!(p.p, 4);
        assert_eq!(p.salt.len(), KDF_SALT_LEN);
    }

    #[test]
    fn master_key_derivation_and_fork() {
        let params = test_kdf_params();
        let mk = params.derive_master_key("hunter2").unwrap();
        assert_eq!(mk.as_bytes().len(), MK_LEN);
        let keys = mk.derive_keys();
        // 两把密钥不同（互不复用）
        assert_ne!(keys.k_data.as_ref(), keys.k_audit.as_ref());
        // 同密码同 salt → 同 MK；不同 salt → 不同 MK
        let mk2 = params.derive_master_key("hunter2").unwrap();
        assert_eq!(mk.as_bytes(), mk2.as_bytes());
        let mut p2 = params.clone();
        p2.salt = random_array();
        let mk3 = p2.derive_master_key("hunter2").unwrap();
        assert_ne!(mk.as_bytes(), mk3.as_bytes());
    }

    #[test]
    fn key_ids_are_stable_and_distinct() {
        let mk = test_kdf_params().derive_master_key("pw").unwrap();
        let keys = mk.derive_keys();
        assert_eq!(keys.audit_key_id(), keys.audit_key_id());
        let mk2 = test_kdf_params().derive_master_key("pw2").unwrap();
        assert_ne!(keys.audit_key_id(), mk2.derive_keys().audit_key_id());
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = random_array::<32>();
        let pt = "hello lightkey, 你好".as_bytes();
        let blob = seal(&key, SealType::Item, "obj-1", pt);
        assert_eq!(&blob[..4], MAGIC);
        assert_eq!(blob[4], FORMAT_VERSION);
        assert_eq!(blob[5], SealType::Item.as_u8());
        let opened = open(&key, SealType::Item, "obj-1", &blob).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn open_fails_on_tamper_wrong_key_wrong_aad_wrong_type() {
        let key = random_array::<32>();
        let pt = b"payload";
        let blob = seal(&key, SealType::Item, "obj-1", pt);
        // 任意字节翻转 → 失败
        let mut tampered = blob.clone();
        let i = tampered.len() / 2;
        tampered[i] ^= 0x01;
        assert!(matches!(
            open(&key, SealType::Item, "obj-1", &tampered),
            Err(Error::Decrypt)
        ));
        // 错误密钥 → 失败
        let key2 = random_array::<32>();
        assert!(matches!(
            open(&key2, SealType::Item, "obj-1", &blob),
            Err(Error::Decrypt)
        ));
        // 错误 AAD（换对象）→ 失败
        assert!(matches!(
            open(&key, SealType::Item, "obj-2", &blob),
            Err(Error::Decrypt)
        ));
        // 类型不符 → 失败
        assert!(matches!(
            open(&key, SealType::Index, "obj-1", &blob),
            Err(Error::Decrypt)
        ));
        // 截断 → 失败
        assert!(matches!(
            open(&key, SealType::Item, "obj-1", &blob[..10]),
            Err(Error::Decrypt)
        ));
        // 全部统一为 Decrypt，无其它变体
    }

    #[test]
    fn nonces_are_unique_across_seals() {
        let key = random_array::<32>();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let blob = seal(&key, SealType::Item, "obj", b"x");
            seen.insert(blob[6..6 + NONCE_LEN].to_vec());
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn now_iso_is_lexicographically_sortable() {
        let a = now_iso();
        let b = bump_iso(&a);
        assert!(a < b);
        assert_eq!(b.len(), a.len());
        assert!(a.ends_with('Z'));
    }
}
