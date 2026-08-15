//! 恢复机制（规格：`docs/recovery.md`）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **恢复码**：高熵 40 字符（5 组 × 8，base32 风格防混淆字符集），含 1 位
//!   校验字符；仅展示一次，应用不记忆、不重新展示。
//! - **恢复信封** `recovery.envelope`：K_recovery = Argon2id(恢复码, 信封内
//!   独立随机 16B salt) 加密的 **MK 副本** + KDF 参数引用；信封可随库进
//!   BYO 云（零知识不破坏）。K_recovery 不在 MK 分叉之内（补充拍板 #1）。
//! - 恢复流程（恢复码 + 新主密码）编排在 [`crate::vault`]：
//!   解信封取回 MK → 新 salt 重派生 MK' → 后台重加密 → 审计密钥轮换链 →
//!   新恢复码新信封，旧信封作废。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, aad, b64_fmt, open, seal, KdfCost, KdfParams, SealType, MK_LEN};
use crate::{Error, Result};

/// 恢复码字符集（base32 风格防混淆：去掉 0/O/1/I/L）。
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// 恢复码总长（含 1 位校验）。
pub const CODE_LEN: usize = 40;
/// 每组字符数（5 组 × 8）。
const GROUP_LEN: usize = 8;
/// 随机字符数（40 - 1 位校验）。
const RAND_CHARS: usize = CODE_LEN - 1;

fn char_index(c: u8) -> Option<usize> {
    ALPHABET.iter().position(|&a| a == c)
}

/// 恢复码：39 随机字符 + 1 位校验字符 = 40 字符；展示为 5 组 × 8（`XXXX-…-XXXX`）。
///
/// 校验字符 = 前 39 个字符索引和 mod 32，可快速发现抄写错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// 生成新恢复码（CSPRNG）。
    pub fn generate() -> RecoveryCode {
        let mut chars = [0u8; CODE_LEN];
        for c in chars[..RAND_CHARS].iter_mut() {
            *c = ALPHABET[crypto::random_array::<1>()[0] as usize % 32];
        }
        let sum: usize = chars[..RAND_CHARS]
            .iter()
            .map(|&c| char_index(c).unwrap())
            .sum();
        chars[RAND_CHARS] = ALPHABET[sum % 32];
        RecoveryCode(String::from_utf8(chars.to_vec()).expect("字符集为 ASCII"))
    }

    /// 校验并解析用户输入（接受含 `-` 分隔或连写）。
    pub fn parse(input: &str) -> Result<RecoveryCode> {
        let cleaned: String = input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect();
        let bytes = cleaned.as_bytes();
        if bytes.len() != CODE_LEN {
            return Err(Error::InvalidRecoveryCode);
        }
        for &b in bytes {
            if char_index(b).is_none() {
                return Err(Error::InvalidRecoveryCode);
            }
        }
        let sum: usize = bytes[..RAND_CHARS]
            .iter()
            .map(|&c| char_index(c).unwrap())
            .sum();
        if bytes[RAND_CHARS] != ALPHABET[sum % 32] {
            return Err(Error::InvalidRecoveryCode);
        }
        Ok(RecoveryCode(cleaned))
    }

    /// 展示形态：5 组 × 8，`XXXX-XXXX-XXXX-XXXX-XXXX`。
    pub fn display(&self) -> String {
        let b = self.0.as_bytes();
        (0..5)
            .map(|g| String::from_utf8(b[g * GROUP_LEN..(g + 1) * GROUP_LEN].to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// 由恢复码 + Argon2id 派生信封密钥 K_recovery（32B，`Zeroizing` 擦除）。
pub fn derive_recovery_key(
    code: &RecoveryCode,
    params: &KdfParams,
) -> Result<Zeroizing<[u8; MK_LEN]>> {
    if params.algorithm != "argon2id" {
        return Err(Error::Kdf(format!("不支持的算法: {}", params.algorithm)));
    }
    let argon_params = argon2::Params::new(params.m, params.t, params.p, Some(MK_LEN))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut out = Zeroizing::new([0u8; MK_LEN]);
    argon
        .hash_password_into(code.as_str().as_bytes(), &params.salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

/// 恢复信封（`recovery.envelope`，JSON；内含密文与 KDF 参数，无任何密钥明文）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEnvelope {
    /// 格式类型，固定 `"lightkey.recovery-envelope"`。
    pub format: String,
    pub version: u32,
    /// 信封 KDF 参数（独立随机 salt；m/t/p 与主 KDF 一致，可演进）。
    pub kdf: KdfParams,
    /// 主 KDF 参数引用（便于升级重加密）。
    pub kdf_ref: KdfCost,
    /// 密封的 MK 副本（LKC1 env 容器，base64）。
    #[serde(with = "b64_fmt")]
    pub sealed: Vec<u8>,
}

/// 信封对象 id（AAD 用）。
pub const ENVELOPE_OBJECT_ID: &str = "recovery.envelope";

impl RecoveryEnvelope {
    /// 新建信封：恢复码 + 信封内独立随机 salt 派生 K_recovery，密封 MK 副本。
    pub fn build(
        code: &RecoveryCode,
        mk: &crypto::MasterKey,
        envelope_kdf: KdfParams,
        main_kdf_ref: KdfCost,
    ) -> Result<RecoveryEnvelope> {
        let k = derive_recovery_key(code, &envelope_kdf)?;
        let sealed = seal(
            k.as_ref(),
            SealType::Envelope,
            ENVELOPE_OBJECT_ID,
            mk.as_bytes(),
        );
        Ok(RecoveryEnvelope {
            format: "lightkey.recovery-envelope".to_string(),
            version: 1,
            kdf: envelope_kdf,
            kdf_ref: main_kdf_ref,
            sealed,
        })
    }

    /// 解信封：恢复码 → K_recovery → 取回 MK 副本。错误恢复码统一
    /// [`Error::Decrypt`]（与密文损坏同文案，防 oracle）。
    pub fn open(&self, code: &RecoveryCode) -> Result<crypto::MasterKey> {
        let k = derive_recovery_key(code, &self.kdf)?;
        let mk_bytes = open(
            k.as_ref(),
            SealType::Envelope,
            ENVELOPE_OBJECT_ID,
            &self.sealed,
        )?;
        if mk_bytes.len() != MK_LEN {
            return Err(Error::Decrypt);
        }
        let mut arr = [0u8; MK_LEN];
        arr.copy_from_slice(&mk_bytes);
        Ok(crypto::MasterKey(Zeroizing::new(arr)))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<RecoveryEnvelope> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// 信封文件的确定性 AAD 引用（与 [`ENVELOPE_OBJECT_ID`] 一致）。
pub fn envelope_aad() -> Vec<u8> {
    aad(SealType::Envelope, ENVELOPE_OBJECT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_shape_checksum_and_parse() {
        let code = RecoveryCode::generate();
        let display = code.display();
        assert_eq!(display.len(), 5 * 8 + 4);
        assert_eq!(display.matches('-').count(), 4);
        // 可往返解析（含分隔符）
        assert_eq!(RecoveryCode::parse(&display).unwrap(), code);
        // 连写也可解析
        let joined: String = display.chars().filter(|c| *c != '-').collect();
        assert_eq!(RecoveryCode::parse(&joined).unwrap(), code);
        // 单字符抄错 → 校验失败（大概率；穷举 40 位置 × 翻转）
        let mut any_accepted = false;
        for i in 0..CODE_LEN {
            for &alt in ALPHABET {
                let mut chars: Vec<u8> = joined.as_bytes().to_vec();
                if chars[i] == alt {
                    continue;
                }
                chars[i] = alt;
                if RecoveryCode::parse(&String::from_utf8(chars).unwrap()).is_ok() {
                    any_accepted = true;
                }
            }
        }
        assert!(!any_accepted, "任意单字符改动都应被校验拒绝");
        // 字符集外字符 / 长度不符 → 拒绝
        assert!(RecoveryCode::parse(&"0".repeat(40)).is_err());
        assert!(RecoveryCode::parse(&joined[..39]).is_err());
        assert!(RecoveryCode::parse(&format!("{joined}X")).is_err());
    }

    #[test]
    fn envelope_roundtrip_and_wrong_code() {
        let code = RecoveryCode::generate();
        let params = crypto::test_kdf_params();
        let mk = params.derive_master_key("主密码").unwrap();
        let mut env_kdf = crypto::test_kdf_params();
        env_kdf.salt = crypto::random_array(); // 信封独立 salt
        let envelope =
            RecoveryEnvelope::build(&code, &mk, env_kdf, KdfCost::from(&params)).unwrap();
        // 序列化往返
        let bytes = envelope.to_bytes().unwrap();
        let envelope2 = RecoveryEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(envelope2, envelope);
        // 正确恢复码 → MK 一致
        let mk2 = envelope2.open(&code).unwrap();
        assert_eq!(mk.as_bytes(), mk2.as_bytes());
        // 错误恢复码 → 统一 Decrypt
        let wrong = RecoveryCode::generate();
        assert!(matches!(envelope2.open(&wrong), Err(Error::Decrypt)));
    }
}
