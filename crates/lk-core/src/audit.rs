//! 审计日志（规格：`docs/audit.md`）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **本地追加式**日志：只允许追加，不允许就地修改/删除；默认永久保留。
//! - 记录「密钥/敏感操作被谁、何时、如何请求」的元数据；**密钥值永不明文**。
//! - 每条事件 `hmac = HMAC-SHA256(K_audit, canonical(event))`；`canonical` 为
//!   事件字段的确定性序列化（字段排序固定）。
//! - **审计密钥轮换验证链**（补充拍板 #2）：切换前用旧 K_audit 追加签名一条
//!   「审计密钥轮换」事件（`oldKeyId`/`newKeyId`）；新密钥验证轮换点之后的新
//!   事件，旧事件通过链条追溯到轮换事件——旧日志全程可验证。
//! - 守护进程是唯一写入方；查询只读；文件权限 0600。
//!
//! M0 边界：解锁失败发生在密钥可用之前（未解锁态无法派生 K_audit），因此
//! 失败解锁**不落审计**（由 `vault.unlock` 限流兜底，见 `docs/ipc.md` §6）；
//! 解锁成功与之后的一切敏感操作均在解锁态签名留痕。

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::crypto::{key_id, now_iso, random_uuid, Keys, MK_LEN};
use crate::{Error, Result};
use zeroize::Zeroizing;

/// 审计文件名（用户数据目录，权限 0600）。
pub const AUDIT_FILE: &str = "audit.log";

/// 敏感参数脱敏占位符。
pub const REDACTED: &str = "<redacted>";

/// 事件结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Allowed,
    Denied,
    Timeout,
}

/// 来源通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditChannel {
    Cli,
    Desktop,
    Approval,
    /// WSL 内客户端经 interop stdio 桥（cross-subsystem.md §7.5；
    /// 补充拍板 #14）。
    #[serde(rename = "wsl-bridge")]
    WslBridge,
    /// E2E 自动批准通道（`LIGHTKEY_E2E_AUTO_APPROVE=rule`，仅规则审批立即
    /// 放行；补充拍板 #22）——测试通道绝不静默：经此放行的规则变更以本
    /// 通道留痕，command 含 requestId 与规则内容。
    #[serde(rename = "auto-approve")]
    AutoApprove,
}

/// 审计事件（D11 字段集；轮换事件扩展 `oldKeyId`/`newKeyId`）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub event_id: Uuid,
    /// ISO-8601 UTC。
    pub ts: String,
    /// 启动者进程（M0：客户端进程名；M2 起为进程链回溯结果）。
    pub starter: String,
    /// 目标程序（M0：daemon）。
    pub target: String,
    /// 命令摘要（敏感参数一律 `<redacted>`）。
    pub command: String,
    pub result: AuditResult,
    pub channel: AuditChannel,
    /// 审计密钥轮换事件专用（旧密钥指纹）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_key_id: Option<String>,
    /// 审计密钥轮换事件专用（新密钥指纹）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key_id: Option<String>,
    /// `HMAC-SHA256(K_audit, canonical(event))`，base64。
    pub hmac: String,
}

impl AuditEvent {
    /// 是否为审计密钥轮换事件。
    pub fn is_rotation(&self) -> bool {
        self.old_key_id.is_some() && self.new_key_id.is_some()
    }

    /// canonical 字节：除 `hmac` 外的全部字段，确定性序列化
    /// （serde_json 默认 Map 为有序 BTreeMap，键序固定）。
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.hmac = String::new();
        Ok(serde_json::to_vec(&clone)?)
    }

    /// 用指定 K_audit 校验本事件 HMAC。
    pub fn verify_hmac(&self, k_audit: &[u8]) -> Result<()> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(k_audit)
            .map_err(|e| Error::Audit(e.to_string()))?;
        mac.update(&self.canonical_bytes()?);
        let expected = mac.finalize().into_bytes();
        let actual = base64::engine::general_purpose::STANDARD
            .decode(&self.hmac)
            .map_err(|e| Error::Audit(format!("hmac 非 base64: {e}")))?;
        if expected.as_slice() == actual.as_slice() {
            Ok(())
        } else {
            Err(Error::Audit(format!(
                "事件 {} HMAC 校验失败",
                self.event_id
            )))
        }
    }
}

/// 事件输入（不含 eventId/ts/hmac，由日志生成）。
#[derive(Debug, Clone)]
pub struct EventInput {
    pub starter: String,
    pub target: String,
    pub command: String,
    pub result: AuditResult,
    pub channel: AuditChannel,
    pub old_key_id: Option<String>,
    pub new_key_id: Option<String>,
}

impl EventInput {
    /// 常规事件。
    pub fn new(starter: &str, command: &str, result: AuditResult) -> EventInput {
        EventInput {
            starter: starter.to_string(),
            target: "daemon".to_string(),
            command: command.to_string(),
            result,
            channel: AuditChannel::Cli,
            old_key_id: None,
            new_key_id: None,
        }
    }

    /// 审计密钥轮换事件（由旧 K_audit 签名）。
    pub fn rotation(old_key_id: &str, new_key_id: &str) -> EventInput {
        EventInput {
            starter: "recovery".to_string(),
            target: "daemon".to_string(),
            command: "audit-key-rotation".to_string(),
            result: AuditResult::Allowed,
            channel: AuditChannel::Cli,
            old_key_id: Some(old_key_id.to_string()),
            new_key_id: Some(new_key_id.to_string()),
        }
    }
}

/// 追加式审计日志（守护进程唯一写入方）。
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// 打开/创建审计日志（0600，追加式）。
    pub fn open(dir: &Path) -> Result<AuditLog> {
        let path = dir.join(AUDIT_FILE);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            // 目录本身应 0700（由调用方保证），文件 0600 兜底
        }
        drop(f);
        Ok(AuditLog { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一条事件：HMAC 签名 → 落盘（fsync）→ 返回完整事件。
    /// 写失败上报错误，不静默丢失。
    pub fn append(&self, keys: &Keys, input: &EventInput) -> Result<AuditEvent> {
        let event = self.build_event(keys, input)?;
        let line = serde_json::to_vec(&event)?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        Ok(event)
    }

    fn build_event(&self, keys: &Keys, input: &EventInput) -> Result<AuditEvent> {
        let mut event = AuditEvent {
            event_id: random_uuid(),
            ts: now_iso(),
            starter: input.starter.clone(),
            target: input.target.clone(),
            command: input.command.clone(),
            result: input.result,
            channel: input.channel,
            old_key_id: input.old_key_id.clone(),
            new_key_id: input.new_key_id.clone(),
            hmac: String::new(),
        };
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(keys.k_audit.as_ref())
            .map_err(|e| Error::Audit(e.to_string()))?;
        mac.update(&event.canonical_bytes()?);
        event.hmac = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Ok(event)
    }

    /// 读取全部事件（只读；不校验）。
    pub fn read(&self) -> Result<Vec<AuditEvent>> {
        let f = File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }

    /// 校验事件数（含轮换链语义）。
    pub fn count(&self) -> Result<usize> {
        Ok(self.read()?.len())
    }

    /// 全链校验：
    ///
    /// - 用 `initial`（当前/初始 K_audit）验证事件；遇到轮换事件时先以旧钥
    ///   验证（并核对 `oldKeyId`），再经 `resolve(newKeyId)` 切换到新钥续验。
    /// - 返回成功验证的事件数。
    /// - 轮换后旧事件需提供对应旧密钥（恢复流程后守护进程仅持新钥，此时
    ///   轮换前的旧事件无法验证——`lk audit --verify` 会如实报告）。
    /// - `resolve` 按 keyId 返回 K_audit 副本（验证用，调用方负责生命周期）。
    pub fn verify(
        &self,
        initial: &Keys,
        resolve: &dyn Fn(&str) -> Option<Zeroizing<[u8; MK_LEN]>>,
    ) -> Result<usize> {
        let events = self.read()?;
        let mut current = Zeroizing::new(*initial.k_audit);
        let mut verified = 0usize;
        for event in &events {
            if event.is_rotation() {
                let old_id = event.old_key_id.as_deref().unwrap_or_default();
                if key_id(current.as_ref()) != old_id {
                    return Err(Error::Audit(format!(
                        "轮换事件 {} 的 oldKeyId 与当前密钥不符",
                        event.event_id
                    )));
                }
                event.verify_hmac(current.as_ref())?;
                let new_id = event.new_key_id.as_deref().unwrap_or_default();
                let next = resolve(new_id)
                    .ok_or_else(|| Error::Audit(format!("缺少新密钥 {} 无法继续验证", new_id)))?;
                if key_id(next.as_ref()) != new_id {
                    return Err(Error::Audit(format!(
                        "解析出的密钥与 newKeyId {} 不符",
                        new_id
                    )));
                }
                current = next;
            } else {
                event.verify_hmac(current.as_ref())?;
            }
            verified += 1;
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_kdf_params;

    fn temp_log(_name: &str) -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        (dir, log)
    }

    #[test]
    fn append_read_and_verify() {
        let (_dir, log) = temp_log("audit1");
        let keys = test_kdf_params()
            .derive_master_key("pw")
            .unwrap()
            .derive_keys();
        let e = log
            .append(
                &keys,
                &EventInput::new("lk", "vault.unlock", AuditResult::Allowed),
            )
            .unwrap();
        assert!(!e.hmac.is_empty());
        log.append(
            &keys,
            &EventInput::new("lk", "item.get <redacted>", AuditResult::Allowed),
        )
        .unwrap();
        assert_eq!(log.count().unwrap(), 2);
        assert_eq!(log.verify(&keys, &|_| None).unwrap(), 2);
    }

    #[test]
    fn tamper_detected() {
        let (_dir, log) = temp_log("audit2");
        let keys = test_kdf_params()
            .derive_master_key("pw")
            .unwrap()
            .derive_keys();
        log.append(
            &keys,
            &EventInput::new("lk", "vault.unlock", AuditResult::Allowed),
        )
        .unwrap();
        let path = log.path().to_path_buf();
        let mut content = std::fs::read(&path).unwrap();
        // 翻转 command 字段中的一个字节（保持 JSON 合法，HMAC 必失败）
        let idx = content
            .windows(b"vault.unlock".len())
            .position(|w| w == b"vault.unlock")
            .unwrap()
            + 2;
        content[idx] ^= 0x01;
        std::fs::write(&path, &content).unwrap();
        assert!(matches!(log.verify(&keys, &|_| None), Err(Error::Audit(_))));
    }

    #[test]
    fn canonical_is_deterministic() {
        let (_dir, log) = temp_log("audit3");
        let keys = test_kdf_params()
            .derive_master_key("pw")
            .unwrap()
            .derive_keys();
        let input = EventInput::new("lk", "item.put", AuditResult::Allowed);
        let e1 = log.build_event(&keys, &input).unwrap();
        let e2 = log.build_event(&keys, &input).unwrap();
        // 不同 eventId/ts → canonical 不同；同事件 canonical 字节稳定
        assert_ne!(e1.canonical_bytes().unwrap(), e2.canonical_bytes().unwrap());
        assert_eq!(e1.canonical_bytes().unwrap(), e1.canonical_bytes().unwrap());
    }

    #[test]
    fn rotation_chain_verifies_with_old_and_new_keys() {
        let (_dir, log) = temp_log("audit4");
        let old_keys = test_kdf_params()
            .derive_master_key("old")
            .unwrap()
            .derive_keys();
        let new_keys = test_kdf_params()
            .derive_master_key("new")
            .unwrap()
            .derive_keys();

        // 轮换前事件（旧钥）
        log.append(
            &old_keys,
            &EventInput::new("lk", "vault.unlock", AuditResult::Allowed),
        )
        .unwrap();
        // 轮换事件（旧钥签名）
        log.append(
            &old_keys,
            &EventInput::rotation(&old_keys.audit_key_id(), &new_keys.audit_key_id()),
        )
        .unwrap();
        // 轮换后事件（新钥）
        log.append(
            &new_keys,
            &EventInput::new("lk", "item.list", AuditResult::Allowed),
        )
        .unwrap();

        // 全链可验证（提供新旧两把钥）
        let new_id = new_keys.audit_key_id();
        let new_k = *new_keys.k_audit;
        let resolve = move |id: &str| -> Option<Zeroizing<[u8; MK_LEN]>> {
            if id == new_id {
                Some(Zeroizing::new(new_k))
            } else {
                None
            }
        };
        let n = log.verify(&old_keys, &resolve).unwrap();
        assert_eq!(n, 3);
        // 只持新钥：轮换点之前的事件无法验证（如实报错）
        assert!(log.verify(&new_keys, &|_| None).is_err());
    }
}
