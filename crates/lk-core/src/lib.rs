//! # lk-core —— LightKey 核心库
//!
//! 轻钥 LightKey 的能力中枢：**加密、数据模型、会话、恢复、审计** 与本地
//! IPC 协议类型。被两个消费者复用，保证行为一致：
//!
//! - `lk-cli`：命令行工具（含 `lk daemon` 守护进程宿主）
//! - `lk-app`：Tauri 2 桌面壳
//!
//! ## 模块与规格文档
//!
//! | 模块 | 职责 | 规格 |
//! |------|------|------|
//! | [`crypto`] | vault 头、KDF 派生、AEAD、自描述密文格式 | `docs/crypto.md` |
//! | [`model`] | 条目（四类 v2）/附件/索引/墓碑数据模型 | `docs/data-model.md` |
//! | [`vault`] | 落盘存储层：条目 CRUD、加密索引、CAS、软删除、初始化/恢复编排 | `docs/data-model.md`、`docs/recovery.md` |
//! | [`session`] | 会话令牌签发/校验/轮换 | `docs/ipc.md` |
//! | [`recovery`] | 恢复码、恢复信封、K_recovery 派生 | `docs/recovery.md` |
//! | [`audit`] | 追加式审计日志 + HMAC 防篡改、密钥轮换验证链 | `docs/audit.md` |
//! | [`ipc`] | JSON-RPC 2.0 协议类型、会话令牌、错误码 | `docs/ipc.md` |
//! | [`sync`] | BYO 变更发现、轮询、冲突收敛（M1） | `docs/sync.md` |
//! | [`authz`] | Agent 授权门三层模型、规则库、启动者判定（M2） | `docs/authorization-gate.md` |
//!
//! ## 里程碑状态
//!
//! M0（单机闭环）已实现：加密、四类条目 CRUD、CAS、墓碑、会话、恢复信封、
//! 审计、IPC 协议类型。M1 同步 / M2 授权门为占位模块。

pub mod audit;
pub mod authz;
pub mod crypto;
pub mod ipc;
pub mod model;
pub mod recovery;
pub mod session;
pub mod sync;
pub mod vault;

use std::io;

use thiserror::Error;
use uuid::Uuid;

/// crate 统一错误类型。
///
/// 解密失败统一为 [`Error::Decrypt`]，Display 文案固定为
/// 「密文被篡改或密钥错误」，不区分「密文损坏/密钥错误」（防 oracle，
/// `docs/crypto.md` §5）。
#[derive(Debug, Error)]
pub enum Error {
    /// 密文被篡改或密钥错误（统一文案，防 oracle）
    #[error("密文被篡改或密钥错误")]
    Decrypt,
    /// 密文容器格式无效（magic/版本/类型/长度不符）
    #[error("密文格式无效: {0}")]
    BadCiphertext(String),
    /// KDF 参数无效
    #[error("KDF 参数无效: {0}")]
    Kdf(String),
    /// 输入/输出错误
    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),
    /// JSON 序列化错误
    #[error("JSON 错误: {0}")]
    Json(#[from] serde_json::Error),
    /// 条目不存在
    #[error("条目不存在: {0}")]
    ItemNotFound(Uuid),
    /// CAS 冲突：base revision 与存储端当前 revision 不匹配
    #[error("条目已被其他设备修改（CAS 冲突）")]
    Conflict,
    /// 库已存在（`lk init` 在已初始化目录上执行）
    #[error("库已存在")]
    VaultExists,
    /// 库未初始化
    #[error("库未初始化")]
    NotInitialized,
    /// 超出规格限制（如附件 > 50MB）
    #[error("超出限制: {0}")]
    Limit(String),
    /// 恢复码格式/校验错误
    #[error("恢复码无效")]
    InvalidRecoveryCode,
    /// 解锁失败（主密码错误或库未初始化，统一文案）
    #[error("解锁失败（主密码错误或库未初始化）")]
    UnlockFailed,
    /// 会话令牌缺失/错误/过期（统一，防探测）
    #[error("会话无效")]
    SessionInvalid,
    /// 审计验证失败
    #[error("审计验证失败: {0}")]
    Audit(String),
    /// 其他业务错误
    #[error("{0}")]
    Other(String),
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Kdf(e.to_string())
    }
}

/// 便捷结果别名。
pub type Result<T> = std::result::Result<T, Error>;
