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
//! ### A 层 · 数据平面（安全核心，trait 服务 + 事件总线，`docs/plugin-architecture.md` §3.1）
//!
//! | 插件 | 模块 | 规格 |
//! |------|------|------|
//! | crypto | [`crypto`] | vault 头、KDF 派生、AEAD、自描述密文格式 | `docs/crypto.md` |
//! | vault-store | [`vault`] | 落盘存储层：条目 CRUD、加密索引、CAS、软删除、初始化/恢复编排 | `docs/data-model.md`、`docs/recovery.md` |
//! | recovery | [`recovery`] | 恢复码、恢复信封、K_recovery 派生 | `docs/recovery.md` |
//! | audit | [`audit`] | 追加式审计日志 + HMAC 防篡改、密钥轮换验证链 | `docs/audit.md` |
//! | session | [`session`] | 会话令牌签发/校验/轮换 | `docs/ipc.md` |
//!
//! ### B 层 · 能力域
//!
//! | 插件 | 模块 | 规格 |
//! |------|------|------|
//! | storage-backend | [`storage`] | BYO 存储后端抽象：本地模拟 / WebDAV / S3（可插拔 trait） | `docs/sync.md` |
//! | sync-engine | [`sync`] | BYO 变更发现、轮询、冲突收敛 | `docs/sync.md` |
//! | authz-gate | [`authz`] | Agent 授权门三层模型、规则库、审批通道 | `docs/authorization-gate.md` |
//! | starter | [`starter`] | 启动者判定：IPC 对端 PID 进程链回溯 + cwd（fail-closed） | `docs/authorization-gate.md` §3 |
//! | path-ns | [`path_ns`] | projectDir 跨命名空间归一化（WSL UNC → `wsl://` 规范形） | `docs/cross-subsystem.md` §7.4 |
//!
//! ### 共享 / 宿主侧
//!
//! | 模块 | 职责 | 规格 |
//! |------|------|------|
//! | [`model`] | 条目（四类 v2）/附件/索引/墓碑数据模型 | `docs/data-model.md` |
//! | [`ipc`] | JSON-RPC 2.0 协议类型、会话令牌、错误码 | `docs/ipc.md` |
//! | [`bus`] | 事件总线（模拟 Cordis `emit`：观察广播，fire-and-forget） | `docs/plugin-architecture.md` §5 |
//! | [`service`] | A/B 层 trait 服务 + C 层装配点（[`service::CoreServices`]） | `docs/plugin-architecture.md` §3/§4 |
//!
//! ## 里程碑状态
//!
//! M0（单机闭环）+ M1（同步）已实现：加密、四类条目 CRUD、CAS、墓碑、会话、
//! 恢复信封、审计、IPC 协议类型、BYO 变更发现（轮询 + CAS 上传 + 墓碑收敛）。
//! M1.5（插件化改造）已实现：A/B 层按插件边界重组为 trait 服务 + 事件总线
//! （[`service`] / [`bus`]；行为不回归：密文格式、存储布局、IPC 协议零变更），
//! D 层真 Cordis 宿主见 `frontend/`。M2 授权门为占位模块。

pub mod audit;
pub mod audit_anchor;
pub mod authz;
pub mod bus;
pub mod crypto;
pub mod ipc;
pub mod model;
pub mod path_ns;
pub mod recovery;
pub mod service;
pub mod session;
pub mod starter;
pub mod storage;
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
    /// 主密码不满足最小长度（建库/恢复设置新主密码时校验）
    #[error("主密码至少 8 位")]
    WeakPassword,
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
    /// 同步：存储端错误（网络 / 4xx / 5xx）→ 本轮放弃，下一轮重试
    #[error("同步存储端错误: {0}")]
    SyncStorage(String),
    /// 同步：远端密文被篡改/无法解密 → 报「同步数据异常」，不自动覆盖本地
    #[error("同步数据异常: {0}")]
    SyncAnomaly(String),
    /// 同步：配置无效（URL 解析 / 后端选择）
    #[error("同步配置无效: {0}")]
    SyncConfig(String),
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
