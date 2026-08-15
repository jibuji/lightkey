//! 加密原语与密文格式（规格：`docs/crypto.md`）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **vault 头**：随机 16 字节 salt + KDF 参数 + 密文格式类型/版本号。
//! - **主密钥派生**：Argon2id(m=64MiB, t=3, p=4)（由主密码）。
//! - **密钥分叉**：HKDF-SHA256 仅分叉两把互不复用的密钥——数据加密密钥
//!   K_data 与审计 HMAC 密钥 K_audit；恢复信封密钥 K_recovery 不在 MK
//!   分叉之内，由恢复码 + Argon2id 独立派生（见 docs/crypto.md 与
//!   docs/decisions.md 补充拍板 #1）。
//! - **原语**：AES-256-GCM，刻意不用 Bitwarden 的 CBC+HMAC 组合。
//! - **自描述密文**：密文 blob 内嵌格式类型与版本号，支持演进与迁移。
//!
//! 占位模块：M0 起在此实现。
