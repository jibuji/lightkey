//! # lk-core —— LightKey 核心库
//!
//! 轻钥 LightKey 的能力中枢：**加密、数据模型、同步、授权门、审计** 与本地
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
//! | [`model`] | 条目/附件/索引/墓碑数据模型、CAS | `docs/data-model.md` |
//! | [`sync`] | BYO 变更发现、轮询、冲突收敛 | `docs/sync.md` |
//! | [`authz`] | Agent 授权门三层模型、规则库、启动者判定 | `docs/authorization-gate.md` |
//! | [`audit`] | 追加式审计日志 + HMAC 防篡改 | `docs/audit.md` |
//! | [`ipc`] | JSON-RPC 2.0 协议类型、会话令牌 | `docs/ipc.md` |
//!
//! ## 骨架状态
//!
//! 本 crate 当前为 M0 骨架：仅声明模块边界（各模块为占位文档），不含业务实现。
//! 实现按 `docs/milestones.md` 的里程碑推进，从 M0（单机闭环）开始。

pub mod audit;
pub mod authz;
pub mod crypto;
pub mod ipc;
pub mod model;
pub mod sync;
