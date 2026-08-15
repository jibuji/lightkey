//! 数据模型（规格：`docs/data-model.md`）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - **条目级密文 blob** + 加密索引（存储端只见密文文件与文件名时间戳）。
//! - 条目 schema 参照 Bitwarden 的 `login` / `secureNote` 映射。
//! - `revisionDate` 支持增量同步；软删除墓碑（30 天延迟硬删）。
//! - 乐观并发：CAS，整条目 last-write-wins。
//! - 附件：每附件独立密钥 + 1 MiB 流式分块。
//!
//! 占位模块：M0 起在此实现。
