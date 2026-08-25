//! 同步与变更发现（规格：`docs/sync.md`、`docs/data-model.md` §4/§6）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - BYO 存储（WebDAV / S3 / 本地模拟 `file://`），无推送、无中间态加载、
//!   静默轮询（默认 60s，可配 15s~1h）。
//! - 每轮协议：GET 远端 `index.lk`（加密）→ 解密对比本地索引 → 有差异才
//!   拉取条目（含墓碑）→ 本地较新则 CAS 上传 → 墓碑收敛 → 合并重写远端索引。
//! - CAS：上传携带 base ETag（存储端 `If-Match`/`If-None-Match`）；校验失败
//!   → CAS 冲突 → 整条目 last-write-wins（revisionDate 更晚者胜；同 revision
//!   按内容 SHA-256 确定性决胜，保证收敛）。
//! - 墓碑：删除在多端传播；硬删需「本端墓碑 ≥ 30 天 且 已同步确认」（远端
//!   索引已反映该墓碑）——远端文件与本地同时清除。
//! - 失败语义：任何一步失败（网络/存储 4xx/5xx/解密异常）→ 本轮放弃，保留
//!   本地状态，下一轮重试；远端密文被篡改 → [`Error::SyncAnomaly`]（报
//!   「同步数据异常」，不自动覆盖本地）。
//! - 首次同步 / 远端索引丢失 → 全量拉取（list 远端对象重建合成索引再走常规
//!   收敛），不阻塞解锁。
//! - 冲突风暴保护：单轮差异过大（> [`STORM_THRESHOLD`]）→ 轮询退避
//!   （指数 ×2，至 [`MAX_SYNC_INTERVAL_SECS`] 上限）。
//! - 已知边界（诚实记录）：对端离线超过 30 天硬删窗口后重新上线，可能把
//!   过期条目当新条目推回（远端无墓碑可对抗）；规格以 last-write-wins 兜底
//!   （data-model.md §4.2「硬删前若对端仍持旧条目」），本实现遵循该语义。
//! - 存储端零知识：只存密文 blob（文件名 = 对象 id，不含内容信息；同步排序
//!   依据加密索引内的 revisionDate，文件名无需时间戳）。
//! - **两阶段并发结构（G1 根治，船长 2026-08-15 定案）**：一轮同步拆为
//!   抓取（只读本地 + 全部网络 I/O，不持守护进程锁）与应用（纯本地写入，
//!   守护进程持短写锁）两阶段；网络 I/O 期间前台命令照常服务。一致性模型：
//!   以抓取时刻的本地索引快照为基点——只上传与快照 revision 一致的密文
//!   （并发更新 → 本轮跳过，下轮再推），合并索引以快照 + 本轮已缓冲的远端
//!   条目为底 → 远端索引引用的密文恒与索引条目一致；应用阶段逐条复核
//!   （本地已更新且不更旧 → 跳过），数据层冲突收敛仍由 CAS + last-write-wins
//!   兜底（不削弱）。

//!
//! 模块布局（内部缝；对外路径 `lk_core::sync::*` 经下方 `pub use` 不变）：
//!
//! - [`config`]：常量 + 配置/摘要/状态类型 + 轮询间隔纯函数；
//! - [`read`]：`VaultRead` trait + `UnlockedVault` 只读视图适配器；
//! - [`plan`]：应用计划 / LWW 裁决 / diff 与索引合并（纯函数）；
//! - [`engine`]：两阶段同步引擎（抓取无锁 → 应用短锁）。

mod config;
mod engine;
mod plan;
mod read;

#[cfg(test)]
mod tests;

pub use config::{
    next_poll_interval, poll_interval_after, storm_level_after, SyncConfig, SyncState, SyncSummary,
    DEFAULT_SYNC_INTERVAL_SECS, MAX_INDEX_CAS_RETRIES, MAX_PUSH_RETRIES, MAX_SYNC_INTERVAL_SECS,
    MIN_SYNC_INTERVAL_SECS, STORM_THRESHOLD,
};
pub use engine::SyncEngine;
pub use plan::SyncPlan;
pub use read::{AttachmentBlobs, VaultRead};
