//! 同步常量、配置与运行状态（`lk_core::sync` 的数据面；纯函数，无 I/O）。

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// 常量 / 配置
// ---------------------------------------------------------------------------

/// 轮询间隔默认：60s。
pub const DEFAULT_SYNC_INTERVAL_SECS: u64 = 60;
/// 轮询间隔可配下限：15s。
pub const MIN_SYNC_INTERVAL_SECS: u64 = 15;
/// 轮询间隔可配上限：1h（补充拍板 #8）。
pub const MAX_SYNC_INTERVAL_SECS: u64 = 3600;
/// 冲突风暴阈值：单轮差异（拉+推）超过该值 → 退避轮询频率。
pub const STORM_THRESHOLD: usize = 64;
/// 索引 CAS 冲突重试上限（重拉重合并；耗尽则本轮部分完成，下轮继续）。
pub const MAX_INDEX_CAS_RETRIES: usize = 3;
/// 单条目 CAS 冲突后的 LWW 重试上限。
pub const MAX_PUSH_RETRIES: usize = 3;

/// 同步配置（`lk config sync set` 写入 `config.json` 的 `sync` 段）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncConfig {
    /// BYO 存储 URL：`file://`（本地模拟）/ `http(s)://`（WebDAV）/ `s3://`。
    pub url: String,
    /// 轮询间隔秒数（15~3600，默认 60）。
    pub interval_secs: u64,
}

impl SyncConfig {
    /// 校验配置（URL 协议 + 间隔范围）；非法 → [`Error::SyncConfig`]。
    pub fn validate(&self) -> Result<()> {
        if !(MIN_SYNC_INTERVAL_SECS..=MAX_SYNC_INTERVAL_SECS).contains(&self.interval_secs) {
            return Err(Error::SyncConfig(format!(
                "轮询间隔须在 {}s~{}s 之间（当前 {}s）",
                MIN_SYNC_INTERVAL_SECS, MAX_SYNC_INTERVAL_SECS, self.interval_secs
            )));
        }
        let scheme = self
            .url
            .split_once("://")
            .map(|(s, _)| s)
            .unwrap_or_default();
        if !matches!(scheme, "file" | "http" | "https" | "s3") {
            return Err(Error::SyncConfig(format!(
                "不支持的存储协议 {scheme:?}（支持 file:// / http(s):// / s3://）"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 摘要 / 状态
// ---------------------------------------------------------------------------

/// 一轮同步的变更摘要（`sync.trigger` / `sync.poll` 返回；**不返回内容**）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    /// 本轮是否实际执行（`sync.poll` 尚未有轮次时 false）。
    pub ran: bool,
    /// 拉取条目数（含墓碑与附件）。
    pub pulled: usize,
    /// 推送条目数（含墓碑与附件）。
    pub pushed: usize,
    /// CAS 冲突收敛次数（last-write-wins 裁决）。
    pub conflicts: usize,
    /// 硬删条目数（30 天 + 已同步确认）。
    pub purged: usize,
    /// 是否有任何变更。
    pub changed: bool,
    /// 非致命提示（如远端对象缺失、附件分块暂缺）。
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl SyncSummary {
    pub fn is_clean(&self) -> bool {
        self.pulled == 0 && self.pushed == 0 && self.purged == 0
    }
}

/// 同步运行状态（守护进程持久化到 `sync-state.json`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    /// 最近成功轮询时间（ISO-8601 UTC；`vault.status` 的同步水位）。
    pub watermark: Option<String>,
    /// 最近一轮摘要。
    pub last_summary: Option<SyncSummary>,
    /// 连续风暴轮数（单轮差异过大 +1，正常轮归零）。
    pub storm_level: u32,
}

/// 风暴退避后的下次轮询间隔：`base * 2^level`，封顶 [`MAX_SYNC_INTERVAL_SECS`]。
pub fn next_poll_interval(base_secs: u64, storm_level: u32) -> u64 {
    let base = base_secs.clamp(MIN_SYNC_INTERVAL_SECS, MAX_SYNC_INTERVAL_SECS);
    base.saturating_mul(2u64.saturating_pow(storm_level.min(14)))
        .min(MAX_SYNC_INTERVAL_SECS)
}

/// 风暴等级更新：单轮差异（拉+推）超过阈值 → 等级 +1；否则归零。
pub fn storm_level_after(diff: usize, current: u32) -> u32 {
    if diff > STORM_THRESHOLD {
        current.saturating_add(1)
    } else {
        0
    }
}

/// 刷新风暴等级后的下次轮询间隔（守护进程轮询线程用）。
pub fn poll_interval_after(base_secs: u64, diff: usize, storm_level: u32) -> u64 {
    next_poll_interval(base_secs, storm_level_after(diff, storm_level))
}
