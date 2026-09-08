//! C 层 daemon 宿主（`docs/plugin-architecture.md` §3.3；决策 #2 A：**下沉为
//! 共享 crate**，供 `lk-cli`（`lk daemon`）与桌面应用内置实例（M2 desktop
//! 任务）复用，行为不回归）。
//!
//! 模块布局（内部缝；对外路径经下方 `pub use` 保持不变）：
//!
//! - `daemon`（核心）：守护进程状态机 + RPC 分发；子模块按命令域分组
//!   （vault / items / sync_cmds / rules / session / authz / lifecycle）；
//! - [`router`]：**执行计划路由**（ADR-0001）——方法 → 执行策略的唯一分发点，
//!   授权门三阶段 / 两阶段同步的锁纪律在此声明（G1：等待不持命令锁）；
//! - [`config`]：`config.json` / `sync-state.json` 读写 + 同步凭据钥匙串；
//! - [`sync`]：同步轮次执行（抓取无锁 → 应用短锁）；
//! - [`transport`]：本地 IPC 传输（UDS / named pipe）+ 对端身份（PID/cwd）
//!   + **通知订阅连接**（决策 #3 A：JSON-RPC notification 推送）；
//! - [`notifier`]：事件总线 → 通知帧的 EventSink（非阻塞广播）。
//!
//! M2 增量（详见各模块文档）：
//!
//! - `authz.evaluate` 三阶段（命令锁内第 1/2 层 + 登记审批 → 锁外 30s 等待 →
//!   重取锁收尾）：第 3 层等待**不持有命令锁**（G1 回归）；
//! - `rule.add|list|remove`（决策 #6）；`approval.result` 回传；`subscribe`
//!   推送订阅；
//! - 启动者判定在守护进程侧从 IPC 对端 PID 回溯（[`lk_core::starter`]），
//!   客户端自报字段一律不信任。

pub mod audit_anchor;
/// 绑定裁决（M2.98，identity-binding.md §5.2/§5.3；identity 三拆之一）：
/// 绑定规则比对序 + finalize 侧重算指纹。daemon 侧裁决入口唯一为
/// `Daemon::fingerprint_adjudicate`（begin 与 finalize 共用，issue #140/#152）。
pub mod binding;
pub mod config;
mod daemon;
pub mod dirs;
/// `command[0]` → canonical 候选解析 + 内存指纹缓存（M2.98；identity 三拆
/// 之一）：PATH/PATHEXT 解析为纯函数，指纹缓存走可注入 [`exe_resolve::FingerprintSource`]。
pub mod exe_resolve;
/// 对端身份面（拍板 #28 候选 4，issue #169）：[`identity::resolve`] 单一解析
/// 入口 → 对端身份 { starter, canonical_cwd, exe_path }（CONTEXT.md「对端
/// 身份」）；委托 core `starter` 与 [`peer_env`] / [`exe_resolve`] / [`binding`]
/// 三拆（保留为内部缝）。**指纹裁决不并入门面**（消费 exe 路径的单独一步）。
pub mod identity;
pub mod notifier;
/// 对端真实 env 读取（M2.98；identity 三拆之一）：Linux `/proc` /
/// Windows PEB（`lk_core::peb` 原语）/ macOS KERN_PROCARGS2，失败 fail-closed；
/// 可注入 [`peer_env::PeerEnv`]。
pub mod peer_env;
pub mod router;
pub mod sync;
pub mod transport;

pub use config::*;
pub use notifier::{frame_for_event, Notifier};
pub use router::{route, strategy_of, ExecutionStrategy};
pub use sync::sync_fail_response;
pub use sync::{run_sync_round, run_sync_round_with};
pub use transport::{PeerInfo, PeerOrigin, PushHub};

// —— daemon 核心的对外面（路径与拆分前一致）——
pub use daemon::lifecycle::{global_shutdown, make_handler, run, serve_embedded, EmbeddedDaemon};
pub use daemon::{Daemon, SharedDaemon, SESSION_TOKEN_FILE};

// —— crate 内部旧路径兼容（router.rs 等兄弟模块引用）——
pub(crate) use daemon::{extract_token, rpc_string};

#[cfg(test)]
mod tests;
