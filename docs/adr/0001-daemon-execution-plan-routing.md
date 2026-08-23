# Daemon RPC 单一执行计划路由

## 状态

accepted（2026-08-24，架构评审 grilling 拍板）

## 决策

lk-daemon 的 RPC 方法分发收敛到唯一入口 `router.rs` 的执行计划路由表
（`method → ExecutionStrategy`），三种策略：

- `Inline`：命令锁内跑完（vault.status / item.* / rule.* 等）；
- `OutsideLock`：锁内预检 → 锁外工作 → 锁内收尾时间戳（`sync.trigger`）；
- `ApprovalDeferred`：锁内 begin → 锁外等审批 ≤30s → 锁内 finalize（`authz.evaluate`）。

背景：M2 后分发逻辑分裂在三处——`Daemon::dispatch` match、
`try_sync_trigger`、`try_authz_evaluate` 各自手写锁纪律与预检；直调
`handle()` 与生产行为不一致（authz.evaluate 返回 method-not-found）。
G1 教训（审批等待曾持命令锁阻塞全部命令）依赖人工约定维持。

理由：G1 这类并发纪律是本项目唯一一次重大回归的根源，其知识必须有
locality——每个方法的锁正确性从策略继承，而非在每个新方法里重新推导。
公开接口不变：`Daemon::handle(line, peer)` 直调与生产路径行为对齐
（interface 即测试面）；测试一律穿单一入口，另加路由表完整性测试
（遍历全部 `M_*` 常量断言可命中）。

## Considered Options

- 留在 lib.rs 原地合并：不新建文件——被否，lib.rs 已 2571 行且是最热区域，
  锁纪律需要一处可指的 locality。
- 两种策略（把 ApprovalDeferred 泛化为「锁外阶段返回闭包」）：被否，
  有无 Pending 登记/超时语义是本质差异，硬统一会造出参数化的浅接口。
- 下沉路由表到 lk-core：被否，违背「lk-core 业务库、宿主编排在 lk-daemon」边界纪律。

## Consequences

- **同步轮询线程不入界**（刻意偏离「彻底单一入口」）：poller 无请求上下文
  （无 token/peer），只要求复用共享预检辅助函数；不要未来"修复"它。
- 新增 RPC 方法 = 在路由表声明策略，不再抄锁样板。
