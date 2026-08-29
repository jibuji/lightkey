/**
 * 错误态兜底的共享组件（issue #85 评审跟进）：VaultPage 加载失败态与
 * ErrorBoundary fallback 的标记同形——⚠️ + 文案 + mono 错误详情 + 重试，
 * 抽成一份避免两处复制漂移。文案由调用方给定（语义不同：加载失败 vs
 * 渲染降级）；重试走调用方各自的恢复通道（reload / 重置边界）。
 */

interface ErrorStateProps {
  /** 调用方语义的失败文案，如「条目加载失败——读取加密库时出错」。 */
  title: string;
  /** 抛出的错误值：Error 取 message，其余 String() 原样展示（不静默吞）。 */
  error: unknown;
  onRetry: () => void;
}

export function ErrorState({ title, error, onRetry }: ErrorStateProps) {
  return (
    <div className="empty" role="alert">
      <div style={{ color: "var(--fg-2)", fontSize: 32 }}>⚠️</div>
      <div>{title}</div>
      <div style={{ color: "var(--fg-2)", fontSize: 12 }} className="mono">
        {error instanceof Error ? error.message : String(error)}
      </div>
      <button className="btn btn-primary btn-sm" onClick={onRetry}>
        重试
      </button>
    </div>
  );
}
