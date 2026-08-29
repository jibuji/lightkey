/**
 * 页面级错误边界（issue #85）：受保护的子树渲染抛错时只降级该子树，
 * 不拖垮整棵 React 树——v0.1.11 事故中规则页崩溃把后续所有操作带崩。
 *
 * 兜底不是静默吞掉：错误照常进 console（契约类错误开发期必须可见），
 * fallback 提供错误详情与重试入口（重置边界 → 重新渲染子树）。
 */

import { Component, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** 受保护区域的可读名（fallback 文案前缀），如「条目页」。 */
  label?: string;
}

interface ErrorBoundaryState {
  error: unknown | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: unknown): void {
    // 不静默：形状错配 / 协议变更等契约错误必须在控制台立即可见（issue #85）
    console.error(`[lightkey] ${this.props.label ?? "组件"} 渲染异常`, error);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (error === null) return this.props.children;
    return (
      <div className="empty" role="alert">
        <div style={{ color: "var(--fg-2)", fontSize: 32 }}>⚠️</div>
        <div>{this.props.label ?? "此区域"}渲染出错，其他区域不受影响</div>
        <div style={{ color: "var(--fg-2)", fontSize: 12 }} className="mono">
          {error instanceof Error ? error.message : String(error)}
        </div>
        <button
          className="btn btn-primary btn-sm"
          onClick={() => this.setState({ error: null })}
        >
          重试
        </button>
      </div>
    );
  }
}
