/**
 * ErrorState（issue #85 评审跟进）：错误态兜底的共享组件——VaultPage 加载
 * 失败态与 ErrorBoundary fallback 标记同形（⚠️ + 文案 + mono 错误详情 +
 * 重试），抽成一份避免两处复制漂移。
 *
 * 渲染缝：DOM（role="alert" + 标题 + 错误详情 + 重试按钮）；
 * 行为缝：点击重试 → 调用方传入的 onRetry。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { ErrorState } from "../components/ErrorState";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

describe("ErrorState（错误态兜底共享组件）", () => {
  it("渲染标题 + 错误详情 + 重试按钮；点重试回调 onRetry", () => {
    const onRetry = vi.fn();
    act(() => {
      root.render(
        <ErrorState
          error={new Error("session.invalid")}
          title="条目加载失败——读取加密库时出错"
          onRetry={onRetry}
        />,
      );
    });

    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    expect(container.textContent).toContain("条目加载失败——读取加密库时出错");
    expect(container.textContent).toContain("session.invalid");
    const retry = Array.from(container.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("重试"),
    );
    expect(retry).toBeDefined();
    act(() => {
      (retry as HTMLButtonElement).click();
    });
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("非 Error 抛出值（如字符串）原样进错误详情", () => {
    act(() => {
      root.render(<ErrorState error="契约错配" title="渲染出错" onRetry={() => {}} />);
    });
    expect(container.textContent).toContain("渲染出错");
    expect(container.textContent).toContain("契约错配");
  });
});
