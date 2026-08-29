/**
 * issue #85 验收：加载失败与空库在 UI 上可区分 + 页面级渲染异常不拖垮应用。
 *
 * 背景（v0.1.11 事故的放大器）：loadItems 把 `summaries.map is not a
 * function` 吞成 null → VaultPage 置空数组 → 用户看到「还没有条目」，
 * 而实际是一次 TypeError；规则页同类错配更把整棵 React 树带崩。
 *
 * - VaultPage 加载失败（list 拒绝 / 适配器返回错形状）→ 错误态 + 重试入口，
 *   绝不呈现空态（「还没有条目」）；
 * - 重试成功 → 恢复正常列表；
 * - ErrorBoundary：受保护子树渲染抛错 → fallback + 重试；兄弟区域不受影响。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { VaultPage } from "../plugins/ui-vault";
import { ErrorBoundary } from "../components/ErrorBoundary";
import type { LightKeyIpc } from "../ipc/types";
import type { Item, ItemSummary } from "../types";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  localStorage.clear();
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.restoreAllMocks();
});

const ITEM: Item = {
  type: "login",
  id: "it-1",
  name: "GitHub",
  revision: "2026-08-29T00:00:00Z",
  username: "alice",
  password: "SECRET",
  uris: [],
  custom: [],
};

const SUMMARY: ItemSummary = {
  id: ITEM.id,
  name: "GitHub",
  type: "login",
  revision: ITEM.revision,
};

/**
 * 最小 ipc stub：只实现 VaultPage 挂载路径触达的 list/get；list 的行为
 * 由用例注入（成功 / 拒绝 / **错形状**——模拟适配器契约回归，如 v0.1.11
 * 把 `{items}` 包装对象原样透传）。
 */
function stubIpc(listImpl: () => Promise<unknown>) {
  return {
    kind: "mock" as const,
    list: vi.fn(listImpl),
    get: vi.fn(async (id: string) => {
      if (id !== ITEM.id) throw new Error("item.not_found");
      return ITEM;
    }),
  } as unknown as LightKeyIpc & { list: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
}

/** VaultPage 直渲染（stub ctx：ipc + toast；事件订阅走真 Context）。 */
function renderVaultPage(ipc: LightKeyIpc): Context {
  const ctx = new Context();
  ctx.ipc = ipc;
  ctx.toast = {
    all: [],
    show: vi.fn(() => 1),
    dismiss: vi.fn(),
    subscribe: vi.fn(() => () => {}),
  };
  act(() => {
    root.render(<VaultPage ctx={ctx} />);
  });
  return ctx;
}

/** flush 挂载期的 loadItems 微任务链。 */
async function flushLoad() {
  await act(async () => {});
}

describe("VaultPage 加载失败 ≠ 空库（issue #85 验收）", () => {
  it("list 拒绝 → 错误态 + 重试入口，而非「还没有条目」；重试成功恢复列表", async () => {
    const ipc = stubIpc(() => Promise.reject(new Error("session.invalid")));
    renderVaultPage(ipc);
    await flushLoad();

    // 错误态：可区分的失败文案 + 重试按钮
    expect(container.textContent).toContain("条目加载失败");
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    expect(container.textContent).toContain("session.invalid");
    // 空态文案绝不在失败时出现（v0.1.11 的静默降级表象）
    expect(container.textContent).not.toContain("还没有条目");

    // 重试：list 恢复正常 → 列表渲染出来
    ipc.list.mockImplementation(() => Promise.resolve([SUMMARY]));
    const retry = Array.from(container.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("重试"),
    );
    expect(retry).toBeDefined();
    act(() => {
      (retry as HTMLButtonElement).click();
    });
    await flushLoad();
    expect(container.textContent).toContain("GitHub");
    expect(container.textContent).not.toContain("条目加载失败");
  });

  it("适配器返回错形状（{items} 包装对象）→ 错误态而非空态", async () => {
    // v0.1.11 回归形状：适配器漏解包，list() 透传 ItemListResult 包装对象
    const ipc = stubIpc(() => Promise.resolve({ items: [SUMMARY] }));
    renderVaultPage(ipc);
    await flushLoad();

    expect(container.textContent).toContain("条目加载失败");
    expect(container.textContent).not.toContain("还没有条目");
    // 错因可见：TypeError 消息进错误详情，不再被吞成无害表象
    expect(container.textContent).toContain("map is not a function");
  });
});

describe("ErrorBoundary（页面级渲染异常不拖垮应用）", () => {
  /** 首渲染抛错、重试后恢复的子组件（可控故障源）。 */
  function Flaky({ broken }: { broken: boolean }): null {
    if (broken) throw new Error("规则页渲染炸了");
    return null;
  }

  function renderCase() {
    act(() => {
      root.render(
        <div>
          <div id="sibling">其他页面安然无恙</div>
          <ErrorBoundary label="规则页">
            <Flaky broken />
          </ErrorBoundary>
        </div>,
      );
    });
  }

  it("子树抛错 → fallback 渲染；兄弟区域不受影响", () => {
    vi.spyOn(console, "error").mockImplementation(() => {}); // React 会让错误进 console
    renderCase();

    expect(container.textContent).toContain("规则页渲染出错");
    expect(container.textContent).toContain("规则页渲染炸了");
    // 关键：边界外的兄弟组件仍在（v0.1.11 中整棵树被带崩）
    expect(container.textContent).toContain("其他页面安然无恙");
    // 不静默吞：错误必须进 console（开发期可见）
    expect(vi.mocked(console.error).mock.calls.length).toBeGreaterThan(0);
  });

  it("重试重置边界 → 子组件恢复渲染", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    renderCase();
    expect(container.textContent).toContain("规则页渲染出错");

    // 边界处于错误态时不渲染子树：须先修复故障源，再经边界自带「重试」
    // 重置（父组件重渲染不会自动清错误）
    act(() => {
      root.render(
        <div>
          <div id="sibling">其他页面安然无恙</div>
          <ErrorBoundary label="规则页">
            <Flaky broken={false} />
          </ErrorBoundary>
        </div>,
      );
    });
    const retry = Array.from(container.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("重试"),
    );
    expect(retry).toBeDefined();
    act(() => {
      (retry as HTMLButtonElement).click();
    });

    expect(container.textContent).not.toContain("规则页渲染出错");
    expect(container.textContent).toContain("其他页面安然无恙");
  });
});
