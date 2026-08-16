/**
 * cordis.yml 装配 + 槽位骨架 + 宿主渲染测试（M1.5 出口：D 层宿主可用）。
 *
 * - loader：yml 解析/校验（@cordisjs/schema）/按序挂载；
 * - 装配：cordis.yml 首批插件（ipc-bridge / preference-store / theme /
 *   toast / 槽位组件）挂载成功，槽位布局数据（order）生效；
 * - 渲染：三栏骨架 + 槽位组件渲染；`theme.changed` 触发宿主重渲染；
 *   `clipboard.copied` → Toast 出现，30s 后清除。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import cordisYml from "../cordis.yml?raw";
import { CordisHost } from "../host/CordisHost";
import { createHost } from "../host/CordisHost";
import { CordisLoader } from "../host/loader";
import { Schema } from "@cordisjs/schema";
import { Context } from "@cordisjs/core";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

describe("cordis.yml loader", () => {
  it("解析 + schema 校验（非法条目拒绝）", () => {
    const loader = new CordisLoader(new Context(), {});
    const entries = loader.parse(cordisYml);
    // 16 条：4 服务 + 12 槽位组件（5 sidebar + 3 topbar + 4 content）
    expect(entries).toHaveLength(16);
    expect(entries[0].name).toBe("ipc-bridge");
    expect(entries.find((e) => e.name === "lock")?.order).toBe(99);
    expect(entries.find((e) => e.name === "theme")?.config).toEqual({
      defaultTheme: "dark",
    });

    // 非法条目：缺 name / 非法 slot → ValidationError
    expect(() =>
      loader.parse("- order: 1\n  slot: bogus\n"),
    ).toThrowError();
    expect(() => loader.parse("name: not-an-array\n")).toThrowError(
      "cordis.yml 顶层必须是插件条目数组",
    );
    // schema 逐条目校验的字段面（@cordisjs/schema 可独立复用）
    const entrySchema = Schema.object({
      name: Schema.string().required(),
      order: Schema.number(),
    });
    expect(() => entrySchema({ name: "x" })).not.toThrow();
    expect(() => entrySchema({ order: 1 })).toThrowError();
  });

  it("挂载未知插件名 → 报错（装配契约不可静默降级）", async () => {
    const loader = new CordisLoader(new Context(), {});
    await expect(loader.load("- name: ghost\n")).rejects.toThrowError(
      "cordis.yml 引用了未注册插件：ghost",
    );
  });

  it("disabled 条目跳过挂载", async () => {
    const seen: string[] = [];
    const ctx = new Context();
    const registry = {
      alpha: () => {
        seen.push("alpha");
      },
      beta: () => {
        seen.push("beta");
      },
    };
    const loader = new CordisLoader(ctx, registry);
    await loader.load("- name: alpha\n- name: beta\n  disabled: true\n");
    expect(seen).toEqual(["alpha"]);
  });
});

describe("cordis.yml 装配（createHost）", () => {
  it("首批插件 + 槽位布局数据（顺序）生效", async () => {
    const host = await createHost();
    try {
      // sidebar：导航项顺序 + 底部锁定（order 99）
      expect(host.slots.list("sidebar").map((e) => e.name)).toEqual([
        "nav-vault",
        "nav-rules",
        "nav-settings",
        "nav-audit",
        "lock",
      ]);
      expect(host.slots.list("topbar").map((e) => e.name)).toEqual([
        "search",
        "sync-status",
        "theme-toggle",
      ]);
      expect(host.slots.list("content").map((e) => e.name)).toEqual([
        "page-vault",
        "page-rules",
        "page-settings",
        "page-audit",
      ]);
      // 布局元数据：content 页面路由
      expect(host.slots.page("vault")?.name).toBe("page-vault");
      // 服务装配完整
      expect(host.ctx.theme.current).toBe("dark");
      expect(host.ctx.session.unlocked).toBe(false);
      expect(host.ctx.preference.get("theme")).toBeNull();
      expect(host.nav.current).toBe("vault");
    } finally {
      host.dispose();
    }
  });

  it("dispose 卸载全部插件（服务随纤维拆除）", async () => {
    const host = await createHost();
    host.dispose();
    // 卸载后服务从 store 拆除（effect 清理异步；等待微任务）
    await vi.waitFor(() => {
      expect(host.ctx.theme).toBeUndefined();
    });
  });
});

describe("宿主渲染（三栏骨架 + 槽位 + 事件重渲染）", () => {
  it("骨架渲染：顶栏/侧栏/内容 + 锁定面板；theme.changed 重渲染；clipboard Toast + 30s 清除", async () => {
    // 装配（异步：loader 逐条挂载）
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    // createHost 在 CordisHost effect 内异步执行 → 先渲染装配中，再渲染骨架
    await act(async () => {
      root.render(<CordisHost />);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // 三栏骨架 + 槽位组件（导航项 aria-label；锁定面板；主题按钮）
    expect(container.querySelector(".sidebar")).not.toBeNull();
    expect(container.querySelector(".topbar")).not.toBeNull();
    expect(container.querySelector(".content")).not.toBeNull();
    for (const label of ["条目", "规则", "设置", "审计", "锁定"]) {
      expect(container.querySelector(`[aria-label="${label}"]`)).not.toBeNull();
    }
    expect(container.textContent).toContain("已锁定");
    expect(container.textContent).toContain("🌙 暗");

    // theme.changed 重渲染：点击切换 → 宿主重渲染 + CSS 变量更新
    act(() => {
      (container.querySelector('[aria-label="切换主题"]') as HTMLButtonElement).click();
    });
    expect(container.textContent).toContain("☀️ 浅");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("lightkey:pref:theme")).toBe("light");

    // 解锁（mock 适配器；主密码 demo-password）→ 内容区切到条目演示页
    const passwordInput = container.querySelector(
      'input[aria-label="主密码"]',
    ) as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    )!.set!;
    act(() => {
      valueSetter.call(passwordInput, "demo-password");
      passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
    });
    act(() => {
      (container.querySelector(".lock-panel form") as HTMLFormElement).requestSubmit();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.textContent).toContain("已解锁");
    expect(container.textContent).toContain("模拟 item.changed");

    // clipboard.copied → Toast；30s 后自动清除（宿主重渲染）
    act(() => {
      (
        Array.from(container.querySelectorAll("button")).find((b) =>
          b.textContent?.includes("复制"),
        ) as HTMLButtonElement
      ).click();
    });
    expect(container.textContent).toContain("已复制，30 秒后自动清除");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(container.textContent).not.toContain("已复制，30 秒后自动清除");
  });
});
