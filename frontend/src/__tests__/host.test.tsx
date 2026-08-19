/**
 * cordis.yml 装配 + 槽位骨架 + 宿主渲染测试（M1.5 出口 + M2 桌面层）。
 *
 * - loader：yml 解析/校验（@cordisjs/schema）/按序挂载；
 * - 装配：cordis.yml 全量插件（4 地基服务 + 5 sidebar + 3 topbar + 5
 *   ui-* content + approval/desktop-shell 服务）挂载成功，槽位布局数据
 *   （order）生效；
 * - 渲染：锁态 = 整页 ui-unlock（无三栏）；解锁 = 三栏骨架 + 当前页
 *   ui-vault；`theme.changed` 触发宿主重渲染；`clipboard.copied` → Toast，
 *   30s 后清除。
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
    // 20 条：6 服务（4 地基 + approval + desktop-shell）+ 14 槽位组件
    // （5 sidebar + 3 topbar + 6 content ui-*：M2.5 增 ui-onboarding）
    expect(entries).toHaveLength(20);
    expect(entries[0].name).toBe("ipc-bridge");
    expect(entries.find((e) => e.name === "lock")?.order).toBe(99);
    expect(entries.find((e) => e.name === "theme")?.config).toEqual({
      defaultTheme: "dark",
    });
    // M2/M2.5：ui-* 挂 content；approval / desktop-shell 为服务
    expect(entries.find((e) => e.name === "ui-unlock")?.page).toBe("unlock");
    expect(entries.find((e) => e.name === "ui-onboarding")?.page).toBe("onboarding");
    expect(entries.find((e) => e.name === "approval")?.slot).toBeUndefined();
    expect(entries.find((e) => e.name === "desktop-shell")?.slot).toBeUndefined();

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
  it("全量插件 + 槽位布局数据（顺序）生效", async () => {
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
      // content：ui-onboarding（首启向导，order 0）→ ui-unlock（锁态整页）
      // → ui-* 页面（M2.5 锁定态前置）
      expect(host.slots.list("content").map((e) => e.name)).toEqual([
        "ui-onboarding",
        "ui-unlock",
        "ui-vault",
        "ui-rules",
        "ui-settings",
        "ui-audit",
      ]);
      // 布局元数据：content 页面路由
      expect(host.slots.page("vault")?.name).toBe("ui-vault");
      expect(host.slots.page("unlock")?.name).toBe("ui-unlock");
      expect(host.slots.page("onboarding")?.name).toBe("ui-onboarding");
      // 服务装配完整（M2：desktop-shell 提供 ctx.shell）
      expect(host.ctx.theme.current).toBe("dark");
      expect(host.ctx.session.unlocked).toBe(false);
      expect(host.ctx.preference.get("theme")).toBeNull();
      expect(host.ctx.shell).toBeDefined();
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

describe("宿主渲染（锁态整页 ↔ 三栏切换 + 槽位 + 事件重渲染）", () => {
  it("锁态 = ui-unlock 整页（无三栏）；解锁 = 三栏 + ui-vault；theme 切换；clipboard Toast", async () => {
    // 装配（异步：loader 逐条挂载）
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      root.render(<CordisHost />);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // 锁态：先等 `vault.status` 探测（300ms mock 延迟）→ 有库 → 整页解锁
    // （无 sidebar/topbar 三栏）；探测中 = 检测占位（M2.5 首启门控）
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.querySelector(".screen-unlock")).not.toBeNull();
    expect(container.querySelector(".sidebar")).toBeNull();
    expect(container.querySelector(".topbar")).toBeNull();
    expect(container.querySelector('input[aria-label="主密码"]')).not.toBeNull();

    // 解锁（mock 适配器；主密码 demo-password）→ 切三栏 + ui-vault
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
      (container.querySelector(".unlock-form") as HTMLFormElement).requestSubmit();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // 解锁
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // item.list
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // item.get ×N
    });
    expect(container.querySelector(".screen-unlock")).toBeNull();
    expect(container.querySelector(".sidebar")).not.toBeNull();
    expect(container.querySelector(".topbar")).not.toBeNull();
    expect(container.textContent).toContain("全部条目");
    expect(container.textContent).toContain("GitHub");

    // theme.changed 重渲染（三栏顶栏主题切换）+ 偏好持久化
    act(() => {
      (container.querySelector('[aria-label="切换主题"]') as HTMLButtonElement).click();
    });
    expect(container.textContent).toContain("☀️ 浅");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("lightkey:pref:theme")).toBe("light");

    // clipboard.copied → Toast（详情页复制按钮）；30s 后自动清除
    act(() => {
      (
        Array.from(container.querySelectorAll("button")).find((b) =>
          b.title?.includes("复制用户名"),
        ) as HTMLButtonElement
      ).click();
    });
    expect(container.textContent).toContain("已复制，30 秒后自动清除");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(container.textContent).not.toContain("已复制，30 秒后自动清除");

    // 侧栏锁定 → 回锁态整页
    act(() => {
      (container.querySelector('[aria-label="锁定"]') as HTMLButtonElement).click();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.querySelector(".screen-unlock")).not.toBeNull();
    expect(container.querySelector(".sidebar")).toBeNull();
  });
});
