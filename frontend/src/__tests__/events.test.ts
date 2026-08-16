/**
 * 事件总线契约单测（M1.5 出口：`docs/testing.md` §4 M1.5 行）。
 *
 * 覆盖：`item.changed` 三方响应、`session.unlocked/locked` 切换、
 * `theme.changed` 重渲染、`clipboard.copied` Toast + 30s 清除。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";
import type { ItemChangedPayload, ThemeName } from "../events";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { toast, CLIPBOARD_TOAST_TEXT } from "../plugins/toast";
import { theme, THEME_PALETTES } from "../plugins/theme";
import type { ToastMessage } from "../services/types";

beforeEach(() => {
  localStorage.clear();
  vi.useRealTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("item.changed —— 一事件三方响应（emit 观察广播）", () => {
  it("sync 推送 / audit 记录 / ui 刷新三方都收到，且互不依赖", () => {
    const ctx = new Context();
    const sync: ItemChangedPayload[] = [];
    const audit: ItemChangedPayload[] = [];
    const ui: ItemChangedPayload[] = [];
    // 订阅顺序 = 分发顺序；三方独立注册
    ctx.on("item.changed", (p) => sync.push(p));
    ctx.on("item.changed", (p) => audit.push(p));
    ctx.on("item.changed", (p) => ui.push(p));

    const created: ItemChangedPayload = {
      itemId: "it-1",
      revisionDate: "2026-08-16T00:00:00Z",
      type: "login",
      deleted: false,
    };
    ctx.emit("item.changed", created);
    expect(sync).toEqual([created]);
    expect(audit).toEqual([created]);
    expect(ui).toEqual([created]);

    // 软删除变体（deleted=true + revision 前进）
    const deleted: ItemChangedPayload = {
      itemId: "it-1",
      revisionDate: "2026-08-16T00:00:01Z",
      type: "login",
      deleted: true,
    };
    ctx.emit("item.changed", deleted);
    for (const seen of [sync, audit, ui]) {
      expect(seen).toEqual([created, deleted]);
    }
  });

  it("emit 按订阅顺序分发（fire-and-forget，无返回值聚合）", () => {
    const ctx = new Context();
    const order: string[] = [];
    ctx.on("item.changed", () => order.push("sync"));
    ctx.on("item.changed", () => order.push("audit"));
    ctx.on("item.changed", () => order.push("ui"));
    const result = ctx.emit("item.changed", {
      itemId: "it-2",
      revisionDate: "r",
      type: "note",
      deleted: false,
    });
    // emit 无返回值：观察广播不聚合结果（与 Rust 侧 EventBus 同契约）
    expect(result).toBeUndefined();
    expect(order).toEqual(["sync", "audit", "ui"]);
  });
});

describe("session.unlocked / session.locked —— 会话切换", () => {
  it("ipc-bridge mock 适配器：解锁 → unlocked(password)，锁定 → locked(manual)", async () => {
    vi.useFakeTimers();
    const ctx = new Context();
    await ctx.plugin(ipcBridge, {});

    const states: string[] = [];
    ctx.on("session.unlocked", (p) => states.push(`unlocked:${p.via}`));
    ctx.on("session.locked", (p) => states.push(`locked:${p.reason}`));

    expect(ctx.session.unlocked).toBe(false);
    const unlockPromise = ctx.session.unlock("demo-password");
    await vi.advanceTimersByTimeAsync(300);
    await unlockPromise;
    expect(ctx.session.unlocked).toBe(true);

    const lockPromise = ctx.session.lock();
    await vi.advanceTimersByTimeAsync(300);
    await lockPromise;
    expect(ctx.session.unlocked).toBe(false);

    expect(states).toEqual(["unlocked:password", "locked:manual"]);
  });

  it("错误密码不广播事件（统一 vault.invalid，防探测）", async () => {
    vi.useFakeTimers();
    const ctx = new Context();
    await ctx.plugin(ipcBridge, {});
    const states: string[] = [];
    ctx.on("session.unlocked", () => states.push("unlocked"));
    const unlockPromise = ctx.session.unlock("wrong");
    // 同步挂拒绝处理：mock 的 300ms 延迟在 advanceTimers 期间触发 reject，
    // 处理器必须先于计时器存在（否则产生 unhandled rejection——CI 环境
    // 的 unhandled-rejection 检查先于下方断言触发，本地时序则碰巧通过）。
    const rejection = unlockPromise.catch((err: unknown) => err);
    await vi.advanceTimersByTimeAsync(300);
    await expect(rejection).resolves.toMatchObject({
      name: "VaultInvalidError",
      message: "vault.invalid",
    });
    expect(ctx.session.unlocked).toBe(false);
    expect(states).toEqual([]);
  });

  it("via / reason 负载符合契约取值", () => {
    const ctx = new Context();
    const seen: string[] = [];
    ctx.on("session.unlocked", (p) => seen.push(p.via));
    ctx.on("session.locked", (p) => seen.push(p.reason));
    ctx.emit("session.unlocked", { via: "password" });
    ctx.emit("session.unlocked", { via: "biometric" });
    ctx.emit("session.unlocked", { via: "recovery" });
    ctx.emit("session.locked", { reason: "manual" });
    ctx.emit("session.locked", { reason: "timeout" });
    ctx.emit("session.locked", { reason: "lockscreen" });
    ctx.emit("session.locked", { reason: "daemon-exit" });
    expect(seen).toEqual([
      "password",
      "biometric",
      "recovery",
      "manual",
      "timeout",
      "lockscreen",
      "daemon-exit",
    ]);
  });
});

describe("theme.changed —— 暗/浅切换 + 偏好持久化 + 重渲染信号", () => {
  it("toggle → 事件广播 + CSS 变量应用 + preference-store 持久化", async () => {
    const ctx = new Context();
    await ctx.plugin(preferenceStore, {});
    await ctx.plugin(theme, { defaultTheme: "dark" });

    const changes: ThemeName[] = [];
    ctx.on("theme.changed", (p) => changes.push(p.theme));

    expect(ctx.theme.current).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.style.getPropertyValue("--bg-0")).toBe(
      THEME_PALETTES.dark["--bg-0"],
    );

    ctx.theme.toggle();
    expect(ctx.theme.current).toBe("light");
    expect(changes).toEqual(["light"]);
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.style.getPropertyValue("--bg-0")).toBe(
      THEME_PALETTES.light["--bg-0"],
    );
    // 持久化（preference-store）
    expect(localStorage.getItem("lightkey:pref:theme")).toBe("light");

    // 新实例（新 ctx）恢复偏好（defaultTheme 被偏好覆盖）
    const ctx2 = new Context();
    await ctx2.plugin(preferenceStore, {});
    await ctx2.plugin(theme, { defaultTheme: "dark" });
    expect(ctx2.theme.current).toBe("light");

    // 相同值不重复广播
    ctx2.theme.set("light");
    expect(changes).toEqual(["light"]);
  });

  it("set(浅) 明确切换；defaultTheme 缺省为 dark", async () => {
    const ctx = new Context();
    await ctx.plugin(preferenceStore, {});
    await ctx.plugin(theme, {});
    expect(ctx.theme.current).toBe("dark");
    ctx.theme.set("light");
    expect(ctx.theme.current).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("插件卸载撤销主题变量（可逆副作用）", async () => {
    const ctx = new Context();
    await ctx.plugin(preferenceStore, {});
    const fiber = await ctx.plugin(theme, { defaultTheme: "dark" });
    expect(document.documentElement.dataset.theme).toBe("dark");
    fiber.dispose();
    await vi.waitFor(() => {
      expect(document.documentElement.dataset.theme).toBeUndefined();
    });
    expect(document.documentElement.style.getPropertyValue("--bg-0")).toBe("");
  });
});

describe("clipboard.copied —— Toast + 30s 清除", () => {
  it("复制 → Toast「已复制，30 秒后自动清除」；30s 后自动清除；新复制重置计时", async () => {
    vi.useFakeTimers();
    const ctx = new Context();
    await ctx.plugin(toast, {});

    const snapshots: ToastMessage[][] = [];
    ctx.toast.subscribe((m) => snapshots.push(m));

    const clearedAt = new Date(Date.now() + 30_000).toISOString();
    ctx.emit("clipboard.copied", { source: "it-1", field: "password", clearedAt });
    expect(ctx.toast.all).toHaveLength(1);
    expect(ctx.toast.all[0].text).toBe(CLIPBOARD_TOAST_TEXT);
    expect(ctx.toast.all[0].clearedAt).toBe(clearedAt);

    // 30s 后自动清除
    await vi.advanceTimersByTimeAsync(30_000);
    expect(ctx.toast.all).toHaveLength(0);

    // 新复制：计时重置（20s 后仍在，30s 后清除）
    ctx.emit("clipboard.copied", {
      source: "it-2",
      field: "username",
      clearedAt: new Date(Date.now() + 30_000).toISOString(),
    });
    await vi.advanceTimersByTimeAsync(20_000);
    expect(ctx.toast.all).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(ctx.toast.all).toHaveLength(0);
  });

  it("dismiss 立即关闭并取消计时", async () => {
    vi.useFakeTimers();
    const ctx = new Context();
    await ctx.plugin(toast, {});
    ctx.emit("clipboard.copied", {
      source: "it-1",
      field: "password",
      clearedAt: new Date(Date.now() + 30_000).toISOString(),
    });
    expect(ctx.toast.all).toHaveLength(1);
    ctx.toast.dismiss(ctx.toast.all[0].id);
    expect(ctx.toast.all).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(ctx.toast.all).toHaveLength(0);
  });
});
