/**
 * ipc-bridge tauri 模式壳事件 `lk-shell-quick-save` 分支单测（issue #177）。
 *
 * 覆盖（问题点：listen 的 dispose 竞态 + 失败静默）：
 * - 卸载发生在 listen resolve 前 → 迟到 resolve 立即退订，无监听残留（无泄漏）；
 * - 真实 Tauri 运行时 listen 失败（Promise reject）→ console.error 可观测信号；
 * - 伪 tauri 适配器同步抛错（测试环境，无 __TAURI_INTERNALS__）→ 静默降级；
 * - 正常路径：监听注册 → 事件翻译 quick.save-request → 卸载退订，与现状一致。
 *
 * mock DOM 分支（window.addEventListener `lk-shell-quick-save`）另见
 * quickSave.test.tsx「壳事件翻译」用例，此处只覆盖 tauri 分支。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";

const { listenMock } = vi.hoisted(() => ({ listenMock: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: listenMock }));

import { ipcBridge } from "../plugins/ipc-bridge";
import type { LightKeyIpc, NotificationFrame } from "../ipc/types";

/** 最小 tauri 适配器桩：ipcBridge 只用得到这些成员（其余成员测试不触达）。 */
function fakeTauriAdapter(): LightKeyIpc {
  return {
    kind: "tauri",
    status: vi.fn(async () => ({ unlocked: false, initialized: true })),
    unlock: vi.fn(async () => undefined),
    init: vi.fn(async () => ({ recoveryCode: "x" })),
    lock: vi.fn(async () => undefined),
    subscribeNotifications: vi.fn(
      async (_h: (f: NotificationFrame) => void) => () => {},
    ),
  } as unknown as LightKeyIpc;
}

/** 模拟真实 Tauri 运行时在场（isTauriRuntime 判据；测试默认无 __TAURI_INTERNALS__）。 */
function stubRealRuntime() {
  Reflect.defineProperty(window, "__TAURI_INTERNALS__", {
    value: {},
    configurable: true,
  });
}
function restoreRuntimeStub() {
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
}

let activeDisposers: Array<() => void> = [];

beforeEach(() => {
  listenMock.mockReset();
  activeDisposers = [];
});

afterEach(() => {
  for (const dispose of activeDisposers) dispose();
  activeDisposers = [];
  restoreRuntimeStub();
});

describe("ipc-bridge tauri 模式壳事件（issue #177）", () => {
  async function mount(): Promise<{ ctx: Context; dispose(): void }> {
    const ctx = new Context();
    const fiber = await ctx.plugin(ipcBridge, { adapter: fakeTauriAdapter() });
    activeDisposers.push(fiber.dispose);
    return { ctx, dispose: fiber.dispose };
  }

  it("竞态：卸载发生在 listen resolve 前 → 迟到 resolve 立即退订，无残留监听", async () => {
    let resolveListen!: (u: () => void) => void;
    listenMock.mockReturnValue(
      new Promise<() => void>((resolve) => {
        resolveListen = resolve;
      }),
    );

    const { dispose } = await mount();
    expect(listenMock).toHaveBeenCalledWith("lk-shell-quick-save", expect.any(Function));

    // 卸载发生在 resolve 前（退订句柄尚未拿到——旧实现此处即泄漏点）
    dispose();

    // 迟到的 resolve：必须立即调用 unlisten（不残留已注册的 tauri 监听）
    const unlisten = vi.fn();
    resolveListen(unlisten);
    await vi.waitFor(() => expect(unlisten).toHaveBeenCalledTimes(1));
  });

  it("真实 Tauri 运行时 listen 失败（Promise reject）→ console.error 可观测信号", async () => {
    const failure = new Error("plugin:event|listen invoke 失败");
    listenMock.mockRejectedValue(failure);
    stubRealRuntime(); // 真实运行时判据（__TAURI_INTERNALS__ 在场）
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await mount();
      await vi.waitFor(() => expect(errorSpy).toHaveBeenCalledTimes(1));
      expect(errorSpy.mock.calls[0]![0]).toContain("lk-shell-quick-save");
      expect(errorSpy.mock.calls[0]![1]).toBe(failure);
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("伪 tauri 适配器同步抛错（无真实运行时）→ 静默降级，无 console.error", async () => {
    listenMock.mockImplementation(() => {
      throw new TypeError(
        "Cannot read properties of undefined (reading 'transformCallback')",
      );
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await mount(); // 插件挂载不炸（同步抛错被兜住）
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("正常路径：监听注册 → 事件翻译 quick.save-request → 卸载退订", async () => {
    const unlisten = vi.fn();
    listenMock.mockResolvedValue(unlisten);

    const { ctx, dispose } = await mount();
    expect(listenMock).toHaveBeenCalledWith("lk-shell-quick-save", expect.any(Function));

    // 触发已注册的 tauri 监听（Rust 壳 emit → 本层翻译）
    const seen: number[] = [];
    ctx.on("quick.save-request", () => seen.push(1));
    const handler = listenMock.mock.calls[0]![1] as () => void;
    handler();
    expect(seen).toEqual([1]);

    // 卸载 → 退订句柄被调用（无论 resolve 在 dispose 前还是后都恰好一次）
    dispose();
    await vi.waitFor(() => expect(unlisten).toHaveBeenCalledTimes(1));
  });
});