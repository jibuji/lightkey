/**
 * 审批强提醒（issue #95；D 层单测）。
 *
 * 接缝：`ctx.shell` 服务面（desktop-shell 提供）与 `approval` 插件的行为面
 * ——提醒**什么时候**发、发什么。原生壳内部（系统通知 API / 任务栏闪烁）
 * 不在本层测试范围（无 Tauri 运行时），由 lk-app 的命令面承载。
 *
 * 回归背景：审批弹窗是纯 webview DOM 层，窗口最小化 / 隐藏到托盘 /
 * 被遮挡时用户零感知，30s 倒计时静默走完即默认拒绝——用户连发生过一次
 * 授权尝试都不知道。提醒必须不依赖窗口可见性。
 *
 * 保守口径（安全边界）：通知正文只含启动者与项目目录，**不含命令行与
 * 条目名**——通知会落进系统通知中心与锁屏预览，等同离开守护进程保护。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { approval } from "../plugins/approval";
import { desktopShell } from "../plugins/desktop-shell";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { toast } from "../plugins/toast";
import { theme } from "../plugins/theme";
import { MockAdapter } from "../ipc/mockAdapter";

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
  for (const el of Array.from(document.body.querySelectorAll(".approval-root"))) {
    el.remove();
  }
  vi.useRealTimers();
});

/** 装配 ipc-bridge（mock 适配器）+ toast + desktop-shell + approval。 */
async function mountHost(): Promise<{ ctx: Context; mock: MockAdapter }> {
  const ctx = new Context();
  const mock = new MockAdapter();
  await ctx.plugin(ipcBridge, { adapter: mock });
  await ctx.plugin(preferenceStore, {});
  await ctx.plugin(theme, { defaultTheme: "dark" });
  await ctx.plugin(toast, {});
  // approval 依赖 ctx.shell：须先于 approval 装配
  await ctx.plugin(desktopShell, {});
  await ctx.plugin(approval, {});
  return { ctx, mock };
}

async function unlock(ctx: Context) {
  const p = ctx.session.unlock("demo-password");
  await vi.advanceTimersByTimeAsync(300);
  await p;
}

/** 锁定（mock 适配器同为延时响应；锁定时 approval 会清队列并关弹窗）。 */
async function lockSession(ctx: Context) {
  await act(async () => {
    const p = ctx.session.lock();
    await vi.advanceTimersByTimeAsync(300);
    await p;
  });
}

/** 审批入队为异步（enqueue 先读 config 再渲染）；flush 掉 mock 300ms 延迟。 */
async function flushApproval() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(300);
  });
}

describe("审批强提醒（#95）", () => {
  it("请求入队 → 发一次提醒，载荷只含启动者与项目目录", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const alert = vi.spyOn(ctx.shell, "alertApproval");

    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-1",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish --otp 123456",
        keys: ["NPM_TOKEN", "GH_TOKEN"],
      });
    });
    await flushApproval();

    // 深度相等即构成保守口径的断言：命令行与条目名不得进通知载荷
    expect(alert).toHaveBeenCalledTimes(1);
    expect(alert).toHaveBeenCalledWith({
      starter: "claude",
      projectDir: "/work/proj-a",
    });
  });

  it("锁定态普通帧（needsUnlock 未置位）→ 不提醒", async () => {
    const { ctx, mock } = await mountHost();
    const alert = vi.spyOn(ctx.shell, "alertApproval");

    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-locked",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();

    expect(alert).not.toHaveBeenCalled();
  });

  it("队列已有待批请求 → 不重复提醒（避免通知刷屏）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const alert = vi.spyOn(ctx.shell, "alertApproval");

    for (const requestId of ["req-a", "req-b", "req-c"]) {
      act(() => {
        mock.simulateAuthzRequest({
          requestId,
          starter: "claude",
          projectDir: "/work/proj-a",
          command: "npm publish",
          keys: ["NPM_TOKEN"],
        });
      });
      await flushApproval();
    }

    expect(alert).toHaveBeenCalledTimes(1);
  });

  it("队列清空后（锁定再解锁）再有请求 → 重新提醒", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const alert = vi.spyOn(ctx.shell, "alertApproval");

    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-1",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    expect(alert).toHaveBeenCalledTimes(1);

    // 锁定：清队列并关弹窗（approval 自行响应 session.locked）
    await lockSession(ctx);
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-2",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();

    expect(alert).toHaveBeenCalledTimes(2);
  });

  it("提醒通道失败（原生壳不可用时）→ 不阻塞弹窗与倒计时", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.shell, "alertApproval").mockRejectedValue(new Error("no native shell"));

    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-fail",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();

    const dialog = document.body.querySelector(".approval-dialog");
    expect(dialog).not.toBeNull();
    expect(dialog!.querySelector(".ring-num")!.textContent).toBe("30");
  });
});
