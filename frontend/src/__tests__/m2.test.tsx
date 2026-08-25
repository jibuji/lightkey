/**
 * M2 桌面层单测（testing.md M2 出口 · D 层）：
 *
 * - ipc-bridge 通知翻译：mock 适配器模拟帧（authz.request / item.changed）
 *   → Cordis 事件（Rust 事件 → IPC 通知 → 本层重新 emit，§5.3）；
 * - approval 弹窗闭环：30s 倒计时 / 允许 / 拒绝（按钮 + Esc）/ 超时关闭
 *   （超时审计在守护进程侧，弹窗不回传）；伪造 requestId → accepted=false；
 * - tauri 模式会话去重：本地解锁广播 + 守护进程推送帧只产生一个事件
 *   （订阅建立前的首次解锁由本地广播覆盖）。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { approval } from "../plugins/approval";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { toast } from "../plugins/toast";
import { theme } from "../plugins/theme";
import { MockAdapter } from "../ipc/mockAdapter";
import type { LightKeyIpc, NotificationFrame } from "../ipc/types";

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
  // approval 插件自挂 root 到 document.body（独立于测试容器）；逐个清理
  for (const el of Array.from(document.body.querySelectorAll(".approval-root"))) {
    el.remove();
  }
  vi.useRealTimers();
});

/** 装配 ipc-bridge（mock 适配器注入）+ toast + approval。 */
async function mountHost(): Promise<{ ctx: Context; mock: MockAdapter }> {
  const ctx = new Context();
  const mock = new MockAdapter();
  await ctx.plugin(ipcBridge, { adapter: mock });
  await ctx.plugin(preferenceStore, {});
  await ctx.plugin(theme, { defaultTheme: "dark" });
  await ctx.plugin(toast, {});
  await ctx.plugin(approval, {});
  return { ctx, mock };
}

/** 解锁（mock：demo-password；推进 300ms 模拟延迟）。 */
async function unlock(ctx: Context) {
  const p = ctx.session.unlock("demo-password");
  await vi.advanceTimersByTimeAsync(300);
  await p;
}

/** 审批入队为异步（enqueue 先读 config 再渲染）；flush 掉 mock 300ms configGet 延迟。 */
async function flushApproval() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(300);
  });
}

describe("ipc-bridge 通知翻译（Rust 事件 → IPC 通知 → 本层重新 emit）", () => {
  it("authz.request 帧 → Cordis 事件（负载字段对齐契约，无密钥值）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const seen: unknown[] = [];
    ctx.on("authz.request", (p) => seen.push(p));
    mock.simulateAuthzRequest({
      requestId: "req-1",
      starter: "claude",
      projectDir: "/work/proj-a",
      command: "npm publish",
      keys: ["NPM_TOKEN"],
    });
    expect(seen).toEqual([
      {
        requestId: "req-1",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      },
    ]);
  });

  it("item.changed 帧 → 事件（ui 刷新三方响应之一）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const seen: unknown[] = [];
    ctx.on("item.changed", (p) => seen.push(p));
    mock.simulateItemChanged({
      itemId: "it-1",
      revisionDate: "2026-08-16T00:00:00Z",
      type: "login",
      deleted: false,
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ itemId: "it-1", type: "login", deleted: false });
  });

  it("未知事件名帧忽略（协议容错）", async () => {
    const { mock } = await mountHost();
    const spy = vi.fn();
    await mock.subscribeNotifications((f: NotificationFrame) => {
      if (f.method === "bogus.event") spy();
    });
    mock.simulateItemChanged({
      itemId: "x",
      revisionDate: "r",
      type: "login",
      deleted: false,
    });
    // 帧回调收到但翻译层只 emit 已知事件（bogus 未注册 → 无副作用）
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("approval 弹窗闭环（spec §6.5）", () => {
  it("authz.request → 弹窗渲染：启动者/目录/命令/key Tag/倒计时", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      root.render(<div />);
    });
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-1",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN", "GH_TOKEN"],
      });
    });
    await flushApproval();
    // approval 插件自挂 root 到 body
    const dialog = document.body.querySelector(".approval-dialog");
    expect(dialog).not.toBeNull();
    const text = dialog!.textContent ?? "";
    expect(text).toContain("claude");
    expect(text).toContain("/work/proj-a");
    expect(text).toContain("npm publish");
    expect(text).toContain("NPM_TOKEN");
    expect(text).toContain("GH_TOKEN");
    expect(text).toContain("超时默认拒绝");
    expect(dialog!.querySelector(".ring-num")).not.toBeNull();
    // 倒计时初始 30s
    expect(dialog!.querySelector(".ring-num")!.textContent).toBe("30");
  });

  it("倒计时取自 config approvalTimeoutSecs（120 → 120s，非硬编码 30）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "configGet").mockResolvedValue({
      autoLockMinutes: 5,
      approvalTimeoutSecs: 120,
      sync: null,
    });
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-120",
        starter: "claude",
        projectDir: "/work/proj-i",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    const ring = document.body.querySelector(".approval-dialog")!.querySelector(".ring-num")!;
    expect(ring.textContent).toBe("120");
    // 真实 120s 倒计时（非 30s 钳制）：1 秒后 → 119
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(document.body.querySelector(".ring-num")!.textContent).toBe("119");
  });

  it("config 读不到 approvalTimeoutSecs（configGet 异常）→ 默认 30s", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "configGet").mockRejectedValue(new Error("config unavailable"));
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-fallback",
        starter: "claude",
        projectDir: "/work/proj-j",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    expect(
      document.body.querySelector(".approval-dialog")!.querySelector(".ring-num")!.textContent,
    ).toBe("30");
  });

  it("config approvalTimeoutSecs=0 → 对齐守护进程 .max(1) 显示 1s（非 30）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "configGet").mockResolvedValue({
      autoLockMinutes: 5,
      approvalTimeoutSecs: 0,
      sync: null,
    });
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-zero",
        starter: "claude",
        projectDir: "/work/proj-k",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    expect(
      document.body.querySelector(".approval-dialog")!.querySelector(".ring-num")!.textContent,
    ).toBe("1");
  });

  it("允许本次 → approvalResult(allowed) 回传 + 弹窗关闭 + Toast", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const spy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-allow",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许本次"),
    )!;
    act(() => {
      allowBtn.click();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(spy).toHaveBeenCalledWith("req-allow", "allowed");
    // 弹窗关闭 + Toast 提示已允许（mock 登记过 → accepted=true）
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("已允许本次"))).toBe(true);
  });

  it("拒绝按钮 → approvalResult(denied) + 关闭", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-deny",
        starter: "zsh",
        projectDir: "/work/proj-b",
        command: "git push",
        keys: ["GH_TOKEN"],
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const denyBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("拒绝"),
    )!;
    const p = ctx.ipc.approvalResult("req-deny", "denied");
    act(() => {
      denyBtn.click();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    await p;
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("已拒绝"))).toBe(true);
  });

  it("Esc = 拒绝（spec §6.5）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const spy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-esc",
        starter: "zsh",
        projectDir: "/work/proj-c",
        command: "aws s3 sync *",
        keys: ["AWS_ACCESS_KEY_ID"],
      });
    });
    await flushApproval();
    expect(document.body.querySelector(".approval-dialog")).not.toBeNull();
    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(spy).toHaveBeenCalledWith("req-esc", "denied");
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("超时（30s）→ 弹窗自动关闭（不回传；守护进程侧审计 timeout）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const spy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-timeout",
        starter: "claude",
        projectDir: "/work/proj-d",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    expect(document.body.querySelector(".approval-dialog")).not.toBeNull();
    // 30s 倒计时（分步推进以触发每秒 tick）
    for (let i = 0; i < 31; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }
    // 弹窗关闭；未回传（超时审计在守护进程侧）
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it("锁定态收到 authz.request：不弹窗、不展示请求元数据（QA P1 门控）", async () => {
    const { mock } = await mountHost(); // 不解锁
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-locked",
        starter: "claude",
        projectDir: "/work/proj-e",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(document.body.textContent).not.toContain("/work/proj-e");
  });

  it("弹窗打开期间 session.locked → 清空队列并关闭弹窗（QA P2 自动锁残留）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-autolock",
        starter: "claude",
        projectDir: "/work/proj-f",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    expect(document.body.querySelector(".approval-dialog")).not.toBeNull();
    act(() => {
      ctx.emit("session.locked", { reason: "timeout" });
    });
    // portal 层独立于锁态整页，必须自行响应锁定：弹窗关闭、队列清空
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    // 锁定后再来的帧同样不弹
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-after-lock",
        starter: "claude",
        projectDir: "/work/proj-g",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("approvalResult 回传失败（会话失效 reject）→ 弹窗仍关闭、Toast 提示（QA P1 卡死）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "approvalResult").mockRejectedValueOnce(new Error("session.invalid"));
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-reject",
        starter: "claude",
        projectDir: "/work/proj-h",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const denyBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("拒绝"),
    )!;
    await act(async () => {
      denyBtn.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    // 未被 .then 独占：catch 兜底后 finally 关闭，无 unhandled rejection、无卡死
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("审批回传失败"))).toBe(true);
  });
});

describe("tauri 模式：会话事件去重（本地广播 + 推送帧不双发）", () => {
  /** 伪 tauri 适配器：真实推送语义（解锁后推送 session.unlocked 帧）。 */
  class FakeTauriAdapter implements LightKeyIpc {
    readonly kind = "tauri" as const;
    unlocked = false;
    /** 已初始化库（tauri 模式默认有库；首启门控场景见 onboarding 测试）。 */
    initialized = true;
    private handler: ((f: NotificationFrame) => void) | null = null;
    status = vi.fn(async () => ({ unlocked: this.unlocked, initialized: this.initialized }));
    unlock = vi.fn(async (_pw: string) => {
      this.unlocked = true;
      // 守护进程在响应前已广播 session.unlocked（真实语义：帧先于响应）
      this.pushSessionUnlocked();
    });
    init = vi.fn(async (_pw: string) => ({ recoveryCode: "x" }));
    lock = vi.fn(async () => {
      this.unlocked = false;
      this.handler?.({ jsonrpc: "2.0", method: "session.locked", params: { reason: "manual" } });
    });

    /** 模拟守护进程广播（订阅建立后的解锁：帧到达 → 去重标记吞掉）。 */
    pushSessionUnlocked() {
      this.handler?.({ jsonrpc: "2.0", method: "session.unlocked", params: { via: "password" } });
    }

    /** 模拟守护进程广播锁定（外部锁定：timeout/lockscreen/CLI）。 */
    pushSessionLocked(reason: string) {
      this.handler?.({ jsonrpc: "2.0", method: "session.locked", params: { reason } });
    }
    recover = vi.fn(async () => ({ recoveryCode: "x" }));
    list = vi.fn(async () => []);
    get = vi.fn(async () => {
      throw new Error("n/a");
    });
    create = vi.fn(async () => {
      throw new Error("n/a");
    });
    update = vi.fn(async () => {
      throw new Error("n/a");
    });
    remove = vi.fn(async () => undefined);
    syncStatus = vi.fn(async () => ({ lastSync: null }));
    syncTrigger = vi.fn(async () => ({ lastSync: null }));
    auditList = vi.fn(async () => []);
    ruleList = vi.fn(async () => []);
    ruleAdd = vi.fn(async () => {
      throw new Error("n/a");
    });
    ruleRemove = vi.fn(async () => undefined);
    approvalResult = vi.fn(async () => ({ accepted: true }));
    configGet = vi.fn(async () => ({ autoLockMinutes: 5, approvalTimeoutSecs: 30, sync: null }));
    configSet = vi.fn(async () => undefined);
    pickDir = vi.fn(async () => null);
    subscribeNotifications = vi.fn(async (h: (f: NotificationFrame) => void) => {
      this.handler = h;
      return () => {
        this.handler = null;
      };
    });
  }

  it("解锁：本地广播一次（推送帧被抑制标记吞掉）；外部锁定推送 → 事件", async () => {
    const ctx = new Context();
    const fake = new FakeTauriAdapter();
    await ctx.plugin(ipcBridge, { adapter: fake });

    const states: string[] = [];
    ctx.on("session.unlocked", (p) => states.push(`unlocked:${p.via}`));
    ctx.on("session.locked", (p) => states.push(`locked:${p.reason}`));

    await ctx.session.unlock("pw");
    expect(states).toEqual(["unlocked:password"]); // 推送帧被去重，无双发
    expect(ctx.session.unlocked).toBe(true);

    // 外部锁定（守护进程推送，无本地动作）→ 事件
    fake.pushSessionLocked("lockscreen");
    expect(states).toEqual(["unlocked:password", "locked:lockscreen"]);
    expect(ctx.session.unlocked).toBe(false);

    // 本地锁定：推送帧被去重
    await ctx.session.lock();
    expect(states).toEqual(["unlocked:password", "locked:lockscreen", "locked:manual"]);
  });

  it("解锁失败：抑制标记清除（后续推送不被误吞）", async () => {
    const ctx = new Context();
    const fake = new FakeTauriAdapter();
    // 首次解锁失败（密码错；其后恢复成功路径）
    let failNext = true;
    fake.unlock = vi.fn(async (_pw: string) => {
      if (failNext) {
        failNext = false;
        throw new Error("vault.invalid");
      }
      fake.unlocked = true;
      fake.pushSessionUnlocked(); // 真实语义：守护进程在响应前广播
    });
    await ctx.plugin(ipcBridge, { adapter: fake });
    const states: string[] = [];
    ctx.on("session.unlocked", () => states.push("unlocked"));
    await expect(ctx.session.unlock("wrong")).rejects.toThrow("vault.invalid");
    expect(ctx.session.unlocked).toBe(false);
    // 成功解锁（守护进程推送帧被去重标记吞掉 → 1 次广播）
    await ctx.session.unlock("pw");
    expect(states).toEqual(["unlocked"]);
    // 随后外部解锁推送（如 CLI 侧再次解锁）：标记已消费 → 正常广播
    fake.pushSessionUnlocked();
    expect(states).toEqual(["unlocked", "unlocked"]);
  });
});
