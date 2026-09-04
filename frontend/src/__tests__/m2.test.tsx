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
import { AuditPage } from "../plugins/ui-audit";
import { desktopShell } from "../plugins/desktop-shell";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { RulesPage } from "../plugins/ui-rules";
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

/** 装配 ipc-bridge（mock 适配器注入）+ toast + desktop-shell + approval。
 *  desktop-shell 必装（#95 起 approval 注入 ctx.shell 发强提醒）——与真实
 *  装配（`cordis.yml`）一致：shell 缺失时 cordis 会推迟 approval 启动。 */
async function mountHost(): Promise<{ ctx: Context; mock: MockAdapter }> {
  const ctx = new Context();
  const mock = new MockAdapter();
  await ctx.plugin(ipcBridge, { adapter: mock });
  await ctx.plugin(preferenceStore, {});
  await ctx.plugin(theme, { defaultTheme: "dark" });
  await ctx.plugin(toast, {});
  await ctx.plugin(desktopShell, {});
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

/** React 受控组件输入（原生 setter；同 onboarding.test 的 setInput）。 */
function setInput(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
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
        // mock 缺省注入的固定挑战（真实守护进程为一次性随机值，#78）
        challenge: "mock-challenge",
        // 锁定态一体化标志（#67）：mock 缺省 false，帧原样透传
        needsUnlock: false,
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
        kind: "inject",
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
        kind: "inject",
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
        kind: "inject",
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
        kind: "inject",
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
        kind: "inject",
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
    expect(spy).toHaveBeenCalledWith("req-allow", "allowed", "mock-challenge");
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
        kind: "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const denyBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("拒绝"),
    )!;
    const p = ctx.ipc.approvalResult("req-deny", "denied", "mock-challenge");
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
        kind: "inject",
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
    expect(spy).toHaveBeenCalledWith("req-esc", "denied", "mock-challenge");
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
      kind: "inject",
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

  it("锁定态收到普通 authz.request：不弹窗、不展示请求元数据（QA P1 门控）", async () => {
    const { mock } = await mountHost(); // 不解锁
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-locked",
        starter: "claude",
        projectDir: "/work/proj-e",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        needsUnlock: false,
      kind: "inject",
      });
    });
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(document.body.textContent).not.toContain("/work/proj-e");
  });

  it("锁定态 + needsUnlock（#67）：弹窗渲染主密码栏；解锁并允许携带 masterPassword", async () => {
    const { ctx, mock } = await mountHost(); // 不解锁（锁态一体化流程）
    const spy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-unlock",
        starter: "claude",
        projectDir: "/work/proj-l",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        needsUnlock: true,
      kind: "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog");
    expect(dialog).not.toBeNull();
    const text = dialog!.textContent ?? "";
    // 身份确认栏：主密码输入（labels：临时解锁）
    expect(text).toContain("主密码");
    expect(text).toContain("临时解锁");
    expect(text).toContain("npm publish");
    // 空密码不可提交（解锁并允许 disabled）
    const allowBtn = Array.from(dialog!.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("解锁并允许"),
    )!;
    expect((allowBtn as HTMLButtonElement).disabled).toBe(true);
    // 输入正确主密码 → 解锁并允许 → approvalResult(allowed, masterPassword)
    const input = dialog!.querySelector('input[aria-label="主密码"]') as HTMLInputElement;
    setInput(input, "demo-password");
    await act(async () => {
      allowBtn.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(spy).toHaveBeenCalledWith("req-unlock", "allowed", "mock-challenge", "demo-password");
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("已允许本次"))).toBe(true);
  });

  it("锁定态一体化：主密码错误 → VaultInvalidError → 弹窗停留显示错误可重试（#67）", async () => {
    const { mock } = await mountHost(); // 不解锁
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-unlock-bad",
        starter: "claude",
        projectDir: "/work/proj-m",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        needsUnlock: true,
      kind: "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const input = dialog.querySelector('input[aria-label="主密码"]') as HTMLInputElement;
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("解锁并允许"),
    )!;
    // 错误密码：mock 抛 VaultInvalidError → 弹窗停留 + 错误文案（条目保留可重试）
    setInput(input, "wrong-password");
    await act(async () => {
      allowBtn.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(document.body.querySelector(".approval-dialog")).not.toBeNull();
    expect(document.body.textContent).toContain("解锁失败（主密码错误或库未初始化）");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    // 重试正确密码 → 关闭
    const input2 = document.body.querySelector('input[aria-label="主密码"]') as HTMLInputElement;
    const allowBtn2 = Array.from(document.body.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("解锁并允许"),
    )!;
    setInput(input2, "demo-password");
    await act(async () => {
      allowBtn2.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
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
      kind: "inject",
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
      kind: "inject",
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
      kind: "inject",
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

describe("M2.9 值披露弹窗（kind=read/export；docs/value-disclosure.md §6）", () => {
  it("read 帧：展示条目名/启动者/目录、无命令框、有「允许并为此项目记住」", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-read",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.get",
        keys: ["API_KEY"],
        kind: "read",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    // 条目名 Tag（不展示值）
    expect(dialog.textContent).toContain("API_KEY");
    // read 弹窗不渲染命令框（读值无命令绑定）
    expect(dialog.querySelector(".approval-cmd-box")).toBeNull();
    // 记住按钮在（read 专属）
    const rememberBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许并为此项目记住"),
    );
    expect(rememberBtn).toBeDefined();

    // 点击记住 = allow 决策 + 追加 rule.add（capability=read，keys=[条目名]）
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      rememberBtn!.click();
    });
    await act(async () => {
      // approvalResult 与 ruleAdd 各有 300ms 模拟延迟
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(resultSpy).toHaveBeenCalledWith("req-read", "allowed", "mock-challenge");
    expect(ruleSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        projectDir: "/work/proj-a",
        command: "",
        capability: "read",
        keys: ["API_KEY"],
      }),
    );
    // 弹窗关闭
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("export 帧：展示数据包规模、无记住按钮（恒弹窗语义）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-export",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.export",
        keys: ["合同.pdf"],
        kind: "export",
        exportMeta: { name: "合同.pdf", mime: "application/pdf", size: 1024 },
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    expect(dialog.textContent).toContain("合同.pdf");
    // 数据包规模（formatSize(1024) = "1.0 KB"）
    expect(dialog.textContent).toContain("1.0 KB");
    expect(dialog.textContent).toContain("application/pdf");
    // export 不提供记住按钮（规则不豁免导出）
    const rememberBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许并为此项目记住"),
    );
    expect(rememberBtn).toBeUndefined();
    // 允许/拒绝照常
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("允许本次"),
      ),
    ).toBe(true);
  });

  it("inject 帧：无 exportMeta、无记住按钮（既有形态回归）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-inject",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        kind: "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    expect(dialog.querySelector(".approval-cmd-box")).not.toBeNull();
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("允许并为此项目记住"),
      ),
    ).toBe(false);
  });
});

describe("读通道一体化解锁弹窗（kind=read/export + needsUnlock；补充拍板 #23 / issue #105）", () => {
  // 钉住：记住按钮渲染条件 = `(isRead || (isWrite && !isWriteDelete)) &&
  // !needsUnlock`（M2.97 写门扩面后锁态一律无「允许并为此项目记住」——
  // remember 不被静默丢弃）。
  it("锁态 read 弹窗：无「记住」按钮（真正变更断言）、主密码栏在场；解锁并允许携带 masterPassword 且不追加 rule.add", async () => {
    const { ctx, mock } = await mountHost(); // 不解锁（锁态一体化流程）
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-locked-read",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.get",
        keys: ["API_KEY"],
        needsUnlock: true,
        kind: "read",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    // 主密码栏在场（临时解锁，不创建会话）+ 提示不带「注入」误导
    expect(dialog.textContent).toContain("主密码");
    expect(dialog.textContent).toContain("不创建会话");
    // 锁态 read：无「允许并为此项目记住」（isRead && !needsUnlock 为假——
    // 临时 vault 无法持久化规则，不承诺做不到的事）
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("允许并为此项目记住"),
      ),
    ).toBe(false);
    // read 形态仍不渲染 $ 命令框（读值无命令绑定）
    expect(dialog.querySelector(".approval-cmd-box")).toBeNull();
    // 解锁并允许 → approvalResult(allowed, masterPassword)，不追加 rule.add
    const input = dialog.querySelector('input[aria-label="主密码"]') as HTMLInputElement;
    setInput(input, "demo-password");
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("解锁并允许"),
    )!;
    await act(async () => {
      allowBtn.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(resultSpy).toHaveBeenCalledWith(
      "req-locked-read",
      "allowed",
      "mock-challenge",
      "demo-password",
    );
    expect(ruleSpy).not.toHaveBeenCalled();
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("锁态 export 弹窗：无记住按钮、主密码栏在场；解锁并允许携带 masterPassword", async () => {
    const { ctx, mock } = await mountHost(); // 不解锁（锁态一体化流程）
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-locked-export",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.export",
        keys: ["合同.pdf"],
        needsUnlock: true,
        kind: "export",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    expect(dialog.textContent).toContain("导出条目数据包");
    expect(dialog.textContent).toContain("主密码");
    // export 恒无记住按钮（锁态/解锁态一致）
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("允许并为此项目记住"),
      ),
    ).toBe(false);
    // 解锁并允许携带主密码（不经 remember 分支）
    const input = dialog.querySelector('input[aria-label="主密码"]') as HTMLInputElement;
    setInput(input, "demo-password");
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("解锁并允许"),
    )!;
    await act(async () => {
      allowBtn.click();
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(resultSpy).toHaveBeenCalledWith(
      "req-locked-export",
      "allowed",
      "mock-challenge",
      "demo-password",
    );
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });
});

describe("规则管理审批弹窗（kind=rule；补充拍板 #22 / issue #104）", () => {
  it("rule.add 帧：命令框展示操作、keys Tag、无「记住」按钮（规则操作本身即持久动作）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-rule-add",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "rule.add publish",
        keys: ["NPM_TOKEN", "GH_TOKEN"],
        kind: "rule",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    // 命令框承载操作（无 $ 前缀——非 shell 命令）
    expect(dialog.querySelector(".approval-cmd-box")!.textContent).toContain("rule.add publish");
    expect(dialog.querySelector(".approval-cmd-box")!.textContent).not.toContain("$");
    // 持久授权提示 + keys Tag
    expect(dialog.textContent).toContain("持久");
    expect(dialog.textContent).toContain("NPM_TOKEN");
    expect(dialog.textContent).toContain("GH_TOKEN");
    // 倒计时照常
    expect(dialog.querySelector(".ring-num")).not.toBeNull();
    // 无「允许并为此项目记住」（规则操作本身即持久动作，补充拍板 #22）
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("允许并为此项目记住"),
      ),
    ).toBe(false);

    // 允许本次 = approvalResult(allowed)；不追加 rule.add（与 read 的记住路径区分）
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许本次"),
    )!;
    act(() => {
      allowBtn.click();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(resultSpy).toHaveBeenCalledWith("req-rule-add", "allowed", "mock-challenge");
    expect(ruleSpy).not.toHaveBeenCalled();
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("rule.remove 帧：提示删除既有规则（撤销能力），展示操作", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-rule-remove",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "rule.remove publish",
        keys: ["NPM_TOKEN"],
        kind: "rule",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    expect(dialog.textContent).toContain("删除既有授权规则");
    expect(dialog.querySelector(".approval-cmd-box")!.textContent).toContain("rule.remove publish");
    // 拒绝照常可用
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) => b.textContent?.includes("拒绝")),
    ).toBe(true);
  });

  it("未知 kind：防御性渲染——明确提示未知，不回退按 inject 渲染（无 $ 命令框）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-unknown-kind",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "telemetry.dump",
        keys: ["NPM_TOKEN"],
        // 协议演进：新版守护进程发来的未知 kind 字符串
        kind: "telemetry" as unknown as "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    // 明确提示未知类型（含原始 kind 值）与升级指引
    expect(dialog.textContent).toContain("未知审批类型");
    expect(dialog.textContent).toContain("telemetry");
    // 不按 inject 渲染：不出现 $ 命令框（防御，规格 #102 故事 25）
    expect(dialog.querySelector(".approval-cmd-box")).toBeNull();
    // 拒绝/允许照常可用（不 crash；建议拒绝的文案在场）
    expect(dialog.textContent).toContain("建议拒绝");
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) => b.textContent?.includes("拒绝")),
    ).toBe(true);
    // kind 缺失的畸形帧同样走防御分支
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-missing-kind",
        starter: "zsh",
        projectDir: "/work/proj-b",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        kind: undefined,
      });
    });
    await flushApproval();
    const dialog2 = document.body.querySelectorAll(".approval-dialog");
    expect(dialog2.length).toBeGreaterThan(0);
  });
});

describe("M2.97 写门审批弹窗（kind=write；docs/write-gate.md §6）", () => {
  it("write put 帧：动作/目标条目名/projectDir/倒计时渲染，不展示值", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-write-put",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.put API_TOKEN",
        keys: ["API_TOKEN"],
        kind: "write",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const text = dialog.textContent ?? "";
    // 动作类 + RPC 摘要（含目标条目名）+ projectDir
    expect(text).toContain("写入条目（create/update）");
    expect(text).toContain("item.put API_TOKEN");
    expect(text).toContain("/work/proj-a");
    // 30s 倒计时照常
    expect(dialog.querySelector(".ring-num")!.textContent).toBe("30");
    // 不展示值：条目名 Tag 之外无任何值载荷；非 needsUnlock 无主密码栏
    expect(dialog.querySelector('input[type="password"]')).toBeNull();
    expect(text).toContain("条目值不会显示");
    // 命令框非 shell 形态：无 $ 前缀（同规则门先例）
    expect(dialog.querySelector(".approval-cmd-box")!.textContent).not.toContain("$");
  });

  it("write put 帧：记住按钮 → 生成最小写规则（capability=write、keys=[条目名]、actions=[create,update]）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-write-remember",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.put API_TOKEN",
        keys: ["API_TOKEN"],
        kind: "write",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const rememberBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许并为此项目记住"),
    );
    expect(rememberBtn).toBeDefined();
    act(() => {
      rememberBtn!.click();
    });
    await act(async () => {
      // approvalResult 与 ruleAdd 各有 300ms 模拟延迟
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(resultSpy).toHaveBeenCalledWith("req-write-remember", "allowed", "mock-challenge");
    expect(ruleSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        projectDir: "/work/proj-a",
        name: "write-API_TOKEN",
        command: "",
        keys: ["API_TOKEN"],
        capability: "write",
        // 帧面不可分 create/update（§5.2 RPC 不拆）→ 记住授予 put 全类；
        // delete 不在其中（协议恒弹窗，规则写不进去）
        actions: ["create", "update"],
      }),
    );
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("write delete 帧：恒弹窗语义——无记住按钮；允许路径不追加规则", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-write-delete",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "item.delete API_TOKEN",
        keys: ["API_TOKEN"],
        kind: "write",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const text = dialog.textContent ?? "";
    expect(text).toContain("删除条目（delete）");
    expect(text).toContain("item.delete API_TOKEN");
    // 恒弹窗语义明示（任何规则不豁免）
    expect(text).toContain("任何规则不豁免");
    // delete 无记住按钮（对齐 export 恒弹窗先例）
    expect(
      Array.from(dialog.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("允许并为此项目记住"),
      ),
    ).toBeUndefined();
    // 允许本次照常；不追加规则
    const allowBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("允许本次"),
    )!;
    act(() => {
      allowBtn.click();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(resultSpy).toHaveBeenCalledWith("req-write-delete", "allowed", "mock-challenge");
    expect(ruleSpy).not.toHaveBeenCalled();
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });
});

describe("M2.98 程序指纹失配审批弹窗（kind=inject + fingerprintMismatch；identity-binding.md §7）", () => {
  /** 失配帧参数（绑定注入规则命中命令形态但指纹不符）。 */
  const mismatchParams = {
    requestId: "req-fp-1",
    starter: "claude",
    projectDir: "/work/proj-a",
    command: "npm publish",
    keys: ["NPM_TOKEN"],
    kind: "inject" as const,
    fingerprintMismatch: {
      resolvedExePath: "C:\\Program Files\\nodejs\\npm.cmd",
      sha256Short: "a1b2c3d4",
    },
  };

  it("失配帧：主题明示「指纹不符/可能已更新」+ 路径 + 8 位摘要 + 三按钮，不渲染完整哈希", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    act(() => {
      mock.simulateAuthzRequest(mismatchParams);
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const text = dialog.textContent ?? "";
    // 主题：程序指纹与规则不符（可能已更新）
    expect(text).toContain("程序指纹与规则不符");
    expect(text).toContain("可能已更新");
    // 展示当前解析路径（不改写为 basename 之外的形式——原样展示）
    expect(text).toContain("C:\\Program Files\\nodejs\\npm.cmd");
    // 8 位 SHA-256 前缀摘要（不展示完整值）
    expect(text).toContain("a1b2c3d4");
    // 三按钮：拒绝 / 本次允许 / 以新指纹重新授权
    const btns = Array.from(dialog.querySelectorAll("button")).map((b) =>
      b.textContent!.trim(),
    );
    expect(btns.some((t) => t.includes("拒绝"))).toBe(true);
    expect(btns.some((t) => t.includes("允许本次"))).toBe(true);
    expect(btns.some((t) => t.includes("以新指纹重新授权"))).toBe(true);
    // kind 仍为 inject：渲染 $ 命令框（失配 = 视同未命中的 inject 审批）
    expect(dialog.querySelector(".approval-cmd-box")!.textContent).toContain("npm publish");
    // 未操作：不回传、不触发 ruleAdd
    expect(resultSpy).not.toHaveBeenCalled();
    expect(ruleSpy).not.toHaveBeenCalled();
  });

  it("sha256Short 为 64 位完整哈希（协议外防御）→ UI 只展示前 8 位", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    // 直接经订阅发帧（绕开 simulateAuthzRequest 的类型面，模拟恶意/未来帧）
    act(() => {
      mock.simulateAuthzRequest({
        ...mismatchParams,
        requestId: "req-fp-fullhash",
        fingerprintMismatch: {
          resolvedExePath: "/usr/bin/npm",
          sha256Short: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        },
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const text = dialog.textContent ?? "";
    // 只显示 8 位前缀；完整 64 位值绝不出现在 DOM
    expect(text).toContain("abcdef01");
    expect(text).not.toContain("abcdef0123456789abcdef0123456789");
  });

  it("「以新指纹重新授权」→ 允许当前审批 + ruleAdd（fingerprint 仅 exePath，capability=inject）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    act(() => {
      mock.simulateAuthzRequest(mismatchParams);
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    const reauthBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("以新指纹重新授权"),
    )!;
    act(() => {
      reauthBtn.click();
    });
    await act(async () => {
      // approvalResult 与 ruleAdd 各有 300ms 模拟延迟
      await vi.advanceTimersByTimeAsync(1000);
    });
    // 本次允许（失配帧走普通 allowed 回传）
    expect(resultSpy).toHaveBeenCalledWith("req-fp-1", "allowed", "mock-challenge");
    // 重新授权追加规则更新请求（仅绑定规则命中失配的审批帧）：capability=inject、
    // 绑定当前解析路径（daemon finalize 侧重算 sha/size，前端只声明 exePath）
    expect(ruleSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        capability: "inject",
        fingerprint: { exePath: "C:\\Program Files\\nodejs\\npm.cmd" },
      }),
    );
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("「本次允许」（失配帧）→ 仅回传 allowed，不追加 ruleAdd（一次性放行）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    const resultSpy = vi.spyOn(ctx.ipc, "approvalResult");
    const ruleSpy = vi.spyOn(ctx.ipc, "ruleAdd");
    act(() => {
      mock.simulateAuthzRequest(mismatchParams);
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
    expect(resultSpy).toHaveBeenCalledTimes(1);
    expect(resultSpy).toHaveBeenCalledWith("req-fp-1", "allowed", "mock-challenge");
    expect(ruleSpy).not.toHaveBeenCalled();
    expect(document.body.querySelector(".approval-dialog")).toBeNull();
  });

  it("非失配 inject 帧：无「以新指纹重新授权」按钮（仅绑定规则失配帧提供）", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    act(() => {
      mock.simulateAuthzRequest({
        requestId: "req-fp-none",
        starter: "claude",
        projectDir: "/work/proj-a",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        kind: "inject",
      });
    });
    await flushApproval();
    const dialog = document.body.querySelector(".approval-dialog")!;
    expect(
      Array.from(dialog.querySelectorAll("button")).some((b) =>
        b.textContent?.includes("以新指纹重新授权"),
      ),
    ).toBe(false);
  });

  it("畸形 fingerprintMismatch（缺 resolvedExePath / 非字符串）→ 防御：不 crash、按普通 inject 渲染、无重新授权按钮", async () => {
    const { ctx, mock } = await mountHost();
    await unlock(ctx);
    for (const bad of [
      { resolvedExePath: "", sha256Short: "a1b2c3d4" },
      { resolvedExePath: 42, sha256Short: "a1b2c3d4" },
      { resolvedExePath: "/usr/bin/npm", sha256Short: "" },
      null,
      "oops",
    ]) {
      act(() => {
        mock.simulateAuthzRequest({
          requestId: `req-fp-bad-${Math.random()}`,
          starter: "claude",
          projectDir: "/work/proj-a",
          command: "npm publish",
          keys: ["NPM_TOKEN"],
          kind: "inject",
          fingerprintMismatch: bad as never,
        });
      });
      await flushApproval();
      // 不 crash，弹窗在场；无失配主题/路径/摘要与重新授权按钮（防御渲染）
      const dialog = document.body.querySelector(".approval-dialog")!;
      expect(dialog).not.toBeNull();
      expect(dialog.textContent).not.toContain("程序指纹与规则不符");
      expect(
        Array.from(dialog.querySelectorAll("button")).some((b) =>
          b.textContent?.includes("以新指纹重新授权"),
        ),
      ).toBe(false);
      act(() => {
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300);
      });
    }
  });
});

describe("M2.97 规则页 / 审计页展示（write-gate.md §6/§8）", () => {
  it("规则列表：write 规则展示 capability + actions Tag；read 规则同现状；旧 inject 规则（capability 缺省）按命令展示", async () => {
    const { ctx } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "ruleList").mockResolvedValue([
      {
        id: "r-w",
        projectDir: "/work/proj-a",
        name: "写规则",
        command: "",
        keys: ["API_TOKEN"],
        capability: "write",
        actions: ["create", "update"],
        created: "2026-09-02T00:00:00Z",
      },
      {
        id: "r-r",
        projectDir: "/work/proj-a",
        name: "读规则",
        command: "",
        keys: ["API_KEY"],
        capability: "read",
        created: "2026-09-01T00:00:00Z",
      },
      {
        id: "r-i",
        projectDir: "/work/proj-b",
        name: "旧注入规则",
        command: "npm publish",
        keys: ["NPM_TOKEN"],
        created: "2026-08-14T10:00:00Z",
      },
    ]);
    await act(async () => {
      root.render(<RulesPage ctx={ctx} />);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const cards = Array.from(container.querySelectorAll("#page-rules .rule-card"));
    expect(cards).toHaveLength(3);
    const writeCard = cards.find((c) => c.textContent?.includes("写规则"))!;
    expect(writeCard.textContent).toContain("写入规则（按条目名授权写入）");
    expect(writeCard.textContent).toContain("write");
    expect(writeCard.textContent).toContain("create");
    expect(writeCard.textContent).toContain("update");
    const readCard = cards.find((c) => c.textContent?.includes("读规则"))!;
    expect(readCard.textContent).toContain("读值规则（按条目名授权读取）");
    expect(readCard.textContent).toContain("read");
    // capability != write 时 actions 被忽略、不展示（Rust serde 口径）
    expect(readCard.textContent).not.toContain("create");
    const injectCard = cards.find((c) => c.textContent?.includes("旧注入规则"))!;
    expect(injectCard.textContent).toContain("npm publish");
    // capability 缺省（旧规则）无 write/read 形态标注
    expect(injectCard.textContent).not.toContain("写入规则");
    expect(injectCard.textContent).not.toContain("读值规则");
  });

  it("审计页：写门事件按 §8 字段落表（command=派生动作+条目名、result、channel）", async () => {
    const { ctx } = await mountHost();
    await unlock(ctx);
    vi.spyOn(ctx.ipc, "auditList").mockResolvedValue([
      {
        eventId: "w1",
        ts: "2026-09-02T10:00:00Z",
        starter: "zsh",
        target: "API_TOKEN",
        command: "item.update API_TOKEN",
        result: "allowed",
        channel: "approval",
      },
      {
        eventId: "w2",
        ts: "2026-09-02T10:01:00Z",
        starter: "claude",
        target: "deploy-notes",
        command: "item.create deploy-notes",
        result: "allowed",
        channel: "cli",
      },
      {
        eventId: "w3",
        ts: "2026-09-02T10:02:00Z",
        starter: "claude",
        target: "release-notes",
        command: "item.delete release-notes",
        result: "denied",
        channel: "wsl-bridge",
      },
    ]);
    await act(async () => {
      root.render(<AuditPage ctx={ctx} />);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const page = container.querySelector("#page-audit")!;
    // §8 口径：command=动作派生 + 条目名（值不明文），风格与既有审计行一致
    expect(page.textContent).toContain("item.update API_TOKEN");
    expect(page.textContent).toContain("item.create deploy-notes");
    expect(page.textContent).toContain("item.delete release-notes");
    // 结果 Tag（allowed/denied）与来源通道
    expect(page.textContent).toContain("允许");
    expect(page.textContent).toContain("拒绝");
    expect(page.textContent).toContain("审批");
    expect(page.textContent).toContain("CLI");
    expect(page.textContent).toContain("WSL 桥接");
    expect(page.querySelectorAll(".audit-row")).toHaveLength(3);
  });
});
