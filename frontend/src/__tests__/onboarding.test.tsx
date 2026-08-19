/**
 * M2.5 首次初始化向导单测（testing.md M2.5 出口 · D 层）：
 *
 * - 首启门控互斥：无库（initialized=false）→ 整页初始化向导；有库 →
 *   解锁页（宿主 Skeleton 按 session.initialized 裁决，与 ui-unlock 互斥）；
 * - 四步全流程：欢迎 → 设主密码（弱密码/不一致门控 + 强度条）→ 真实恢复码
 *   （来自 mock vault.init 响应，仅一次；勾选门控）→ 完成 → unlock 进入
 *   已解锁主界面（三栏）；
 * - 回退导航（step3→2→1）；已建库后改密码 → vault.init 已存在库 → 统一
 *   文案不区分（ipc.md §3 防探测）；原密码重进 → 复用恢复码（不重复 init）。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { CordisHost } from "../host/CordisHost";
import { MockAdapter } from "../ipc/mockAdapter";
import { DEMO_RECOVERY_CODE } from "../ipc/mockData";

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

/** 挂载全量宿主（注入 mock 适配器）；推进状态探测（300ms mock 延迟）。 */
async function mountHost(mock: MockAdapter): Promise<void> {
  await act(async () => {
    root.render(<CordisHost ipcAdapter={mock} />);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  // vault.status 探测（首启门控数据源）
  await act(async () => {
    await vi.advanceTimersByTimeAsync(300);
  });
}

/** 原生 setter 模拟输入（React 受控组件）。 */
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

function click(el: Element) {
  act(() => {
    (el as HTMLButtonElement).click();
  });
}

/** 点击文案匹配的按钮。 */
function findButton(text: string): HTMLButtonElement {
  const btn = Array.from(container.querySelectorAll("button")).find((b) =>
    b.textContent?.includes(text),
  );
  expect(btn, `按钮「${text}」应存在`).toBeDefined();
  return btn as HTMLButtonElement;
}

/** 向导从 step1 走到 step2 并输入密码。 */
function fillStep2(password: string, confirm = password) {
  click(findButton("开始设置"));
  setInput(container.querySelector('input[aria-label="主密码"]') as HTMLInputElement, password);
  setInput(container.querySelector('input[aria-label="确认主密码"]') as HTMLInputElement, confirm);
}

const STRONG_PW = "L1ghtK3y@2026!";

describe("首启门控（无库 → 初始化向导；有库 → 解锁页，互斥）", () => {
  it("无库（模拟全新安装）：启动 → 初始化向导而非解锁页", async () => {
    const mock = new MockAdapter();
    mock.simulateFreshInstall();
    await mountHost(mock);

    expect(container.querySelector(".screen-onboarding")).not.toBeNull();
    expect(container.querySelector(".screen-unlock")).toBeNull();
    expect(container.querySelector(".sidebar")).toBeNull();
    // step1 欢迎页
    expect(container.textContent).toContain("欢迎使用 LightKey");
    expect(container.textContent).toContain("开始设置");
    // 门控数据源：mock 库未初始化
    expect(mock.isInitialized()).toBe(false);
  });

  it("有库（回归）：启动 → 解锁页而非向导", async () => {
    const mock = new MockAdapter();
    await mountHost(mock);

    expect(container.querySelector(".screen-unlock")).not.toBeNull();
    expect(container.querySelector(".screen-onboarding")).toBeNull();
    expect(container.querySelector('input[aria-label="主密码"]')).not.toBeNull();
  });

  it("探测中（initialized=null）：渲染检测占位，不闪解锁页", async () => {
    const mock = new MockAdapter();
    mock.simulateFreshInstall();
    await act(async () => {
      root.render(<CordisHost ipcAdapter={mock} />);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    // 探测未返回：占位（无解锁页、无向导——避免错误页闪烁）
    expect(container.textContent).toContain("正在检测库状态");
    expect(container.querySelector(".screen-unlock")).toBeNull();
    expect(container.querySelector(".screen-onboarding")).toBeNull();
    // 探测返回 → 向导
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.querySelector(".screen-onboarding")).not.toBeNull();
  });
});

describe("初始化向导四步流", () => {
  it("欢迎 → 设主密码（弱/不一致门控 + 强度）→ 恢复码 → 完成 → 已解锁主界面", async () => {
    const mock = new MockAdapter();
    mock.simulateFreshInstall();
    await mountHost(mock);
    const initSpy = vi.spyOn(mock, "init");

    // step1 → step2
    click(findButton("开始设置"));
    expect(container.querySelector('[data-testid="onboard-step-2"]')).not.toBeNull();
    // 进度点：1、2 点亮
    expect(container.querySelectorAll(".ostep.active")).toHaveLength(2);

    // 弱密码（6 位）：强度「弱」+ 错误提示 + 下一步禁用
    setInput(container.querySelector('input[aria-label="主密码"]') as HTMLInputElement, "abc123");
    expect(container.querySelector(".strength-label")?.textContent).toBe("弱");
    expect(container.textContent).toContain("主密码至少 8 位");
    expect(findButton("下一步").disabled).toBe(true);

    // 不一致：强密码 + 不同确认 → 「两次输入不一致」+ 禁用
    setInput(container.querySelector('input[aria-label="主密码"]') as HTMLInputElement, STRONG_PW);
    setInput(
      container.querySelector('input[aria-label="确认主密码"]') as HTMLInputElement,
      "different1",
    );
    expect(container.querySelector(".strength-label")?.textContent).toBe("极强");
    expect(container.textContent).toContain("两次输入不一致");
    expect(findButton("下一步").disabled).toBe(true);

    // 一致 → 下一步可用 → step3（真实恢复码来自 vault.init 响应）
    setInput(
      container.querySelector('input[aria-label="确认主密码"]') as HTMLInputElement,
      STRONG_PW,
    );
    expect(findButton("下一步").disabled).toBe(false);
    click(findButton("下一步"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // vault.init
    });
    expect(container.querySelector('[data-testid="onboard-step-3"]')).not.toBeNull();
    // 恢复码 = 后端返回（仅一次；前端不生成/不落盘）
    expect(initSpy).toHaveBeenCalledWith(STRONG_PW);
    expect(container.querySelector('[data-testid="ob-code"]')?.textContent).toBe(
      DEMO_RECOVERY_CODE,
    );

    // 勾选门控：未勾选时「下一步」禁用；勾选后可用 → step4
    expect(findButton("下一步").disabled).toBe(true);
    const check = container.querySelector('input[aria-label="我已妥善保存恢复码"]') as HTMLInputElement;
    act(() => {
      check.click();
    });
    expect(findButton("下一步").disabled).toBe(false);
    click(findButton("下一步"));
    expect(container.querySelector('[data-testid="onboard-step-4"]')).not.toBeNull();
    expect(container.textContent).toContain("初始化完成");
    // 进度点全亮
    expect(container.querySelectorAll(".ostep.active")).toHaveLength(4);

    // 完成 → unlock → 已解锁主界面（三栏）；向导消失
    click(findButton("进入 LightKey"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // vault.unlock
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // item.list
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // item.get ×N
    });
    expect(container.querySelector(".screen-onboarding")).toBeNull();
    expect(container.querySelector(".sidebar")).not.toBeNull();
    expect(container.querySelector(".topbar")).not.toBeNull();
    expect(container.textContent).toContain("全部条目");
    expect(mock.isUnlocked()).toBe(true);
    expect(mock.isInitialized()).toBe(true);
  });

  it("回退导航：step3 → 上一步 → step2（密码保留）；step2 → 上一步 → step1", async () => {
    const mock = new MockAdapter();
    mock.simulateFreshInstall();
    await mountHost(mock);

    fillStep2(STRONG_PW);
    click(findButton("下一步"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300); // vault.init
    });
    expect(container.querySelector('[data-testid="onboard-step-3"]')).not.toBeNull();

    // step3 → step2：密码/确认保留（不重复 init 即可重进）
    click(findButton("上一步"));
    expect(container.querySelector('[data-testid="onboard-step-2"]')).not.toBeNull();
    expect((container.querySelector('input[aria-label="主密码"]') as HTMLInputElement).value).toBe(
      STRONG_PW,
    );
    // step2 → step1
    click(findButton("上一步"));
    expect(container.querySelector('[data-testid="onboard-step-1"]')).not.toBeNull();
    expect(container.textContent).toContain("欢迎使用 LightKey");
  });

  it("已建库后改密码重进 → 统一文案（不区分弱密码/已存在库）；原密码 → 复用恢复码", async () => {
    const mock = new MockAdapter();
    mock.simulateFreshInstall();
    await mountHost(mock);
    const initSpy = vi.spyOn(mock, "init");

    // 首次建库成功
    fillStep2(STRONG_PW);
    click(findButton("下一步"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.querySelector('[data-testid="onboard-step-3"]')).not.toBeNull();
    expect(initSpy).toHaveBeenCalledTimes(1);

    // 回退 step2 改密码 → 下一步 → vault.init 已存在库 → 统一文案（不区分）
    click(findButton("上一步"));
    setInput(
      container.querySelector('input[aria-label="主密码"]') as HTMLInputElement,
      "AnotherPw@2026!",
    );
    setInput(
      container.querySelector('input[aria-label="确认主密码"]') as HTMLInputElement,
      "AnotherPw@2026!",
    );
    click(findButton("下一步"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(container.textContent).toContain("初始化失败（主密码不符合要求或库已存在）");
    expect(container.querySelector('[data-testid="onboard-step-2"]')).not.toBeNull();
    expect(initSpy).toHaveBeenCalledTimes(2); // 第二次 init 被后端拒绝

    // 改回原密码 → 复用首次 init 结果（不重复调用 init）→ 直达 step3
    setInput(
      container.querySelector('input[aria-label="主密码"]') as HTMLInputElement,
      STRONG_PW,
    );
    setInput(
      container.querySelector('input[aria-label="确认主密码"]') as HTMLInputElement,
      STRONG_PW,
    );
    click(findButton("下一步"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(initSpy).toHaveBeenCalledTimes(2);
    expect(container.querySelector('[data-testid="onboard-step-3"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="ob-code"]')?.textContent).toBe(
      DEMO_RECOVERY_CODE,
    );
  });
});
