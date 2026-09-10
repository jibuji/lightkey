/**
 * M2.99 快速保存 D 层单测（testing.md · quick-capture.md §8）。
 *
 * 覆盖：
 * - 名称建议纯函数 `suggestSecretName`（前缀表矩阵）；
 * - 面板生命周期：quick.save-request 已解锁 → 打开 + 剪贴板预填 + 建议名；
 *   锁态 → 不开面板（不读剪贴板）+ toast + pending → 解锁后自动重冒；
 *   未初始化 → 指向向导（不置 pending）；面板打开期间锁定 → 关闭；
 * - 保存闭环：创建 secret 条目（mock 库断言）、面板关闭、切 vault 页、
 *   「保存后清空剪贴板」勾选 → clipboardRead 变 null；§5.3 规格 toast
 *   「勾选保存后清空可避免明文残留」保存成功必现（勾选/未勾选均断言）；
 *   重名软提示；
 * - 壳事件翻译：`lk-shell-quick-save`（DOM CustomEvent，mock 分支）→
 *   总线事件 `quick.save-request`（与 tauri 真实事件同名同路径）；
 * - 名称建议偏好开关（preference）关闭 → 不预填建议名。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Context } from "@cordisjs/core";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { toast } from "../plugins/toast";
import {
  QUICK_SAVE_CLEAR_HINT_TOAST,
  QUICK_SAVE_NAME_SUGGEST_KEY,
  suggestSecretName,
  uiQuickSave,
} from "../plugins/ui-quick-save";
import { uiVault } from "../plugins/ui-vault";
import { SlotRegistry, type SlotEntry } from "../host/slots";
import { MockAdapter } from "../ipc/mockAdapter";

/** 快存面板 portal 挂载标记（ui-quick-save 自挂 root 的 data-portal）。 */
const PORTAL_SELECTOR = '[data-portal="quick-save"]';

/** 当前测试的活跃插件 disposer 集：afterEach 逐个 dispose。
 *  必须做——ipc-bridge mock 分支在 `window` 上挂 `lk-shell-quick-save`
 *  监听（与 tauri 真实事件同名同路径），不 dispose 会让上一个测试的
 *  context 响应下一个测试的派发、开出自己的面板污染 DOM。 */
let activeDisposers: Array<() => void> = [];

/** VaultPage 渲染容器（issue #171 选中断言用；afterEach 卸载清 DOM）。 */
let vaultRoots: Array<{ root: Root; container: HTMLDivElement }> = [];

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  activeDisposers = [];
  vaultRoots = [];
});

afterEach(() => {
  for (const dispose of activeDisposers) dispose();
  activeDisposers = [];
  for (const { root, container } of vaultRoots) {
    act(() => root.unmount());
    container.remove();
  }
  vaultRoots = [];
  // 兜底清理：dispose 之外可能残留的 portal 容器与 Modal overlay
  for (const el of Array.from(
    document.body.querySelectorAll(`${PORTAL_SELECTOR}, .modal-overlay`),
  )) {
    el.remove();
  }
  vi.useRealTimers();
});

/** 装配 ipc-bridge（mock 适配器）+ preference-store + toast + quick-save；
 *  nav 由宿主提供此处打桩。与 cordis.yml 装配一致（quick-save 注入
 *  ipc/toast/session/preference/nav）。
 *  `pre`：插件挂载**前**对 mock 的预置钩子（如 simulateFreshInstall——
 *  必须在 ipc-bridge 的 status() 探测**之前**生效，否则 initial 状态被
 *  挂载时的旧值捕获）。 */
async function mountQuickSave(
  pre?: (mock: MockAdapter) => void,
): Promise<{ ctx: Context; mock: MockAdapter; go: ReturnType<typeof vi.fn> }> {
  const ctx = new Context();
  const mock = new MockAdapter();
  pre?.(mock);
  const go = vi.fn();
  const mount = async (plugin: Parameters<Context["plugin"]>[0], config?: Record<string, unknown>) => {
    const fiber = await ctx.plugin(plugin, config as never);
    activeDisposers.push(fiber.dispose);
  };
  await mount(ipcBridge, { adapter: mock });
  await mount(preferenceStore, {});
  await mount(toast, {});
  ctx.provide("nav", {
    current: "vault",
    go,
    subscribe: () => () => {},
  });
  await mount(uiQuickSave, {});
  return { ctx, mock, go };
}

/** 解锁（mock：demo-password；推进 300ms 模拟延迟）。 */
async function unlock(ctx: Context) {
  const p = ctx.session.unlock("demo-password");
  await vi.advanceTimersByTimeAsync(300);
  await p;
}

/** 触发壳事件（mock 分支翻译路径；与 tauri `lk-shell-quick-save` 同名）。
 *  必须包 act：否则 React 挂载被推迟到定时器推进之后，面板 effect 里
 *  clipboardRead 的 300ms 定时器来不及在 flush 内触发，prefill 断言必挂。 */
function fireShellQuickSave() {
  act(() => {
    window.dispatchEvent(new CustomEvent("lk-shell-quick-save"));
  });
}

/** 推进 mock 延迟并 flush React（面板打开时的 list + clipboardRead 并发
 *  300ms；保存后的 create 300ms）。 */
async function flush(ms = 300) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/** 面板内输入框按 placeholder 查找（Modal 用 createPortal 挂到 document.body，
 *  不在插件自挂容器内——全局查询）。 */
function inputByPlaceholder(placeholder: string): HTMLInputElement | null {
  return document.querySelector<HTMLInputElement>(`input[placeholder="${placeholder}"]`);
}

function formSubmit() {
  const form = document.querySelector<HTMLFormElement>("form");
  if (!form) throw new Error("quick-save form not found");
  act(() => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}

/* ================= issue #171：保存成功后选中新条目（VaultPage 侧装配） ================= */

/** 在快存 ctx 上补挂 ui-vault 插件（槽位注册；组件不渲染——真实装配里 ui-vault
 *  常驻，但 VaultPage 随页面切换/锁态卸载）。返回 content 槽位 entry，用于
 *  按需渲染 VaultPage。 */
async function mountUiVault(ctx: Context): Promise<SlotEntry> {
  ctx.provide("slots", new SlotRegistry());
  const fiber = await ctx.plugin(uiVault, {});
  activeDisposers.push(fiber.dispose);
  const entry = ctx.slots.page("vault");
  if (!entry) throw new Error("ui-vault content slot not registered");
  return entry;
}

/** 渲染 ui-vault 槽位组件（VaultPage）到独立容器（recorded 便于 afterEach 清理）。
 *  与宿主 Skeleton 的同款接线：`entry.component` 即 `VaultPage`（携带插件层
 *  selectTargetRef）。 */
function renderVaultComponent(entry: SlotEntry): HTMLDivElement {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(createElement(entry.component));
  });
  vaultRoots.push({ root, container });
  return container;
}

describe("suggestSecretName —— 启发建议名纯函数（quick-capture.md §4.3）", () => {
  it("前缀表命中 → 静态建议名；无匹配 → null", () => {
    expect(suggestSecretName("sk-ant-0123456789abcdef")).toBe("api_key");
    expect(suggestSecretName("ghp_abcdefghijklmnopqrstuvwxyz")).toBe("github_token");
    expect(suggestSecretName("github_pat_11ABCDEF00_xxxxxxxx")).toBe("github_token");
    // glpat- 不在规格 §4.3 前缀表内（已按规格移除）→ 不命中任何条目
    expect(suggestSecretName("glpat-xxxxxxxxxxxx")).toBeNull();
    expect(suggestSecretName("AKIAIOSFODNN7EXAMPLE")).toBe("aws_access_key");
    expect(suggestSecretName("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")).toBe("jwt_token");
    expect(suggestSecretName("xoxb-123456789-abcdefgh")).toBe("slack_token");
    expect(suggestSecretName("hello world")).toBeNull();
    expect(suggestSecretName("")).toBeNull();
  });
});

describe("quick.save-request —— 面板生命周期", () => {
  it("已解锁：事件 → 面板打开，剪贴板值预填 + 建议名（最小权限：仅面板打开时读一次）", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-ant-0123456789abcdef");

    fireShellQuickSave();
    // 面板打开是同步的（事件处理器），但预填依赖 clipboardRead + list 的
    // 300ms mock 延迟；并发推进一次即都落定
    await flush();

    expect(document.querySelector(PORTAL_SELECTOR)).not.toBeNull();
    const valueInput = inputByPlaceholder("（剪贴板为空，请手动粘贴）");
    const nameInput = inputByPlaceholder("例如：GitHub Token");
    expect(valueInput?.value).toBe("sk-ant-0123456789abcdef");
    expect(nameInput?.value).toBe("api_key");
    // 无同名条目：不显示重名软提示
    expect(document.body.textContent).not.toContain("同名条目");
  });

  it("剪贴板为空 → 值留空 + 提示语；名称无建议", async () => {
    const { ctx } = await mountQuickSave();
    await unlock(ctx);
    // 默认 mockClipboard = null（空剪贴板）
    fireShellQuickSave();
    await flush();
    expect(inputByPlaceholder("（剪贴板为空，请手动粘贴）")?.value).toBe("");
    expect(inputByPlaceholder("例如：GitHub Token")?.value).toBe("");
  });

  it("名称建议偏好关闭（preference '0'）→ 不预填建议名", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    ctx.preference.set(QUICK_SAVE_NAME_SUGGEST_KEY, "0");
    mock.setClipboardText("sk-ant-x");
    fireShellQuickSave();
    await flush();
    // 值仍预填（与建议名是两条独立路径），名称留空
    expect(inputByPlaceholder("（剪贴板为空，请手动粘贴）")?.value).toBe("sk-ant-x");
    expect(inputByPlaceholder("例如：GitHub Token")?.value).toBe("");
  });

  it("锁态：不开面板（不读剪贴板）、toast 提示、pending → 解锁后自动重冒", async () => {
    const { ctx, mock } = await mountQuickSave();
    mock.setClipboardText("sk-locked-secret");
    // 先等 vault.status 探测落定（300ms mock 延迟；否则 initialized 为
    // null 走「正在加载」分支，不是锁态分支）
    await flush();
    // 锁态触发
    fireShellQuickSave();
    await flush(0);
    expect(document.querySelector(PORTAL_SELECTOR)).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("解锁后即可快速保存"))).toBe(true);

    // 解锁 → flush pending 自动打开面板（拍板点 ②：pending 解锁消费后清）。
    // unlock 的 emit（openPanel）发生在 act 之外：面板挂载/effect 定时器在
    // 第一轮 flush 的收尾阶段才落定，剪贴板读取定时器需第二轮 flush 触发
    const p = ctx.session.unlock("demo-password");
    await vi.advanceTimersByTimeAsync(300);
    await p;
    await flush(); // 面板挂载 + effect 调度（剪贴板 300ms 读取）
    await flush(); // 读取落定 → 预填
    expect(document.querySelector(PORTAL_SELECTOR)).not.toBeNull();
    // 解锁重冒时读取剪贴板（值已注入；面板打开那一刻读取）
    expect(inputByPlaceholder("（剪贴板为空，请手动粘贴）")?.value).toBe("sk-locked-secret");
  });

  it("未初始化：提示指向首启向导，不开面板、不置 pending（解锁不重冒）", async () => {
    // 首启标志须在 ipc-bridge 挂载（status 探测）前生效——否则探测捕获旧值
    const { ctx } = await mountQuickSave((mock) => mock.simulateFreshInstall());
    // 状态探测（vault.status 300ms）
    await flush();
    fireShellQuickSave();
    await flush(0);
    expect(document.querySelector(PORTAL_SELECTOR)).toBeNull();
    expect(ctx.toast.all.some((t) => t.text.includes("首次初始化"))).toBe(true);
    // 之后初始化 → 解锁 → 不应重冒（pending 从未置位）
    const init = ctx.session.initialize("new-password-1");
    await vi.advanceTimersByTimeAsync(300);
    await init;
    const p = ctx.session.unlock("new-password-1");
    await vi.advanceTimersByTimeAsync(300);
    await p;
    await flush();
    expect(document.querySelector(PORTAL_SELECTOR)).toBeNull();
  });

  it("面板打开期间被锁定 → 面板关闭", async () => {
    const { ctx } = await mountQuickSave();
    await unlock(ctx);
    fireShellQuickSave();
    await flush();
    expect(document.querySelector(PORTAL_SELECTOR)).not.toBeNull();
    const p = ctx.session.lock();
    await vi.advanceTimersByTimeAsync(300);
    await p;
    expect(document.querySelector(PORTAL_SELECTOR)).toBeNull();
  });
});

describe("保存闭环", () => {
  it("命名并保存 → 创建 secret 条目 + 面板关闭 + 切 vault 页", async () => {
    const { ctx, mock, go } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-save-me");
    fireShellQuickSave();
    await flush();

    // 名称建议 api_key → 直接提交（值已预填）
    formSubmit();
    await flush();

    // 条目已入库（mock 库断言；名字即建议名）；list 有 300ms 延迟
    const listP = ctx.ipc.list();
    await flush();
    const items = await listP;
    expect(items.some((i) => i.name === "api_key" && i.type === "secret")).toBe(true);
    // 面板关闭 + 已切到 vault 页
    expect(document.querySelector(PORTAL_SELECTOR)).toBeNull();
    expect(go).toHaveBeenCalledWith("vault");
  });

  it("保存成功 → §5.3 规格 toast「勾选保存后清空可避免明文残留」（默认未勾选也提示）", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-toast-hint");
    fireShellQuickSave();
    await flush();
    formSubmit();
    await flush();
    // 主 toast + §5.3 提醒 toast 并现
    expect(ctx.toast.all.some((t) => t.text === "已保存到 LightKey")).toBe(true);
    expect(ctx.toast.all.some((t) => t.text === QUICK_SAVE_CLEAR_HINT_TOAST)).toBe(true);
  });

  it("勾选「保存后清空剪贴板」→ 保存成功后剪贴板被置空，§5.3 toast 同时提示", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-clear-me");
    fireShellQuickSave();
    await flush();

    // 勾选清空（设置页同款 switch 结构；Modal 内容挂 document.body）。
    // React 对 checkbox 的 onChange 走原生 click；change 事件补齐兜底
    const checkbox = document.querySelector<HTMLInputElement>('input[type="checkbox"]');
    expect(checkbox).not.toBeNull();
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "checked")!.set!;
    act(() => {
      setter.call(checkbox!, true);
      checkbox!.dispatchEvent(new Event("click", { bubbles: true }));
      checkbox!.dispatchEvent(new Event("change", { bubbles: true }));
    });

    formSubmit();
    await flush(); // create 完成 → clear 开始
    await flush(); // clear 完成
    const readP = ctx.ipc.clipboardRead();
    await flush(); // 读路径 300ms
    expect(await readP).toBeNull();
    // 勾选清空（已置空）仍按规格提示 §5.3 toast
    expect(ctx.toast.all.some((t) => t.text === QUICK_SAVE_CLEAR_HINT_TOAST)).toBe(true);
  });

  it("重名软提示：库内已有同名条目 → 面板提示（不阻止保存）", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    // 预置一个同名条目（名称 = 建议名 api_key）
    const p = ctx.ipc.create({ type: "secret", name: "api_key", value: "old" } as never);
    await vi.advanceTimersByTimeAsync(300);
    await p;
    mock.setClipboardText("sk-dup");
    fireShellQuickSave();
    await flush();
    expect(document.body.textContent).toContain("同名条目");
  });

  it("名称为空提交 → 校验错误（不落库）", async () => {
    const { ctx } = await mountQuickSave();
    await unlock(ctx);
    // 剪贴板空 → 值空；名称空 → 提交被拦
    fireShellQuickSave();
    await flush();
    const beforeP = ctx.ipc.list();
    await flush();
    const before = (await beforeP).length; // 解锁后 fixture 条目数
    formSubmit();
    expect(document.body.textContent).toContain("请填写名称");
    // 未创建任何条目（条目数不变）
    const afterP = ctx.ipc.list();
    await flush();
    expect((await afterP).length).toBe(before);
  });
});

describe("保存成功后选中新条目（issue #171 —— quick-capture.md §3.1 步骤 4）", () => {
  it("保存成功 → vault.select 携带新条目 id（载荷零密钥值，只有 id）", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-select-event");
    fireShellQuickSave();
    await flush();

    const payloads: string[] = [];
    ctx.on("vault.select", (p) => payloads.push(p.itemId));
    formSubmit();
    await flush();

    const listP = ctx.ipc.list();
    await flush();
    const created = (await listP).find((i) => i.name === "api_key");
    expect(created).toBeDefined();
    // 载荷 = 刚创建条目的 id（ui-vault 据此选中）
    expect(payloads).toEqual([created!.id]);
  });

  it("保存成功（vault 页已挂载）→ 列表选中新条目 + 详情展示", async () => {
    const { ctx, mock } = await mountQuickSave();
    const entry = await mountUiVault(ctx);
    await unlock(ctx);
    const container = renderVaultComponent(entry);
    await flush(700); // VaultPage 初始加载（list 300 + get×N 300）

    mock.setClipboardText("sk-select-mounted");
    fireShellQuickSave();
    await flush();
    formSubmit();
    // create 300 + 其 item.changed 触发的重载 300 + vault.select 选中
    await flush(700);

    expect(container.querySelector(".item.selected .item-name")?.textContent).toBe("api_key");
    expect(container.querySelector(".detail-title")?.textContent).toBe("api_key");
  });

  it("保存成功（vault 页未挂载，如从设置页发起）→ 插件层 pending 兜底，随后挂载即选中", async () => {
    const { ctx, mock } = await mountQuickSave();
    // ui-vault 插件常驻挂载（pending 捕获就位）；VaultPage 组件不渲染
    // （当前页不是 vault）——事件无人接收，靠插件层暂存
    const entry = await mountUiVault(ctx);
    await unlock(ctx);
    mock.setClipboardText("sk-select-pending");
    fireShellQuickSave();
    await flush();
    formSubmit();
    await flush(); // create 完成 → vault.select → ui-vault 插件层 pending

    const container = renderVaultComponent(entry);
    await flush(700); // 挂载后首次加载 → 消费 pending → 选中
    expect(container.querySelector(".item.selected .item-name")?.textContent).toBe("api_key");
  });

  it("pending 消费后不残留：其后手动选其它条目 + item.changed 刷新 → 选中保持（防劫持）", async () => {
    const { ctx, mock } = await mountQuickSave();
    const entry = await mountUiVault(ctx);
    await unlock(ctx);
    const container = renderVaultComponent(entry);
    await flush(700);

    mock.setClipboardText("sk-select-hijack");
    fireShellQuickSave();
    await flush();
    formSubmit();
    await flush(700);
    expect(container.querySelector(".item.selected .item-name")?.textContent).toBe("api_key");

    // 手动选 fixture 条目 NPM_TOKEN
    const other = Array.from(container.querySelectorAll(".item")).find((el) =>
      el.textContent?.includes("NPM_TOKEN"),
    ) as HTMLButtonElement;
    act(() => other.click());
    expect(container.querySelector(".item.selected .item-name")?.textContent).toBe("NPM_TOKEN");

    // 任意 item.changed 刷新：选中必须保持（vault.select 的 pending 已消费，
    // 不得跳回 api_key）。须包 act：事件处理器内同步 reload -> 状态更新被
    // React 合并，effect 的 loadItems 定时器才能在本轮 flush 内触发——
    // 否则更新被推迟到 act 收尾（定时器已推进完），列表卡在加载态。
    act(() => {
      mock.simulateItemChanged({
        itemId: "github",
        revisionDate: "2026-08-16T00:00:01Z",
        type: "login",
        deleted: false,
      });
    });
    await flush(700);
    expect(container.querySelector(".item.selected .item-name")?.textContent).toBe("NPM_TOKEN");
  });
});

describe("壳事件翻译（ipc-bridge mock 分支）", () => {
  it("lk-shell-quick-save（DOM 事件）→ 总线事件 quick.save-request → 面板打开", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-event-path");
    const seen: number[] = [];
    ctx.on("quick.save-request", () => seen.push(1));

    fireShellQuickSave();
    await flush();
    expect(seen).toEqual([1]);
    expect(document.querySelector(PORTAL_SELECTOR)).not.toBeNull();
  });

  it("面板已打开时重复触发 → 忽略（不重复读取/重复开面板）", async () => {
    const { ctx, mock } = await mountQuickSave();
    await unlock(ctx);
    mock.setClipboardText("sk-once");
    fireShellQuickSave();
    await flush();
    // 打开后改剪贴板并再触发：面板不复读（保持原值）
    mock.setClipboardText("sk-twice");
    fireShellQuickSave();
    await flush();
    expect(inputByPlaceholder("（剪贴板为空，请手动粘贴）")?.value).toBe("sk-once");
  });
});