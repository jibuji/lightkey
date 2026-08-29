/**
 * tauri 适配器 × 守护进程响应形状契约（D 层 ↔ Rust IPC 面）。
 *
 * 替身 `invoke` 一律返回**守护进程的真实响应形状**（`crates/lk-core/src/ipc.rs`：
 * `item.list` → `ItemListResult{items}`、`item.put` → `ItemPutResult{item}`、
 * `item.get` → 条目本体、`vault.unlock` → `UnlockResult{token}`）。适配器必须
 * 解包到 `LightKeyIpc` 声明的形态，否则上层拿到的不是数组/条目本体。
 *
 * 回归背景：mock 适配器形状正确，故既有测试的绿灯掩盖了 tauri 真实通道的
 * 错配（桌面新建成功但列表恒空、且一次 `item.get` 都不发出）。
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke, listen } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(async () => async () => {}),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));

import { TauriAdapter } from "../ipc/tauriAdapter";
import { loadItems } from "../items/collection";
import type { AuditEvent, AuthRule, Item, ItemDraft, ItemSummary } from "../types";

const REV = "2026-08-29T01:03:02.847270Z";

const ITEM = {
  id: "579ef9ae-e8e8-4447-948a-9f7cc7705463",
  type: "login",
  name: "GitHub",
  username: "u",
  password: "p",
  uris: [],
  custom: [],
  revision: REV,
  deleted: false,
} as unknown as Item;

const SUMMARY = {
  id: ITEM.id,
  name: "GitHub",
  type: "login",
  revision: REV,
  deleted: false,
} as unknown as ItemSummary;

const RULE = {
  id: "bb6b26f7-6b8b-4def-8a59-f47df9627378",
  projectDir: "C:\\proj",
  name: "publish",
  command: "npm *",
  keys: ["NPM_TOKEN"],
  capability: "inject",
  created: REV,
} as unknown as AuthRule;

const AUDIT_EVENT = {
  eventId: "e1",
  ts: REV,
  starter: "desktop",
  target: "daemon",
  command: "item.list",
  result: "allowed",
  channel: "desktop",
} as unknown as AuditEvent;

/** 守护进程真实响应形状（对照 Rust `RpcResponse::ok` 的 result 载荷）。 */
function daemonResponse(method: string): unknown {
  switch (method) {
    case "vault.unlock":
      return { jsonrpc: "2.0", id: 0, result: { token: "a".repeat(64) } };
    case "item.list":
      return { jsonrpc: "2.0", id: 0, result: { items: [SUMMARY] } };
    case "item.get":
      return { jsonrpc: "2.0", id: 0, result: ITEM };
    case "item.put":
      return { jsonrpc: "2.0", id: 0, result: { item: ITEM } };
    case "rule.list":
      return { jsonrpc: "2.0", id: 0, result: { rules: [RULE] } };
    case "rule.add":
      return { jsonrpc: "2.0", id: 0, result: { rule: RULE } };
    case "audit.list":
      return { jsonrpc: "2.0", id: 0, result: { events: [AUDIT_EVENT], total: 1 } };
    default:
      return { jsonrpc: "2.0", id: 0, result: {} };
  }
}

let ipc: TauriAdapter;

beforeEach(async () => {
  invoke.mockReset();
  invoke.mockImplementation(async (_cmd: string, args: { method: string }) =>
    daemonResponse(args.method),
  );
  ipc = new TauriAdapter();
  await ipc.unlock("<REDACTED>");
});

/** `item.list` 结果带 `{items}` 包装：适配器须返回数组本体。 */
describe("tauri 适配器 × 守护进程响应形状", () => {
  it("list() 返回条目数组本体（不是 {items} 包装对象）", async () => {
    const items = await ipc.list();
    expect(Array.isArray(items)).toBe(true);
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe(ITEM.id);
  });

  it("loadItems 编排（list → 逐个 get）能加载出条目", async () => {
    const res = await loadItems(ipc);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.items[0]?.name).toBe("GitHub");
    // 编排第二段必须真的发出 item.get
    expect(invoke.mock.calls.some((c) => (c[1] as { method: string }).method === "item.get")).toBe(
      true,
    );
  });

  it("create()/update() 返回条目本体（不是 {item} 包装对象）", async () => {
    const draft = { type: "login", name: "GitHub", username: "u", password: "p" } as ItemDraft;
    const created = await ipc.create(draft);
    expect(created.id).toBe(ITEM.id);
    const updated = await ipc.update(ITEM.id, draft, { expectedRevision: REV });
    expect(updated.id).toBe(ITEM.id);
  });

  it("auditList() 返回事件数组本体（不是 {events,total} 包装对象）", async () => {
    const events = await ipc.auditList();
    expect(Array.isArray(events)).toBe(true);
    expect(events).toHaveLength(1);
  });

  it("ruleList()/ruleAdd() 返回数组本体与规则本体", async () => {
    const rules = await ipc.ruleList();
    expect(Array.isArray(rules)).toBe(true);
    expect(rules[0].id).toBe(RULE.id);
    const added = await ipc.ruleAdd({
      projectDir: "C:\\proj",
      name: "publish",
      command: "npm *",
      keys: ["NPM_TOKEN"],
    });
    expect(added.id).toBe(RULE.id);
  });
});

/** issue #85 契约防线：列表类响应非数组即抛——形状错配在开发/测试期变红。 */
describe("tauri 适配器形状断言（列表类响应非数组即报错）", () => {
  beforeEach(() => {
    // 三个用例统一让守护进程回空 result 载荷（覆盖外层 beforeEach 的默认形状）
    invoke.mockImplementation(async () => ({ jsonrpc: "2.0", id: 0, result: {} }));
  });

  it("item.list 响应缺数组字段 → 抛契约错误（不静默返回 undefined）", async () => {
    await expect(ipc.list()).rejects.toThrow(/item\.list/);
  });

  it("audit.list 响应缺数组字段 → 抛契约错误", async () => {
    await expect(ipc.auditList()).rejects.toThrow(/audit\.list/);
  });

  it("rule.list 响应缺数组字段 → 抛契约错误", async () => {
    await expect(ipc.ruleList()).rejects.toThrow(/rule\.list/);
  });
});
