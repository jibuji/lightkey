/**
 * Mock 适配器 —— 内存数据层（含 300ms 模拟延迟）。
 *
 * 语义对齐产品行为（docs/ipc.md）：
 * - 解锁需主密码（demo-password）；错误统一抛 VaultInvalidError（不区分
 *   「密码错/库未建」，防探测）。
 * - 锁定 = 内存擦除：条目/规则回到初始 fixture，会话令牌失效。
 * - item.update 走 CAS：expectedRevision 与当前 revision 不符 → ConflictError。
 * - 软删除语义：remove 即从库移除（mock 不模拟墓碑延迟）。
 *
 * QA 钩子：`window.__LIGHTKEY_MOCK__.simulateExternalEdit(id)` 可模拟其他
 * 设备已修改某条目（改 revision），用于验证 CAS 冲突提示。仅 dev 可用。
 */

import type { AuditEvent, AuthRule, Item, ItemDraft, ItemSummary, SyncStatus } from "../types";
import {
  ConflictError,
  VaultInvalidError,
  type LightKeyIpc,
  type UpdateOptions,
} from "./types";
import {
  MOCK_AUDIT,
  MOCK_ITEMS,
  MOCK_MASTER_PASSWORD,
  MOCK_RULES,
} from "./mockData";

const LATENCY_MS = 300;

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), LATENCY_MS));
}

/**
 * 拒绝路径的延迟。
 *
 * 不能写成 `delay(Promise.reject(err))`：`Promise.reject` 在调用瞬间即产生
 * 已拒绝的内层 promise，其 rejection 在下一个微任务检查点就会触发
 * `unhandledRejection`（此时外层的 300ms 计时器尚未 adopt 它，处理器也无
 * 从挂上）。这里让 rejection 只在计时器触发时产生，调用方（测试）可在
 * 计时器前先行挂处理器，杜绝 unhandled rejection。
 */
function delayReject(error: Error): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(error), LATENCY_MS));
}

function nowStamp(): string {
  return new Date().toISOString().slice(0, 19) + "Z";
}

function newId(): string {
  return "it" + Math.random().toString(36).slice(2, 8);
}

export class MockAdapter implements LightKeyIpc {
  private unlocked = false;
  private items: Item[] = [];
  private rules: AuthRule[] = [];
  private audit: AuditEvent[] = [];

  /** 解锁后重建内存库（fixture）；锁定则擦除。 */
  private resetStore(restore: boolean) {
    this.items = restore ? structuredClone(MOCK_ITEMS) : [];
    this.rules = restore ? structuredClone(MOCK_RULES) : [];
    this.audit = restore ? [...MOCK_AUDIT] : [];
  }

  private requireUnlocked() {
    if (!this.unlocked) throw new Error("session.invalid");
  }

  /* ---------- vault ---------- */

  async status(): Promise<{ unlocked: boolean }> {
    return delay({ unlocked: this.unlocked });
  }

  async unlock(masterPassword: string): Promise<void> {
    if (masterPassword !== MOCK_MASTER_PASSWORD) {
      return delayReject(new VaultInvalidError());
    }
    this.resetStore(true);
    this.unlocked = true;
    return delay(undefined);
  }

  async lock(): Promise<void> {
    this.unlocked = false;
    this.resetStore(false);
    return delay(undefined);
  }

  /* ---------- item ---------- */

  async list(): Promise<ItemSummary[]> {
    this.requireUnlocked();
    return delay(
      this.items.map((it) => ({ id: it.id, name: it.name, type: it.type, revision: it.revision })),
    );
  }

  async get(id: string): Promise<Item> {
    this.requireUnlocked();
    const it = this.items.find((x) => x.id === id);
    if (!it) return delayReject(new Error("item.not_found"));
    // 返回副本：前端持有的条目与 mock 库隔离，模拟真实 IPC 的序列化边界
    // （否则外部修改会经共享引用泄漏进前端 state，CAS 冲突无法复现）
    return delay(structuredClone(it));
  }

  async create(draft: ItemDraft): Promise<Item> {
    this.requireUnlocked();
    const item = { ...draft, id: newId(), revision: nowStamp() } as Item;
    this.items.unshift(item);
    return delay(structuredClone(item));
  }

  async update(id: string, draft: ItemDraft, opts?: UpdateOptions): Promise<Item> {
    this.requireUnlocked();
    const idx = this.items.findIndex((x) => x.id === id);
    if (idx < 0) return delayReject(new Error("item.not_found"));
    const current = this.items[idx];
    if (opts?.expectedRevision !== undefined && opts.expectedRevision !== current.revision) {
      return delayReject(new ConflictError());
    }
    const updated = { ...draft, id, revision: nowStamp() } as Item;
    this.items[idx] = updated;
    return delay(structuredClone(updated));
  }

  async remove(id: string): Promise<void> {
    this.requireUnlocked();
    this.items = this.items.filter((x) => x.id !== id);
    return delay(undefined);
  }

  /* ---------- sync / audit / rule ---------- */

  async syncStatus(): Promise<SyncStatus> {
    this.requireUnlocked();
    return delay({ synced: true, pollSec: 60, lastSync: nowStamp() });
  }

  async syncTrigger(): Promise<SyncStatus> {
    this.requireUnlocked();
    return delay({ synced: true, pollSec: 60, lastSync: nowStamp() });
  }

  async auditList(): Promise<AuditEvent[]> {
    this.requireUnlocked();
    return delay([...this.audit]);
  }

  async ruleList(): Promise<AuthRule[]> {
    this.requireUnlocked();
    return delay([...this.rules]);
  }

  async ruleCreate(rule: AuthRule): Promise<void> {
    this.requireUnlocked();
    this.rules.push(rule);
    return delay(undefined);
  }

  async ruleRemove(id: string): Promise<void> {
    this.requireUnlocked();
    this.rules = this.rules.filter((r) => r.id !== id);
    return delay(undefined);
  }

  /* ---------- QA 钩子（仅 mock；模拟其他设备修改以演示 CAS 冲突） ---------- */

  /**
   * 模拟其他设备已修改该条目（revision 改为“未来”时间戳，保证与当前库内
   * revision 必然不同，从而稳定触发 CAS 冲突）。
   */
  simulateExternalEdit(id: string): void {
    const it = this.items.find((x) => x.id === id);
    if (it) it.revision = new Date(Date.now() + 60_000).toISOString().slice(0, 19) + "Z";
  }

  /** QA 只读检查 */
  readItem(id: string): Item | null {
    return this.items.find((x) => x.id === id) ?? null;
  }
}

/** 暴露 QA 钩子（dev console 用；真实适配器无此面） */
export function installMockQaHooks(adapter: MockAdapter) {
  (window as unknown as Record<string, unknown>).__LIGHTKEY_MOCK__ = {
    simulateExternalEdit: (id: string) => adapter.simulateExternalEdit(id),
    readItem: (id: string) => adapter.readItem(id),
  };
}
