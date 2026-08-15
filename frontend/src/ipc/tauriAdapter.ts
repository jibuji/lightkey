/**
 * Tauri 适配器 —— 后端 M0 完成后替换 mock 的正式实现（本任务仅搭好骨架，
 * 后端 IPC 未就绪时不启用）。
 *
 * 传输：Tauri 2 `invoke`（Rust 侧经 lk-app 桥接到 lk-daemon 的
 * JSON-RPC 2.0，docs/ipc.md §2）。方法名即 RPC method（vault.unlock 等）。
 */

import { invoke } from "@tauri-apps/api/core";

import type { AuditEvent, AuthRule, Item, ItemDraft, ItemSummary, SyncStatus } from "../types";
import {
  ConflictError,
  VaultInvalidError,
  type LightKeyIpc,
  type UpdateOptions,
} from "./types";

/** 会话令牌：解锁后由 vault.unlock 签发，随每次解锁轮换（ipc.md §3） */
let sessionToken: string | null = null;

function call<T>(method: string, params?: Record<string, unknown>): Promise<T> {
  return invoke<T>(method, { ...params, token: sessionToken });
}

function mapError(e: unknown): Error {
  const code = (e as { code?: string; message?: string })?.code;
  if (code === "item.conflict") return new ConflictError();
  if (code === "vault.invalid") return new VaultInvalidError();
  return e instanceof Error ? e : new Error(String(e));
}

export class TauriAdapter implements LightKeyIpc {
  async status(): Promise<{ unlocked: boolean }> {
    return call("vault.status");
  }

  async unlock(masterPassword: string): Promise<void> {
    try {
      const res = await call<{ token: string }>("vault.unlock", { masterPassword });
      sessionToken = res.token;
    } catch (e) {
      throw mapError(e);
    }
  }

  async lock(): Promise<void> {
    try {
      await call("vault.lock");
    } finally {
      sessionToken = null;
    }
  }

  async list(): Promise<ItemSummary[]> {
    try {
      return await call("item.list");
    } catch (e) {
      throw mapError(e);
    }
  }

  async get(id: string): Promise<Item> {
    try {
      return await call("item.get", { id });
    } catch (e) {
      throw mapError(e);
    }
  }

  /** 新建：item.put（ipc.md §4；无 id → 守护进程生成） */
  async create(draft: ItemDraft): Promise<Item> {
    try {
      return await call("item.put", { item: draft });
    } catch (e) {
      throw mapError(e);
    }
  }

  /** 整条替换（CAS）：item.put，expectedRevision 必填 */
  async update(id: string, draft: ItemDraft, opts?: UpdateOptions): Promise<Item> {
    try {
      return await call("item.put", {
        id,
        item: draft,
        expectedRevision: opts?.expectedRevision,
      });
    } catch (e) {
      throw mapError(e);
    }
  }

  async remove(id: string): Promise<void> {
    try {
      await call("item.delete", { id }); // ipc.md §4（软删除 → 墓碑）
    } catch (e) {
      throw mapError(e);
    }
  }

  async syncStatus(): Promise<SyncStatus> {
    try {
      return await call("sync.status");
    } catch (e) {
      throw mapError(e);
    }
  }

  async syncTrigger(): Promise<SyncStatus> {
    try {
      return await call("sync.trigger");
    } catch (e) {
      throw mapError(e);
    }
  }

  async auditList(): Promise<AuditEvent[]> {
    try {
      return await call("audit.list");
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleList(): Promise<AuthRule[]> {
    try {
      return await call("rule.list");
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleCreate(rule: AuthRule): Promise<void> {
    try {
      await call("rule.create", { rule });
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleRemove(id: string): Promise<void> {
    try {
      await call("rule.remove", { id });
    } catch (e) {
      throw mapError(e);
    }
  }
}
