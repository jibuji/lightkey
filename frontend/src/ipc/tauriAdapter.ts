/**
 * Tauri 适配器 —— 真实守护进程桥（M2 desktop：lk-app Rust 壳内置守护实例）。
 *
 * 传输：Tauri 2 `invoke` → Rust 侧 `rpc` command → 守护进程 JSON-RPC 2.0
 * （docs/ipc.md §2）。方法名即 RPC method（vault.unlock 等）；返回完整
 * JSON-RPC 响应（result/error），错误码由本层映射为类型化错误。
 *
 * 通知订阅（决策 #3 A）：`subscribeNotifications` 注册 `lk-notify` Tauri
 * 事件监听（Rust 推送流 → 事件 → 本层帧回调）；解锁成功后自动以新令牌
 * 调 `subscribe` 命令建立推送流（锁定/重解锁后重订阅）。
 */

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import type {
  AuditEvent,
  AuthRule,
  ConfigPatch,
  ConfigView,
  Item,
  ItemDraft,
  ItemSummary,
  RuleInput,
  SyncStatus,
} from "../types";
import {
  ConflictError,
  SessionInvalidError,
  VaultInvalidError,
  type LightKeyIpc,
  type NotificationFrame,
  type UpdateOptions,
} from "./types";

/** 会话令牌：解锁后由 vault.unlock 签发，随每次解锁轮换（ipc.md §3） */
let sessionToken: string | null = null;

/** 通知帧回调（subscribeNotifications 登记；解锁后自动订阅）。 */
let onFrame: ((frame: NotificationFrame) => void) | null = null;
let unlisten: UnlistenFn | null = null;

/** 调 Rust 桥（rpc command）：返回完整 JSON-RPC 响应；error → 映射抛错。 */
async function rpc<T>(
  method: string,
  params?: Record<string, unknown>,
): Promise<T> {
  const res = await invoke<{ result?: T; error?: { code?: string; message?: string } }>("rpc", {
    method,
    params: { ...params, token: sessionToken },
  });
  return unwrap(res);
}

function mapError(e: unknown): Error {
  const code = (e as { code?: string; message?: string })?.code;
  const message = (e as { message?: string })?.message;
  if (code === "item.conflict" || message === "item.conflict") return new ConflictError();
  if (code === "vault.invalid" || message === "vault.invalid") return new VaultInvalidError();
  if (message === "session.invalid") return new SessionInvalidError();
  return e instanceof Error ? e : new Error(String(e));
}

/** 解析 JSON-RPC 响应：error → 映射抛错；result → 返回。 */
function unwrap<T>(res: { result?: T; error?: { code?: string; message?: string } }): T {
  if (res.error) throw mapError(res.error);
  return res.result as T;
}

/** 建立推送流（需有效会话令牌；失败静默——下次解锁重试）。 */
async function ensureSubscribed(): Promise<void> {
  if (!sessionToken) return;
  try {
    await invoke("subscribe", { token: sessionToken });
  } catch {
    // 订阅失败不阻断主流程（通知为增强通道；会话事件经 ipc-bridge 本地兜底）
  }
}

export class TauriAdapter implements LightKeyIpc {
  readonly kind = "tauri" as const;

  async status(): Promise<{ unlocked: boolean }> {
    return rpc("vault.status");
  }

  async unlock(masterPassword: string): Promise<void> {
    try {
      const res = await rpc<{ token: string }>("vault.unlock", { masterPassword });
      sessionToken = res.token;
      await ensureSubscribed();
    } catch (e) {
      throw mapError(e);
    }
  }

  async lock(): Promise<void> {
    try {
      await rpc("vault.lock");
    } catch (e) {
      throw mapError(e);
    } finally {
      sessionToken = null;
      // 推送流保留（守护进程侧订阅连接跨锁定有效）；下轮解锁重订阅新令牌
    }
  }

  async recover(recoveryCode: string, newPassword: string): Promise<{ recoveryCode: string }> {
    try {
      const res = await rpc<{ recoveryCode: string }>("vault.recover", { recoveryCode, newPassword });
      sessionToken = null;
      return res;
    } catch (e) {
      throw mapError(e);
    }
  }

  async list(): Promise<ItemSummary[]> {
    try {
      return rpc<ItemSummary[]>("item.list");
    } catch (e) {
      throw mapError(e);
    }
  }

  async get(id: string): Promise<Item> {
    try {
      return rpc<Item>("item.get", { id });
    } catch (e) {
      throw mapError(e);
    }
  }

  /** 新建：item.put（ipc.md §4；无 id → 守护进程生成） */
  async create(draft: ItemDraft): Promise<Item> {
    try {
      return rpc<Item>("item.put", { item: draft });
    } catch (e) {
      throw mapError(e);
    }
  }

  /** 整条替换（CAS）：item.put，expectedRevision 必填 */
  async update(id: string, draft: ItemDraft, opts?: UpdateOptions): Promise<Item> {
    try {
      return rpc<Item>("item.put", { id, item: draft, expectedRevision: opts?.expectedRevision });
    } catch (e) {
      throw mapError(e);
    }
  }

  async remove(id: string): Promise<void> {
    try {
      await rpc("item.delete", { id }); // ipc.md §4（软删除 → 墓碑）
    } catch (e) {
      throw mapError(e);
    }
  }

  async syncStatus(): Promise<SyncStatus> {
    try {
      return rpc<SyncStatus>("sync.status");
    } catch (e) {
      throw mapError(e);
    }
  }

  async syncTrigger(): Promise<SyncStatus> {
    try {
      return rpc<SyncStatus>("sync.trigger");
    } catch (e) {
      throw mapError(e);
    }
  }

  async auditList(): Promise<AuditEvent[]> {
    try {
      return rpc<AuditEvent[]>("audit.list");
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleList(): Promise<AuthRule[]> {
    try {
      return rpc<AuthRule[]>("rule.list", { channel: "desktop" });
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleAdd(input: RuleInput): Promise<AuthRule> {
    try {
      return rpc<AuthRule>("rule.add", { ...input, channel: "desktop" });
    } catch (e) {
      throw mapError(e);
    }
  }

  async ruleRemove(id: string): Promise<void> {
    try {
      await rpc("rule.remove", { id, channel: "desktop" });
    } catch (e) {
      throw mapError(e);
    }
  }

  async approvalResult(
    requestId: string,
    decision: "allowed" | "denied",
  ): Promise<{ accepted: boolean }> {
    try {
      return rpc<{ accepted: boolean }>("approval.result", { requestId, decision });
    } catch (e) {
      throw mapError(e);
    }
  }

  async configGet(): Promise<ConfigView> {
    try {
      return invoke<ConfigView>("config_get");
    } catch (e) {
      throw mapError(e);
    }
  }

  async configSet(patch: ConfigPatch): Promise<void> {
    try {
      await invoke("config_set", { patch });
    } catch (e) {
      throw mapError(e);
    }
  }

  async pickDir(): Promise<string | null> {
    try {
      return await invoke<string | null>("pick_dir");
    } catch {
      return null; // 对话框不可用（如 Linux 无桌面）→ 回退手动输入
    }
  }

  async subscribeNotifications(
    handler: (frame: NotificationFrame) => void,
  ): Promise<() => void> {
    onFrame = handler;
    if (!unlisten) {
      try {
        unlisten = await listen<string>("lk-notify", (event) => {
          let frame: NotificationFrame;
          try {
            frame = JSON.parse(event.payload);
          } catch {
            return; // 非法帧忽略（协议容错）
          }
          onFrame?.(frame);
        });
      } catch {
        unlisten = null;
      }
    }
    // 已解锁（如热重载）→ 立即建立推送流
    await ensureSubscribed();
    return () => {
      onFrame = null;
    };
  }
}
