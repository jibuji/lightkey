/**
 * ipc-bridge 插件（`docs/plugin-architecture.md` §3.4/§8.2；M2 扩展）。
 *
 * 统一 IPC 门面 + mock/tauri 适配器。职责：
 *
 * - 提供 `ctx.ipc`（`LightKeyIpc`：status/unlock/lock/item/sync/audit/
 *   rule/approval/config/pickDir + 通知订阅）；
 * - 提供 `ctx.session`（解锁态 + 事件翻译）：
 *   - **tauri 模式**：会话事件由守护进程经通知桥推送（`session.unlocked`/
 *     `session.locked`/`authz.request`/`item.changed` → 帧 → 本层重新
 *     `emit`，§5.3）；本地解锁/锁定用**抑制标记**去重（首次解锁发生在
 *     订阅建立前，须本地广播；对应推送帧随后到达时跳过，防双发）；
 *   - **mock 模式**：无推送，本地广播；模拟帧经 QA 钩子驱动同一翻译路径。
 * - `notifyItemChanged`：模拟 Rust `item.changed` 的翻译路径（QA/演示用）。
 */

import type { Context, Plugin } from "@cordisjs/core";
import type { AuthzRequestPayload, ItemChangedPayload } from "../events";
import { createIpc } from "../ipc";
import type { LightKeyIpc, NotificationFrame } from "../ipc/types";
import type { SessionService } from "../services/types";

export interface IpcBridgeConfig {
  /** 测试注入适配器（缺省 = `createIpc()`：Tauri 环境用 tauri 适配器，否则 mock）。 */
  adapter?: LightKeyIpc;
}

/** 通知帧可翻译的事件名（Rust 事件 → IPC 通知 → 本层重新 emit，§5.2）。 */
const NOTIFICATION_EVENTS = new Set([
  "item.changed",
  "session.unlocked",
  "session.locked",
  "authz.request",
]);

export const ipcBridge: Plugin.Function<Context, IpcBridgeConfig> = Object.assign(
  (ctx: Context, config: IpcBridgeConfig = {}) => {
    const ipc: LightKeyIpc = config.adapter ?? createIpc();
    // tauri 模式：守护进程会推送会话事件（帧翻译路径）；本地广播仅覆盖
    // 订阅建立前的首次解锁（用抑制标记与后续推送去重）
    const pushMode = ipc.kind === "tauri";

    let unlocked = false;
    /** 本地解锁/锁定广播的抑制标记（对应推送帧到达即消费，防双发）。 */
    let suppress: "session.unlocked" | "session.locked" | null = null;

    const translate = (frame: NotificationFrame) => {
      const { method, params } = frame;
      if (!NOTIFICATION_EVENTS.has(method)) return;
      if (method === "session.unlocked" || method === "session.locked") {
        if (suppress === method) {
          suppress = null; // 本地已广播（订阅建立前的首次解锁）；防双发
          return;
        }
        // 其它会话事件到达：陈旧标记失效（订阅建立前的本地广播无对应推送
        // 帧，标记须在下一个会话事件时清除，防吞掉后续外部推送）
        suppress = null;
        unlocked = method === "session.unlocked";
      }
      // 帧负载 = 事件契约负载（最小字段；事件名逐一为已知类型）
      switch (method) {
        case "item.changed":
          ctx.emit("item.changed", params as unknown as ItemChangedPayload);
          break;
        case "session.unlocked":
          ctx.emit("session.unlocked", params as { via: "password" | "biometric" | "recovery" });
          break;
        case "session.locked":
          ctx.emit("session.locked", params as { reason: "manual" | "timeout" | "lockscreen" | "daemon-exit" });
          break;
        case "authz.request":
          ctx.emit("authz.request", params as unknown as AuthzRequestPayload);
          break;
      }
    };

    const session: SessionService = {
      get unlocked() {
        return unlocked;
      },
      async unlock(masterPassword: string) {
        if (pushMode) suppress = "session.unlocked";
        try {
          await ipc.unlock(masterPassword);
        } catch (e) {
          suppress = null;
          throw e;
        }
        unlocked = true;
        ctx.emit("session.unlocked", { via: "password" });
        if (!pushMode) suppress = null; // mock 无推送：立即清标记
      },
      async lock() {
        if (pushMode) suppress = "session.locked";
        try {
          await ipc.lock();
        } catch (e) {
          suppress = null;
          throw e;
        }
        unlocked = false;
        ctx.emit("session.locked", { reason: "manual" });
        if (!pushMode) suppress = null;
      },
      notifyItemChanged(payload: ItemChangedPayload) {
        // 翻译路径：Rust 事件 → IPC 通知 → 本层重新 emit（§5.3）
        ctx.emit("item.changed", payload);
      },
    };

    ctx.provide("ipc", ipc);
    ctx.provide("session", session);

    // 启动时同步解锁态（真实环境 = vault.status 轮询/通知；mock 一次读取）。
    // 已解锁（如热重载/守护重启后仍解锁）→ 广播解锁事件（宿主据此切三栏）。
    void ipc.status().then((s) => {
      if (s.unlocked && !unlocked) {
        unlocked = true;
        ctx.emit("session.unlocked", { via: "password" });
      }
    });

    // M2：通知订阅（决策 #3 A）——Rust 通知帧 → 本层重新 emit
    let unsubscribe: (() => void) | null = null;
    void ipc.subscribeNotifications(translate).then((u) => {
      unsubscribe = u;
    });

    // 可逆副作用：卸载时退订通知（Cordis 卸载自动撤销语义 §5.4）
    return () => {
      unsubscribe?.();
    };
  },
);
