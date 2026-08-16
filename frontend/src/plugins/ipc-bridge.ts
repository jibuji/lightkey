/**
 * ipc-bridge 插件（首批，`docs/plugin-architecture.md` §3.4/§8.2）。
 *
 * 统一 IPC 门面 + mock/tauri 适配器（复用 `src/ipc/` 既有实现；mock 适配器
 * 保证无 Tauri 环境可跑通 ui 骨架）。职责：
 *
 * - 提供 `ctx.ipc`（`LightKeyIpc`：status/unlock/lock/item 与 sync 系列方法）；
 * - 提供 `ctx.session`（解锁态 + 事件翻译）：解锁成功 → 广播
 *   `session.unlocked({via})`，锁定 → 广播 `session.locked({reason})`
 *   （真实环境这两个事件由 Rust session 经 IPC 通知翻译而来，§5.3；
 *   M1.5 IPC 协议零变更，本地路径由本插件在适配器返回后广播）；
 * - `notifyItemChanged`：模拟 Rust `item.changed` 的翻译路径
 *   （mock / QA 钩子 / 演示面板用；M2 接入真实 IPC 通知后由通知回调驱动）。
 */

import type { Context, Plugin } from "@cordisjs/core";
import type { ItemChangedPayload } from "../events";
import { createIpc } from "../ipc";
import type { LightKeyIpc } from "../ipc/types";
import type { SessionService } from "../services/types";

export interface IpcBridgeConfig {
  /** 测试注入适配器（缺省 = `createIpc()`：Tauri 环境用 tauri 适配器，否则 mock）。 */
  adapter?: LightKeyIpc;
}

export const ipcBridge: Plugin.Function<Context, IpcBridgeConfig> = Object.assign(
  (ctx: Context, config: IpcBridgeConfig = {}) => {
    const ipc: LightKeyIpc = config.adapter ?? createIpc();

    let unlocked = false;
    const session: SessionService = {
      get unlocked() {
        return unlocked;
      },
      async unlock(masterPassword: string) {
        await ipc.unlock(masterPassword);
        unlocked = true;
        ctx.emit("session.unlocked", { via: "password" });
      },
      async lock() {
        await ipc.lock();
        unlocked = false;
        ctx.emit("session.locked", { reason: "manual" });
      },
      notifyItemChanged(payload: ItemChangedPayload) {
        // 翻译路径：Rust 事件 → IPC 通知 → 本层重新 emit（§5.3）
        ctx.emit("item.changed", payload);
      },
    };

    ctx.provide("ipc", ipc);
    ctx.provide("session", session);

    // 启动时同步解锁态（真实环境 = vault.status 轮询/通知；mock 一次读取）
    void ipc.status().then((s) => {
      unlocked = s.unlocked;
    });
  },
);
