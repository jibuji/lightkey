/**
 * desktop-shell 插件（M2；`docs/plugin-architecture.md` §3.4 + 决策 #4 A）。
 *
 * 窗口/托盘/锁屏联动：
 * - **托盘/窗口动作**（显示/锁定/退出、关闭=隐藏托盘、锁屏自动锁定）由
 *   lk-app Rust 壳实现（Rust 侧直接持有守护实例与系统事件源）；
 * - 本插件（TS）提供 `ctx.shell` 服务面（`closeToTray` / `quit`），供
 *   ui 插件按需调用；Tauri 环境走 `app_quit` 命令，浏览器/mock 为
 *   no-op（提示）；
 * - 会话推送（`session.locked` 等）经 ipc-bridge 翻译为 Cordis 事件，
 *   宿主据此回解锁页——本插件不重复接线。
 */

import { invoke } from "@tauri-apps/api/core";
import type { Context, Plugin } from "@cordisjs/core";
import type { ApprovalAlertPayload, ShellService } from "../services/types";

export const desktopShell: Plugin.Function<Context> = Object.assign((ctx: Context) => {
  const shell: ShellService = {
    async closeToTray() {
      // Rust 侧已拦截 close 事件（决策 #4 A：隐藏托盘、保持解锁）；此处
      // 为显式调用面（如「最小化到托盘」按钮，V1 无此按钮，保留接口）
      ctx.toast.show("窗口已最小化到托盘（关闭按钮同语义）");
    },
    async quit() {
      try {
        await invoke("app_quit");
      } catch {
        ctx.toast.show("退出仅桌面（Tauri）环境生效");
      }
    },
    async alertApproval(payload: ApprovalAlertPayload) {
      try {
        // 载荷即通知正文的全部输入（保守口径由类型面锁死：只有
        // starter / projectDir，命令与条目名无处可传）
        // 展开为对象字面量：interface 无隐式索引签名，直接传会过不了
        // `invoke` 的 `InvokeArgs`（`npm run build` 的 tsc 会红）
        await invoke("approval_alert", { ...payload });
      } catch {
        // 提醒是旁路：非桌面环境（mock/浏览器）或通知被拒时静默降级，
        // 不弹 Toast 干扰——审批弹窗本身仍在，闭环不受影响。
      }
    },
  };
  ctx.provide("shell", shell);
}, {
  inject: ["toast"],
});
