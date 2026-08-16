/**
 * IPC 门面 —— 应用唯一入口。Tauri 运行时 = 真实守护进程桥（tauriAdapter →
 * lk-app Rust 壳 → 内置守护实例）；浏览器（npm run dev / 测试）= 内存
 * mock 适配器。页面只依赖 LightKeyIpc 接口，不感知适配器差异。
 */

import { TauriAdapter } from "./tauriAdapter";
import { MockAdapter, installMockQaHooks } from "./mockAdapter";
import type { LightKeyIpc } from "./types";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function createIpc(): LightKeyIpc {
  if (isTauriRuntime()) {
    // M2 desktop：Rust 壳已提供 rpc/subscribe 命令桥 → 真实守护进程
    return new TauriAdapter();
  }
  const mock = new MockAdapter();
  installMockQaHooks(mock);
  return mock;
}

export type { LightKeyIpc } from "./types";
export { ConflictError, SessionInvalidError, VaultInvalidError } from "./types";
