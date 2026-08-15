/**
 * IPC 门面 —— 应用唯一入口。当前运行于浏览器（npm run dev）时使用内存
 * mock 适配器；后端 M0 完成并接入 Tauri 后，切换 createIpc 的返回值即可
 * 无缝换到真实 IPC（页面只依赖 LightKeyIpc 接口，不感知适配器差异）。
 */

import { MockAdapter, installMockQaHooks } from "./mockAdapter";
import type { LightKeyIpc } from "./types";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function createIpc(): LightKeyIpc {
  if (isTauriRuntime()) {
    // 后端 M0 未完成：Tauri 壳下暂退回 mock，保证桌面壳预览可用。
    // eslint-disable-next-line no-console
    console.warn("[ipc] Tauri runtime detected but backend IPC not ready; using mock adapter.");
    const mock = new MockAdapter();
    installMockQaHooks(mock);
    return mock;
  }
  const mock = new MockAdapter();
  installMockQaHooks(mock);
  return mock;
}

export type { LightKeyIpc } from "./types";
export { ConflictError, VaultInvalidError } from "./types";
