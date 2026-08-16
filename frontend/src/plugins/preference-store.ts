/**
 * preference-store 插件（首批，`docs/plugin-architecture.md` §3.4）。
 *
 * 非敏感 UI 偏好落盘：localStorage（`lightkey:pref:` 前缀），无 localStorage
 * 环境（测试/SSR）退回内存 Map。**不进加密库、不进 config.json**（§9）。
 *
 * 提供 `ctx.preference`；地基（无上游依赖），theme 依赖本插件。
 */

import type { Context, Plugin } from "@cordisjs/core";
import type { PreferenceService } from "../services/types";

export const PREFERENCE_KEY_PREFIX = "lightkey:pref:";

export interface PreferenceStoreConfig {
  /** localStorage 命名空间前缀（测试注入隔离用）。 */
  prefix?: string;
}

export const preferenceStore: Plugin.Function<Context, PreferenceStoreConfig> = Object.assign(
  (ctx: Context, config: PreferenceStoreConfig = {}) => {
    const prefix = config.prefix ?? PREFERENCE_KEY_PREFIX;
    const memory = new Map<string, string>();
    const storage: Storage | null =
      typeof localStorage !== "undefined" ? localStorage : null;

    const service: PreferenceService = {
      get(key: string): string | null {
        const full = prefix + key;
        if (storage) {
          return storage.getItem(full);
        }
        return memory.get(full) ?? null;
      },
      set(key: string, value: string): void {
        const full = prefix + key;
        if (storage) {
          storage.setItem(full, value);
        } else {
          memory.set(full, value);
        }
      },
      remove(key: string): void {
        const full = prefix + key;
        if (storage) {
          storage.removeItem(full);
        } else {
          memory.delete(full);
        }
      },
      reset(): void {
        if (storage) {
          for (let i = storage.length - 1; i >= 0; i--) {
            const key = storage.key(i);
            if (key?.startsWith(prefix)) storage.removeItem(key);
          }
        }
        memory.clear();
      },
    };
    ctx.provide("preference", service);
  },
);
