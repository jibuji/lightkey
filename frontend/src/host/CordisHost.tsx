/**
 * Cordis 宿主（React 宿主薄层，`docs/plugin-architecture.md` §8.2）。
 *
 * 职责（Cordis 不管的部分，宿主自写）：
 *
 * 1. 读取 `cordis.yml` 装配结果（loader：条目 = 插件 + 槽位/顺序布局数据）；
 * 2. 提供宿主服务（`slots` 槽位注册表 / `nav` 页面导航，先于插件挂载）；
 * 3. 渲染三栏骨架（`Skeleton`，宿主写死），槽位组件按布局数据挂入；
 * 4. 订阅事件总线（`theme.changed` / `session.unlocked` / `session.locked`
 *    / `item.changed`）触发重渲染；
 * 5. 挂载 Toast 层（`ctx.toast.subscribe`）。
 *
 * 服务装配顺序（与 §4.2 依赖图一致）：ipc-bridge / preference-store 为地基，
 * theme ← preference-store，骨架组件 ← slots/nav/session/theme/…。
 * 插件挂载顺序由 cordis.yml 条目顺序 + `inject` 依赖声明共同保证。
 */

import { useEffect, useReducer, useState } from "react";
import { Context } from "@cordisjs/core";
import type { Plugin } from "@cordisjs/core";
import cordisYml from "../cordis.yml?raw";
import { ipcBridge } from "../plugins/ipc-bridge";
import { preferenceStore } from "../plugins/preference-store";
import { theme } from "../plugins/theme";
import { toast } from "../plugins/toast";
import {
  lock,
  navAudit,
  navRules,
  navSettings,
  navVault,
  pageAudit,
  pageRules,
  pageSettings,
  pageVault,
  search,
  syncStatus,
  themeToggle,
} from "../plugins/skeleton";
import { CordisLoader } from "./loader";
import { Skeleton } from "./Skeleton";
import { SlotRegistry } from "./slots";
import type { NavService, ToastMessage } from "../services/types";

/** 插件注册表（Vite 静态 import；M2 新增插件 = 此处注册 + cordis.yml 增条目）。 */
export const PLUGIN_REGISTRY: Record<string, Plugin> = {
  "ipc-bridge": ipcBridge,
  "preference-store": preferenceStore,
  theme,
  toast,
  // sidebar
  "nav-vault": navVault,
  "nav-rules": navRules,
  "nav-settings": navSettings,
  "nav-audit": navAudit,
  lock,
  // topbar
  search,
  "sync-status": syncStatus,
  "theme-toggle": themeToggle,
  // content
  "page-vault": pageVault,
  "page-rules": pageRules,
  "page-settings": pageSettings,
  "page-audit": pageAudit,
};

export interface HostInstance {
  ctx: Context;
  slots: SlotRegistry;
  nav: NavService;
  /** 卸载全部插件（dispose）。 */
  dispose: () => void;
}

/** 创建宿主：装配宿主服务 + 挂载 cordis.yml 全部插件。 */
export async function createHost(registry: Record<string, Plugin> = PLUGIN_REGISTRY): Promise<HostInstance> {
  const ctx = new Context();
  const slots = new SlotRegistry();

  // 宿主服务先于插件挂载（plugins 经 inject 声明依赖）
  const hostServices = await ctx.plugin((c) => {
    c.provide("slots", slots);
    c.provide("nav", createNavService());
  });

  const loader = new CordisLoader(ctx, registry);
  const mounted = await loader.load(cordisYml);
  return {
    ctx,
    slots,
    nav: ctx.nav,
    dispose: () => {
      for (const m of mounted) m.dispose();
      hostServices.dispose();
    },
  };
}

/** 导航服务（宿主）：当前页 + 订阅。 */
function createNavService(): NavService {
  let current = "vault";
  const listeners = new Set<() => void>();
  return {
    get current() {
      return current;
    },
    go(page: string) {
      if (page === current) return;
      current = page;
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

/** Toast 层（右下角；`clipboard.copied` → Toast + 30s 清除，见 toast 插件）。 */
function ToastLayer({ toastService }: { toastService: HostInstance["ctx"]["toast"] }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  useEffect(() => toastService.subscribe(setToasts), [toastService]);
  if (!toasts.length) return null;
  return (
    <div className="toast-root" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className="toast">
          <span className="dot dot-ok" aria-hidden />
          <span>{t.text}</span>
          <button
            type="button"
            className="toast-dismiss"
            aria-label="关闭"
            onClick={() => toastService.dismiss(t.id)}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

/** 根组件：装配宿主 → 渲染三栏骨架 + 事件重渲染。 */
export function CordisHost() {
  const [host, setHost] = useState<HostInstance | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  // 事件重渲染计数器（theme.changed / session.* / item.changed）
  const [, forceTick] = useReducer((x: number) => x + 1, 0);

  useEffect(() => {
    let disposed = false;
    void createHost().then(
      (h) => {
        if (disposed) {
          h.dispose();
          return;
        }
        setHost(h);
      },
      (error: unknown) => setBootError(String(error instanceof Error ? error.message : error)),
    );
    return () => {
      disposed = true;
    };
  }, []);

  // 订阅总线事件 → 重渲染（theme.changed 重渲染 / 会话切换 / item.changed）
  useEffect(() => {
    if (!host) return;
    const offTheme = host.ctx.on("theme.changed", () => forceTick());
    const offUnlocked = host.ctx.on("session.unlocked", () => forceTick());
    const offLocked = host.ctx.on("session.locked", () => forceTick());
    const offChanged = host.ctx.on("item.changed", () => forceTick());
    const offNav = host.nav.subscribe(() => forceTick());
    return () => {
      offTheme();
      offUnlocked();
      offLocked();
      offChanged();
      offNav();
    };
  }, [host]);

  if (bootError) {
    return (
      <div className="content-panel card">
        <h2>宿主装配失败</h2>
        <p className="error-text">{bootError}</p>
      </div>
    );
  }
  if (!host) {
    return <div className="content-panel card muted">装配中…</div>;
  }
  return (
    <>
      <Skeleton
        ctx={host.ctx}
        topbar={host.slots.list("topbar")}
        sidebar={host.slots.list("sidebar")}
        content={host.slots.list("content")}
        currentPage={host.nav.current}
      />
      <ToastLayer toastService={host.ctx.toast} />
    </>
  );
}
