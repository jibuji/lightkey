/**
 * ui 骨架插件（M1.5 首批：React 宿主 + 槽位 + 最小壳）。
 *
 * 每个槽位组件 = 一个 Cordis 插件条目（cordis.yml）：组件本体写死
 * （components.tsx，声明 `slot` 字段），布局数据（slot/order/page）
 * 来自 yml 条目配置，经 @cordisjs/schema 校验后注册进 `ctx.slots`。
 *
 * 组件与槽位的对应（§6.1）：
 * - sidebar：nav-vault / nav-rules / nav-settings / nav-audit（导航项本身
 *   也是组件）+ lock（底部锁定，order 99）；
 * - topbar：search / sync-status / theme-toggle；
 * - content：page-vault / page-rules / page-settings / page-audit
 *   （M2 由 ui-* 插件替换）。
 */

import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Schema } from "@cordisjs/schema";
import type { Context, Plugin } from "@cordisjs/core";
import type { SlotName } from "../../host/slots";
import {
  LockButton,
  NavItem,
  PlaceholderPage,
  SearchBox,
  SyncStatus,
  ThemeToggle,
  VaultPageDemo,
} from "./components";

/** 槽位组件共享配置（布局数据；组件声明作缺省）。 */
export const slotComponentConfig = Schema.object({
  slot: Schema.union([
    Schema.const("topbar"),
    Schema.const("sidebar"),
    Schema.const("content"),
  ]),
  order: Schema.number(),
  page: Schema.string(),
});

export interface SlotComponentConfig {
  slot?: SlotName;
  order?: number;
  page?: string;
}

/** 槽位组件配置校验（yml 原始值 → schema 校验；Config 入口为 unknown）。 */
function validateSlotConfig(raw: unknown): SlotComponentConfig {
  return slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]);
}

/** 注册槽位组件（布局数据优先 yml，缺省回退组件声明/常量）。 */
function register(
  ctx: Context,
  name: string,
  config: SlotComponentConfig,
  component: { slot?: SlotName } & ComponentType<Record<string, unknown>>,
  fallbackSlot: SlotName,
  defaultOrder: number,
) {
  ctx.slots.register({
    name,
    slot: config.slot ?? component.slot ?? fallbackSlot,
    order: config.order ?? defaultOrder,
    component,
    meta: config.page ? { page: config.page } : undefined,
  });
}

/** 复用既有图标（src/components/Icons.tsx）。 */
function icon(name: string): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width={16} height={16} fill="none" stroke="currentColor" strokeWidth={2}>
      {name === "vault" && (
        <>
          <rect x="3" y="3" width="18" height="18" rx="3" />
          <path d="M3 9h18M9 21V9" />
        </>
      )}
      {name === "rules" && (
        <>
          <path d="M12 2 4 6v6c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10V6l-8-4z" />
          <path d="M9 12l2 2 4-4" />
        </>
      )}
      {name === "settings" && <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 3h-5l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z" />}
      {name === "audit" && (
        <>
          <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
          <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
          <path d="M9 7h7M9 11h7" />
        </>
      )}
    </svg>
  );
}

/* ---------------- sidebar · 导航 ---------------- */

const navPlugin = (page: string, label: string, iconName: string): Plugin.Function<Context, SlotComponentConfig> =>
  Object.assign(
    (ctx: Context, config: SlotComponentConfig) => {
      register(
        ctx,
        `nav-${page}`,
        config,
        (() => {
          const Comp = () => (
            <NavItem
              page={config.page ?? page}
              label={label}
              icon={icon(iconName)}
              current={ctx.nav.current}
              onGo={(p) => ctx.nav.go(p)}
            />
          );
          Comp.slot = "sidebar";
          return Comp;
        })() as ComponentType<Record<string, unknown>>,
        "sidebar",
        10,
      );
    },
    {
      inject: ["slots", "nav"],
      Config: validateSlotConfig,
    },
  );

export const navVault = navPlugin("vault", "条目", "vault");
export const navRules = navPlugin("rules", "规则", "rules");
export const navSettings = navPlugin("settings", "设置", "settings");
export const navAudit = navPlugin("audit", "审计", "audit");

/* ---------------- sidebar · 锁定 ---------------- */

export const lock: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    register(
      ctx,
      "lock",
      config,
      (() => {
        const Comp = () => (
          <LockButton unlocked={ctx.session.unlocked} onLock={() => void ctx.session.lock()} />
        );
        Comp.slot = "sidebar";
        return Comp;
      })() as ComponentType<Record<string, unknown>>,
      "sidebar",
      99,
    );
  },
  { inject: ["slots", "session"], Config: validateSlotConfig },
);

/* ---------------- topbar ---------------- */

export const search: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    register(
      ctx,
      "search",
      config,
      (() => {
        const Comp = () => (
          <SearchBox
            onEnter={() => ctx.toast.show("搜索在 M2 随 ui-vault 实现")}
          />
        );
        Comp.slot = "topbar";
        return Comp;
      })() as ComponentType<Record<string, unknown>>,
      "topbar",
      10,
    );
  },
  { inject: ["slots", "toast"], Config: validateSlotConfig },
);

export const syncStatus: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    register(
      ctx,
      "sync-status",
      config,
      (() => {
        const Comp = () => {
          const [pending, setPending] = useState(false);
          const [lastSync, setLastSync] = useState<string | null>(null);
          const [unlocked, setUnlocked] = useState(ctx.session.unlocked);
          useEffect(() => {
            const offChanged = ctx.on("item.changed", () => setPending(true));
            const offUnlocked = ctx.on("session.unlocked", () => {
              setUnlocked(true);
              setPending(false);
            });
            const offLocked = ctx.on("session.locked", () => setUnlocked(false));
            return () => {
              offChanged();
              offUnlocked();
              offLocked();
            };
          }, []);
          return (
            <SyncStatus
              unlocked={unlocked}
              pending={pending}
              lastSync={lastSync}
              onSync={() => {
                void ctx.ipc.syncTrigger().then((s) => {
                  setLastSync(s.lastSync ?? null);
                  setPending(false);
                });
              }}
            />
          );
        };
        Comp.slot = "topbar";
        return Comp;
      })() as ComponentType<Record<string, unknown>>,
      "topbar",
      20,
    );
  },
  {
    inject: ["slots", "ipc", "session"],
    Config: validateSlotConfig,
  },
);

export const themeToggle: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    register(
      ctx,
      "theme-toggle",
      config,
      (() => {
        const Comp = () => (
          <ThemeToggle theme={ctx.theme.current} onToggle={() => ctx.theme.toggle()} />
        );
        Comp.slot = "topbar";
        return Comp;
      })() as ComponentType<Record<string, unknown>>,
      "topbar",
      30,
    );
  },
  { inject: ["slots", "theme"], Config: validateSlotConfig },
);

/* ---------------- content · 页面 ---------------- */

const pagePlugin = (page: string, title: string, description: string): Plugin.Function<Context, SlotComponentConfig> =>
  Object.assign(
    (ctx: Context, config: SlotComponentConfig) => {
      register(
        ctx,
        `page-${page}`,
        config,
        (() => {
          const Comp = () => <PlaceholderPage title={title} description={description} />;
          Comp.slot = "content";
          return Comp;
        })() as ComponentType<Record<string, unknown>>,
        "content",
        10,
      );
    },
    {
      inject: ["slots"],
      Config: validateSlotConfig,
    },
  );

/** 条目页占位（事件总线演示面板）。 */
export const pageVault: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    register(
      ctx,
      "page-vault",
      config,
      (() => {
        const Comp = () => <VaultPageDemo ctx={ctx} />;
        Comp.slot = "content";
        return Comp;
      })() as ComponentType<Record<string, unknown>>,
      "content",
      10,
    );
  },
  {
    inject: ["slots", "session", "theme", "toast", "ipc"],
    Config: validateSlotConfig,
  },
);

export const pageRules = pagePlugin("rules", "规则", "M2 实现规则 CRUD（ui-rules，规则库在 vault 内加密、按项目目录绑定）。");
export const pageSettings = pagePlugin("settings", "设置", "M2 实现同步/安全/审计保留 + 主题选择（ui-settings，依赖 theme）。");
export const pageAudit = pagePlugin("audit", "审计", "M2 实现事件流只读展示（ui-audit；无密钥值）。");
