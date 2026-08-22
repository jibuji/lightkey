/**
 * theme 插件（首批，`docs/plugin-architecture.md` §3.4；`design/spec.md` §2）。
 *
 * 设计 tokens 的数据驱动落点：暗/浅两套 CSS 变量（暗 = spec §2 拍板值，
 * 浅 = 同色系浅色扩展），应用层在 `document.documentElement`（`data-theme`
 * 属性 + 变量），切换经 `ctx.theme`：
 *
 * - 初始主题：偏好（preference-store）→ 插件配置 `defaultTheme` → dark；
 * - `set`/`toggle`：应用变量 + 偏好持久化 + 广播 `theme.changed`（重渲染）；
 * - 依赖：`inject: ['preference']`（Cordis 自动排加载顺序）。
 */

import type { Context, Plugin } from "@cordisjs/core";
import { Schema } from "@cordisjs/schema";
import type { ThemeName } from "../events";
import type { PreferenceService, ThemeService } from "../services/types";

export interface ThemeConfig {
  /** 默认主题（无偏好时的初始值；缺省 dark）。 */
  defaultTheme?: ThemeName;
}

export const themeConfigSchema = Schema.object({
  defaultTheme: Schema.union([Schema.const("dark"), Schema.const("light")]),
});

/** 暗/浅两套 tokens（暗 = design/spec.md §2.1 拍板值；浅 = 同色系扩展）。 */
export const THEME_PALETTES: Record<ThemeName, Record<string, string>> = {
  dark: {
    "--bg-0": "#171310",
    "--bg-1": "#201a14",
    "--bg-2": "#2a2118",
    "--bg-3": "#362b1e",
    "--border": "rgba(255,233,209,.09)",
    "--fg-0": "#f1e9da",
    "--fg-1": "#bcae98",
    "--fg-2": "#857762",
    "--brand": "#f08a3c",
    "--brand-strong": "#d97a2e",
    "--accent": "#cf8ba3",
    "--danger": "#e5534b",
    "--success": "#9aac5e",
    "--warning": "#ecc94b",
  },
  light: {
    "--bg-0": "#f5efe6",
    "--bg-1": "#fdf8ef",
    "--bg-2": "#ece2d0",
    "--bg-3": "#e3d6bf",
    "--border": "rgba(96,64,28,.14)",
    "--fg-0": "#2b2419",
    "--fg-1": "#6b5d4a",
    "--fg-2": "#9a8b75",
    "--brand": "#e07f2e",
    "--brand-strong": "#c96d20",
    "--accent": "#b76e89",
    "--danger": "#d6453d",
    "--success": "#7d8f45",
    "--warning": "#b08a1e",
  },
};

/** 主题偏好键（preference-store）。 */
export const THEME_PREFERENCE_KEY = "theme";

/** 最近一次向 documentElement 应用主题的插件实例标识（模块级共享状态：
 *  React.StrictMode dev 双挂载时，首个宿主的 dispose 可能异步晚于第二个
 *  宿主的 apply；清理须只由「最后应用者」执行，否则会把新实例刚应用的
 *  tokens 擦掉（QA P2：浅色偏好 reload 后视觉不回显）。 */
let themeApplierSeq = 0;

export const theme: Plugin.Function<Context, ThemeConfig> = Object.assign(
  (ctx: Context, config: ThemeConfig = {}) => {
    const preference: PreferenceService = ctx.preference;
    let current: ThemeName =
      (preference.get(THEME_PREFERENCE_KEY) as ThemeName) ??
      config.defaultTheme ??
      "dark";

    const applierId = ++themeApplierSeq;
    const apply = (name: ThemeName) => {
      const palette = THEME_PALETTES[name];
      const root =
        typeof document !== "undefined" ? document.documentElement : null;
      if (root) {
        for (const [key, value] of Object.entries(palette)) {
          root.style.setProperty(key, value);
        }
        root.dataset.theme = name;
        themeApplierSeq = applierId; // 本实例成为「最后应用者」
      }
    };
    apply(current);

    const service: ThemeService = {
      get current() {
        return current;
      },
      set(name: ThemeName) {
        if (name === current) return;
        current = name;
        preference.set(THEME_PREFERENCE_KEY, name);
        apply(name);
        ctx.emit("theme.changed", { theme: name });
      },
      toggle() {
        service.set(current === "dark" ? "light" : "dark");
      },
    };
    ctx.provide("theme", service);

    // 可逆副作用：插件卸载时清除主题变量（Cordis 卸载自动撤销语义 §5.4）。
    // 仅「最后应用者」清理：避免 StrictMode 双挂载下旧宿主的 dispose 擦掉
    // 新宿主刚应用的 tokens（QA P2）。
    ctx.effect(() => {
      return () => {
        const root = typeof document !== "undefined" ? document.documentElement : null;
        if (root && themeApplierSeq === applierId) {
          // 遍历 token 键（与 THEME_PALETTES 同源，避免硬编码列表与 palette 漂移）
          for (const key of Object.keys(THEME_PALETTES.dark)) {
            root.style.removeProperty(key);
          }
          delete root.dataset.theme;
        }
      };
    });
  },
  {
    
    inject: ["preference"],
    Config: (raw: unknown) => themeConfigSchema(raw as Parameters<typeof themeConfigSchema>[0]),
  },
);
