/**
 * cordis.yml 薄 loader（`docs/plugin-architecture.md` §6.2/§8.1）。
 *
 * 数据驱动装配：yml 条目 = 插件 + 布局数据（`slot` / `order` / `page`）。
 * 契约与 `@cordisjs/plugin-loader` 的 EntryOptions 对齐（name/config/
 * disabled 同语义；slot/order/page 为布局扩展字段），条目经
 * `@cordisjs/schema` 校验。
 *
 * 说明：`@cordisjs/plugin-loader`（4.x）面向 Node 运行时（fs 读写 +
 * 动态 import 插件模块），浏览器/Vite 构建无法直接运行；本 loader 以
 * 同语义实现：解析 + 校验 + 按序 `ctx.plugin()` 挂载，插件解析走
 * 静态注册表（Vite 打包内联）。yml 文件仍随应用发布（`frontend/cordis.yml`）。
 */

import { Schema } from "@cordisjs/schema";
import type { Context, Plugin } from "@cordisjs/core";
import { load as parseYaml } from "js-yaml";
import { SLOT_NAMES, type SlotName } from "./slots";

/** cordis.yml 单条目（EntryOptions + 布局扩展）。 */
export interface PluginEntry {
  /** 插件名（注册表 key）。 */
  name: string;
  /** 插件配置（经插件自身 Config schema 校验）。 */
  config?: Record<string, unknown>;
  /** 槽位（布局数据；组件声明可作缺省）。 */
  slot?: SlotName;
  /** 槽位内顺序（布局数据）。 */
  order?: number;
  /** content 页面路由名（页面组件）。 */
  page?: string;
  disabled?: boolean;
}

export const pluginEntrySchema = Schema.object({
  name: Schema.string().required(),
  config: Schema.any(),
  slot: Schema.union(SLOT_NAMES.map((s) => Schema.const(s))),
  order: Schema.number(),
  page: Schema.string(),
  disabled: Schema.boolean(),
});

export const pluginListSchema = Schema.array(pluginEntrySchema);

/** 插件注册表（Vite 静态 import；M2 新增插件 = 注册 + yml 增条目）。 */
export type PluginRegistry = Record<string, Plugin>;

export interface MountedPlugin {
  entry: PluginEntry;
  /** 卸载句柄（宿主 dispose 时逐个 dispose）。 */
  dispose: () => void;
}

export class CordisLoader {
  constructor(
    private readonly ctx: Context,
    private readonly registry: PluginRegistry,
  ) {}

  /** 解析 + 校验 yml（@cordisjs/schema）；非法条目直接抛错（装配契约不可静默降级）。 */
  parse(raw: string): PluginEntry[] {
    const data = parseYaml(raw);
    if (!Array.isArray(data)) {
      throw new Error("cordis.yml 顶层必须是插件条目数组（EntryOptions[]）");
    }
    return pluginListSchema(data);
  }

  /** 按序挂载全部条目；返回已挂载条目（含卸载句柄）。 */
  async load(raw: string): Promise<MountedPlugin[]> {
    const entries = this.parse(raw);
    const mounted: MountedPlugin[] = [];
    for (const entry of entries) {
      if (entry.disabled) continue;
      const plugin = this.registry[entry.name];
      if (!plugin) {
        throw new Error(`cordis.yml 引用了未注册插件：${entry.name}`);
      }
      // 布局数据（slot/order/page）为条目级字段（§6.2 示例形态），
      // 合并进插件配置（插件 Config schema 校验合并后的对象）。
      const config: Record<string, unknown> = { ...entry.config };
      if (entry.slot !== undefined) config.slot = entry.slot;
      if (entry.order !== undefined) config.order = entry.order;
      if (entry.page !== undefined) config.page = entry.page;
      const fiber = await this.ctx.plugin(plugin, config);
      mounted.push({ entry, dispose: () => fiber.dispose() });
    }
    return mounted;
  }
}
