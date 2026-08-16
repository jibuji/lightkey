/**
 * 槽位注册表（`docs/plugin-architecture.md` §6.1）。
 *
 * - 槽位骨架（三栏）→ 宿主写死（`Skeleton.tsx`）；
 * - 槽位内组件有无/顺序 → 数据驱动：插件（= 组件模块）注册时携带
 *   `slot`（组件声明）与 `order`（布局数据，来自 cordis.yml）。
 *
 * 固定槽位：`topbar`（顶栏）/ `sidebar`（侧栏）/ `content`（内容区）。
 */

import type { ComponentType } from "react";

export type SlotName = "topbar" | "sidebar" | "content";

export const SLOT_NAMES: SlotName[] = ["topbar", "sidebar", "content"];

export interface SlotEntry {
  /** 组件名（cordis.yml 条目名；全局唯一）。 */
  name: string;
  /** 槽位（组件声明；yml 配置可覆盖）。 */
  slot: SlotName;
  /** 槽位内顺序（布局数据；缺省 100）。 */
  order: number;
  /** 挂入的 React 组件。 */
  component: ComponentType<Record<string, unknown>>;
  /** 布局/页面元数据透传（如 content 页面的 page 名）。 */
  meta?: Record<string, unknown>;
}

export class SlotRegistry {
  private entries: SlotEntry[] = [];

  register(entry: SlotEntry): void {
    const existing = this.entries.findIndex((e) => e.name === entry.name);
    if (existing >= 0) {
      this.entries[existing] = entry;
      return;
    }
    this.entries.push(entry);
  }

  /** 某槽位的组件（按 order 升序；同 order 按名字母序——布局数据决定顺序）。 */
  list(slot: SlotName): SlotEntry[] {
    return this.entries
      .filter((e) => e.slot === slot)
      .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
  }

  all(): SlotEntry[] {
    return [...this.entries];
  }

  /** content 槽位里 page 为 `page` 的组件（页面路由）。 */
  page(page: string): SlotEntry | undefined {
    return this.list("content").find((e) => e.meta?.page === page);
  }
}
