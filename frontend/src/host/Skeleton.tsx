/**
 * 三栏骨架（宿主写死，`docs/plugin-architecture.md` §6.1；`design/spec.md` §5）。
 *
 * - `topbar`：顶栏（搜索 + 同步状态 + 主题切换——槽位内组件有无/顺序数据驱动）；
 * - `sidebar`：64px 图标栏（导航项 + 底部锁定）；
 * - `content`：内容区（当前页面 = nav 选中页；锁定态 → 解锁面板）。
 *
 * 骨架只负责「放哪」；槽位内组件由 slot 注册表提供（顺序 = 布局数据）。
 * 宿主订阅事件总线（`theme.changed` / `session.*` / `item.changed`）触发
 * 重渲染（事件重渲染，M1.5 出口）。
 */

import type { Context } from "@cordisjs/core";
import type { ReactNode } from "react";
import type { SlotEntry } from "./slots";
import { LockPanel } from "../plugins/skeleton/components";

export interface SkeletonProps {
  ctx: Context;
  topbar: SlotEntry[];
  sidebar: SlotEntry[];
  content: SlotEntry[];
  /** 当前页面（nav 选中；content 槽位组件按 page 元数据匹配）。 */
  currentPage: string;
}

export function Skeleton({ ctx, topbar, sidebar, content, currentPage }: SkeletonProps) {
  const unlocked = ctx.session.unlocked;
  const active = content.find((e) => e.meta?.page === currentPage) ?? content[0];
  const lockedView: ReactNode = unlocked ? null : <LockPanel ctx={ctx} />;

  return (
    <div className="app">
      <aside className="sidebar" aria-label="侧栏">
        <div className="sidebar-brand" aria-hidden>
          <span className="brand-mark" />
        </div>
        <nav className="sidebar-nav">
          {sidebar.map((entry) => (
            <entry.component key={entry.name} />
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar" aria-label="顶栏">
          <div className="topbar-left">{topbar.map((entry) => <entry.component key={entry.name} />)}</div>
          <div className="topbar-right" />
        </header>
        <div className="content">
          {lockedView ?? (active ? <active.component key={active.name} /> : null)}
        </div>
      </div>
    </div>
  );
}
