/**
 * 三栏骨架（宿主写死，`docs/plugin-architecture.md` §6.1；`design/spec.md` §5）。
 *
 * - 解锁态：`topbar`（搜索 + 同步状态 + 主题切换）+ `sidebar`（64px 图标栏
 *   + 底部锁定）+ `content`（当前页 = nav 选中页；槽位内组件由 slot 注册表
 *   提供，顺序 = 布局数据）；
 * - **锁态：整页 ui-unlock（无三栏）**——宿主按 `session.unlocked/locked`
 *   在「整页解锁」与「三栏」间切换（spec §6.2 宿主职责；ui-unlock 挂
 *   content 槽位 page="unlock"，锁态单独渲染）；
 * - **锁态 + 无库（M2.5 首启）：整页 ui-onboarding（初始化向导）**——与
 *   ui-unlock 互斥：门控数据 = `session.initialized`（守护进程 vault.status
 *   探测；null = 探测中，渲染检测占位）；完成后 unlock → session.unlocked
 *   自动切三栏。
 *
 * 骨架只负责「放哪」；槽位内组件由 slot 注册表提供。宿主订阅事件总线
 * （`theme.changed` / `session.*` / `item.changed` / `vault.initialized`）
 * 触发重渲染。
 */

import type { Context } from "@cordisjs/core";
import type { ReactNode } from "react";
import type { SlotEntry } from "./slots";

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

  // 锁态：M2.5 首启门控——无库 → 整页初始化向导；有库 → 整页 ui-unlock
  // （互斥；门控数据 = session.initialized；null = 探测中，渲染占位）
  if (!unlocked) {
    const initialized = ctx.session.initialized;
    if (initialized === null) {
      return (
        <div className="app">
          <div className="content">
            <div className="content-panel card muted">正在检测库状态…</div>
          </div>
        </div>
      );
    }
    const lockedPage = initialized ? "unlock" : "onboarding";
    const locked = content.find((e) => e.meta?.page === lockedPage);
    if (locked) return <locked.component key={locked.name} />;
    return (
      <div className="app">
        <div className="content">
          <div className="content-panel card muted">已锁定（ui-unlock 未装配）</div>
        </div>
      </div>
    );
  }

  const pages = content.filter((e) => e.meta?.page && e.meta.page !== "unlock");
  const active = pages.find((e) => e.meta?.page === currentPage) ?? pages[0];
  const lockedView: ReactNode = null;

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
