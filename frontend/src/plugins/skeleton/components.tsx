/**
 * ui 骨架组件（M1.5「React 宿主 + 槽位 + 最小壳」；M2 搜索接线）。
 *
 * 组件本体 = React 写死（§7 数据驱动边界 ④：组件内部怎么画、展示哪些
 * 字段由 React 决定；数据只决定「用哪个组件、放哪个槽位、什么顺序」）。
 * 每个组件声明 `slot` 字段（§6.1 组件 slot 声明），插件工厂注册时以
 * yml 布局数据（slot/order/page）为准、组件声明为缺省。
 *
 * M2 的 ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit 为独立
 * 插件（`frontend/src/plugins/ui-*.tsx`）；本文件保留骨架侧栏/顶栏组件。
 */

import type { ReactNode } from "react";
import type { ThemeName } from "../../events";

/* ------------------------------------------------------------------ */
/* sidebar · 导航项 / 锁定                                              */
/* ------------------------------------------------------------------ */

export interface NavItemProps {
  page: string;
  label: string;
  icon: ReactNode;
  current: string;
  onGo: (page: string) => void;
}

/** 导航项（组件 = 注册到 sidebar 槽位的组件；新增导航 = 新增条目）。 */
export function NavItem({ page, label, icon, current, onGo }: NavItemProps) {
  return (
    <button
      type="button"
      className={`sidebar-nav-item${current === page ? " active" : ""}`}
      title={label}
      aria-label={label}
      onClick={() => onGo(page)}
    >
      {icon}
      <span className="sidebar-nav-label">{label}</span>
    </button>
  );
}
NavItem.slot = "sidebar" as const;

export interface LockButtonProps {
  unlocked: boolean;
  onLock: () => void;
}

/** 侧栏底部锁定按钮（spec §5 骨架；锁定 → `session.locked` 事件链）。 */
export function LockButton({ unlocked, onLock }: LockButtonProps) {
  return (
    <button
      type="button"
      className={`sidebar-nav-item lock${unlocked ? "" : " disabled"}`}
      title={unlocked ? "锁定" : "已锁定"}
      aria-label="锁定"
      disabled={!unlocked}
      onClick={onLock}
    >
      <svg viewBox="0 0 24 24" width={16} height={16} fill="none" stroke="currentColor" strokeWidth={2}>
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    </button>
  );
}
LockButton.slot = "sidebar" as const;

/* ------------------------------------------------------------------ */
/* topbar · 搜索 / 同步状态 / 主题切换                                   */
/* ------------------------------------------------------------------ */

export interface SearchBoxProps {
  value: string;
  onChange: (value: string) => void;
  /** 回车 → ui-vault 空态引导新建（spec §6.2）。 */
  onEnter: (query: string) => void;
}

/** 搜索框（300ms 防抖在插件侧；ui-vault 消费 `vault.search` 事件）。 */
export function SearchBox({ value, onChange, onEnter }: SearchBoxProps) {
  return (
    <input
      type="search"
      className="topbar-search"
      placeholder="搜索名称、账号、用途…"
      aria-label="搜索"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onEnter((e.target as HTMLInputElement).value);
      }}
    />
  );
}
SearchBox.slot = "topbar" as const;

export interface SyncStatusProps {
  unlocked: boolean;
  pending: boolean;
  lastSync: string | null;
  onSync: () => void;
}

/** 同步状态点 + 同步按钮；`item.changed` → 置 pending（三方响应之一：推送侧）。 */
export function SyncStatus({ unlocked, pending, lastSync, onSync }: SyncStatusProps) {
  return (
    <div className="topbar-sync" title={lastSync ? `上次同步 ${lastSync}` : "未同步"}>
      <span
        className={`sync-dot${unlocked ? (pending ? " pending" : " idle") : " locked"}`}
        aria-label={unlocked ? (pending ? "有变更待同步" : "已同步") : "已锁定"}
      />
      <button type="button" className="btn btn-ghost btn-sm" disabled={!unlocked} onClick={onSync}>
        同步
      </button>
    </div>
  );
}
SyncStatus.slot = "topbar" as const;

export interface ThemeToggleProps {
  theme: ThemeName;
  onToggle: () => void;
}

/** 暗/浅切换（theme 插件；`theme.changed` → 宿主重渲染）。 */
export function ThemeToggle({ theme, onToggle }: ThemeToggleProps) {
  return (
    <button
      type="button"
      className="btn btn-ghost btn-sm"
      title={theme === "dark" ? "切换浅色" : "切换暗色"}
      aria-label="切换主题"
      onClick={onToggle}
    >
      {theme === "dark" ? "🌙 暗" : "☀️ 浅"}
    </button>
  );
}
ThemeToggle.slot = "topbar" as const;
