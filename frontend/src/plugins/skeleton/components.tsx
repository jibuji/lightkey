/**
 * ui 骨架组件（M1.5「React 宿主 + 槽位 + 最小壳」）。
 *
 * 组件本体 = React 写死（§7 数据驱动边界 ④：组件内部怎么画、展示哪些
 * 字段由 React 决定；数据只决定「用哪个组件、放哪个槽位、什么顺序」）。
 * 每个组件声明 `slot` 字段（§6.1 组件 slot 声明），插件工厂注册时以
 * yml 布局数据（slot/order/page）为准、组件声明为缺省。
 *
 * M2 的 ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit 在
 * 此骨架上实现（`docs/milestones.md` M1.5）。
 */

import { useEffect, useState, type ReactNode } from "react";
import type { Context } from "@cordisjs/core";
import type { ItemChangedPayload, ThemeName } from "../../events";
import { CLIPBOARD_CLEAR_MS } from "../../events";

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
  onEnter: (query: string) => void;
}

/** 搜索框（M2 随 ui-vault 接真实搜索；骨架内回车 → 提示）。 */
export function SearchBox({ onEnter }: SearchBoxProps) {
  return (
    <input
      type="search"
      className="topbar-search"
      placeholder="搜索（M2 随 ui-vault 实现）"
      aria-label="搜索"
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

/* ------------------------------------------------------------------ */
/* content · 页面（M2 前为占位/事件总线演示）                              */
/* ------------------------------------------------------------------ */

/** 事件总线演示页（vault 页占位；展示 session / item.changed / clipboard 链路）。 */
export function VaultPageDemo({ ctx }: { ctx: Context }) {
  const [log, setLog] = useState<string[]>([]);
  const [theme, setTheme] = useState<ThemeName>(ctx.theme.current);
  const [unlocked, setUnlocked] = useState(ctx.session.unlocked);

  // 事件日志（最近 6 条；host 重渲染时保持）
  const push = (line: string) => setLog((prev) => [...prev.slice(-5), line]);

  useEffect(() => {
    const offChanged = ctx.on("item.changed", (p: ItemChangedPayload) => {
      push(`item.changed ${p.type} ${p.itemId.slice(0, 8)} ${p.deleted ? "删除" : "更新"}@${p.revisionDate}`);
    });
    const offUnlocked = ctx.on("session.unlocked", () => {
      setUnlocked(true);
      push("session.unlocked");
    });
    const offLocked = ctx.on("session.locked", (p) => {
      setUnlocked(false);
      push(`session.locked (${p.reason})`);
    });
    const offTheme = ctx.on("theme.changed", (p) => {
      setTheme(p.theme);
      push(`theme.changed → ${p.theme}`);
    });
    return () => {
      offChanged();
      offUnlocked();
      offLocked();
      offTheme();
    };
  }, [ctx]);

  const demoCopy = () => {
    const clearedAt = new Date(Date.now() + CLIPBOARD_CLEAR_MS).toISOString();
    ctx.emit("clipboard.copied", { source: "demo", field: "password", clearedAt });
    push(`clipboard.copied（${CLIPBOARD_CLEAR_MS / 1000}s 后清除）`);
  };

  return (
    <div className="content-panel card">
      <h2>条目（ui-vault 占位 · M2）</h2>
      <p className="muted">
        M2 在此实现列表/搜索/详情/编辑；本页为 M1.5 事件总线演示面板。
      </p>
      <div className="demo-row">
        <span className={`tag${unlocked ? " tag-ok" : ""}`}>{unlocked ? "已解锁" : "已锁定"}</span>
        <span className="tag">{theme === "dark" ? "暗色" : "浅色"}</span>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => ctx.session.notifyItemChanged({
          itemId: "demo-item",
          revisionDate: new Date().toISOString(),
          type: "login",
          deleted: false,
        })}>
          模拟 item.changed
        </button>
        <button type="button" className="btn btn-ghost btn-sm" onClick={demoCopy}>
          复制（clipboard.copied）
        </button>
      </div>
      <pre className="event-log" aria-label="事件日志">
        {log.length ? log.join("\n") : "（事件日志：解锁/锁定、item.changed、theme.changed…）"}
      </pre>
    </div>
  );
}

export interface PlaceholderPageProps {
  title: string;
  description: string;
  /** 组件内部展示写死（§7 边界 ④），文案经 props 传入由工厂绑定。 */
}

/** 占位页（rules / settings / audit；M2 实现对应 ui-* 插件）。 */
export function PlaceholderPage({ title, description }: PlaceholderPageProps) {
  return (
    <div className="content-panel card">
      <h2>{title}</h2>
      <p className="muted">{description}</p>
    </div>
  );
}
PlaceholderPage.slot = "content" as const;

/** 解锁面板（M1.5 最小壳；M2 由 ui-unlock 替换——见 spec §6.1）。 */
export function LockPanel({ ctx }: { ctx: Context }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await ctx.session.unlock(password);
      setPassword("");
    } catch {
      setError("解锁失败（主密码错误或库未初始化）");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="content-panel lock-panel">
      <h2>已锁定</h2>
      <p className="muted">
        密钥只在守护进程内存中，锁定即擦除。解锁后回到保险库。
        <br />
        （M1.5 骨架运行在 ipc-bridge mock 适配器：演示密码 demo-password）
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <input
          type="password"
          className="text-input"
          placeholder="主密码"
          aria-label="主密码"
          value={password}
          disabled={busy}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        {error && <p className="error-text">{error}</p>}
        <button type="submit" className="btn btn-primary" disabled={busy || !password}>
          解锁
        </button>
      </form>
    </div>
  );
}
