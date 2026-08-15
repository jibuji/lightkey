/**
 * VaultApp —— 解锁后的主界面布局（spec §5）：
 * 侧栏（64px 图标栏 + 底部锁定）· 顶栏（搜索 + 同步状态）· 内容区（页面切换）。
 */

import { useState, type RefObject } from "react";
import type { LightKeyIpc } from "../ipc";
import type { PageId, SyncStatus } from "../types";
import { Icon, type IconName } from "./Icons";
import { ItemsPage } from "./ItemsPage";
import { RulesPage } from "./RulesPage";
import { SettingsPage } from "./SettingsPage";
import { AuditPage } from "./AuditPage";
import { useToast } from "./Toast";

const NAV: { id: PageId; icon: IconName; title: string }[] = [
  { id: "items", icon: "list", title: "全部条目" },
  { id: "rules", icon: "shield", title: "授权规则" },
  { id: "settings", icon: "gear", title: "设置" },
  { id: "audit", icon: "doc", title: "审计日志" },
];

interface VaultAppProps {
  ipc: LightKeyIpc;
  onLock: () => void;
  /** 搜索框 ref（回车 → 新建条目） */
  searchRef?: RefObject<HTMLInputElement>;
  onSearchEnter?: () => void;
  newItemSignal?: number;
}

export function VaultApp({ ipc, onLock, searchRef, onSearchEnter, newItemSignal = 0 }: VaultAppProps) {
  const { toast } = useToast();
  const [page, setPage] = useState<PageId>("items");
  const [search, setSearch] = useState("");
  const [sync, setSync] = useState<SyncStatus>({ synced: true, pollSec: 60 });

  const syncNow = async () => {
    const s = await ipc.syncTrigger();
    setSync(s);
    toast(`同步完成：无变更（轮询 ${s.pollSec}s）`, "ok");
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-brand" title="LightKey">
          <span className="brand-mark">
            <Icon name="brand" size={20} />
          </span>
        </div>
        <nav className="sidebar-nav">
          {NAV.map((n) => (
            <button
              key={n.id}
              className={`nav-item${page === n.id ? " active" : ""}`}
              title={n.title}
              aria-label={n.title}
              onClick={() => setPage(n.id)}
            >
              <Icon name={n.icon} size={18} />
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <button
            className="nav-item"
            title="锁定"
            aria-label="锁定"
            onClick={() => {
              void ipc.lock().then(() => {
                setPage("items");
                setSearch("");
                toast("已锁定 · 内存密钥已擦除", "ok");
                onLock();
              });
            }}
          >
            <Icon name="lock" size={18} />
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="search-wrap">
            <Icon name="search" size={16} />
            <input
              ref={searchRef}
              type="text"
              placeholder="搜索名称、账号、用途或内容…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onSearchEnter?.();
              }}
            />
          </div>
          <div className="topbar-right">
            <span className="sync-state" title={`已同步 · 轮询 ${sync.pollSec}s`}>
              <span className="dot dot-ok" />
              已同步
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => void syncNow()}>
              同步
            </button>
          </div>
        </header>

        <div className="content">
          {page === "items" ? (
            <ItemsPage ipc={ipc} search={search} newItemSignal={newItemSignal} />
          ) : page === "rules" ? (
            <RulesPage ipc={ipc} />
          ) : page === "settings" ? (
            <SettingsPage />
          ) : (
            <AuditPage ipc={ipc} />
          )}
        </div>
      </div>
    </div>
  );
}
