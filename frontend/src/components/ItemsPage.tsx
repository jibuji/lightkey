/**
 * ItemsPage —— 条目列表 + 详情双栏（spec §5/§6.2/§6.3）：
 * 筛选 chips（全部/登录/笔记/密钥/文件）· 搜索命中高亮 · 详情按类型分组 ·
 * 新建/编辑弹窗 · 删除确认 · CAS 冲突（覆盖/取消）。
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { LightKeyIpc } from "../ipc";
import { mdRender, mdSnippet } from "../markdown/highlight";
import type { Item, ItemDraft, ItemType } from "../types";
import { Icon, type IconName } from "./Icons";
import { ItemModal } from "./ItemModal";
import { Modal } from "./Modal";
import { useCopy, useToast } from "./Toast";

export type FilterValue = "all" | ItemType;

const FILTERS: { value: FilterValue; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "login", label: "登录" },
  { value: "note", label: "笔记" },
  { value: "secret", label: "密钥" },
  { value: "file", label: "文件" },
];

const TYPE_META: Record<
  ItemType,
  { icon: IconName; label: string; sub: (it: Item) => string }
> = {
  login: { icon: "globe", label: "登录", sub: (it) => (it.type === "login" ? it.username : "—") },
  note: { icon: "fileText", label: "笔记", sub: (it) => (it.type === "note" ? mdSnippet(it.content) : "—") },
  secret: {
    icon: "key",
    label: "密钥",
    sub: (it) =>
      it.type === "secret"
        ? it.purpose || (it.value ? `••••${it.value.slice(-4)}` : "—")
        : "—",
  },
  file: {
    icon: "file",
    label: "文件",
    sub: (it) => (it.type === "file" ? [it.size, it.fileType].filter(Boolean).join(" · ") || "—" : "—"),
  },
};

/** 300ms 防抖 */
function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

/** 搜索命中高亮 */
function Highlighted({ text, q }: { text: string; q: string }) {
  if (!q) return <>{text}</>;
  const lower = text.toLowerCase();
  const needle = q.toLowerCase();
  const out: ReactNode[] = [];
  let i = 0;
  let idx = lower.indexOf(needle);
  let key = 0;
  while (idx >= 0) {
    if (idx > i) out.push(<span key={key++}>{text.slice(i, idx)}</span>);
    out.push(
      <mark key={key++} className="hl">
        {text.slice(idx, idx + needle.length)}
      </mark>,
    );
    i = idx + needle.length;
    idx = lower.indexOf(needle, i);
  }
  if (i < text.length) out.push(<span key={key++}>{text.slice(i)}</span>);
  return <>{out}</>;
}

interface ItemsPageProps {
  ipc: LightKeyIpc;
  /** 顶栏搜索词（由 VaultApp 持有） */
  search: string;
  /** 顶栏搜索框回车 → 新建（spec §6.2 空态引导） */
  newItemSignal: number;
}

export function ItemsPage({ ipc, search, newItemSignal }: ItemsPageProps) {
  const { toast } = useToast();
  const copy = useCopy();

  const [filter, setFilter] = useState<FilterValue>("all");
  const q = useDebounced(search.trim().toLowerCase(), 300);

  const [items, setItems] = useState<Item[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const [modal, setModal] = useState<{ mode: "create" } | { mode: "edit"; id: string } | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [conflict, setConflict] = useState<{ id: string; draft: ItemDraft } | null>(null);

  /* ---------- 数据加载 ---------- */
  useEffect(() => {
    let alive = true;
    setItems(null);
    ipc
      .list()
      .then((summaries) => Promise.all(summaries.map((s) => ipc.get(s.id))))
      .then((full) => {
        if (!alive) return;
        setItems(full);
        setSelectedId((prev) => {
          if (prev && full.some((it) => it.id === prev)) return prev;
          return full[0]?.id ?? null;
        });
      })
      .catch(() => {
        if (alive) setItems([]);
      });
    return () => {
      alive = false;
    };
  }, [ipc, reloadTick]);

  useEffect(() => {
    if (newItemSignal > 0) setModal({ mode: "create" });
  }, [newItemSignal]);

  /* ---------- 列表 ---------- */
  const filtered = useMemo(() => {
    if (!items) return null;
    return items.filter((it) => {
      if (filter !== "all" && it.type !== filter) return false;
      if (!q) return true;
      const hay = [
        it.name,
        it.type === "login" ? it.username : "",
        it.type === "login" ? it.uris.join(" ") : "",
        it.type === "secret" ? it.purpose : "",
        it.type === "secret" ? it.value : "",
        it.type === "note" ? it.content : "",
        it.type === "file" ? it.note : "",
        it.type === "file" ? it.attachment : "",
        it.type === "file" ? it.fileType : "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [items, filter, q]);

  const selected = useMemo(
    () => (items ? items.find((it) => it.id === selectedId) ?? null : null),
    [items, selectedId],
  );

  const selectItem = useCallback(
    (id: string) => {
      setSelectedId(id);
      setRevealed(false);
      // 堆叠布局（≤900px）下详情在列表下方：滚入视口（served 原型行为）
      if (window.innerWidth <= 900) {
        requestAnimationFrame(() => {
          document.getElementById("detail")?.scrollIntoView({ block: "start" });
        });
      }
    },
    [],
  );

  const reload = useCallback(() => setReloadTick((t) => t + 1), []);

  /* ---------- 保存 / CAS ---------- */
  const handleSaved = useCallback(
    (item: Item) => {
      setModal(null);
      toast(item && modal?.mode === "edit" ? "条目已保存（revisionDate 已更新）" : "条目已创建", "ok");
      setSelectedId(item.id);
      reload();
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [modal, reload, toast],
  );

  const handleConflict = useCallback((id: string, draft: ItemDraft) => {
    setModal(null);
    setConflict({ id, draft });
  }, []);

  const conflictOverwrite = useCallback(async () => {
    if (!conflict) return;
    try {
      await ipc.update(conflict.id, conflict.draft);
      setConflict(null);
      toast("已覆盖其他设备的修改", "ok");
      reload();
    } catch {
      toast("保存失败，请重试", "warn");
    }
  }, [conflict, ipc, reload, toast]);

  /* ---------- 删除 ---------- */
  const doDelete = useCallback(async () => {
    if (!deleteId) return;
    try {
      await ipc.remove(deleteId);
      setDeleteId(null);
      setSelectedId((prev) => (prev === deleteId ? null : prev));
      toast("已软删除 · 30 天后硬删", "ok");
      reload();
    } catch {
      toast("删除失败，请重试", "warn");
    }
  }, [deleteId, ipc, reload, toast]);

  const deletingItem = useMemo(
    () => (deleteId && items ? items.find((it) => it.id === deleteId) : null),
    [deleteId, items],
  );

  /* ---------- 渲染 ---------- */
  return (
    <div id="page-items" className="page items-page active">
      <div className="pane-list">
        <div className="pane-list-head">
          <h2 className="pane-title">全部条目</h2>
          <button className="btn btn-primary btn-sm" onClick={() => setModal({ mode: "create" })}>
            <Icon name="plus" size={14} strokeWidth={2.5} />
            新建
          </button>
        </div>
        <div className="filters">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              className={`chip${filter === f.value ? " active" : ""}`}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="item-list">
          {filtered === null ? (
            <div className="empty">加载中…</div>
          ) : filtered.length === 0 ? (
            <div className="empty">
              <div style={{ color: "var(--fg-2)", fontSize: 32 }}>{q ? "🔍" : "🗝️"}</div>
              <div>{q ? "未找到匹配条目，按回车新建" : "还没有条目，添加第一条吧"}</div>
              {!q ? (
                <button className="btn btn-primary btn-sm" onClick={() => setModal({ mode: "create" })}>
                  新建条目
                </button>
              ) : null}
            </div>
          ) : (
            filtered.map((it) => {
              const m = TYPE_META[it.type];
              return (
                <button
                  key={it.id}
                  className={`item${it.id === selectedId ? " selected" : ""}`}
                  onClick={() => selectItem(it.id)}
                >
                  <span className={`item-icon ${it.type}`}>
                    <Icon name={m.icon} size={15} />
                  </span>
                  <span className="item-body">
                    <span className="item-name">
                      <Highlighted text={it.name} q={q} />
                    </span>
                    <span className="item-sub">
                      <Highlighted text={m.sub(it)} q={q} />
                    </span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>

      <div id="detail" className="pane-detail">
        {selected ? (
          <DetailCard
            item={selected}
            revealed={revealed}
            onToggleReveal={() => setRevealed((v) => !v)}
            onEdit={() => setModal({ mode: "edit", id: selected.id })}
            onDelete={() => setDeleteId(selected.id)}
            onCopy={copy}
          />
        ) : (
          <div className="empty">选择左侧条目查看详情</div>
        )}
      </div>

      {/* 新建 / 编辑 */}
      {modal ? (
        <ItemModal
          ipc={ipc}
          item={modal.mode === "edit" ? (items?.find((it) => it.id === modal.id) ?? null) : null}
          onClose={() => setModal(null)}
          onSaved={handleSaved}
          onConflict={handleConflict}
        />
      ) : null}

      {/* 删除确认 */}
      {deletingItem ? (
        <Modal
          title={`删除「${deletingItem.name}」？`}
          desc="这是软删除：写入墓碑并在 30 天后硬删；墓碑会随同步传播。"
          onClose={() => setDeleteId(null)}
        >
          <div className="modal-actions">
            <button className="btn btn-ghost" onClick={() => setDeleteId(null)}>
              取消
            </button>
            <button className="btn btn-danger" onClick={() => void doDelete()}>
              删除
            </button>
          </div>
        </Modal>
      ) : null}

      {/* CAS 冲突：条目已被其他设备修改 */}
      {conflict ? (
        <Modal
          title="条目已被其他设备修改"
          desc="你正在编辑的版本已过期；覆盖将丢弃其他设备的新修改（乐观并发 CAS）。"
          onClose={() => setConflict(null)}
        >
          <div className="modal-actions">
            <button className="btn btn-ghost" onClick={() => setConflict(null)}>
              取消
            </button>
            <button className="btn btn-danger" onClick={() => void conflictOverwrite()}>
              覆盖
            </button>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

/* ================= 详情卡片（按类型分组） ================= */

interface DetailCardProps {
  item: Item;
  revealed: boolean;
  onToggleReveal: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onCopy: (text: string) => void;
}

function DetailCard({ item, revealed, onToggleReveal, onEdit, onDelete, onCopy }: DetailCardProps) {
  const { toast } = useToast();
  const m = TYPE_META[item.type];
  const maskValue = (v: string) => (revealed ? v : "••••••••••••");

  return (
    <div className="detail-card">
      <div className="detail-head">
        <span className={`item-icon ${item.type}`}>
          <Icon name={m.icon} size={17} />
        </span>
        <div>
          <h3 className="detail-title">{item.name}</h3>
          <div className="detail-sub">
            {m.label} · 修订于 {item.revision.slice(0, 10)} · 存储端仅见密文
          </div>
        </div>
        <div className="detail-actions">
          <button className="icon-btn" title="编辑" onClick={onEdit}>
            <Icon name="edit" size={15} />
          </button>
          <button
            className="icon-btn"
            title="删除（软删除，30 天硬删）"
            style={{ color: "var(--fg-1)" }}
            onClick={onDelete}
          >
            <Icon name="trash" size={15} />
          </button>
        </div>
      </div>

      {item.type === "login" ? (
        <>
          <div className="section-title">登录信息</div>
          <div className="field-row">
            <div>
              <div className="field-row-label">用户名</div>
              <div className="field-row-value">
                <span className="mono">{item.username}</span>
                <button className="icon-btn" title="复制用户名" onClick={() => onCopy(item.username)}>
                  <Icon name="copy" size={15} />
                </button>
              </div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">密码</div>
              <div className="field-row-value">
                <span className={revealed ? "mono" : "mask"}>{maskValue(item.password)}</span>
                <button className="icon-btn" title={revealed ? "隐藏" : "显示"} onClick={onToggleReveal}>
                  <Icon name="eye" size={15} />
                </button>
                <button className="icon-btn" title="复制密码" onClick={() => onCopy(item.password)}>
                  <Icon name="copy" size={15} />
                </button>
              </div>
            </div>
          </div>
          {item.uris.length ? (
            <>
              <div className="section-title">站点</div>
              {item.uris.map((u) => (
                <div key={u} className="uri-row">
                  <Icon name="globe" size={15} /> {u}
                </div>
              ))}
            </>
          ) : null}
          {item.custom.length ? (
            <>
              <div className="section-title">自定义字段</div>
              {item.custom.map((c, i) => (
                <div className="field-row" key={i}>
                  <div>
                    <div className="field-row-label">{c.name}</div>
                    <div className="field-row-value">
                      <span className={c.hidden ? "mask" : ""}>{c.hidden ? "••••••••" : c.value}</span>
                      {c.hidden ? (
                        <button className="icon-btn" title="复制" onClick={() => onCopy(c.value)}>
                          <Icon name="copy" size={15} />
                        </button>
                      ) : null}
                    </div>
                  </div>
                </div>
              ))}
            </>
          ) : null}
        </>
      ) : null}

      {item.type === "note" ? (
        <>
          <div className="section-title">笔记内容（Markdown）</div>
          <div className="md-render" dangerouslySetInnerHTML={{ __html: mdRender(item.content) }} />
        </>
      ) : null}

      {item.type === "secret" ? (
        <>
          <div className="section-title">密钥信息</div>
          <div className="field-row">
            <div>
              <div className="field-row-label">密钥值</div>
              <div className="field-row-value">
                <span className={revealed ? "mono" : "mask"}>{maskValue(item.value)}</span>
                <button className="icon-btn" title={revealed ? "隐藏" : "显示"} onClick={onToggleReveal}>
                  <Icon name="eye" size={15} />
                </button>
                <button className="icon-btn" title="复制密钥值" onClick={() => onCopy(item.value)}>
                  <Icon name="copy" size={15} />
                </button>
              </div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">用途</div>
              <div className="field-row-value">{item.purpose || "—"}</div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">过期时间</div>
              <div className="field-row-value">
                {item.expiresAt ? (
                  <>
                    {item.expiresAt} <span style={{ color: "var(--fg-2)" }}>（到期后不再自动注入）</span>
                  </>
                ) : (
                  "无过期时间"
                )}
              </div>
            </div>
          </div>
        </>
      ) : null}

      {item.type === "file" ? (
        <>
          <div className="section-title">文件信息</div>
          <div className="field-row">
            <div>
              <div className="field-row-label">备注</div>
              <div className="field-row-value">{item.note || "—"}</div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">大小</div>
              <div className="field-row-value">{item.size || "—"}</div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">类型</div>
              <div className="field-row-value">
                <span className="key-tag">{item.fileType || "—"}</span>
              </div>
            </div>
          </div>
          <div className="section-title">附件（加密存储 · 上限 50MB）</div>
          <div className="attachment-row">
            <Icon name="paperclip" size={14} /> {item.attachment || "—"}
            <span style={{ color: "var(--fg-2)" }}>{item.size}</span>
            <button
              className="icon-btn"
              title="下载（M0 为模拟）"
              onClick={() => toast("原型演示：附件下载为模拟行为", "ok")}
            >
              <Icon name="download" size={15} />
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}
