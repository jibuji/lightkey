/**
 * ui-vault 插件（M2；spec §5/§6.2/§6.3）。
 *
 * 条目列表/搜索/详情/编辑：
 * - 筛选 chips（全部/登录/笔记/密钥/文件）+ 搜索（300ms 防抖、命中高亮；
 *   **搜索不涉及密钥明文值与笔记全文**——haystack = 名称/账号/域名/用途/备注）；
 * - 详情按类型分组；密码字段遮罩 + 眼睛 + 复制（`clipboard.copied` → Toast
 *   「已复制，30 秒后自动清除」+ 剪贴板 30s 清除）；
 * - 编辑走 CAS：冲突提示「条目已被其他设备修改」+ 覆盖/取消；
 * - `item.changed` 三方响应之一：ui 刷新（Rust 通知 → 帧 → 本层事件）。
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ComponentType } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import { mdRender, mdSnippet } from "../markdown/highlight";
import type { CustomField, Item, ItemDraft, ItemType } from "../types";
import { Icon, type IconName } from "../components/Icons";
import { Modal } from "../components/Modal";
import { MdEditor } from "../components/MdEditor";
import {
  CopyButton,
  Highlighted,
  PasswordField,
  useDebounced,
} from "../components/atoms";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";

export type FilterValue = "all" | ItemType;

const FILTERS: { value: FilterValue; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "login", label: "登录" },
  { value: "note", label: "笔记" },
  { value: "secret", label: "密钥" },
  { value: "file", label: "文件" },
];

const TYPE_META: Record<ItemType, { icon: IconName; label: string; sub: (it: Item) => string }> = {
  login: { icon: "globe", label: "登录", sub: (it) => (it.type === "login" ? it.username : "—") },
  note: { icon: "fileText", label: "笔记", sub: (it) => (it.type === "note" ? mdSnippet(it.content) : "—") },
  secret: {
    icon: "key",
    label: "密钥",
    // 副行 = 用途或脱敏尾 4 位（spec §6.2：不涉及明文值）
    sub: (it) => (it.type === "secret" ? it.purpose || `••••${it.value.slice(-4)}` : "—"),
  },
  file: {
    icon: "file",
    label: "文件",
    sub: (it) => (it.type === "file" ? [it.size, it.fileType].filter(Boolean).join(" · ") || "—" : "—"),
  },
};

/** 条目页本体（content 槽位，page=vault）。 */
export function VaultPage({ ctx }: { ctx: Context }) {
  const toast = ctx.toast;

  const [filter, setFilter] = useState<FilterValue>("all");
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim().toLowerCase(), 300);

  const [items, setItems] = useState<Item[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const [modal, setModal] = useState<{ mode: "create" } | { mode: "edit"; id: string } | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [conflict, setConflict] = useState<{ id: string; draft: ItemDraft } | null>(null);

  /* ---------- 数据加载 + 事件订阅 ---------- */
  const reload = useCallback(() => setReloadTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    setItems(null);
    ctx.ipc
      .list()
      .then((summaries) => Promise.all(summaries.map((s) => ctx.ipc.get(s.id))))
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
  }, [ctx, reloadTick]);

  // 三方响应之一：Rust 事件 → IPC 通知 → 本层事件 → ui 刷新
  useEffect(() => {
    const off = ctx.on("item.changed", () => reload());
    return () => {
      off();
    };
  }, [ctx, reload]);
  // topbar 搜索（300ms 防抖在搜索组件侧；此处直接消费）
  useEffect(() => {
    const off = ctx.on("vault.search", (p) => setSearch(p.query));
    return () => {
      off();
    };
  }, [ctx]);
  // topbar 搜索回车 → 空态「未找到，按回车新建」引导
  useEffect(() => {
    const off = ctx.on("vault.search-enter", () => setModal({ mode: "create" }));
    return () => {
      off();
    };
  }, [ctx]);

  /* ---------- 列表 ---------- */
  const filtered = useMemo(() => {
    if (!items) return null;
    return items.filter((it) => {
      if (filter !== "all" && it.type !== filter) return false;
      if (!q) return true;
      // spec §6.2：名称/用户名/域名/备注；**不含密钥明文值与笔记全文**
      const hay = [
        it.name,
        it.type === "login" ? it.username : "",
        it.type === "login" ? it.uris.join(" ") : "",
        it.type === "secret" ? it.purpose : "",
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

  const selectItem = useCallback((id: string) => {
    setSelectedId(id);
    setRevealed(false);
    // 堆叠布局（≤900px）下详情在列表下方：滚入视口（served 原型行为）
    if (window.innerWidth <= 900) {
      requestAnimationFrame(() => {
        document.getElementById("detail")?.scrollIntoView({ block: "start" });
      });
    }
  }, []);

  /* ---------- 保存 / CAS ---------- */
  const handleSaved = useCallback(
    (item: Item) => {
      setModal(null);
      toast.show(
        modal?.mode === "edit" ? "条目已保存（revisionDate 已更新）" : "条目已创建",
      );
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
      await ctx.ipc.update(conflict.id, conflict.draft);
      setConflict(null);
      toast.show("已覆盖其他设备的修改");
      reload();
    } catch {
      toast.show("保存失败，请重试");
    }
  }, [conflict, ctx, reload, toast]);

  /* ---------- 删除 ---------- */
  const doDelete = useCallback(async () => {
    if (!deleteId) return;
    try {
      await ctx.ipc.remove(deleteId);
      setDeleteId(null);
      setSelectedId((prev) => (prev === deleteId ? null : prev));
      toast.show("已软删除 · 30 天后硬删");
      reload();
    } catch {
      toast.show("删除失败，请重试");
    }
  }, [deleteId, ctx, reload, toast]);

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
            ctx={ctx}
            item={selected}
            revealed={revealed}
            onToggleReveal={() => setRevealed((v) => !v)}
            onEdit={() => setModal({ mode: "edit", id: selected.id })}
            onDelete={() => setDeleteId(selected.id)}
          />
        ) : (
          <div className="empty">选择左侧条目查看详情</div>
        )}
      </div>

      {/* 新建 / 编辑 */}
      {modal ? (
        <ItemForm
          ctx={ctx}
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

function DetailCard({
  ctx,
  item,
  revealed,
  onToggleReveal,
  onEdit,
  onDelete,
}: {
  ctx: Context;
  item: Item;
  revealed: boolean;
  onToggleReveal: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const m = TYPE_META[item.type];

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
                <CopyButton ctx={ctx} text={item.username} source={item.id} field="username" title="复制用户名" />
              </div>
            </div>
          </div>
          <div className="field-row">
            <div>
              <div className="field-row-label">密码</div>
              <PasswordField
                ctx={ctx}
                value={item.password}
                revealed={revealed}
                onToggleReveal={onToggleReveal}
                source={item.id}
                field="password"
              />
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
                        <CopyButton ctx={ctx} text={c.value} source={item.id} field={c.name} title="复制" />
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
              <PasswordField
                ctx={ctx}
                value={item.value}
                revealed={revealed}
                onToggleReveal={onToggleReveal}
                source={item.id}
                field="value"
              />
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
              onClick={() => ctx.toast.show("原型演示：附件下载为模拟行为")}
            >
              <Icon name="download" size={15} />
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}

/* ================= 新建 / 编辑表单 ================= */

const TYPE_ORDER: ItemType[] = ["login", "note", "secret", "file"];
const TYPE_LABELS: Record<ItemType, string> = { login: "登录", note: "笔记", secret: "密钥", file: "文件" };
const FILE_LIMIT = 50 * 1024 * 1024; // 50MB

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface SelectedFile {
  name: string;
  size: string;
  fileType: string;
}

function ItemForm({
  ctx,
  item,
  onClose,
  onSaved,
  onConflict,
}: {
  ctx: Context;
  /** null = 新建 */
  item: Item | null;
  onClose: () => void;
  onSaved: (item: Item) => void;
  onConflict: (id: string, draft: ItemDraft) => void;
}) {
  const toast = ctx.toast;

  const [type, setType] = useState<ItemType>(item?.type ?? "login");
  const [name, setName] = useState(item?.name ?? "");

  // login
  const [username, setUsername] = useState(item?.type === "login" ? item.username : "");
  const [password, setPassword] = useState(item?.type === "login" ? item.password : "");
  const [uri, setUri] = useState(item?.type === "login" ? item.uris.join(", ") : "");
  const [custom, setCustom] = useState<CustomField[]>(
    item?.type === "login" ? item.custom.map((c) => ({ ...c })) : [],
  );

  // note
  const [content, setContent] = useState(item?.type === "note" ? item.content : "");

  // secret
  const [value, setValue] = useState(item?.type === "secret" ? item.value : "");
  const [purpose, setPurpose] = useState(item?.type === "secret" ? item.purpose : "");
  const [expiresAt, setExpiresAt] = useState(item?.type === "secret" ? item.expiresAt : "");

  // file
  const [note, setNote] = useState(item?.type === "file" ? item.note : "");
  const [selFile, setSelFile] = useState<SelectedFile | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showPwd, setShowPwd] = useState(false);

  const setCustomAt = (i: number, key: "name" | "value", v: string) =>
    setCustom((list) => list.map((f, idx) => (idx === i ? { ...f, [key]: v } : f)));
  const removeCustomAt = (i: number) => setCustom((list) => list.filter((_, idx) => idx !== i));
  const addCustom = () => setCustom((list) => [...list, { name: "", value: "", hidden: false }]);

  const onFileChosen = () => {
    const input = fileInputRef.current;
    const f = input?.files?.[0];
    if (!f) return;
    if (f.size > FILE_LIMIT) {
      toast.show("超过 50MB 上限，已拒绝选择");
      input.value = "";
      setSelFile(null);
      return;
    }
    setSelFile({ name: f.name, size: fmtSize(f.size), fileType: f.type || "application/octet-stream" });
    toast.show(`已选择附件 ${f.name}`);
  };

  const save = async () => {
    if (busy) return;
    const trimmed = name.trim();
    if (!trimmed) {
      setError("请填写名称");
      return;
    }
    setError("");
    const base = { name: trimmed };

    let draft: ItemDraft;
    if (type === "login") {
      const u = username.trim();
      const p = password.trim();
      if (!u || !p) {
        setError("请填写用户名与密码");
        return;
      }
      draft = {
        ...base,
        type: "login",
        username: u,
        password: p,
        uris: uri.split(",").map((s) => s.trim()).filter(Boolean),
        // 空行（名称与值皆空）不入库；hidden 标志编辑时保留
        custom: custom
          .map((f) => ({ ...f, name: f.name.trim(), value: f.value.trim() }))
          .filter((f) => f.name || f.value),
      } as ItemDraft;
    } else if (type === "note") {
      if (!content.trim()) {
        setError("请填写笔记内容");
        return;
      }
      draft = { ...base, type: "note", content } as ItemDraft;
    } else if (type === "secret") {
      if (!value.trim()) {
        setError("请填写密钥值");
        return;
      }
      draft = {
        ...base,
        type: "secret",
        value: value.trim(),
        purpose: purpose.trim(),
        expiresAt: expiresAt || "",
      } as ItemDraft;
    } else {
      const existing = item?.type === "file" ? item : null;
      if (!selFile && !existing) {
        setError("请选择附件文件（上限 50MB）");
        return;
      }
      draft = {
        ...base,
        type: "file",
        note: note.trim(),
        size: selFile ? selFile.size : existing!.size,
        fileType: selFile ? selFile.fileType : existing!.fileType,
        attachment: selFile ? selFile.name : existing!.attachment,
      } as ItemDraft;
    }

    setBusy(true);
    try {
      if (item) {
        const updated = await ctx.ipc.update(item.id, draft, { expectedRevision: item.revision });
        onSaved(updated);
      } else {
        const created = await ctx.ipc.create(draft);
        onSaved(created);
      }
    } catch (e) {
      setBusy(false);
      if (e instanceof Error && e.name === "ConflictError") {
        if (item) onConflict(item.id, draft);
        else setError("保存失败，请重试");
      } else {
        setError("保存失败，请重试");
      }
    }
  };

  const fileInfo = selFile
    ? `${selFile.name} · ${selFile.size}`
    : item?.type === "file"
      ? `${item.attachment} · ${item.size}`
      : "未选择文件";

  return (
    <Modal
      title={item ? "编辑条目" : "新建条目"}
      desc="保存后写入加密库 · 乐观并发（CAS）"
      wide={type === "note"}
      onClose={onClose}
    >
      <div className="form-grid">
        <label className="field">
          <span className="field-label">名称</span>
          <span className="input-wrap">
            <input value={name} placeholder="例如：GitHub" onChange={(e) => setName(e.target.value)} />
          </span>
        </label>

        <div className="field">
          <span className="field-label">类型</span>
          <div className="filters" style={{ marginBottom: 0 }}>
            {TYPE_ORDER.map((t) => (
              <button
                key={t}
                type="button"
                className={`chip${type === t ? " active" : ""}`}
                aria-label={`类型：${TYPE_LABELS[t]}`}
                title={`类型：${TYPE_LABELS[t]}`}
                onClick={() => setType(t)}
              >
                {TYPE_LABELS[t]}
              </button>
            ))}
          </div>
        </div>

        {type === "login" ? (
          <>
            <label className="field">
              <span className="field-label">用户名</span>
              <span className="input-wrap">
                <input value={username} onChange={(e) => setUsername(e.target.value)} />
              </span>
            </label>
            <label className="field">
              <span className="field-label">密码</span>
              <span className="input-wrap">
                <input
                  type={showPwd ? "text" : "password"}
                  className="mono has-affix"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  className="icon-btn input-affix"
                  title={showPwd ? "隐藏密码" : "显示密码"}
                  aria-label={showPwd ? "隐藏密码" : "显示密码"}
                  onClick={() => setShowPwd((v) => !v)}
                >
                  <Icon name="eye" size={15} />
                </button>
              </span>
            </label>
            <label className="field">
              <span className="field-label">站点（URI）</span>
              <span className="input-wrap">
                <input value={uri} placeholder="example.com" onChange={(e) => setUri(e.target.value)} />
              </span>
            </label>
            <div className="field">
              <span className="field-label">自定义字段（可选）</span>
              {custom.map((f, i) => (
                <div className="custom-field-row" key={i}>
                  <input
                    className="custom-field-name"
                    value={f.name}
                    placeholder="字段名"
                    aria-label={`自定义字段 ${i + 1} 名称`}
                    onChange={(e) => setCustomAt(i, "name", e.target.value)}
                  />
                  <input
                    value={f.value}
                    placeholder="值"
                    aria-label={`自定义字段 ${i + 1} 值`}
                    onChange={(e) => setCustomAt(i, "value", e.target.value)}
                  />
                  <button
                    type="button"
                    className="icon-btn"
                    title="删除字段"
                    aria-label={`删除自定义字段 ${i + 1}`}
                    onClick={() => removeCustomAt(i)}
                  >
                    <Icon name="trash" size={15} />
                  </button>
                </div>
              ))}
              <div>
                <button type="button" className="btn btn-ghost btn-sm" onClick={addCustom}>
                  <Icon name="plus" size={14} strokeWidth={2.5} />
                  添加字段
                </button>
              </div>
            </div>
          </>
        ) : null}

        {type === "note" ? (
          <label className="field">
            <span className="field-label">Markdown 内容（语法高亮 · 不做预览）</span>
            <MdEditor value={content} onChange={setContent} placeholder="# 标题&#10;&#10;正文…" />
          </label>
        ) : null}

        {type === "secret" ? (
          <>
            <label className="field">
              <span className="field-label">密钥值</span>
              <span className="input-wrap">
                <input
                  value={value}
                  placeholder="例如：npm_demo_token_0000"
                  onChange={(e) => setValue(e.target.value)}
                />
              </span>
            </label>
            <label className="field">
              <span className="field-label">用途</span>
              <span className="input-wrap">
                <input
                  value={purpose}
                  placeholder="例如：发布 npm 包（仅白名单命令注入）"
                  onChange={(e) => setPurpose(e.target.value)}
                />
              </span>
            </label>
            <label className="field">
              <span className="field-label">过期时间（可选）</span>
              <span className="input-wrap">
                <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
              </span>
            </label>
          </>
        ) : null}

        {type === "file" ? (
          <>
            <label className="field">
              <span className="field-label">附件（加密存储）</span>
              <span className="attach-box">
                <input
                  ref={fileInputRef}
                  type="file"
                  id="f-file"
                  style={{ display: "none" }}
                  onChange={onFileChosen}
                />
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => fileInputRef.current?.click()}
                >
                  选择文件…
                </button>
                <span className="attach-info">{fileInfo}</span>
              </span>
              <span className="limit-hint">单文件上限 50MB · 文件本体独立加密，存储端不可见</span>
            </label>
            <label className="field">
              <span className="field-label">备注</span>
              <span className="input-wrap">
                <input value={note} placeholder="可选说明" onChange={(e) => setNote(e.target.value)} />
              </span>
            </label>
          </>
        ) : null}

        {error ? (
          <p className="field-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>

      <div className="modal-actions">
        <button className="btn btn-ghost" onClick={onClose}>
          取消
        </button>
        <button className="btn btn-primary" disabled={busy} onClick={() => void save()}>
          <Icon name="check" size={14} />
          保存
        </button>
      </div>
    </Modal>
  );
}

/** 插件工厂：注册 content 槽位组件（page=vault）。 */
export const uiVault: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-vault",
      slot: config.slot ?? "content",
      order: config.order ?? 10,
      component: (() => {
        const Comp = () => <VaultPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "vault" },
    });
  },
  {
    inject: ["slots", "ipc", "toast", "session"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);
