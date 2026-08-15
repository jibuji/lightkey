/**
 * ItemModal —— 新建/编辑条目（spec §6.3）：
 * 类型选择（登录/笔记/密钥/文件 chips）→ 类型对应表单。
 * 笔记用宽版弹窗（modal-wide：min-width 720-800px、编辑框 min-height 400px）；
 * 文件附件单文件上限 50MB，超限拦截提示。
 */

import { useRef, useState } from "react";
import type { LightKeyIpc } from "../ipc";
import type { CustomField, Item, ItemDraft, ItemType } from "../types";
import { Icon } from "./Icons";
import { MdEditor } from "./MdEditor";
import { Modal } from "./Modal";
import { useToast } from "./Toast";

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

interface ItemModalProps {
  ipc: LightKeyIpc;
  /** null = 新建 */
  item: Item | null;
  onClose: () => void;
  /** 保存成功（父层负责 toast/重载） */
  onSaved: (item: Item) => void;
  /** CAS 冲突（父层接管覆盖/取消弹窗） */
  onConflict: (id: string, draft: ItemDraft) => void;
}

export function ItemModal({ ipc, item, onClose, onSaved, onConflict }: ItemModalProps) {
  const { toast } = useToast();

  const [type, setType] = useState<ItemType>(item?.type ?? "login");
  const [name, setName] = useState(item?.name ?? "");

  // login
  const [username, setUsername] = useState(item?.type === "login" ? item.username : "");
  const [password, setPassword] = useState(item?.type === "login" ? item.password : "");
  const [uri, setUri] = useState(item?.type === "login" ? item.uris.join(", ") : "");
  // login 自定义字段（spec §6.3 字段增删）
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
  /** M4：密码字段圆点遮罩 + 眼睛切换明文（spec §3 组件库） */
  const [showPwd, setShowPwd] = useState(false);

  const setCustomAt = (i: number, key: "name" | "value", v: string) =>
    setCustom((list) => list.map((f, idx) => (idx === i ? { ...f, [key]: v } : f)));
  const removeCustomAt = (i: number) => setCustom((list) => list.filter((_, idx) => idx !== i));
  const addCustom = () => setCustom((list) => [...list, { name: "", value: "", hidden: false }]);

  const pickFile = () => {
    const input = fileInputRef.current;
    if (!input) return;
    input.click();
  };

  const onFileChosen = () => {
    const input = fileInputRef.current;
    const f = input?.files?.[0];
    if (!f) return;
    if (f.size > FILE_LIMIT) {
      toast("超过 50MB 上限，已拒绝选择", "warn");
      input.value = "";
      setSelFile(null);
      return;
    }
    const picked: SelectedFile = {
      name: f.name,
      size: fmtSize(f.size),
      fileType: f.type || "application/octet-stream",
    };
    setSelFile(picked);
    toast(`已选择附件 ${f.name}（${picked.size}）`, "ok");
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
        const updated = await ipc.update(item.id, draft, { expectedRevision: item.revision });
        onSaved(updated);
      } else {
        const created = await ipc.create(draft);
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
                <button type="button" className="btn btn-ghost btn-sm" onClick={pickFile}>
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
