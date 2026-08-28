/**
 * ui-rules 插件（M2；spec §6.4 / authorization-gate.md §4）。
 *
 * 规则列表（项目目录 + 命令 + key 名 Tag 集合 + 删除）；新建：项目目录
 * 选择器（tauri 原生目录对话框 + 手动输入） + 命令 + **key 名多选**（仅
 * 显示保险库内已有密钥条目名——「已授权 key 名」，authorization-gate.md
 * §2 最小授权）。提示条「规则保存在加密库内，随库同步」。
 *
 * 写入唯一合法路径之二（CLI `lk rule add` + 本页）；变更写审计（守护进程
 * 侧）；`item.changed(kind="rule")` 推送 → 列表刷新（跨端同步可见）。
 */

import { useCallback, useEffect, useState, type ComponentType } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import type { AuthRule, ItemSummary } from "../types";
import { Icon } from "../components/Icons";
import { Modal } from "../components/Modal";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";
import { formatProjectDir } from "../utils/projectDir";

/** 规则页本体（content 槽位，page=rules）。 */
export function RulesPage({ ctx }: { ctx: Context }) {
  const toast = ctx.toast;
  const [rules, setRules] = useState<AuthRule[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(() => {
    ctx.ipc.ruleList().then(setRules).catch(() => setRules([]));
  }, [ctx]);

  useEffect(() => {
    load();
  }, [load]);

  // 跨端同步：规则变更（含 CLI 侧）→ item.changed(kind="rule") → 刷新
  useEffect(() => {
    const off = ctx.on("item.changed", (p) => {
      if (p.type === "rule") load();
    });
    return () => {
      off();
    };
  }, [ctx, load]);

  const doRemove = useCallback(
    (id: string) => {
      void ctx.ipc.ruleRemove(id).then(() => {
        toast.show("规则已删除（已写审计）");
        load();
      });
    },
    [ctx, load, toast],
  );

  return (
    <div id="page-rules" className="page active">
      <div className="page-head">
        <h2 className="pane-title">Agent 授权规则</h2>
        <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
          <Icon name="plus" size={14} strokeWidth={2.5} />
          新建规则
        </button>
      </div>
      <p className="page-note">
        <Icon name="lock" size={13} /> 规则保存在加密库内、按项目目录绑定，随库同步；写入只经
        CLI（lk rule add）或本页。
      </p>
      <div className="rule-list">
        {rules === null ? (
          <div className="empty">加载中…</div>
        ) : rules.length === 0 ? (
          <div className="empty">还没有规则 · 一切请求默认拒绝</div>
        ) : (
          rules.map((r) => (
            <div className="rule-card" key={r.id}>
              <div className="rule-head">
                <div>
                  <div className="rule-cmd">
                    {/* M2.9 值披露：read 规则无命令绑定，按 capability 区分展示 */}
                    {r.capability === "read" ? "读值规则（按条目名授权读取）" : r.command}
                    {r.capability === "read" ? (
                      <span
                        className="key-tag"
                        style={{ marginLeft: 8, verticalAlign: "middle" }}
                      >
                        read
                      </span>
                    ) : null}
                  </div>
                  <div className="rule-dir">
                    <Icon name="folder" size={14} /> {formatProjectDir(r.projectDir)}
                    <span style={{ color: "var(--fg-2)" }}>· {r.name}</span>
                  </div>
                </div>
                <button
                  className="icon-btn"
                  title="删除规则"
                  style={{ color: "var(--fg-1)" }}
                  onClick={() => doRemove(r.id)}
                >
                  <Icon name="trash" size={15} />
                </button>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
                {r.keys.map((k) => (
                  <span className="key-tag" key={k}>
                    {k}
                  </span>
                ))}
              </div>
            </div>
          ))
        )}
      </div>

      {showCreate ? (
        <RuleCreateModal
          ctx={ctx}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            toast.show("规则已创建（已写审计）");
            load();
          }}
        />
      ) : null}
    </div>
  );
}

/** 新建规则弹窗：目录选择器 + 命令 + key 名多选（仅已授权 key 名）。 */
function RuleCreateModal({
  ctx,
  onClose,
  onCreated,
}: {
  ctx: Context;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [dir, setDir] = useState("");
  const [name, setName] = useState("");
  const [cmd, setCmd] = useState("");
  const [keys, setKeys] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [secretNames, setSecretNames] = useState<string[]>([]);

  // key 名多选数据源：保险库内 secret 条目名（最小授权可见面）；
  // 仅保留合法环境变量名（守护进程侧同规则校验：[A-Za-z_][A-Za-z0-9_]*）
  useEffect(() => {
    let alive = true;
    void ctx.ipc
      .list()
      .then((items: ItemSummary[]) => {
        if (!alive) return;
        setSecretNames(
          items
            .filter((it) => it.type === "secret")
            .map((it) => it.name)
            .filter((n) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(n)),
        );
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [ctx]);

  const toggleKey = useCallback(
    (k: string) =>
      setKeys((prev) => (prev.includes(k) ? prev.filter((x) => x !== k) : [...prev, k])),
    [],
  );

  const pickDir = useCallback(async () => {
    const picked = await ctx.ipc.pickDir();
    if (picked) {
      setDir(picked);
      setError("");
    }
  }, [ctx]);

  const save = async () => {
    if (busy) return;
    const dirT = dir.trim();
    const nameT = name.trim();
    const cmdT = cmd.trim();
    if (!dirT || !nameT || !cmdT) {
      setError("请填写项目目录、规则名与命令");
      return;
    }
    if (!keys.length) {
      setError("请至少选择一个注入的 key 名");
      return;
    }
    setError("");
    setBusy(true);
    try {
      await ctx.ipc.ruleAdd({ projectDir: dirT, name: nameT, command: cmdT, keys });
      onCreated();
    } catch (e) {
      const detail = (e as { message?: string })?.message ?? "";
      setError(detail.includes("invalid params") ? "规则校验失败（目录须为存在的绝对路径）" : "保存失败，请重试");
      setBusy(false);
    }
  };

  return (
    <Modal
      title="新建授权规则"
      desc="规则入库加密 · 按项目目录绑定 · 仅授权最小 key 名集合"
      onClose={onClose}
    >
      <div className="form-grid">
        <label className="field">
          <span className="field-label">项目目录</span>
          <span className="input-wrap" style={{ display: "flex", gap: 8 }}>
            <input
              value={dir}
              placeholder="~/work/proj-a（绝对路径）"
              onChange={(e) => setDir(e.target.value)}
              style={{ flex: 1 }}
            />
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => void pickDir()}>
              选择…
            </button>
          </span>
          <span className="limit-hint">桌面环境可用原生目录选择器；路径将规范化后入库</span>
        </label>
        <label className="field">
          <span className="field-label">规则名</span>
          <span className="input-wrap">
            <input value={name} placeholder="例如：发布 npm 包" onChange={(e) => setName(e.target.value)} />
          </span>
        </label>
        <label className="field">
          <span className="field-label">命令（可 glob）</span>
          <span className="input-wrap">
            <input
              value={cmd}
              placeholder="npm publish 或 npm *"
              onChange={(e) => setCmd(e.target.value)}
            />
          </span>
        </label>
        <div className="field">
          <span className="field-label">注入的 key 名（多选 · 仅显示库内已有密钥）</span>
          {secretNames.length === 0 ? (
            <span className="limit-hint">保险库还没有密钥条目——先在「条目」页新建 secret 类型条目</span>
          ) : (
            <div className="key-options">
              {secretNames.map((k) => (
                <label key={k} className={`key-option${keys.includes(k) ? " selected" : ""}`}>
                  <input type="checkbox" checked={keys.includes(k)} onChange={() => toggleKey(k)} />
                  <span className="key-tag">{k}</span>
                </label>
              ))}
            </div>
          )}
        </div>
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
          创建
        </button>
      </div>
    </Modal>
  );
}

/** 插件工厂：注册 content 槽位组件（page=rules）。 */
export const uiRules: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-rules",
      slot: config.slot ?? "content",
      order: config.order ?? 20,
      component: (() => {
        const Comp = () => <RulesPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "rules" },
    });
  },
  {
    inject: ["slots", "ipc", "toast"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);
