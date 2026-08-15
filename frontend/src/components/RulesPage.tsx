/**
 * 规则管理页（spec §6.4，M2 骨架）：规则列表 + 新建/删除（mock 数据驱动，
 * 走 IPC 接口层）；提示条「规则保存在加密库内，随库同步」。
 */

import { useCallback, useEffect, useState } from "react";
import type { LightKeyIpc } from "../ipc";
import type { AuthRule } from "../types";
import { Icon } from "./Icons";
import { Modal } from "./Modal";
import { useToast } from "./Toast";

interface RulesPageProps {
  ipc: LightKeyIpc;
}

export function RulesPage({ ipc }: RulesPageProps) {
  const { toast } = useToast();
  const [rules, setRules] = useState<AuthRule[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(() => {
    ipc.ruleList().then(setRules).catch(() => setRules([]));
  }, [ipc]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div id="page-rules" className="page active">
      <div className="page-head">
        <h2 className="pane-title">Agent 授权规则</h2>
        <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
          <Icon name="plus" size={14} strokeWidth={2.5} />
          新建规则
        </button>
      </div>
      <p className="page-note">规则保存在加密库内、按项目目录绑定，随库同步；写入只经 CLI 或本页。</p>
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
                  <div className="rule-cmd">{r.command}</div>
                  <div className="rule-dir">
                    <Icon name="folder" size={14} /> {r.projectDir}
                  </div>
                </div>
                <button
                  className="icon-btn"
                  title="删除规则"
                  style={{ color: "var(--fg-1)" }}
                  onClick={() => {
                    void ipc.ruleRemove(r.id).then(() => {
                      toast("规则已删除（已写审计）", "ok");
                      load();
                    });
                  }}
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
          ipc={ipc}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            toast("规则已创建（已写审计）", "ok");
            load();
          }}
        />
      ) : null}
    </div>
  );
}

function RuleCreateModal({
  ipc,
  onClose,
  onCreated,
}: {
  ipc: LightKeyIpc;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [dir, setDir] = useState("");
  const [cmd, setCmd] = useState("");
  const [keys, setKeys] = useState("");

  // M2 页骨架：本地 mock 直写（不占 IPC 方法），与原型行为一致
  const save = () => {
    const dirT = dir.trim();
    const cmdT = cmd.trim();
    const keysT = keys.split(",").map((s) => s.trim()).filter(Boolean);
    if (!dirT || !cmdT || !keysT.length) {
      toast("请完整填写规则", "warn");
      return;
    }
    const rule: AuthRule = {
      id: "r" + Math.random().toString(36).slice(2, 6),
      projectDir: dirT,
      command: cmdT,
      keys: keysT,
      created: new Date().toISOString().slice(0, 19) + "Z",
    };
    void ipc.ruleCreate(rule).then(onCreated);
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
          <span className="input-wrap">
            <input value={dir} placeholder="~/work/proj-a" onChange={(e) => setDir(e.target.value)} />
          </span>
        </label>
        <label className="field">
          <span className="field-label">命令</span>
          <span className="input-wrap">
            <input value={cmd} placeholder="npm publish" onChange={(e) => setCmd(e.target.value)} />
          </span>
        </label>
        <label className="field">
          <span className="field-label">注入的 key 名（逗号分隔）</span>
          <span className="input-wrap">
            <input
              value={keys}
              placeholder="NPM_TOKEN, NPM_CONFIG_..."
              onChange={(e) => setKeys(e.target.value)}
            />
          </span>
        </label>
      </div>
      <div className="modal-actions">
        <button className="btn btn-ghost" onClick={onClose}>
          取消
        </button>
        <button className="btn btn-primary" onClick={save}>
          创建
        </button>
      </div>
    </Modal>
  );
}
