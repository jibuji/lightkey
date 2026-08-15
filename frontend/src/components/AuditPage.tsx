/**
 * 审计页（spec §6.6，M2 骨架）：事件流（时间/启动者/目标/命令摘要/结果 Tag）
 * + 结果筛选 chips；只读，无密钥值。数据走 IPC audit.list（mock）。
 */

import { useEffect, useState } from "react";
import type { LightKeyIpc } from "../ipc";
import type { AuditEvent, AuditResult } from "../types";

const RESULT_LABEL: Record<AuditResult, string> = {
  allowed: "允许",
  denied: "拒绝",
  timeout: "超时",
};

const FILTERS: { value: "all" | AuditResult; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "allowed", label: "允许" },
  { value: "denied", label: "拒绝" },
  { value: "timeout", label: "超时" },
];

export function AuditPage({ ipc }: { ipc: LightKeyIpc }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [afilter, setAfilter] = useState<"all" | AuditResult>("all");

  useEffect(() => {
    ipc.auditList().then(setEvents).catch(() => setEvents([]));
  }, [ipc]);

  const rows = (events ?? []).filter((a) => afilter === "all" || a.result === afilter);

  return (
    <div id="page-audit" className="page active">
      <div className="page-head">
        <h2 className="pane-title">审计日志</h2>
        <div className="filters">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              className={`chip${afilter === f.value ? " active" : ""}`}
              onClick={() => setAfilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      <p className="page-note">本地追加式存储 · 带 HMAC 防篡改 · 密钥值永不明文</p>
      <div className="audit-list">
        {events === null ? (
          <div className="empty">加载中…</div>
        ) : rows.length === 0 ? (
          <div className="empty">该筛选下暂无事件</div>
        ) : (
          rows.map((a, i) => (
            <div className="audit-row" key={i}>
              <span className="audit-ts">{a.ts}</span>
              <div className="audit-main">
                <div className="audit-cmd">
                  {a.starter} → {a.target}
                </div>
                <div className="audit-meta">
                  {a.dir} · {a.note} · HMAC 校验通过
                </div>
              </div>
              <span className={`result-tag result-${a.result}`}>{RESULT_LABEL[a.result]}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
