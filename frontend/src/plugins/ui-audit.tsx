/**
 * ui-audit 插件（M2；spec §6.6 / audit.md）。
 *
 * 事件流只读：时间/启动者/目标/命令摘要/结果 Tag/来源通道；结果筛选
 * chips；**无密钥值**（审计事件含命令摘要，敏感参数守护进程侧已脱敏）。
 * 本地追加式 + HMAC 防篡改（`audit.verify` 由 CLI 提供，本页只读展示）。
 */

import { useCallback, useEffect, useState, type ComponentType } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import type { AuditChannel, AuditEvent, AuditResult } from "../types";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";

const RESULT_LABEL: Record<AuditResult, string> = {
  allowed: "允许",
  denied: "拒绝",
  timeout: "超时",
};

const CHANNEL_LABEL: Record<AuditChannel, string> = {
  cli: "CLI",
  desktop: "桌面",
  approval: "审批",
  "wsl-bridge": "WSL 桥接",
};

const FILTERS: { value: "all" | AuditResult; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "allowed", label: "允许" },
  { value: "denied", label: "拒绝" },
  { value: "timeout", label: "超时" },
];

/** 审计页本体（content 槽位，page=audit）。 */
export function AuditPage({ ctx }: { ctx: Context }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [afilter, setAfilter] = useState<"all" | AuditResult>("all");

  const load = useCallback(() => {
    ctx.ipc.auditList().then(setEvents).catch(() => setEvents([]));
  }, [ctx]);

  useEffect(() => {
    load();
  }, [load]);

  // 任何写入（条目/规则/审批）都会追加审计 → 顺带刷新
  useEffect(() => {
    const off = ctx.on("item.changed", () => {
      load();
    });
    return () => {
      off();
    };
  }, [ctx, load]);

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
          rows.map((a) => (
            <div className="audit-row" key={a.eventId}>
              <span className="audit-ts">{a.ts.slice(0, 19).replace("T", " ")}</span>
              <div className="audit-main">
                <div className="audit-cmd">
                  {a.starter} → {a.target}
                </div>
                <div className="audit-meta">
                  {a.command} · 来源 {CHANNEL_LABEL[a.channel]}
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

/** 插件工厂：注册 content 槽位组件（page=audit）。 */
export const uiAudit: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-audit",
      slot: config.slot ?? "content",
      order: config.order ?? 40,
      component: (() => {
        const Comp = () => <AuditPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "audit" },
    });
  },
  {
    inject: ["slots", "ipc"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);
