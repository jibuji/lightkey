/**
 * 强交互原子组件（`docs/plugin-architecture.md` §7.2：手写 React、注册进
 * 组件注册表、**不拆内部结构**；数据驱动的最小单位 = 组件整体）。
 *
 * 清单（design/spec.md §3）：
 * - [`PasswordField`]：密码遮罩 + 眼睛切换 + 复制（复制 → `clipboard.copied`
 *   事件 → Toast「已复制，30s 后清除」+ 剪贴板 30s 自动清除）；
 * - [`CopyButton`]：复制图标按钮（同 30s 清除语义）；
 * - [`CountdownRing`]：倒计时环形（审批弹窗 30s 默认拒绝，spec §6.5）。
 */

import { useEffect, useRef, useState, type ReactNode } from "react";
import type { Context } from "@cordisjs/core";
import { CLIPBOARD_CLEAR_MS } from "../events";
import { Icon } from "./Icons";

/**
 * 复制 + 30s 自动清除（D12 / spec §6.3：`clipboard.copied` → Toast +
 * 30s 清除计时；clearedAt = 发送方给出的清除时刻）。
 */
export function copyWithClear(
  ctx: Context,
  text: string,
  source: string,
  field: string,
): void {
  const clearedAt = new Date(Date.now() + CLIPBOARD_CLEAR_MS).toISOString();
  ctx.emit("clipboard.copied", { source, field, clearedAt });
  if (navigator.clipboard?.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        // 30 秒后自动清除剪贴板（产品承诺行为，browser-fill.md 同款）
        setTimeout(() => {
          navigator.clipboard.writeText("").catch(() => undefined);
        }, CLIPBOARD_CLEAR_MS);
      })
      .catch(() => undefined);
  }
}

/** 复制图标按钮（原子组件：图标 + 复制 + 30s 清除）。 */
export function CopyButton({
  ctx,
  text,
  source,
  field,
  title = "复制",
}: {
  ctx: Context;
  text: string;
  source: string;
  field: string;
  title?: string;
}) {
  return (
    <button
      type="button"
      className="icon-btn"
      title={title}
      aria-label={title}
      onClick={() => copyWithClear(ctx, text, source, field)}
    >
      <Icon name="copy" size={15} />
    </button>
  );
}

/**
 * 密码字段（原子组件：遮罩圆点 + 眼睛切换 + 复制；读态/编辑态通用）。
 * `revealed` 由外部持有（详情页全局显隐），组件只渲染。
 */
export function PasswordField({
  ctx,
  value,
  revealed,
  onToggleReveal,
  source,
  field,
  masked = "••••••••••••",
}: {
  ctx: Context;
  value: string;
  revealed: boolean;
  onToggleReveal: () => void;
  source: string;
  field: string;
  /** 遮罩形态（缺省 12 圆点）。 */
  masked?: string;
}) {
  return (
    <span className="field-row-value">
      <span className={revealed ? "mono" : "mask"}>{revealed ? value : masked}</span>
      <button
        type="button"
        className="icon-btn"
        title={revealed ? "隐藏" : "显示"}
        aria-label={revealed ? "隐藏" : "显示"}
        onClick={onToggleReveal}
      >
        <Icon name="eye" size={15} />
      </button>
      <CopyButton ctx={ctx} text={value} source={source} field={field} title="复制" />
    </span>
  );
}

/** 倒计时环形（审批弹窗：剩余秒数 + SVG 圆环进度；超时默认拒绝）。 */
export function CountdownRing({ total, remain }: { total: number; remain: number }) {
  const R = 28;
  const C = 2 * Math.PI * R;
  const ratio = Math.max(0, Math.min(1, remain / total));
  return (
    <span className="ring-wrap" aria-label={`剩余 ${remain} 秒`}>
      <svg width="44" height="44" viewBox="0 0 44 44" aria-hidden="true">
        <circle cx="22" cy="22" r={R} fill="none" stroke="var(--bg-3)" strokeWidth="3" />
        <circle
          cx="22"
          cy="22"
          r={R}
          fill="none"
          stroke={remain <= 5 ? "var(--danger)" : "var(--warning)"}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={(C * (1 - ratio)).toFixed(1)}
          transform="rotate(-90 22 22)"
        />
      </svg>
      <span className="ring-num">{remain}</span>
    </span>
  );
}

/** 原子组件注册表（插件引用入口；组件本体不拆内部结构，§7.2）。 */
export const ATOM_REGISTRY: Record<string, ReactNode> = {
  "password-field": "PasswordField",
  "copy-button": "CopyButton",
  "countdown-ring": "CountdownRing",
  "markdown-editor": "MdEditor",
};

/** 300ms 防抖（搜索等）。 */
export function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

/** 搜索命中高亮（spec §6.2；不涉及明文值）。 */
export function Highlighted({ text, q }: { text: string; q: string }) {
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

/** 输入聚焦到末尾（编辑弹窗打开时）。 */
export function useFocusEnd(ref: React.RefObject<HTMLInputElement | null>) {
  const first = useRef(true);
  useEffect(() => {
    if (!first.current || !ref.current) return;
    first.current = false;
    const el = ref.current;
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
  }, [ref]);
}
