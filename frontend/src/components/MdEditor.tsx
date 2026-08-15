/**
 * MdEditor —— 轻量 Markdown 编辑（语法高亮层 + 透明文本 textarea 叠加，
 * 照搬 served 原型 .md-hl/.md-editor 机制）：编辑区内语法高亮，不做预览、
 * 不做 WYSIWYG（spec §4 笔记定义）。
 */

import { useEffect, useRef } from "react";
import { mdHighlight } from "../markdown/highlight";

interface MdEditorProps {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}

export function MdEditor({ value, onChange, placeholder }: MdEditorProps) {
  const taRef = useRef<HTMLTextAreaElement>(null);
  const hlRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const ta = taRef.current;
    const hl = hlRef.current;
    if (!ta || !hl) return;
    const sync = () => {
      hl.innerHTML = mdHighlight(ta.value);
      hl.scrollTop = ta.scrollTop;
      hl.scrollLeft = ta.scrollLeft;
    };
    const onScroll = () => {
      hl.scrollTop = ta.scrollTop;
      hl.scrollLeft = ta.scrollLeft;
    };
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => {
      if (ta.parentElement) ta.parentElement.style.height = `${ta.offsetHeight}px`;
    }) : null;
    ta.addEventListener("input", sync);
    ta.addEventListener("scroll", onScroll);
    ro?.observe(ta);
    sync();
    return () => {
      ta.removeEventListener("input", sync);
      ta.removeEventListener("scroll", onScroll);
      ro?.disconnect();
    };
  }, []);

  return (
    <span className="md-wrap">
      <span ref={hlRef} className="md-hl" aria-hidden="true" />
      <textarea
        ref={taRef}
        className="md-editor"
        spellCheck={false}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </span>
  );
}
