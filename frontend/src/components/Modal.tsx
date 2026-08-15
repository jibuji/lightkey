/**
 * Modal —— 通用弹窗（spec §3：bg-1、--r-lg、shadow-2、遮罩、Esc 关闭）。
 * wide 变体 = 笔记 Markdown 编辑宽版（min-width 720-800px，编辑框 min-height 400px）。
 */

import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

interface ModalProps {
  title: string;
  desc?: string;
  /** 宽版（笔记类型弹窗） */
  wide?: boolean;
  onClose: () => void;
  children: ReactNode;
  /** 挂载后回调（焦点管理用） */
  onMount?: (root: HTMLElement) => void;
}

export function Modal({ title, desc, wide, onClose, children, onMount }: ModalProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    if (ref.current) onMount?.(ref.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return createPortal(
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div ref={ref} className={`modal${wide ? " modal-wide" : ""}`} role="dialog" aria-modal="true">
        <h3 className="modal-title">{title}</h3>
        {desc ? <p className="modal-desc">{desc}</p> : null}
        {children}
      </div>
    </div>,
    document.body,
  );
}
