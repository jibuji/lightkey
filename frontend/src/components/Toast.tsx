/**
 * Toast —— 全局提示（spec §3：右下、bg-1、shadow-2）。
 * 「已复制，30 秒后自动清除」类提示经 toast() 触发。
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export type ToastKind = "ok" | "warn";

interface ToastItem {
  id: number;
  msg: string;
  kind: ToastKind;
}

interface ToastApi {
  toast: (msg: string, kind?: ToastKind) => void;
}

const ToastContext = createContext<ToastApi>({ toast: () => undefined });

export function useToast(): ToastApi {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const toast = useCallback((msg: string, kind: ToastKind = "ok") => {
    const id = nextId.current++;
    setItems((prev) => [...prev, { id, msg, kind }]);
    // 原型节奏：2400ms 淡出，2800ms 移除
    setTimeout(() => {
      setItems((prev) => prev.map((t) => (t.id === id ? { ...t, leaving: true } : t)));
    }, 2400);
    setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 2800);
  }, []);

  const api = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-root" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className="toast">
            <span
              className="dot"
              style={{ background: t.kind === "ok" ? "var(--success)" : "var(--warning)" }}
            />
            <span>{t.msg}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/** 复制文本 + Toast「已复制 · 30 秒后自动清除剪贴板」（spec §6.3 / browser-fill.md） */
export function useCopy(): (text: string) => void {
  const { toast } = useToast();
  return useCallback(
    (text: string) => {
      const done = () => toast("已复制 · 30 秒后自动清除剪贴板", "ok");
      if (navigator.clipboard?.writeText) {
        navigator.clipboard
          .writeText(text)
          .then(() => {
            done();
            // 30 秒后自动清除剪贴板（产品承诺行为）
            setTimeout(() => {
              navigator.clipboard.writeText("").catch(() => undefined);
            }, 30000);
          })
          .catch(() => done());
      } else {
        done();
      }
    },
    [toast],
  );
}
