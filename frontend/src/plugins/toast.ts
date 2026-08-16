/**
 * toast 插件：右下角提示（design/spec.md §3 Toast）。
 *
 * 监听 `clipboard.copied` → 「已复制，30 秒后自动清除」+ 30s 清除计时
 * （D12 / spec §6.3 同款行为；`clearedAt` 为负载内的清除时刻）。
 *
 * 提供 `ctx.toast`（`show` / `dismiss` / `subscribe`），React 宿主经
 * `subscribe` 渲染 Toast 层。
 */

import type { Context, Plugin } from "@cordisjs/core";
import type { ToastMessage, ToastService } from "../services/types";

export const CLIPBOARD_TOAST_TEXT = "已复制，30 秒后自动清除";

export const toast: Plugin.Function<Context> = Object.assign((ctx: Context) => {
  let nextId = 1;
  let toasts: ToastMessage[] = [];
  const listeners = new Set<(toasts: ToastMessage[]) => void>();
  const timers = new Map<number, ReturnType<typeof setTimeout>>();

  const notify = () => {
    for (const listener of listeners) listener([...toasts]);
  };

  const push = (text: string, clearedAt: string | null): number => {
    const id = nextId++;
    const message: ToastMessage = {
      id,
      text,
      clearedAt: clearedAt ?? new Date(Date.now() + 30_000).toISOString(),
    };
    toasts = [...toasts, message];
    // 自动清除（默认 30s；`clipboard.copied` 的 clearedAt 由发送方给出）
    const timer = setTimeout(() => {
      toasts = toasts.filter((t) => t.id !== id);
      timers.delete(id);
      notify();
    }, 30_000);
    timers.set(id, timer);
    notify();
    return id;
  };

  // `clipboard.copied` → Toast + 30s 清除（事件总线契约 §5.2）
  ctx.on("clipboard.copied", (payload) => {
    push(CLIPBOARD_TOAST_TEXT, payload.clearedAt);
  });

  const service: ToastService = {
    get all() {
      return toasts;
    },
    show(text: string) {
      return push(text, null);
    },
    dismiss(id: number) {
      const timer = timers.get(id);
      if (timer) clearTimeout(timer);
      timers.delete(id);
      toasts = toasts.filter((t) => t.id !== id);
      notify();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  ctx.provide("toast", service);

  // 可逆副作用：卸载时清计时器（插件卸载自动撤销）
  return () => {
    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();
    listeners.clear();
  };
}, {  });
