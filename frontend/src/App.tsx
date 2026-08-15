/**
 * LightKey 桌面应用前端 —— 入口根组件。
 *
 * 解锁/锁定屏幕切换 + 全局 Toast。数据层走 IPC 接口（src/ipc/）：
 * 当前为内存 mock 适配器（浏览器直跑）；后端 M0 完成后自动切换 Tauri IPC。
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { UnlockScreen } from "./components/UnlockScreen";
import { VaultApp } from "./components/VaultApp";
import { ToastProvider } from "./components/Toast";
import { createIpc } from "./ipc";

export default function App() {
  const ipc = useMemo(() => createIpc(), []);
  const [unlocked, setUnlocked] = useState(false);
  /** 顶栏搜索回车 → ItemsPage 新建（spec §6.2 空态引导）。
   * 消费式信号：ItemsPage 开弹窗后经 onAckNewItem 置零，
   * 避免切页/锁定重挂载后弹窗幽灵重开（review M1）。 */
  const [newItemSignal, setNewItemSignal] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void ipc.status().then((s) => {
      if (s.unlocked) setUnlocked(true);
    });
  }, [ipc]);

  const handleSearchEnter = () => {
    if (unlocked) setNewItemSignal(true);
  };
  const ackNewItem = useCallback(() => setNewItemSignal(false), []);

  return (
    <ToastProvider>
      {unlocked ? (
        <VaultApp
          ipc={ipc}
          onLock={() => setUnlocked(false)}
          searchRef={searchRef}
          onSearchEnter={handleSearchEnter}
          newItemSignal={newItemSignal}
          onAckNewItem={ackNewItem}
        />
      ) : (
        <UnlockScreen ipc={ipc} onUnlocked={() => setUnlocked(true)} />
      )}
    </ToastProvider>
  );
}
