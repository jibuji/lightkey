/**
 * D 层服务接口（Cordis `provide` 的服务面）+ `Context` 类型增强。
 *
 * 服务与插件的对应（`docs/plugin-architecture.md` §3.4/§4.2）：
 *
 * | 服务 | 提供者 | 依赖 | 里程碑 |
 * |------|--------|------|--------|
 * | `ctx.ipc` | ipc-bridge | 地基（mock/tauri 适配器） | M1.5（首批） |
 * | `ctx.preference` | preference-store | 地基（localStorage 落盘） | M1.5（首批） |
 * | `ctx.theme` | theme | ← preference-store | M1.5（首批） |
 * | `ctx.toast` | toast | 地基（监听 `clipboard.copied`） | M1.5 |
 * | `ctx.session` | ipc-bridge | ← ipc（解锁态 + 事件翻译） | M1.5 |
 * | `ctx.slots` | React 宿主 | 地基（槽位注册表） | M1.5 |
 * | `ctx.nav` | React 宿主 | 地基（页面导航） | M1.5 |
 */

import type { LightKeyIpc } from "../ipc/types";
import type { ItemChangedPayload, ThemeName } from "../events";
import type { SlotRegistry } from "../host/slots";

/** preference-store 服务：非敏感 UI 偏好（localStorage；不进加密库/config.json）。 */
export interface PreferenceService {
  /** 读偏好；不存在 → null。 */
  get(key: string): string | null;
  /** 写偏好（JSON 字符串化落盘）。 */
  set(key: string, value: string): void;
  /** 删除偏好。 */
  remove(key: string): void;
  /** 清空全部偏好（QA/测试）。 */
  reset(): void;
}

/** theme 服务：设计 tokens（暗/浅）+ 偏好持久化 + `theme.changed` 广播。 */
export interface ThemeService {
  /** 当前主题（初始：偏好 → 插件配置 defaultTheme → dark）。 */
  readonly current: ThemeName;
  /** 切换主题（持久化 + 广播 `theme.changed`；相同值不广播）。 */
  set(theme: ThemeName): void;
  /** 暗/浅互切。 */
  toggle(): void;
}

/** 一条 Toast 消息。 */
export interface ToastMessage {
  id: number;
  text: string;
  /** 自动清除时刻（ISO-8601）。 */
  clearedAt: string;
}

/** toast 服务：右下角提示；`clipboard.copied` → 「已复制，30 秒后自动清除」。 */
export interface ToastService {
  /** 当前可见消息（新 → 旧）。 */
  readonly all: ToastMessage[];
  /** 手动提示（普通 Toast）。 */
  show(text: string): number;
  /** 立即关闭（同时取消自动清除计时）。 */
  dismiss(id: number): void;
  /** 订阅消息列表变化（React 重渲染用）；返回退订。 */
  subscribe(listener: (toasts: ToastMessage[]) => void): () => void;
}

/** session 服务（ipc-bridge 提供）：解锁态 + 首启门控 + 事件翻译。 */
export interface SessionService {
  readonly unlocked: boolean;
  /** 库是否已初始化（`vault.status.initialized`；null = 尚未探测到）。
   *  无库 = 首启 → 初始化向导；有库 → 解锁页（M2.5 互斥门控）。 */
  readonly initialized: boolean | null;
  /** 解锁（mock/tauri 适配器；成功 → 广播 `session.unlocked`）。 */
  unlock(masterPassword: string): Promise<void>;
  /**
   * 初始化向导：vault.init 建库（主密码策略/恢复码生成全在后端）。
   * 恢复码仅此一次返回（前端不生成、不落盘）；成功 → 标记库已初始化
   * （不广播事件：向导中途不打断，完成后经 unlock 切主界面）。
   */
  initialize(masterPassword: string): Promise<{ recoveryCode: string }>;
  /** 锁定（适配器；广播 `session.locked(manual)`）。 */
  lock(): Promise<void>;
  /**
   * 模拟 Rust 侧事件（`item.changed`）。
   *
   * 真实环境：Rust vault-store → IPC 通知 → ipc-bridge 翻译 → 本层重新
   * `emit`（§5.3）。M1.5 IPC 协议零变更，无通知通道，此方法供 mock
   * 适配器 / QA 钩子 / 演示面板模拟该翻译路径。
   */
  notifyItemChanged(payload: ItemChangedPayload): void;
}

/** nav 服务（宿主提供）：内容页切换（sidebar 导航项 → content 页面）。 */
export interface NavService {
  /** 当前页面（初始 = 第一个 content 槽位组件的 page，缺省 'vault'）。 */
  readonly current: string;
  /** 切页（不存在页面时忽略）。 */
  go(page: string): void;
  /** 订阅切换（React 重渲染用）；返回退订。 */
  subscribe(listener: () => void): () => void;
}

/** desktop-shell 服务：窗口/托盘联动（决策 #4 A；tauri 环境生效，mock no-op）。 */
export interface ShellService {
  /** 关闭主窗口 = 隐藏到托盘、保持解锁（Rust 侧已拦截 close 事件；备用命令）。 */
  closeToTray(): Promise<void>;
  /** 退出应用（托盘退出 = 守护退出 = 锁定）。 */
  quit(): Promise<void>;
}

declare module "@cordisjs/core" {
  interface Context {
    ipc: LightKeyIpc;
    preference: PreferenceService;
    theme: ThemeService;
    toast: ToastService;
    session: SessionService;
    slots: SlotRegistry;
    nav: NavService;
    /** desktop-shell 插件提供（M2）。 */
    shell: ShellService;
  }
}
