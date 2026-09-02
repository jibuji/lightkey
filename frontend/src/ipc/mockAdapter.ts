/**
 * Mock 适配器 —— 内存数据层（含 300ms 模拟延迟）。
 *
 * 语义对齐产品行为（docs/ipc.md）：
 * - 解锁需主密码（demo-password）；错误统一抛 VaultInvalidError（不区分
 *   「密码错/库未建」，防探测）。
 * - 锁定 = 内存擦除：条目/规则回到初始 fixture，会话令牌失效。
 * - item.update 走 CAS：expectedRevision 与当前 revision 不符 → ConflictError。
 * - 软删除语义：remove 即从库移除（mock 不模拟墓碑延迟）。
 * - 规则/审批/config（M2）：规则 CRUD 走 `rule.add|list|remove`（决策 #6）；
 *   approvalResult 对已知 requestId 返回 accepted；config 内存态；恢复码
 *   接受 demo 码并重设主密码。
 * - 通知订阅（决策 #3 A）：`subscribeNotifications` 仅登记回调；模拟帧经
 *   QA 钩子触发（`simulateAuthzRequest` / `simulateItemChanged`），用于
 *   验证 ipc-bridge 的帧翻译路径与审批弹窗闭环。
 *
 * QA 钩子：`window.__LIGHTKEY_MOCK__`（仅 dev 可用）。
 */

import type {
  AuditEvent,
  AuthRule,
  ConfigPatch,
  ConfigView,
  Item,
  ItemDraft,
  ItemSummary,
  RuleInput,
  SyncStatus,
} from "../types";
import {
  ConflictError,
  VaultInvalidError,
  type LightKeyIpc,
  type NotificationFrame,
  type UpdateOptions,
} from "./types";
import { ERROR_CODES, NOTIFICATIONS } from "./protocol";
import {
  DEMO_RECOVERY_CODE,
  MOCK_AUDIT,
  MOCK_ITEMS,
  MOCK_MASTER_PASSWORD,
  MOCK_RULES,
} from "./mockData";

const LATENCY_MS = 300;

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), LATENCY_MS));
}

/**
 * 拒绝路径的延迟。
 *
 * 不能写成 `delay(Promise.reject(err))`：`Promise.reject` 在调用瞬间即产生
 * 已拒绝的内层 promise，其 rejection 在下一个微任务检查点就会触发
 * `unhandledRejection`（此时外层的 300ms 计时器尚未 adopt 它，处理器也无
 * 从挂上）。这里让 rejection 只在计时器触发时产生，调用方（测试）可在
 * 计时器前先行挂处理器，杜绝 unhandled rejection。
 */
function delayReject(error: Error): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(error), LATENCY_MS));
}

function nowStamp(): string {
  return new Date().toISOString().slice(0, 19) + "Z";
}

function newId(): string {
  return "it" + Math.random().toString(36).slice(2, 8);
}

/**
 * mock 首启标志（localStorage；仅 QA/dev）：`simulateFreshInstall` 写入，
 * MockAdapter 构造时读取——浏览器 E2E 可「重载后仍为首启」，真实走
 * 启动 → vault.status 探测 → 向导 的完整路径。
 */
const MOCK_FRESH_KEY = "lightkey:mock:fresh";

export class MockAdapter implements LightKeyIpc {
  readonly kind = "mock" as const;

  private unlocked = false;
  /** 库是否已初始化（M2.5 首启门控；默认已初始化 = 回归解锁页，
   *  首启场景经 `simulateFreshInstall` 模拟；localStorage 标志跨重载）。 */
  private initialized = localStorage.getItem(MOCK_FRESH_KEY) !== "1";
  private masterPassword = MOCK_MASTER_PASSWORD;
  private items: Item[] = [];
  private rules: AuthRule[] = [];
  private audit: AuditEvent[] = [];
  /** 通知订阅回调（subscribeNotifications 登记；QA 钩子触发模拟帧）。 */
  private onFrame: ((frame: NotificationFrame) => void) | null = null;
  /** 待审批 requestId 集合（approvalResult 据此裁决 accepted）。 */
  private pendingApprovals = new Set<string>();
  /** 锁定态一体化待审（#67）：这些 requestId 的 allowed 决策须先解锁
   *  （masterPassword === MOCK_MASTER_PASSWORD），错误抛 VaultInvalidError
   *  且条目保留（弹窗停留可重试）；锁态也允许提交（模拟守护进程跳过
   *  require_session）。 */
  private unlockApprovals = new Set<string>();
  /** 模拟 config（守护进程 config.json 的内存等价物）。 */
  private config: ConfigView = {
    autoLockMinutes: 5,
    approvalTimeoutSecs: 30,
    sync: { url: "webdavs://dav.example.com/lightkey", intervalSecs: 60 },
  };

  /** 解锁后重建内存库（fixture）；锁定则擦除。 */
  private resetStore(restore: boolean) {
    this.items = restore ? structuredClone(MOCK_ITEMS) : [];
    this.rules = restore ? structuredClone(MOCK_RULES) : [];
    this.audit = restore ? [...MOCK_AUDIT] : [];
    this.pendingApprovals.clear();
    this.unlockApprovals.clear();
  }

  private requireUnlocked() {
    if (!this.unlocked) throw new Error(ERROR_CODES.SESSION_INVALID);
  }

  /* ---------- vault ---------- */

  /** vault.status：解锁态、库是否已初始化（M2.5 首启门控：无库 → 向导） */
  async status(): Promise<{
    unlocked: boolean;
    initialized: boolean;
    auditAnchorOk?: boolean;
  }> {
    return delay({
      unlocked: this.unlocked,
      initialized: this.initialized,
      auditAnchorOk: true, // mock 恒健康
    });
  }

  async init(masterPassword: string): Promise<{ recoveryCode: string }> {
    if (this.initialized) {
      return delayReject(new VaultInvalidError()); // 已存在库：与弱密码统一文案
    }
    if (masterPassword.length < 8) {
      return delayReject(new VaultInvalidError()); // 主密码策略留后端；mock 对齐
    }
    this.masterPassword = masterPassword;
    this.initialized = true;
    this.unlocked = false;
    // 建库成功 = 首启结束：清除 simulateFreshInstall 的 localStorage 标志，
    // 否则重载后新实例仍视为未初始化、又回向导（QA P2：对齐真实落盘语义）
    localStorage.removeItem(MOCK_FRESH_KEY);
    this.resetStore(false); // 新库为空（解锁时才回填演示 fixture）
    return delay({ recoveryCode: DEMO_RECOVERY_CODE });
  }

  async unlock(masterPassword: string): Promise<void> {
    if (masterPassword !== this.masterPassword) {
      return delayReject(new VaultInvalidError());
    }
    this.resetStore(true);
    this.unlocked = true;
    return delay(undefined);
  }

  async lock(): Promise<void> {
    this.unlocked = false;
    this.resetStore(false);
    return delay(undefined);
  }

  async recover(recoveryCode: string, newPassword: string): Promise<{ recoveryCode: string }> {
    if (recoveryCode.replace(/\s/g, "") !== DEMO_RECOVERY_CODE.replace(/\s/g, "")) {
      return delayReject(new VaultInvalidError());
    }
    // 新主密码同 vault.init 策略：≥8 位（ipc.md §4；对齐 tauriAdapter 对
    // vault.weak_password 的 VaultInvalidError 映射，QA P2：原为 <4 位）
    if (newPassword.length < 8) {
      return delayReject(new VaultInvalidError());
    }
    // 恢复 = 更换主密码 + 重建库（与守护进程 vault.recover 语义一致：锁定态）
    this.masterPassword = newPassword;
    this.resetStore(true);
    this.unlocked = false;
    return delay({ recoveryCode: DEMO_RECOVERY_CODE });
  }

  /* ---------- item ---------- */

  async list(): Promise<ItemSummary[]> {
    this.requireUnlocked();
    return delay(
      this.items.map((it) => ({ id: it.id, name: it.name, type: it.type, revision: it.revision })),
    );
  }

  async get(id: string): Promise<Item> {
    this.requireUnlocked();
    const it = this.items.find((x) => x.id === id);
    if (!it) return delayReject(new Error(ERROR_CODES.ITEM_NOT_FOUND));
    // 返回副本：前端持有的条目与 mock 库隔离，模拟真实 IPC 的序列化边界
    // （否则外部修改会经共享引用泄漏进前端 state，CAS 冲突无法复现）
    return delay(structuredClone(it));
  }

  async create(draft: ItemDraft): Promise<Item> {
    this.requireUnlocked();
    const item = { ...draft, id: newId(), revision: nowStamp() } as Item;
    this.items.unshift(item);
    this.emitItemChanged(item);
    return delay(structuredClone(item));
  }

  async update(id: string, draft: ItemDraft, opts?: UpdateOptions): Promise<Item> {
    this.requireUnlocked();
    const idx = this.items.findIndex((x) => x.id === id);
    if (idx < 0) return delayReject(new Error(ERROR_CODES.ITEM_NOT_FOUND));
    const current = this.items[idx];
    if (opts?.expectedRevision !== undefined && opts.expectedRevision !== current.revision) {
      return delayReject(new ConflictError());
    }
    const updated = { ...draft, id, revision: nowStamp() } as Item;
    this.items[idx] = updated;
    this.emitItemChanged(updated);
    return delay(structuredClone(updated));
  }

  async remove(id: string): Promise<void> {
    this.requireUnlocked();
    const it = this.items.find((x) => x.id === id);
    this.items = this.items.filter((x) => x.id !== id);
    if (it) this.emitItemChanged({ ...it, revision: nowStamp() }, true);
    return delay(undefined);
  }

  /* ---------- sync / audit ---------- */

  async syncStatus(): Promise<SyncStatus> {
    this.requireUnlocked();
    return delay({ lastSync: nowStamp() });
  }

  async syncTrigger(): Promise<SyncStatus> {
    this.requireUnlocked();
    return delay({ lastSync: nowStamp() });
  }

  async auditList(): Promise<AuditEvent[]> {
    this.requireUnlocked();
    return delay([...this.audit]);
  }

  /* ---------- rule（决策 #6：rule.add|list|remove；含 name） ---------- */

  async ruleList(): Promise<AuthRule[]> {
    this.requireUnlocked();
    return delay([...this.rules]);
  }

  async ruleAdd(input: RuleInput): Promise<AuthRule> {
    this.requireUnlocked();
    // 对齐真实守护进程校验：目录须为绝对路径（浏览器无文件系统，「存在」
    // 只能由真实侧判定；mock 至少拦截相对路径，保证前端 invalid 分支可达）。
    // capability 感知（M2.9 / M2.97）：read/write 规则不绑定命令（command
    // 恒为空串）；inject 规则必须带命令。
    const isAbsolute = /^([a-zA-Z]:[\\/]|\/)/.test(input.projectDir);
    const noCommand = input.capability === "read" || input.capability === "write";
    if (
      !input.projectDir ||
      !isAbsolute ||
      !input.name ||
      !input.keys.length ||
      (noCommand ? !!input.command : !input.command)
    ) {
      return delayReject(new Error("invalid params"));
    }
    const rule: AuthRule = {
      id: "r" + Math.random().toString(36).slice(2, 6),
      ...input,
      created: nowStamp(),
    };
    this.rules.unshift(rule);
    return delay(structuredClone(rule));
  }

  async ruleRemove(id: string): Promise<void> {
    this.requireUnlocked();
    this.rules = this.rules.filter((r) => r.id !== id);
    return delay(undefined);
  }

  /* ---------- approval / config / 目录选择器 / 通知订阅 ---------- */

  async approvalResult(
    requestId: string,
    decision: "allowed" | "denied",
    _challenge: string,
    masterPassword?: string,
  ): Promise<{ accepted: boolean }> {
    // 锁定态一体化（#67）：unlock 待审允许在锁态提交（守护进程对 desktop
    // 来源跳过 require_session）；allowed 须先解锁（主密码校验），错误
    // 抛 VaultInvalidError 且条目保留（弹窗停留于倒计时内可重试）。
    if (this.unlockApprovals.has(requestId)) {
      if (decision === "allowed") {
        if (masterPassword !== this.masterPassword) {
          throw new VaultInvalidError();
        }
        this.unlockApprovals.delete(requestId);
        const accepted = this.pendingApprovals.delete(requestId);
        return delay({ accepted });
      }
      this.unlockApprovals.delete(requestId);
      const accepted = this.pendingApprovals.delete(requestId);
      return delay({ accepted });
    }
    this.requireUnlocked();
    const accepted = this.pendingApprovals.delete(requestId);
    return delay({ accepted });
  }

  async configGet(): Promise<ConfigView> {
    return delay(structuredClone(this.config));
  }

  async configSet(patch: ConfigPatch): Promise<void> {
    const next = structuredClone(this.config);
    if (patch.autoLockMinutes !== undefined) next.autoLockMinutes = patch.autoLockMinutes;
    if (patch.syncUrl !== undefined) {
      next.sync =
        patch.syncUrl.trim() === ""
          ? null
          : { url: patch.syncUrl.trim(), intervalSecs: patch.pollSecs ?? 60 };
    } else if (patch.pollSecs !== undefined && next.sync) {
      next.sync.intervalSecs = patch.pollSecs;
    }
    this.config = next;
    return delay(undefined);
  }

  async pickDir(): Promise<string | null> {
    // 浏览器无原生目录选择器；QA 钩子可注入模拟结果
    return delay(this.mockPickDir);
  }

  async subscribeNotifications(
    onFrame: (frame: NotificationFrame) => void,
  ): Promise<() => void> {
    this.onFrame = onFrame;
    return () => {
      if (this.onFrame === onFrame) this.onFrame = null;
    };
  }

  /* ---------- QA 钩子（仅 mock；验证帧翻译 / 审批弹窗闭环） ---------- */

  /** 模拟守护进程推送 authz.request 帧（审批弹窗演示/测试入口）。
   *  `challenge` 缺省给固定值（mock 不校验，仅透传给弹窗回传）。
   *  `needsUnlock`（#67）：锁定态一体化——弹窗须收集主密码；见
   *  `unlockApprovals`。`kind`（M2.9 值披露 + M2.97 写门）/
   *  `exportMeta`：审批类型与 export 数据包规模元信息。 */
  simulateAuthzRequest(params: {
    requestId: string;
    starter: string;
    projectDir: string;
    command: string;
    keys: string[];
    challenge?: string;
    needsUnlock?: boolean;
    kind?: "inject" | "read" | "export" | "rule" | "write";
    exportMeta?: { name: string; mime: string; size: number } | null;
  }): void {
    this.pendingApprovals.add(params.requestId);
    if (params.needsUnlock) {
      this.unlockApprovals.add(params.requestId);
    }
    this.onFrame?.({
      jsonrpc: "2.0",
      method: NOTIFICATIONS.AUTHZ_REQUEST,
      params: {
        challenge: "mock-challenge",
        needsUnlock: params.needsUnlock ?? false,
        ...params,
      },
    });
  }

  /** 模拟守护进程推送 item.changed 帧（ui-vault 刷新 / CAS 场景）。 */
  simulateItemChanged(params: {
    itemId: string;
    revisionDate: string;
    type: string;
    deleted: boolean;
  }): void {
    this.onFrame?.({ jsonrpc: "2.0", method: NOTIFICATIONS.ITEM_CHANGED, params });
  }

  /** 模拟目录选择结果（pickDir 返回值；null = 用户取消）。 */
  mockPickDir: string | null = null;

  /**
   * 模拟其他设备已修改该条目（revision 改为“未来”时间戳，保证与当前库内
   * revision 必然不同，从而稳定触发 CAS 冲突）。
   */
  simulateExternalEdit(id: string): void {
    const it = this.items.find((x) => x.id === id);
    if (it) it.revision = new Date(Date.now() + 60_000).toISOString().slice(0, 19) + "Z";
  }

  /** QA 只读检查 */
  readItem(id: string): Item | null {
    return this.items.find((x) => x.id === id) ?? null;
  }

  /** 模拟未初始化环境（全新安装首启）：清空库 + 回默认主密码；
   *  写 localStorage 标志，重载后仍为首启（浏览器 E2E 全路径）。 */
  simulateFreshInstall(): void {
    localStorage.setItem(MOCK_FRESH_KEY, "1");
    this.initialized = false;
    this.unlocked = false;
    this.masterPassword = MOCK_MASTER_PASSWORD;
    this.resetStore(false);
  }

  /** 模拟已有库（回归解锁页；清首启标志）。 */
  simulateInstalled(): void {
    localStorage.removeItem(MOCK_FRESH_KEY);
    this.initialized = true;
    this.unlocked = false;
    this.masterPassword = MOCK_MASTER_PASSWORD;
    this.resetStore(false);
  }

  /** QA 只读检查：mock 是否处于解锁态。 */
  isUnlocked(): boolean {
    return this.unlocked;
  }

  /** QA 只读检查：mock 库是否已初始化（首启门控依据）。 */
  isInitialized(): boolean {
    return this.initialized;
  }

  private emitItemChanged(item: Item, deleted = false) {
    this.onFrame?.({
      jsonrpc: "2.0",
      method: NOTIFICATIONS.ITEM_CHANGED,
      params: { itemId: item.id, revisionDate: item.revision, type: item.type, deleted },
    });
  }
}

/** 暴露 QA 钩子（dev console 用；真实适配器无此面） */
export function installMockQaHooks(adapter: MockAdapter) {
  (window as unknown as Record<string, unknown>).__LIGHTKEY_MOCK__ = {
    simulateExternalEdit: (id: string) => adapter.simulateExternalEdit(id),
    simulateAuthzRequest: (params: Parameters<MockAdapter["simulateAuthzRequest"]>[0]) =>
      adapter.simulateAuthzRequest(params),
    simulateItemChanged: (params: Parameters<MockAdapter["simulateItemChanged"]>[0]) =>
      adapter.simulateItemChanged(params),
    setPickDirResult: (path: string | null) => {
      adapter.mockPickDir = path;
    },
    simulateFreshInstall: () => adapter.simulateFreshInstall(),
    simulateInstalled: () => adapter.simulateInstalled(),
    readItem: (id: string) => adapter.readItem(id),
    isUnlocked: () => adapter.isUnlocked(),
    isInitialized: () => adapter.isInitialized(),
  };
}
