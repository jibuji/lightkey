/**
 * ui-quick-save 插件（M2.99 快速保存；quick-capture.md §3.1/§4.2，补充拍板
 * #27 / issue #161）。
 *
 * **无槽位服务插件（自挂 portal，approval 插件同款结构）**：服务插件跨锁态
 * 存活（宿主锁态整页 ↔ 三栏切换不卸载本插件），锁态引导 / pending flush /
 * 面板本体都在这里，不依赖 ui-vault 挂载态——这是本插件独立成服务而非
 * 内嵌 ui-vault 的原因（规格 §4.2 实现注记）。
 *
 * 订阅 `quick.save-request`（壳托盘「快速保存剪贴板…」→ Tauri 本地事件 →
 * ipc-bridge 翻译，TS 内 emit，零负载）：
 *
 * - **已解锁** → 打开快速保存面板：值 = 剪贴板文本（`clipboardRead` 在
 *   面板打开那一刻**单次读取**——最小权限，无后台轮询/监听）、名称框自动
 *   聚焦、启发建议名（保守前缀表；preference `quickSave.nameSuggest` 可关，
 *   默认开）、重名**软提示**（同名条目计数，不阻止——名字即身份，重名
 *   合法，data-model 无唯一约束）、可选「用途」+「保存后清空剪贴板」勾选
 *   （**默认关**——外部复制内容非 LightKey 所有，不自动清，quick-capture.md
 *   §5）；保存 = `ctx.ipc.create`（secret 类型，desktop 通道写门受信豁免）
 *   → toast + 切到 vault 页（列表经 `item.changed` 既有刷新路径自动可见；
 *   新条目**选中**经 `vault.select` 本地事件交给 ui-vault，§3.1 步骤 4，
 *   issue #171）；
 * - **锁态** → 只 toast「解锁后即可快速保存」+ 置 pending，**不读剪贴板、
 *   不留值**（锁态 fail-closed 同向，§5）；`session.unlocked` → flush 自动
 *   重冒面板（拍板点 ②：锁定不清 pending，消费后清）；
 * - **未初始化** → toast 指向首启向导（不置 pending）；
 * - **不触碰「锁态写一体化」**（write-gate.md §12 留档默认不做）。
 *
 * 面板内值流：剪贴板 → clipboardRead → 本插件内存 → item.put（desktop
 * 豁免）→ 加密库；值不进事件帧 / 日志 / 审计（沿用 `item.create <name>`
 * 脱敏口径）。
 */

import { createRoot, type Root } from "react-dom/client";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import { Modal } from "../components/Modal";
import { SessionInvalidError } from "../ipc";
import type { ItemDraft } from "../types";

/** 名称建议偏好键（preference-store；"0" = 关闭，其余 = 开启，默认开）。
 *  非敏感 UI 偏好，localStorage 落盘，不进加密库/config.json。 */
export const QUICK_SAVE_NAME_SUGGEST_KEY = "quickSave.nameSuggest";

/** 启发建议前缀表（保守静态映射，只做输入框初值、用户可改；quick-capture.md
 *  §4.3）。无匹配 → null（名称留空由用户输入）。 */
const NAME_SUGGESTIONS: ReadonlyArray<{ re: RegExp; name: string }> = [
  { re: /^sk-/, name: "api_key" },
  { re: /^ghp_|^github_pat_/, name: "github_token" },
  { re: /^glpat-/, name: "gitlab_token" },
  { re: /^AKIA/, name: "aws_access_key_id" },
  { re: /^eyJ/, name: "jwt_token" },
  { re: /^xox[baprs]-/, name: "slack_token" },
];

/** 名称建议纯函数（可单测）：按剪贴板值前缀给静态建议名；无匹配 → null。 */
export function suggestSecretName(value: string): string | null {
  for (const s of NAME_SUGGESTIONS) {
    if (s.re.test(value)) return s.name;
  }
  return null;
}

/* ================= 面板本体 ================= */

function QuickSavePanel({
  ctx,
  onClose,
}: {
  ctx: Context;
  onClose: () => void;
}) {
  const toast = ctx.toast;
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [purpose, setPurpose] = useState("");
  const [clearAfter, setClearAfter] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  /** 库内条目名快照（解锁态；重名软提示数据源——名字即身份，重名合法）。 */
  const [names, setNames] = useState<string[]>([]);
  /** 已存在同名条目数（随 name 输入实时计数；>0 显示软提示，不阻止保存）。 */
  const dupCount = names.filter((n) => n === name.trim()).length;
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let alive = true;
    // 剪贴板只在面板打开那一刻读一次（最小权限；quick-capture.md §5）
    void (async () => {
      // 重名软提示 best-effort：读不到（如并发锁定）静默（names 空数组）
      try {
        setNames((await ctx.ipc.list()).map((i) => i.name));
      } catch {
        // 忽略：提示是旁路
      }
    })();
    void (async () => {
      const text = await ctx.ipc.clipboardRead();
      if (!alive) return;
      if (text) {
        setValue(text);
        // 名称建议：只做初值；preference 关闭（"0"）时留空由用户输入
        const suggestOn = ctx.preference.get(QUICK_SAVE_NAME_SUGGEST_KEY) !== "0";
        if (suggestOn) {
          const s = suggestSecretName(text);
          if (s) setName(s);
        }
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctx]);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const nm = name.trim();
    const val = value.trim();
    if (!nm) {
      setError("请填写名称");
      return;
    }
    if (!val) {
      setError("请填写密钥值（剪贴板为空时可手动粘贴）");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const created = await ctx.ipc.create({
        type: "secret",
        name: nm,
        value: val,
        purpose: purpose.trim() || "",
      } as ItemDraft);
      // 「保存后清空剪贴板」（默认关）：勾选才置空；失败不阻塞保存完成
      if (clearAfter) {
        try {
          await ctx.ipc.clipboardClear();
        } catch {
          // 忽略：清空失败仅提示层（不往上传）
        }
      }
      toast.show("已保存到 LightKey");
      // 选中新条目（quick-capture.md §3.1 步骤 4）：把 created.id 经
      // vault.select（TS 内事件，载荷只有 id，零密钥值）交给 ui-vault；
      // VaultPage 未挂载（如从设置页发起）时由 ui-vault 插件层 pending
      // 兜底，挂载后的任一次加载消费。
      ctx.emit("vault.select", { itemId: created.id });
      onClose();
      // 切到条目页：列表经 item.changed 既有刷新路径自动可见
      ctx.nav.go("vault");
    } catch (err) {
      setBusy(false);
      if (err instanceof SessionInvalidError) {
        toast.show("会话已失效，请解锁后重试");
        onClose();
      } else {
        setError("保存失败，请重试");
      }
    }
  };

  return (
    <Modal
      title="快速保存"
      desc="密钥值自动取自剪贴板（仅本次读取）· 保存后写入加密库"
      onClose={onClose}
      onMount={() => nameRef.current?.focus()}
    >
      <form className="form-grid" onSubmit={save} autoComplete="off">
        <label className="field">
          <span className="field-label">名称</span>
          <span className="input-wrap">
            <input
              ref={nameRef}
              value={name}
              placeholder="例如：GitHub Token"
              onChange={(e) => setName(e.target.value)}
            />
          </span>
        </label>
        {dupCount > 0 ? (
          <p className="field-error" role="status">
            已存在 {dupCount} 个同名条目，保存将创建重复条目（可改名或继续）
          </p>
        ) : null}
        <label className="field">
          <span className="field-label">密钥值</span>
          <span className="input-wrap">
            <input
              className="mono"
              value={value}
              placeholder="（剪贴板为空，请手动粘贴）"
              onChange={(e) => setValue(e.target.value)}
            />
          </span>
        </label>
        <label className="field">
          <span className="field-label">用途（可选）</span>
          <span className="input-wrap">
            <input
              value={purpose}
              placeholder="例如：发布 npm 包（仅白名单命令注入）"
              onChange={(e) => setPurpose(e.target.value)}
            />
          </span>
        </label>
        <label className="setting-row" style={{ margin: 0 }}>
          <div>
            <div className="setting-label">保存后清空剪贴板</div>
            <div className="setting-desc">剪贴板中是外部复制内容：勾选才清（默认关，避免明文残留）</div>
          </div>
          <span className="switch">
            <input
              type="checkbox"
              checked={clearAfter}
              onChange={(e) => setClearAfter(e.target.checked)}
            />
            <span className="track" />
          </span>
        </label>
        {error ? (
          <p className="field-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            取消
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "保存中…" : "保存"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/* ================= 插件工厂（无槽位服务；自挂 portal） ================= */

/**
 * 插件工厂：订阅 `quick.save-request` / 会话事件，管理面板生命周期。
 * portal 树独立于宿主页面——锁态整页切换不卸载（与 approval 同款结构）。
 */
export const uiQuickSave: Plugin.Function<Context, Record<string, never>> = Object.assign(
  (ctx: Context) => {
    let pending = false;
    let open = false;
    let rootEl: HTMLDivElement | null = null;
    let root: Root | null = null;

    const closePanel = () => {
      open = false;
      if (root) {
        root.unmount();
        root = null;
      }
      if (rootEl) {
        rootEl.remove();
        rootEl = null;
      }
    };

    const openPanel = () => {
      if (open) return;
      open = true;
      if (!rootEl) {
        rootEl = document.createElement("div");
        rootEl.setAttribute("data-portal", "quick-save");
        document.body.appendChild(rootEl);
      }
      root = createRoot(rootEl);
      root.render(<QuickSavePanel ctx={ctx} onClose={closePanel} />);
    };

    // 请求入口：已解锁 → 开面板；锁态 → toast + pending；未初始化 → 指向
    // 向导（不置 pending——解锁无从谈起）；启动探测中 → 稍后再试（不置
    // pending，避免卡住永久重冒）
    ctx.on("quick.save-request", () => {
      if (open) return;
      if (ctx.session.initialized === null) {
        ctx.toast.show("正在加载，请稍后再试");
        return;
      }
      if (ctx.session.initialized === false) {
        ctx.toast.show("请先完成首次初始化（新建加密库）");
        return;
      }
      if (!ctx.session.unlocked) {
        pending = true;
        ctx.toast.show("解锁后即可快速保存");
        return;
      }
      openPanel();
    });

    // 解锁成功 → flush pending（拍板点 ②：锁定不清 pending，消费后清）
    ctx.on("session.unlocked", () => {
      if (pending) {
        pending = false;
        openPanel();
      }
    });

    // 面板打开期间被锁定 → 关闭面板（不留值：值只在面板内存中，关闭即弃）
    ctx.on("session.locked", () => {
      closePanel();
    });

    // 可逆副作用：卸载时清除事件订阅与面板树
    return () => {
      pending = false;
      closePanel();
    };
  },
  {
    inject: ["ipc", "toast", "session", "preference", "nav"],
  },
);