/**
 * ui-unlock 插件（M2；`docs/plugin-architecture.md` §3.4，spec §6.1）。
 *
 * 锁态整页（不挂三栏骨架）：居中品牌图形 → 主密码输入 →「解锁」主按钮；
 * 次级入口「用 Windows Hello 解锁」（**M2 置灰预留**，决策 #5 B）与
 * 「用恢复码恢复」。错误文案统一「解锁失败（主密码错误或库未初始化）」
 * （ipc.md §3：不区分密码错/库未建，防探测）。
 *
 * 宿主按 `session.unlocked/locked` 在「整页解锁」与「三栏」间切换
 * （本组件挂 content 槽位，page="unlock"；锁态由宿主单独渲染）。
 */

import { useState, type ComponentType, type FormEvent } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import { Icon } from "../components/Icons";
import { Modal } from "../components/Modal";
import { VaultInvalidError } from "../ipc";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";

/** 解锁页组件本体（slot=content；宿主锁态整页渲染）。 */
export function UnlockPage({ ctx }: { ctx: Context }) {
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || !password) return;
    setBusy(true);
    setError("");
    try {
      await ctx.session.unlock(password);
      setPassword("");
    } catch (err) {
      // 统一文案：主密码错误 / 库未初始化（防探测，ipc.md §3）
      setError(
        err instanceof VaultInvalidError ? "解锁失败（主密码错误或库未初始化）" : "解锁失败，请重试",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="screen-unlock">
      <div className="unlock-card">
        <div className="brand-mark brand-mark-lg" aria-hidden="true">
          <Icon name="brand" size={34} />
        </div>
        <h1 className="unlock-title">LightKey</h1>
        <p className="unlock-sub">轻钥 · 个人密钥管理</p>
        <form className="unlock-form" onSubmit={submit} autoComplete="off">
          <label className="field">
            <span className="field-label">主密码</span>
            <span className="input-wrap">
              <input
                type={showPw ? "text" : "password"}
                placeholder="输入主密码"
                value={password}
                autoFocus
                aria-label="主密码"
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (error) setError("");
                }}
              />
              <button
                type="button"
                className="icon-btn input-affix"
                aria-label={showPw ? "隐藏密码" : "显示密码"}
                tabIndex={-1}
                onClick={() => setShowPw((v) => !v)}
              >
                <Icon name="eye" size={16} />
              </button>
            </span>
          </label>
          {error ? (
            <p className="field-error" role="alert">
              {error}
            </p>
          ) : null}
          <button type="submit" className="btn btn-primary btn-block" disabled={busy || !password}>
            {busy ? "解锁中…" : "解锁"}
          </button>
        </form>
        <div className="unlock-actions">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled
            title="M2 后快迭代提供（接口已预留）"
          >
            <Icon name="lock" size={15} />
            Windows Hello 解锁
          </button>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowRecovery(true)}>
            用恢复码恢复
          </button>
        </div>
        <p className="unlock-hint">密码仅用于本机解密 · 存储端看不到你的数据</p>
      </div>

      {showRecovery ? (
        <RecoveryModal
          ctx={ctx}
          onClose={() => setShowRecovery(false)}
          onRecovered={() => setShowRecovery(false)}
        />
      ) : null}
    </section>
  );
}
UnlockPage.slot = "content" as const;

/** 恢复码恢复（spec §6.6）：恢复码 + 新主密码 → 新恢复码（仅展示一次）。 */
function RecoveryModal({
  ctx,
  onClose,
  onRecovered,
}: {
  ctx: Context;
  onClose: () => void;
  onRecovered: () => void;
}) {
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [newCode, setNewCode] = useState<string | null>(null);

  const submit = async () => {
    if (busy) return;
    if (!code.trim() || !newPassword) {
      setError("请填写恢复码与新主密码");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await ctx.ipc.recover(code.trim(), newPassword);
      setNewCode(res.recoveryCode);
    } catch {
      setError("恢复失败（恢复码错误或库未初始化）");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={newCode ? "新恢复码（仅展示一次）" : "用恢复码恢复"}
      desc={
        newCode
          ? "请立即抄存或存入你的密码管理器；应用不记忆、不再展示。"
          : "恢复码 + 新设主密码即可取回主密钥副本；恢复后需用新主密码解锁。"
      }
      onClose={onClose}
    >
      {newCode ? (
        <>
          <div className="recovery-code">{newCode}</div>
          <div className="recovery-warn">
            <Icon name="lock" size={14} />
            <span>
              三通道（主密码 / 恢复码 / 已信任设备）全丢 = 数据不可恢复。
              恢复码 + Argon2id 派生信封密钥保护主密钥副本，可随库进 BYO 云。
            </span>
          </div>
          <div className="modal-actions">
            <button
              className="btn btn-primary"
              onClick={() => {
                onRecovered();
                ctx.toast.show("恢复完成 · 请用新主密码解锁");
              }}
            >
              我已保存
            </button>
          </div>
        </>
      ) : (
        <>
          <div className="form-grid">
            <label className="field">
              <span className="field-label">恢复码</span>
              <span className="input-wrap">
                <input
                  className="mono"
                  value={code}
                  placeholder="J4QZ7 K8TW2 MPD9V …"
                  aria-label="恢复码"
                  onChange={(e) => setCode(e.target.value)}
                />
              </span>
            </label>
            <label className="field">
              <span className="field-label">新主密码</span>
              <span className="input-wrap">
                <input
                  type="password"
                  value={newPassword}
                  placeholder="至少 8 位"
                  aria-label="新主密码"
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </span>
            </label>
            {error ? (
              <p className="field-error" role="alert">
                {error}
              </p>
            ) : null}
          </div>
          <div className="modal-actions">
            <button className="btn btn-ghost" onClick={onClose}>
              取消
            </button>
            <button className="btn btn-primary" disabled={busy} onClick={() => void submit()}>
              恢复
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

/** 插件工厂：注册 content 槽位组件（page=unlock；锁态整页由宿主渲染）。 */
export const uiUnlock: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-unlock",
      slot: config.slot ?? UnlockPage.slot ?? "content",
      order: config.order ?? 0,
      component: (() => {
        const Comp = () => <UnlockPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "unlock" },
    });
  },
  {
    inject: ["slots", "session", "ipc", "toast"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);
