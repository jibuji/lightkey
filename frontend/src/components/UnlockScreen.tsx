/**
 * 解锁页（spec §6.1）：居中品牌图形 → 主密码输入 → 解锁按钮；
 * 次级入口 Windows Hello / 恢复码。错误提示统一文案（不区分密码错/库未建）。
 */

import { useState, type FormEvent } from "react";
import type { LightKeyIpc } from "../ipc";
import { VaultInvalidError } from "../ipc";
import { Icon } from "./Icons";
import { Modal } from "./Modal";
import { useCopy, useToast } from "./Toast";

/** 演示恢复码（mock：一次性展示；真实由守护进程生成，见 recovery.md） */
const DEMO_RECOVERY_CODE = "J4QZ7 K8TW2 MPD9V XHC7G N3RFX 5AJKQ M2P8D 9VXH7";

interface UnlockScreenProps {
  ipc: LightKeyIpc;
  onUnlocked: () => void;
}

export function UnlockScreen({ ipc, onUnlocked }: UnlockScreenProps) {
  const { toast } = useToast();
  const copy = useCopy();
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (!password) {
      toast("请输入主密码", "warn");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await ipc.unlock(password);
      setPassword("");
      onUnlocked();
      toast("库已解锁 · 密钥仅存于守护进程内存", "ok");
    } catch (err) {
      setError(err instanceof VaultInvalidError ? "主密码错误或库未初始化" : "解锁失败，请重试");
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
          {error ? <p className="field-error" role="alert">{error}</p> : null}
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {busy ? "解锁中…" : "解锁"}
          </button>
        </form>
        <div className="unlock-actions">
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => toast("Windows Hello 宽限解锁（已信任设备）", "ok")}>
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
        <Modal title="恢复码（仅展示一次）" desc="请立即抄存或存入你的密码管理器；应用不记忆、不再展示。" onClose={() => setShowRecovery(false)}>
          <div className="recovery-code">{DEMO_RECOVERY_CODE}</div>
          <div className="recovery-warn">
            <Icon name="lock" size={14} />
            <span>
              三通道（主密码 / 恢复码 / 已信任设备）全丢 = 数据不可恢复。
              恢复码 + Argon2id 派生信封密钥保护主密钥副本，可随库进 BYO 云。
            </span>
          </div>
          <div className="modal-actions">
            <button className="btn btn-ghost" onClick={() => copy(DEMO_RECOVERY_CODE.replace(/ /g, ""))}>
              复制
            </button>
            <button
              className="btn btn-primary"
              onClick={() => {
                setShowRecovery(false);
                toast("恢复信封已生成并加密保存", "ok");
              }}
            >
              我已保存
            </button>
          </div>
        </Modal>
      ) : null}
    </section>
  );
}
