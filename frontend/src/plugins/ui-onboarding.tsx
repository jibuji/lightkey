/**
 * ui-onboarding 插件（M2.5 首次初始化向导；`docs/plugin-architecture.md`
 * §3.4；设计定稿 = design pilot 原型 `docs/design/prototype/` 四步流程）。
 *
 * 首启门控：库未初始化（`vault.status.initialized=false`）→ 宿主锁态渲染
 * 本插件（整页向导）而非 ui-unlock；与 ui-unlock **互斥**（门控数据 = 守护
 * 进程探测结果，宿主 `Skeleton` 统一裁决）。
 *
 * 四步（忠实原型）：
 *   1 欢迎（品牌 mark + 三特性 + 「开始设置」）
 *   2 设主密码（显隐切换 + 4 段强度条 + 两次一致校验 + 上一步/下一步）
 *   3 保存恢复码（**真实恢复码**：vault.init 响应，仅一次；勾选门控 +
 *      复制 30s 清除）
 *   4 完成（「进入 LightKey」→ unlock 进入已解锁主界面）
 *
 * 安全边界（安全核心留 Rust）：
 * - 主密码最小长度/策略、恢复码生成、库初始化全在后端（vault.init）；
 * - 恢复码只来自 init 响应，前端不生成、不落盘、不记忆；
 * - 主密码仅存于本组件内存态，完成/退出即释放；
 * - 初始化失败（弱密码 / 已存在库）UI 统一文案，不区分（ipc.md §3 防探测）。
 *
 * 已初始化后回退 step2 并改动密码：再次「下一步」会触发 vault.init →
 * 已存在库错误 → 统一文案（设计定稿语义；用户回退恢复原密码可继续）。
 */

import { useRef, useState, type ComponentType, type FormEvent } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import { Icon } from "../components/Icons";
import { copyWithClear } from "../components/atoms";
import { VaultInvalidError } from "../ipc";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";

/** 步骤号（原型四步）。 */
type OnboardStep = 1 | 2 | 3 | 4;

/** 强度档位文案（4 段条 + 标签；与原型一致）。 */
const STRENGTH_LABELS = ["", "弱", "中", "强", "极强"] as const;

/** 强度评分 0..5（原型同款：长度 8/12、大小写混合、数字、符号）。 */
function passwordStrength(pw: string): number {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s += 1;
  if (pw.length >= 12) s += 1;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s += 1;
  if (/\d/.test(pw)) s += 1;
  if (/[^A-Za-z0-9]/.test(pw)) s += 1;
  return s;
}

/** 评分 → 档位（1..4；0 = 空输入不点亮）。 */
function strengthLevel(score: number): 0 | 1 | 2 | 3 | 4 {
  if (score === 0) return 0;
  if (score <= 2) return 1;
  if (score === 3) return 2;
  if (score === 4) return 3;
  return 4;
}

/** 向导本体（slot=content；宿主锁态整页渲染，无三栏）。 */
export function OnboardingPage({ ctx }: { ctx: Context }) {
  const [step, setStep] = useState<OnboardStep>(1);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  /** 后端返回的真实恢复码（仅一次；前端不生成/不落盘）。 */
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  /** 已建库时的密码快照：回退重进 step2 且密码未变 → 复用 init 结果，
   *  避免对已存在库重复 init（幂等跳过）；密码变更 → 后端拒绝 → 统一文案。 */
  const initState = useRef<{ password: string; code: string } | null>(null);

  /** step2 → step3：首次建库（vault.init）；已用同密码建过 → 复用恢复码。 */
  const goToRecovery = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      if (initState.current?.password === password) {
        // 已用当前密码建库（回退后原样重进）：复用唯一一次返回的恢复码
        setRecoveryCode(initState.current.code);
      } else {
        const res = await ctx.session.initialize(password);
        initState.current = { password, code: res.recoveryCode };
        setRecoveryCode(res.recoveryCode);
      }
      setStep(3);
    } catch (err) {
      // 统一文案：主密码校验失败 / 已存在库不区分（防探测，ipc.md §3）
      setError(
        err instanceof VaultInvalidError
          ? "初始化失败（主密码不符合要求或库已存在）"
          : "初始化失败，请重试",
      );
    } finally {
      setBusy(false);
    }
  };

  /** step4 完成：解锁进入主界面（主密码仍在本组件内存态）。 */
  const finish = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await ctx.session.unlock(password);
      setPassword("");
      setConfirm("");
    } catch {
      setError("解锁失败，请重试");
      setBusy(false);
    }
  };

  const goBack = (to: OnboardStep) => {
    setError("");
    setStep(to);
  };

  const st = passwordStrength(password);
  const lv = strengthLevel(st);
  // 实时校验（原型同款）：<8 位提示；两次不一致提示；门控下一步
  const lenOk = password.length >= 8;
  const liveError = !password
    ? ""
    : !lenOk
      ? "主密码至少 8 位"
      : confirm && confirm !== password
        ? "两次输入不一致"
        : "";
  const shownError = error || liveError;

  return (
    <section className="screen-onboarding">
      <div className="onboard-card">
        <div className="onboard-progress" aria-hidden="true">
          {[1, 2, 3, 4].map((n) => (
            <span key={n} className={`ostep${n <= step ? " active" : ""}`} data-step={n} />
          ))}
        </div>

        {/* Step 1：欢迎 */}
        {step === 1 ? (
          <div className="onboard-step active" data-testid="onboard-step-1">
            <div className="brand-mark brand-mark-lg" aria-hidden="true">
              <Icon name="brand" size={34} />
            </div>
            <h1 className="onboard-title">欢迎使用 LightKey</h1>
            <p className="onboard-sub">轻钥 · 个人密钥管理 · 首次使用需要几步初始化</p>
            <ul className="onboard-features">
              <li>
                <span className="feat-ic">
                  <Icon name="check" size={15} />
                </span>
                密钥仅在本机加密解密，云端只见密文
              </li>
              <li>
                <span className="feat-ic">
                  <Icon name="check" size={15} />
                </span>
                BYO 存储：WebDAV / S3 任意自备云
              </li>
              <li>
                <span className="feat-ic">
                  <Icon name="check" size={15} />
                </span>
                恢复码兜底：忘记主密码也能找回
              </li>
            </ul>
            <button type="button" className="btn btn-primary btn-block" onClick={() => goBack(2)}>
              开始设置
            </button>
          </div>
        ) : null}

        {/* Step 2：设主密码 */}
        {step === 2 ? (
          <div className="onboard-step active" data-testid="onboard-step-2">
            <h2 className="onboard-title">设置主密码</h2>
            <p className="onboard-sub">主密码用于加密你的密钥库，仅存于本机，任何云端都看不到它。</p>
            <form
              className="onboard-form"
              autoComplete="off"
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                if (password.length >= 8 && password === confirm && !busy) void goToRecovery();
              }}
            >
              <label className="field">
                <span className="field-label">主密码</span>
                <span className="input-wrap">
                  <input
                    type={showPw ? "text" : "password"}
                    placeholder="至少 8 位"
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
              <div className="strength-meter" data-lv={lv} aria-hidden="true">
                <span className="strength-seg" />
                <span className="strength-seg" />
                <span className="strength-seg" />
                <span className="strength-seg" />
                <span className="strength-label">{lv === 0 ? "—" : STRENGTH_LABELS[lv]}</span>
              </div>
              <label className="field">
                <span className="field-label">确认主密码</span>
                <span className="input-wrap">
                  <input
                    type={showPw ? "text" : "password"}
                    placeholder="再次输入主密码"
                    value={confirm}
                    aria-label="确认主密码"
                    onChange={(e) => {
                      setConfirm(e.target.value);
                      if (error) setError("");
                    }}
                  />
                </span>
              </label>
              {shownError ? (
                <p className="onboard-error" role="alert">
                  {shownError}
                </p>
              ) : null}
              <div className="modal-actions onboard-actions">
                <button type="button" className="btn btn-ghost" onClick={() => goBack(1)}>
                  上一步
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={busy || !lenOk || password !== confirm}
                >
                  {busy ? "创建中…" : "下一步"}
                </button>
              </div>
            </form>
          </div>
        ) : null}

        {/* Step 3：恢复码（仅一次） */}
        {step === 3 && recoveryCode ? (
          <div className="onboard-step active" data-testid="onboard-step-3">
            <h2 className="onboard-title">保存恢复码</h2>
            <p className="onboard-sub">
              恢复码是主密码之外的第二把钥匙，<b className="onboard-warn">仅显示这一次</b>。
            </p>
            <div className="recovery-code" data-testid="ob-code">
              {recoveryCode}
            </div>
            <div className="recovery-warn onboard-recovery-warn">
              <Icon name="lock" size={15} />
              <span>请抄写到纸上或存入密码管理器；应用不会再次展示、不会上传。</span>
            </div>
            <div className="onboard-code-actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => copyWithClear(ctx, recoveryCode.replace(/ /g, ""), "recovery", "code")}
              >
                复制恢复码
              </button>
            </div>
            <label className="onboard-check">
              <input
                type="checkbox"
                checked={saved}
                aria-label="我已妥善保存恢复码"
                onChange={(e) => setSaved(e.target.checked)}
              />
              <span>我已妥善保存恢复码</span>
            </label>
            <div className="modal-actions onboard-actions">
              <button type="button" className="btn btn-ghost" onClick={() => goBack(2)}>
                上一步
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={!saved}
                onClick={() => {
                  setError("");
                  setStep(4);
                }}
              >
                下一步
              </button>
            </div>
          </div>
        ) : null}

        {/* Step 4：完成 */}
        {step === 4 ? (
          <div className="onboard-step active" data-testid="onboard-step-4">
            <div className="onboard-done-icon" aria-hidden="true">
              <Icon name="check" size={30} />
            </div>
            <h2 className="onboard-title">初始化完成</h2>
            <p className="onboard-sub">密钥库已创建并加密，主密码与恢复码均已生效。</p>
            {error ? (
              <p className="onboard-error" role="alert">
                {error}
              </p>
            ) : null}
            <button
              type="button"
              className="btn btn-primary btn-block"
              disabled={busy}
              onClick={() => void finish()}
            >
              {busy ? "进入中…" : "进入 LightKey"}
            </button>
          </div>
        ) : null}
      </div>
    </section>
  );
}
OnboardingPage.slot = "content" as const;

/** 插件工厂：注册 content 槽位组件（page=onboarding；锁态整页由宿主渲染，
 *  与 ui-unlock 互斥——门控数据 = session.initialized）。 */
export const uiOnboarding: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-onboarding",
      slot: config.slot ?? OnboardingPage.slot ?? "content",
      order: config.order ?? 0,
      component: (() => {
        const Comp = () => <OnboardingPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "onboarding" },
    });
  },
  {
    inject: ["slots", "session", "ipc", "toast"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);
