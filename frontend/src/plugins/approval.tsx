/**
 * approval 插件（M2；spec §6.5 + authorization-gate.md §6）。
 *
 * 订阅 `authz.request`（Rust authz-gate → 通知桥 → 帧 → 本层事件）→ 渲染
 * 审批弹窗：启动者 · 项目目录 · 命令（等宽）· 请求 key 名 Tag 集 ·
 * **30s 倒计时环形（默认拒绝）** · 「允许本次」「拒绝」；Esc = 拒绝；
 * 超时自动关闭（守护进程侧 30s 超时审计 `timeout`，弹窗本地倒计时到期
 * 即关闭，不重复回传）。
 *
 * 决策权始终在 Rust 侧（plugin-architecture.md §5.3）：本插件只把用户
 * 选择经 `approval.result` 回传，不持有裁决权；伪造/已超时 requestId →
 * 守护进程忽略（accepted=false）。
 *
 * 无槽位服务插件：自挂 React root 渲染弹窗层（portal 语义）。
 */

import { createRoot, type Root } from "react-dom/client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import type { AuthzRequestPayload } from "../events";
import { CountdownRing } from "../components/atoms";
import { Icon } from "../components/Icons";

/** 审批超时（秒；与守护进程 `approval_timeout_secs` 默认值对齐）。 */
export const APPROVAL_TIMEOUT_SECS = 30;

interface ApprovalItem {
  request: AuthzRequestPayload;
  /** 剩余秒数（倒计时环形）。 */
  remain: number;
}

/** 弹窗本体（手写 React：倒计时环形为原子组件，不拆内部结构）。 */
export function ApprovalDialog({
  item,
  onResolve,
}: {
  item: ApprovalItem;
  onResolve: (requestId: string, decision: "allowed" | "denied") => void;
}) {
  const req = item.request;
  const deny = useCallback(() => onResolve(req.requestId, "denied"), [onResolve, req.requestId]);

  // Esc = 拒绝（spec §6.5；弹窗存在期间生效）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") deny();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [deny]);

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="授权请求审批">
      <div className="modal approval-dialog">
        <h3 className="modal-title">授权请求 · {req.starter}</h3>
        <p className="modal-desc">Agent 请求在项目目录中执行命令并注入密钥（密钥值不会显示）</p>
        <div className="approval-source">
          <span className="approval-avatar">
            <Icon name="terminal" size={18} />
          </span>
          <div>
            <div style={{ fontWeight: 600 }}>{req.starter}</div>
            <div style={{ color: "var(--fg-2)", fontSize: "var(--fs-xs)" }}>
              <Icon name="folder" size={13} /> {req.projectDir}
            </div>
          </div>
        </div>
        <div className="approval-cmd-box">$ {req.command}</div>
        <div className="approval-keys">
          {req.keys.map((k) => (
            <span className="key-tag" key={k}>
              {k}
            </span>
          ))}
        </div>
        <div className="approval-timer">
          <CountdownRing total={APPROVAL_TIMEOUT_SECS} remain={item.remain} />
          <span>
            超时默认<b style={{ color: "var(--danger)" }}>拒绝</b> · 剩余{" "}
            <b>{item.remain}</b> 秒
          </span>
        </div>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={deny}>
            拒绝
          </button>
          <button className="btn btn-primary" onClick={() => onResolve(req.requestId, "allowed")}>
            允许本次
          </button>
        </div>
      </div>
    </div>
  );
}

/** 弹窗宿主：队列消费 + 倒计时（每秒 tick；到期自动关闭不回传——守护进程
 * 侧 30s 超时审计 timeout）。 */
function ApprovalHost({
  current,
  onResolve,
  onExpire,
}: {
  current: ApprovalItem | null;
  onResolve: (requestId: string, decision: "allowed" | "denied") => void;
  onExpire: () => void;
}) {
  // 回调经 ref 持有：插件每次 render() 会新建闭包，但倒计时只随 current 重启
  const resolveRef = useRef(onResolve);
  resolveRef.current = onResolve;
  const expireRef = useRef(onExpire);
  expireRef.current = onExpire;

  const [remain, setRemain] = useState(current?.remain ?? 0);
  useEffect(() => {
    if (!current) return;
    setRemain(current.remain);
    let remain = current.remain;
    const timer = setInterval(() => {
      remain -= 1;
      if (remain <= 0) {
        clearInterval(timer);
        expireRef.current();
        return;
      }
      setRemain(remain);
    }, 1000);
    return () => clearInterval(timer);
  }, [current]);
  return current ? (
    <ApprovalDialog item={{ ...current, remain }} onResolve={resolveRef.current} />
  ) : null;
}

/** 插件工厂：无槽位服务；订阅 authz.request → 弹窗队列。 */
export const approval: Plugin.Function<Context> = Object.assign((ctx: Context) => {
  let rootEl: HTMLDivElement | null = null;
  let root: Root | null = null;

  // 队列（同时多个 evaluate 进第 3 层 → 逐个展示；新请求入队）
  const queue: ApprovalItem[] = [];

  const mount = () => {
    if (rootEl) return;
    rootEl = document.createElement("div");
    rootEl.className = "approval-root";
    document.body.appendChild(rootEl);
    root = createRoot(rootEl);
    render();
  };

  const render = () => {
    if (!root) return;
    root.render(
      <ApprovalHost
        current={queue[0] ?? null}
        onResolve={(requestId, decision) => {
          void ctx.ipc
            .approvalResult(requestId, decision)
            .then(({ accepted }) => {
              // accepted=false = 守护进程已超时/伪造 id；弹窗照常关闭
              if (decision === "allowed") {
                ctx.toast.show(accepted ? "已允许本次（env 仅注入被批准 key）" : "请求已超时，未生效");
              } else {
                ctx.toast.show("已拒绝（已写审计）");
              }
            })
            .catch(() => {
              // 会话失效等回传失败：弹窗仍须关闭，不能卡死（QA P1）
              ctx.toast.show("审批回传失败（会话可能已锁定），弹窗已关闭");
            })
            .finally(() => {
              queue.shift();
              render();
            });
        }}
        onExpire={() => {
          // 超时：守护进程侧 30s 超时审计 timeout；弹窗关闭、不回传
          queue.shift();
          render();
        }}
      />,
    );
  };

  // 订阅 authz.request：入队 + 弹窗（30s 倒计时由宿主驱动）。
  // 锁态门控（QA P1）：锁定时不渲染弹窗、不展示任何请求元数据——守护进程侧
  // 30s 超时默认拒绝照常生效；解锁态才接受弹窗。
  let unlocked = ctx.session.unlocked;
  const offUnlocked = ctx.on("session.unlocked", () => {
    unlocked = true;
  });
  const offLocked = ctx.on("session.locked", () => {
    // 自动锁定/手动锁定时清队列并关弹窗：portal 层独立于锁态整页，
    // 不随宿主卸载，必须自行响应 session.locked（QA P2）
    unlocked = false;
    queue.length = 0;
    render();
  });
  ctx.on("authz.request", (payload: AuthzRequestPayload) => {
    if (!unlocked) return;
    queue.push({ request: payload, remain: APPROVAL_TIMEOUT_SECS });
    mount();
    render();
  });

  return () => {
    // 可逆副作用：卸载时移除弹窗层
    offUnlocked();
    offLocked();
    if (root) root.unmount();
    if (rootEl) rootEl.remove();
    root = null;
    rootEl = null;
    queue.length = 0;
  };
}, {
  inject: ["ipc", "toast", "session"],
});
