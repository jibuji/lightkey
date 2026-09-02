/**
 * approval 插件（M2；spec §6.5 + authorization-gate.md §6）。
 *
 * 订阅 `authz.request`（Rust authz-gate → 通知桥 → 帧 → 本层事件）→ 渲染
 * 审批弹窗：启动者 · 项目目录 · 命令（等宽）· 请求 key 名 Tag 集 ·
 * **倒计时环形（默认拒绝；时长取自 config `approvalTimeoutSecs`，缺省 30s）**
 * · 「允许本次」「拒绝」；Esc = 拒绝；超时自动关闭（守护进程侧超时审计
 * `timeout`，弹窗本地倒计时到期即关闭，不重复回传）。
 *
 * **锁定态一体化（#67 注入 / #23 读通道）**：帧携带 `needsUnlock=true` 时
 * （守护进程锁态收到 `authz.evaluate` / 锁态 `item.get` / `item.export` 且
 * 桌面在场），弹窗额外渲染**主密码输入栏**（身份确认）：「解锁并允许」=
 * 一次性完成 临时解锁 + 本次授权；解锁失败（VaultInvalidError / 限流）→
 * 弹窗停留显示错误，倒计时继续（守护进程侧条目保留可重试，AuthGuard
 * 不绕过）。允许后**不创建会话**——本次交互不产生 item.* 全量能力（#65）。
 * 锁态（`session.unlocked=false`）下只有 needsUnlock 帧会弹窗；普通
 * authz.request 仍被门控丢弃（QA P1 语义不变）。锁态 read/export 弹窗
 * 无「允许并为此项目记住」（临时 vault 无法持久化规则，补充拍板 #23）。
 *
 * **写入门（M2.97，补充拍板 #24；write-gate.md §6）**：kind=write 帧
 * （command=`item.put/delete <name>`，keys=单元素[目标条目名]）渲染动作 +
 * 目标条目名 + projectDir + 30s 倒计时，**不展示值**；「允许并为此项目
 * 记住」仅 put（create/update）提供（= allow + 最小写规则
 * `keys=[条目名] + actions=[create,update]`），**delete 无记住按钮**
 * （恒弹窗语义，任何规则不豁免——对齐 export）。
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
import { VaultInvalidError } from "../ipc";
import { APPROVAL_KINDS } from "../ipc/protocol";
import { formatProjectDir } from "../utils/projectDir";

/** 审批超时默认值（秒；与守护进程 `approval_timeout_secs` 默认值对齐）。
 *  仅作缺省兜底——实际倒计时取自 config `approvalTimeoutSecs`（#50）。 */
export const DEFAULT_APPROVAL_TIMEOUT_SECS = 30;

/** 读取审批超时秒数：config `approvalTimeoutSecs`（缺省/异常 → 默认 30）。
 *  与守护进程 `approval_timeout_secs.max(1)` 逐值对齐（0 → 1s，UI 与决策
 *  窗口不漂移）；负数 / 非有限值 / 缺省 → 默认 30。 */
async function readApprovalTimeoutSecs(ctx: Context): Promise<number> {
  try {
    const cfg = await ctx.ipc.configGet();
    const t = cfg?.approvalTimeoutSecs;
    return typeof t === "number" && Number.isFinite(t) && t >= 0
      ? Math.max(1, t)
      : DEFAULT_APPROVAL_TIMEOUT_SECS;
  } catch {
    return DEFAULT_APPROVAL_TIMEOUT_SECS;
  }
}

/** 字节规模人性化展示（export 弹窗的数据包规模；M2.9 值披露）。 */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** 解析后的审批类型（补充拍板 #22 增 `rule`；M2.97 写门 #24 增 `write`）。
 *  白名单单一来源 = `ipc/protocol.ts` 的 `APPROVAL_KINDS`（镜像 Rust
 *  `ApprovalKind` serde 值）。未知/缺失 → `"unknown"` **防御性渲染**（明确
 *  提示，不回退按 inject 渲染——协议演进时旧 UI 不误导，规格 #102 故事 25）。 */
type ApprovalKindValue = (typeof APPROVAL_KINDS)[keyof typeof APPROVAL_KINDS];
type ParsedKind = ApprovalKindValue | "unknown";

const KIND_WHITELIST: readonly string[] = Object.values(APPROVAL_KINDS);

function parseApprovalKind(raw: unknown): ParsedKind {
  return typeof raw === "string" && KIND_WHITELIST.includes(raw)
    ? (raw as ParsedKind)
    : "unknown";
}

interface ApprovalItem {
  request: AuthzRequestPayload;
  /** 剩余秒数（倒计时环形）。 */
  remain: number;
  /** 倒计时总秒数（config `approvalTimeoutSecs`，入队时读取）。 */
  total: number;
  /** 解锁失败错误文案（#67；弹窗停留显示，可重试）。 */
  error?: string;
}

/** 弹窗本体（手写 React：倒计时环形为原子组件，不拆内部结构）。
 *  `needsUnlock`（#67）：展示主密码输入栏；「解锁并允许」携带
 *  masterPassword 回传。
 *  M2.9 值披露：按 `kind` 选形态——`read`（条目名 Tag、无命令框、
 *  「允许并为此项目记住」= allow + rule.add）；`export`（额外展示数据包
 *  规模，无记住按钮——导出恒弹窗，规则不豁免）；`inject` 为既有形态。
 *  规则管理审批门（补充拍板 #22）：`rule` 展示命令框（`rule.add <name>` /
 *  `rule.remove <name>`）+ keys Tag + 30s 倒计时，**无「记住」按钮**（规则
 *  操作本身就是持久动作）。写入门（补充拍板 #24，M2.97）：`write` 展示
 *  动作（item.put=create/update / item.delete=delete）+ 目标条目名 Tag +
 *  projectDir + 30s 倒计时，**不展示值**；「允许并为此项目记住」仅
 *  put（create/update）提供（= allow + 写规则），**delete 无记住按钮**
 *  （恒弹窗语义，对齐 export）。未知 kind **防御性渲染**：明确提示未知，
 *  不回退按 inject 渲染（协议演进时旧 UI 不误导）。 */
export function ApprovalDialog({
  item,
  onResolve,
}: {
  item: ApprovalItem;
  onResolve: (
    requestId: string,
    decision: "allowed" | "denied",
    challenge: string,
    masterPassword?: string,
    remember?: boolean,
  ) => Promise<void>;
}) {
  const req = item.request;
  const needsUnlock = req.needsUnlock;
  const kind = parseApprovalKind(req.kind);
  const isRead = kind === "read";
  const isExport = kind === "export";
  const isRule = kind === "rule";
  const isWrite = kind === "write";
  const isUnknown = kind === "unknown";
  const isRuleRemove = isRule && req.command.startsWith("rule.remove");
  // 写门动作派生（M2.97，write-gate.md §6）：帧 command 恒为
  // `item.put <name>` / `item.delete <name>`（§5.3 展示用；create/update
  // 由 daemon 从 id 有无权威派生、不进帧——§5.2 RPC 不拆）。既有先例同
  // isRuleRemove：`command.startsWith` 判定动作。
  const isWriteDelete = isWrite && req.command.startsWith("item.delete");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const deny = useCallback(() => {
    void onResolve(req.requestId, "denied", req.challenge);
  }, [onResolve, req.requestId, req.challenge]);

  const allow = useCallback(
    async (remember = false) => {
      if (submitting) return;
      // 解锁弹窗必须提供主密码（守护进程侧校验，错误不 resolve）
      if (needsUnlock && !password) return;
      setSubmitting(true);
      // 解锁结果由插件的 onResolve 决定弹窗去留（失败停留显示 item.error）
      if (needsUnlock) {
        await onResolve(req.requestId, "allowed", req.challenge, password);
      } else {
        await onResolve(req.requestId, "allowed", req.challenge, undefined, remember);
      }
      setSubmitting(false);
    },
    [submitting, needsUnlock, password, onResolve, req.requestId, req.challenge],
  );

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
        <p className="modal-desc">
          {needsUnlock
            ? isRead
              ? "解锁态未就绪：输入主密码完成临时解锁并读取该项目目录下条目的值（不创建会话，仅本次披露）"
              : isExport
                ? "解锁态未就绪：输入主密码完成临时解锁并导出条目数据包（不创建会话，仅本次披露）"
                : "解锁态未就绪：输入主密码完成临时解锁并授权本次注入（不创建会话）"
            : isRead
              ? "Agent 请求读取该项目目录下条目的值（值不会显示，批准后仅返回给发起程序）"
              : isExport
                ? "Agent 请求导出条目数据包（附件明文将离开守护进程，请确认）"
              : isRule
                ? isRuleRemove
                  ? "Agent 请求删除既有授权规则（撤销已授予的读取/注入能力；批准后立即生效并随同步传播）"
                  : "Agent 请求建立持久化授权规则（批准后写入规则库；此为持久授权，请确认范围）"
                : isWrite
                  ? isWriteDelete
                    ? "Agent 请求删除该项目目录下的条目（破坏性操作；任何规则不豁免，恒需本次审批）"
                    : "Agent 请求写入该项目目录下的条目（新建或整条替换；条目值不会显示）"
                  : isUnknown
                    ? `未知审批类型（kind=${String(req.kind ?? "缺失")}）：当前界面版本不认识该请求，请升级应用后处理；无法确认内容前建议拒绝`
                    : "Agent 请求在项目目录中执行命令并注入密钥（密钥值不会显示）"}
        </p>
        <div className="approval-source">
          <span className="approval-avatar">
            <Icon name="terminal" size={18} />
          </span>
          <div>
            <div style={{ fontWeight: 600 }}>{req.starter}</div>
            <div style={{ color: "var(--fg-2)", fontSize: "var(--fs-xs)" }}>
              <Icon name="folder" size={13} /> {formatProjectDir(req.projectDir)}
            </div>
          </div>
        </div>
        {isExport && req.exportMeta ? (
          // export：数据包规模（name/mime/size；不含数据本身）
          <div className="approval-cmd-box">
            {req.exportMeta.name} · {req.exportMeta.mime} · {formatSize(req.exportMeta.size)}
          </div>
        ) : null}
        {isRule ? (
          // 规则门（补充拍板 #22）：命令框承载操作（非 shell 命令，无 $ 前缀）
          <div className="approval-cmd-box">
            {isRuleRemove ? "移除规则：" : "新建规则："}
            {req.command}
          </div>
        ) : isWrite ? (
          // 写门（M2.97）：命令框承载动作 + 目标条目名（`item.put/delete
          // <name>` 是 RPC 摘要而非 shell 命令，无 $ 前缀——同规则门先例）。
          // put 在帧面不可分 create/update（§5.2 RPC 不拆），按动作类展示。
          <div className="approval-cmd-box">
            {isWriteDelete ? "删除条目（delete）：" : "写入条目（create/update）："}
            {req.command}
          </div>
        ) : !isRead && !isExport && !isUnknown ? (
          <div className="approval-cmd-box">$ {req.command}</div>
        ) : null}
        <div className="approval-keys">
          {req.keys.map((k) => (
            <span className="key-tag" key={k}>
              {k}
            </span>
          ))}
        </div>
        {needsUnlock ? (
          <label className="field approval-unlock-field">
            <span className="field-label">主密码（临时解锁 · 仅本次注入）</span>
            <span className="input-wrap">
              <input
                type={showPw ? "text" : "password"}
                placeholder="输入主密码"
                value={password}
                autoFocus
                aria-label="主密码"
                autoComplete="off"
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (item.error !== undefined) item.error = undefined;
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
        ) : null}
        {item.error ? (
          <p className="field-error approval-error" role="alert">
            {item.error}
          </p>
        ) : null}
        <div className="approval-timer">
          <CountdownRing total={item.total} remain={item.remain} />
          <span>
            超时默认<b style={{ color: "var(--danger)" }}>拒绝</b> · 剩余{" "}
            <b>{item.remain}</b> 秒
          </span>
        </div>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={deny} disabled={submitting}>
            拒绝
          </button>
          {/* 「允许并为此项目记住」：allow 决策 + 追加一条最小授权规则（默认
              不持久化，用户显式选择）。适用面 = read（追加 read 规则，M2.9）
              + write 的 put（追加写规则，M2.97）；export 恒弹窗语义 → 不提供
              记住；delete 同为恒弹窗（任何规则不豁免）→ 亦不提供。锁态一体化
              （#23，补充拍板 #23）：临时 vault 无法持久化规则——记住按钮
              渲染条件 = `(isRead || (isWrite && !isWriteDelete)) &&
              !needsUnlock`（write 帧守护进程恒 needs_unlock=false，防御保持
              同一条件），锁态弹窗不承诺做不到的事。 */}
          {(isRead || (isWrite && !isWriteDelete)) && !needsUnlock ? (
            <button
              className="btn"
              onClick={() => void allow(true)}
              disabled={submitting}
            >
              允许并为此项目记住
            </button>
          ) : null}
          <button
            className="btn btn-primary"
            onClick={() => void allow()}
            disabled={submitting || (needsUnlock && !password)}
          >
            {needsUnlock ? "解锁并允许" : "允许本次"}
          </button>
        </div>
      </div>
    </div>
  );
}

/** 弹窗宿主：队列消费 + 倒计时（每秒 tick；到期自动关闭不回传——守护进程
 * 侧超时审计 timeout）。 */
function ApprovalHost({
  current,
  onResolve,
  onExpire,
}: {
  current: ApprovalItem | null;
  onResolve: (
    requestId: string,
    decision: "allowed" | "denied",
    challenge: string,
    masterPassword?: string,
    remember?: boolean,
  ) => Promise<void>;
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
        onResolve={async (requestId, decision, challenge, masterPassword, remember) => {
          try {
            const { accepted } =
              masterPassword === undefined
                ? await ctx.ipc.approvalResult(requestId, decision, challenge)
                : await ctx.ipc.approvalResult(
                    requestId,
                    decision,
                    challenge,
                    masterPassword,
                  );
            if (decision === "allowed") {
              ctx.toast.show(accepted ? "已允许本次（env 仅注入被批准 key）" : "请求已超时，未生效");
              // 审批的「允许并为此项目记住」：allow 后追加一条最小授权规则。
              // read（M2.9 值披露 §6）：channel=desktop、capability=read、
              // keys=[条目名]。write put（M2.97 写门 §6）：capability=write、
              // keys=[条目名] + actions=[create, update]——帧 command 恒为
              // `item.put <name>`，create/update 由 daemon 权威派生、不进帧
              // （§5.2 RPC 不拆），记住授予的是 put 全类；delete 无记住入口
              // （恒弹窗）。projectDir=弹窗展示的 cwd。仅 accepted 时写
              // （超时/伪造回传不预授权）；失败不阻塞弹窗关闭，仅提示。
              const r = queue[0]?.request;
              const isReadFrame = r?.kind === "read";
              const isWritePutFrame = r?.kind === "write" && r.command.startsWith("item.put");
              if (remember && accepted && r && (isReadFrame || isWritePutFrame)) {
                try {
                  await ctx.ipc.ruleAdd({
                    projectDir: r.projectDir,
                    name: `${isReadFrame ? "read" : "write"}-${r.keys[0] ?? "item"}`,
                    command: "",
                    keys: r.keys,
                    capability: isReadFrame ? "read" : "write",
                    ...(isReadFrame ? {} : { actions: ["create", "update"] }),
                  });
                } catch {
                  ctx.toast.show("记住规则写入失败（可稍后在规则页手动添加）");
                }
              }
            } else {
              ctx.toast.show("已拒绝（已写审计）");
            }
            queue.shift();
            render();
          } catch (e) {
            // 解锁失败（#67 锁定态一体化）：弹窗停留显示错误，倒计时继续
            // ——守护进程侧条目保留（未 resolve），可重试；AuthGuard 限流
            // 不绕过。其它错误（会话失效等）→ 弹窗仍须关闭，不能卡死（QA P1）
            if (e instanceof VaultInvalidError && queue[0]?.request.needsUnlock) {
              queue[0].error = "解锁失败（主密码错误或库未初始化）";
              render();
            } else {
              ctx.toast.show("审批回传失败（会话可能已锁定），弹窗已关闭");
              queue.shift();
              render();
            }
          }
        }}
        onExpire={() => {
          // 超时：守护进程侧超时审计 timeout；弹窗关闭、不回传
          queue.shift();
          render();
        }}
      />,
    );
  };

  // 订阅 authz.request：入队 + 弹窗（倒计时由宿主驱动，时长取自 config）。
  // 门控：普通帧仍要求解锁态；锁定态只接受 needsUnlock 一体化帧（#67，
  // 锁态不渲染无关请求元数据——QA P1 语义不变）。
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
    if (!unlocked && !payload.needsUnlock) return;
    // 入队前读 config（#50）：倒计时 total/remain 取自 approvalTimeoutSecs，
    // 与守护进程决策窗口同源；读取期间锁定则不入队。
    void (async () => {
      const total = await readApprovalTimeoutSecs(ctx);
      if (!unlocked && !payload.needsUnlock) return;
      queue.push({ request: payload, remain: total, total });
      // 强提醒（#95）：弹窗只存在于窗口内部，窗口最小化/隐藏到托盘/被遮挡
      // 时用户零感知，必须由操作系统级提醒兜底。仅在队列从空变非空时发
      // （聚合：已在等待的请求不重复刷屏）。
      // 载荷按保守口径只带 starter / projectDir（通知进系统通知中心与锁屏
      // 预览，等同离开守护进程保护）。
      if (queue.length === 1) {
        // 发射后不管：提醒是旁路，其失败不得冒泡成未处理拒绝污染宿主
        void ctx.shell
          .alertApproval({
            starter: payload.starter,
            projectDir: payload.projectDir,
          })
          .catch(() => {});
      }
      mount();
      render();
    })();
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
  inject: ["ipc", "toast", "session", "shell"],
});