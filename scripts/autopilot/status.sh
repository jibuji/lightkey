#!/usr/bin/env bash
# autopilot 存活自查（补充拍板 #29 / 规格 workflows/issue-autopilot.md §9）
#
# 两层看活机制的「本机一眼看全」层；另一层是 .github/workflows/autopilot-watchdog.yml
# （跑在 GitHub 侧，本机整个关机时仍能发现心跳失联并打 heartbeat-stale 标签）。
#
# 用法: bash scripts/autopilot/status.sh [--json]
# 退出码: 0 ALIVE（活）| 0 PAUSED（人主动停的，按设计不算死）
#         1 SUSPECT（心跳超阈值 / stale 标签在场 / 看门狗没跑或已 failure）
#         2 BROKEN（循环根本不可能在跑：host.toml 缺失、gh 不可用、workflow 未合入）
# 回归: bash scripts/autopilot/tests/status.t.sh
set -uo pipefail

STATE_DIR="${AUTOPILOT_STATE_DIR:-${HOME}/.local/state/lightkey-autopilot}"
CONF="${HOME}/.config/lightkey-autopilot/host.toml"
LOOP_LOCK="$STATE_DIR/loop.lock"
LOCK="$STATE_DIR/poll.lock"
LOG="${STATE_DIR}/poll.log"
RUNS_DIR="${STATE_DIR}/runs"
STALE_MINUTES="${AUTOPILOT_STALE_MINUTES:-45}"
JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root" || exit 2

now=$(date -u +%s)
problems=0          # 1 = 可疑
broken=0            # 2 = 坏了/未安装（优先于可疑）
kv() { printf '%-26s %s\n' "$1" "$2"; }
note_bad() { problems=1; printf '  !! %s\n' "$1" >&2; }
note() { printf '  -- %s\n' "$1" >&2; }
note_broken() { broken=2; problems=1; printf '  XXX %s\n' "$1" >&2; }

# ---- 1. 宿主配置 ------------------------------------------------------------
host_id="(unknown)"
if [[ -f "$CONF" ]]; then
  host_id=$(grep -m1 '^[[:space:]]*host_id[[:space:]]*=' "$CONF" | sed 's/.*=[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/')
  tracking=$(grep -m1 '^[[:space:]]*tracking_issue[[:space:]]*=' "$CONF" | sed 's/.*=[[:space:]]*//; s/"//g')
else
  tracking=""
  note_broken "host.toml 不存在（$CONF）→ 循环不可能在跑"
fi

# ---- 2. 驱动源：常驻实例锁 / 本轮锁 / systemd timer ---------------------------
holder_age_min() { # <pid> → 进程已跑分钟数（整型）或空
  local e
  e=$(ps -o etimes= -p "$1" 2>/dev/null | tr -d ' ')
  [[ -n "$e" ]] && echo $(( e / 60 ))
}
lock_pid() { # <锁文件> → 持有者 PID或空
  [[ -f "$1" ]] || return 0
  command -v fuser >/dev/null 2>&1 || return 0
  fuser "$1" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' | head -1
}

loop_owner="-"
lp=$(lock_pid "$LOOP_LOCK")
if [[ -n "$lp" ]]; then
  loop_owner="pid $lp（已跑 $(holder_age_min "$lp") 分）"
  # loop 实例活着但不写心跳 = 卡死；心跳部分在 §3 里判（last-ok 年龄）
else
  loop_owner="无常驻实例"
fi

lock_owner="-"
pid=$(lock_pid "$LOCK")
if [[ -n "$pid" ]]; then
  lock_owner="pid $pid（本轮已跑 $(holder_age_min "$pid") 分）"
  la=$(holder_age_min "$pid")
  [[ -n "$la" ]] && (( la > 60 )) && note_bad "本轮已跑 ${la} 分 > 60 分墙钟上限（§11），子进程可能卡住"
else
  lock_owner="free（此刻没在跑轮次）"
fi

timer_state="(无 systemctl)"
if command -v systemctl >/dev/null 2>&1; then
  timer_state=$(systemctl --user is-enabled lightkey-autopilot.timer 2>/dev/null || true)
  [[ -z "$timer_state" ]] && timer_state="未安装"
  running=$(systemctl --user is-active lightkey-autopilot.timer 2>/dev/null || true)
  [[ -n "$running" ]] && timer_state="$timer_state/$running"
  # 无驱动源只是诊断上下文：活没活由心跳说了算（stale 已在上面报），
  # 手动 run-once / 系统级 timer 都会让这里看着"没驱动源"，不该因此判死
  if [[ -z "$lp" && "$running" != "active" ]]; then
    note "无常驻 loop 也无活动 timer（$timer_state）—— 若你靠手动 run-once 驱动，这条可忽略"
  fi
fi

# ---- 3. tracking issue 心跳（真相面，跨机器可见） ---------------------------
last_ok="" age_min="n/a" stale_label="-" title="" paused=0 labels=""
if [[ -n "${tracking:-}" && "$tracking" =~ ^[0-9]+$ ]]; then
  body=$(gh issue view "$tracking" --json body,title,labels --jq '[.title,(.labels|map(.name)|join(",")),.body] | @tsv' 2>/dev/null | tail -1)
  if [[ -n "$body" ]]; then
    # gh 的 @tsv 会把正文换行转义成字面 \n（首遇真实心跳时实测暴露：grep 跨
    # 「行」咬到 `Z\n-` → 解析失败假报 SUSPECT）→ 先反转义回真实多行
    issue_body=$(printf '%s' "$body" | cut -f3- | sed 's/\\n/\n/g')
    title=$(printf '%s' "$body" | cut -f1)
    labels=$(printf '%s' "$body" | cut -f2)
    case "$title" in *"[PAUSED]"*) paused=1;; esac
    raw=$(printf '%s' "$issue_body" | grep -oE 'last-ok:[[:space:]]*[^ ",]+' | head -1 | sed 's/.*last-ok:[[:space:]]*//')
    last_ok="$raw"
    # 严格形状校验：`date -d ""` 会返回今日零点（= 假装“4 小时前还活着”），必须是 ISO 形状才算
    if [[ -n "$raw" && ! "$raw" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2} ]]; then
      note_bad "last-ok 不是 ISO-8601 形状，视为无心跳：$raw"
      raw=""
    fi
    if [[ -n "$raw" ]]; then
      ts=$(date -u -d "$raw" +%s 2>/dev/null || echo "")
      if [[ -n "$ts" ]]; then
        age_min=$(( (now - ts) / 60 ))
        if (( age_min > STALE_MINUTES )) && (( paused == 0 )); then
          problems=1; note_bad "心跳 stale：${age_min}m > ${STALE_MINUTES}m"
        fi
      else
        note_bad "last-ok 时间戳无法解析：$raw"
      fi
    else
      note_bad "tracking issue 正文没有 last-ok: 行"
    fi
    case ",$labels," in *",heartbeat-stale,"*) stale_label="YES（GitHub 侧看门狗已判定失联）"
        # 外部见证说死了就是死了（哪怕本机算出来心跳很新）：要么真死，要么看门狗
        # 摘标签的路径坏了，两者都值得看一眼；[PAUSED] 下不报警
        (( paused )) || note_bad "heartbeat-stale 标签在场（本机算出的心跳年龄 ${age_min} 分）";;
      *) stale_label="no";;
    esac
    (( paused )) && note "标题含 [PAUSED]：人主动停的，按设计不算死"
  else
    note_broken "gh issue view #$tracking 失败（token 过期 / 无网 / 号配错）"
  fi
else
  note_bad "host.toml 未配 tracking_issue → GitHub 侧看门狗也无从判定"
fi

# ---- 4. 外部见证：看门狗 workflow 自己活着吗 --------------------------------
watchdog="-"
run=$(gh run list --workflow autopilot-watchdog.yml --limit 1 --json status,conclusion,createdAt,displayTitle --jq '.[0] | [.status,(.conclusion//"-"),.createdAt,.displayTitle] | @tsv' 2>/dev/null | tail -1)
if [[ -n "$run" ]]; then
  w_status=$(printf '%s' "$run" | cut -f1); w_concl=$(printf '%s' "$run" | cut -f2); w_at=$(printf '%s' "$run" | cut -f3)
  wts=$(date -u -d "$w_at" +%s 2>/dev/null || echo "")
  if [[ -n "$wts" ]]; then
    w_age=$(( (now - wts) / 60 ))
    watchdog="${w_status}/${w_concl} @ ${w_at} (${w_age}m ago)"
    (( w_age > 120 )) && note_bad "看门狗自己 ${w_age}m 没跑（schedule 可能被 GitHub 停了：私有库 60 天无活动）"
    [[ "$w_concl" == "failure" ]] && note_bad "最近一次看门狗 = failure（心跳失联已被判定，去看 tracking issue 评论）"
  else
    watchdog="${w_status}/${w_concl} @ ${w_at}"
  fi
else
  note_broken "看不到 autopilot-watchdog 运行记录（workflow 未合入 main / gh 无权）"
fi

# ---- 5. 本机日志与配额 ------------------------------------------------------
last_log="-"
[[ -f "$LOG" ]] && last_log="$(tail -3 "$LOG" | tr '\n' ' | ')" || note_bad "没有轮次日志 $LOG"
qf="${STATE_DIR}/quota-$(date -u +%F).json"
quota=$([[ -f "$qf" ]] && head -c 300 "$qf" || echo "0/3（今日未启动过 implement）")

# ---- 6. 在跑的活 ------------------------------------------------------------
inflight=$(gh issue list --state open --label agent-working --json number,title --jq '.[] | "#\(.number) \(.title)"' 2>/dev/null | head -5 | paste -sd' ; ' -)
[[ -z "$inflight" ]] && inflight="(无)"

# ---- 输出 -------------------------------------------------------------------
verdict="ALIVE"; (( problems )) && verdict="SUSPECT"; (( broken )) && verdict="BROKEN"
(( paused )) && (( broken == 0 )) && verdict="PAUSED"

if (( JSON )); then
  printf '{"verdict":"%s","host_id":"%s","last_ok":"%s","age_minutes":"%s","stale_label":"%s","watchdog":"%s","loop_owner":"%s","poll_lock_owner":"%s","timer":"%s","quota":"%s","inflight":"%s","log":"%s"}\n' \
    "$verdict" "$host_id" "$last_ok" "$age_min" "$stale_label" "$watchdog" \
    "$(printf '%s' "$loop_owner" | tr -d '"')" "$(printf '%s' "$lock_owner" | tr -d '"')" \
    "$(printf '%s' "$timer_state" | tr -d '"')" \
    "$(printf '%s' "$quota" | tr -d '"')" "$(printf '%s' "$inflight" | tr -d '"')" "$(printf '%s' "$last_log" | tr -d '"')"
else
  echo "autopilot status — host=${host_id}  verdict=${verdict}"
  kv "GitHub 心跳 last-ok"   "${last_ok:-（无）}  (age ${age_min} 分钟; 阈值 ${STALE_MINUTES})"
  kv "heartbeat-stale 标签"  "$stale_label"
  kv "看门狗 workflow"        "$watchdog"
  kv "驱动源 timer"            "$timer_state"
  kv "常驻 loop（loop.lock）"  "$loop_owner"
  kv "本轮锁（poll.lock）"      "$lock_owner"
  kv "今日配额"               "$quota"
  kv "在跑（agent-working）"  "$inflight"
  kv "轮次日志尾"             "$last_log"
  kv "runs 目录"              "$RUNS_DIR"
  echo
  echo "提示：本机层看不到「机器整个关机」这一类死法 —— 那种只能靠 GitHub 侧看门狗"
  echo "      （autopilot-watchdog.yml）与它打的 heartbeat-stale 标签。"
  echo "      防重复启动/停循环：bash scripts/autopilot/ctl.sh <start|stop|status|run-once|install>"
fi
if (( broken )); then exit 2; elif (( problems )); then exit 1; else exit 0; fi
