#!/usr/bin/env bash
# issue-autopilot 启动层（规格 workflows/issue-autopilot.md §4.1 / 补充拍板 #29）
#
# 「已经启动了就不要再启动」的实现要点：**真相不能是 pid 文件**。
#   - pid 文件有 TOCTOU 竞态（两个 start 都判它"陈旧"就各起一个），被 SIGKILL 后残留
#     = 谎报在跑，pid 被复用 = 谎报没跑。
#   - 真相 = 内核对打开文件描述符持有的 flock：进程一死内核自动释放，不留孤儿锁。
#     所以**唯一的硬保证在子进程里**（`flock -n` 抢到才继续）；父进程事前的
#     `loop_holder` 检查只为给你一句人话提示，两个 start 同时冲进来也无害 ——
#     第二个子进程抢不到锁会自己退出 0。pid 文件仅作人读提示。
# 两把锁，职责不同，互不替代：
#   loop.lock  常驻循环实例锁（防两个 loop 并存）
#   poll.lock  单轮互斥锁（由 poll.sh 自己抢，规格 §4 步骤 1）；loop 在轮次之间不持它，
#              这样人工 `run-once` 与 cron 轮次是**排队**关系，不会被误判成"已在跑"
#
# 用法: bash scripts/autopilot/ctl.sh <command>
#   start [间隔秒]     后台起常驻循环（默认 900s = 15 分钟）；已在跑则提示后退出 0
#   stop               停常驻循环（TERM 整个进程组，等本轮收尾；30s 后 KILL）
#   restart [间隔秒]   stop + start
#   run-once           前台跑一轮（cron 与人工都用它；与循环共用 poll.lock）
#   status [--json]    转 scripts/autopilot/status.sh（两层看活，退出码 0/1/2）
#   tail               跟看轮次日志
#   install            生成 systemd user timer（推荐：机器重启自动续、崩溃可拉起）
#   uninstall          卸掉上面的 timer
set -uo pipefail

STATE_DIR="${AUTOPILOT_STATE_DIR:-$HOME/.local/state/lightkey-autopilot}"
LOOP_LOCK="$STATE_DIR/loop.lock"
PIDFILE="$STATE_DIR/loop.pid"
LOG="$STATE_DIR/poll.log"
INTERVAL_DEFAULT="${AUTOPILOT_INTERVAL:-900}"
ROUND_TIMEOUT_MIN="${AUTOPILOT_ROUND_TIMEOUT_MIN:-60}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLL_BIN="${AUTOPILOT_POLL_BIN:-$HERE/poll.sh}"

mkdir -p "$STATE_DIR"
info() { printf 'autopilot: %s\n' "$1"; }
die()  { printf 'autopilot: %s\n' "$1" >&2; exit "${2:-1}"; }

# 当前持有 loop.lock 的 PID（空 = 没人在跑）
loop_holder() {
  [[ -f "$LOOP_LOCK" ]] || return 0
  command -v fuser >/dev/null 2>&1 || return 0
  fuser "$LOOP_LOCK" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' | head -1
}

require_poll_bin() {
  [[ -f "$POLL_BIN" ]] && return 0
  die "缺轮次驱动 $POLL_BIN —— 循环本体尚未实现（实现清单见 workflows/issue-autopilot.md §16；本轮只落了启动层与看活层）" 2
}

# ---- 内部：常驻循环体。这里是单实例的**唯一硬闸门**。 ------------------------
cmd_loop() {
  local interval="${1:-$INTERVAL_DEFAULT}"
  exec 9>"$LOOP_LOCK"
  if ! flock -n 9; then
    info "已有 loop 持锁，本实例退出（不重复启动）"
    exit 0
  fi
  printf '%s\n' "$$" >"$PIDFILE"
  EXITED=0
  trap 'EXITED=1; info "收到停止信号，本轮结束后退出"' TERM INT
  info "loop 启动 pid=$$ interval=${interval}s poll_bin=$POLL_BIN"
  while (( EXITED == 0 )); do
    # **必须给子进程关掉 fd9**：否则 timeout/bash/sleep 都继承持锁描述符，
    # `fuser loop.lock` 会报出一堆 PID → 看活层误判为「多实例」
    if timeout "$(( ROUND_TIMEOUT_MIN * 60 ))" bash "$POLL_BIN" 9>&-; then
      :
    else
      info "本轮 exit=$?（不中断循环；超时=本轮被 kill，规格 §11）"
    fi
    local waited=0
    while (( waited < interval && EXITED == 0 )); do sleep 1 9>&-; waited=$((waited + 1)); done
  done
  rm -f "$PIDFILE"
  info "loop 已退出"
}

cmd_start() {
  local interval="${1:-$INTERVAL_DEFAULT}"
  require_poll_bin
  local holder; holder="$(loop_holder)"
  if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
    info "已在运行（loop pid=$holder），不重复启动；日志：$LOG"
    exit 0
  fi
  setsid bash "$HERE/ctl.sh" _loop "$interval" </dev/null >>"$LOG" 2>&1 &
  sleep 1
  holder="$(loop_holder)"
  if [[ -n "$holder" ]]; then
    info "已启动（loop pid=$holder，间隔 ${interval}s，日志 $LOG）"
  else
    die "子进程没能持锁或已立即退出 —— 日志尾部：$(tail -3 "$LOG" 2>/dev/null | tr '\n' ' ')" 1
  fi
}

cmd_stop() {
  local holder; holder="$(loop_holder)"
  if [[ -z "$holder" ]]; then
    [[ -f "$PIDFILE" ]] && info "锁无人持有（pid 文件残留 $(cat "$PIDFILE" 2>/dev/null)，按陈旧清理）"
    rm -f "$PIDFILE"
    info "未在运行，无需停止"
    return 0
  fi
  info "停止 loop pid=$holder（TERM 进程组，等本轮收尾，最多 30s）"
  kill -TERM "-$holder" 2>/dev/null || kill -TERM "$holder" 2>/dev/null \
    || die "无法向 pid=$holder 发信号（权限？）" 1
  for _ in $(seq 1 30); do kill -0 "$holder" 2>/dev/null || break; sleep 1; done
  if kill -0 "$holder" 2>/dev/null; then
    info "30s 仍未退出 → KILL（本轮没写心跳，GitHub 侧看门狗会报失活，属预期）"
    kill -KILL "-$holder" 2>/dev/null || kill -KILL "$holder" 2>/dev/null || true
    sleep 1
  fi
  # 只在确认无人持锁后删锁文件（删一个还被人持着的锁 = 下一个 start 能再起一个实例）
  if [[ -z "$(loop_holder)" ]]; then rm -f "$LOOP_LOCK"; fi
  rm -f "$PIDFILE"
  info "已停止"
}

cmd_run_once() {
  require_poll_bin
  info "跑一轮（超时 ${ROUND_TIMEOUT_MIN}m）"
  local rc=0
  timeout "$(( ROUND_TIMEOUT_MIN * 60 ))" bash "$POLL_BIN" "$@" || rc=$?
  case $rc in
    0)   info "本轮 OK" ;;
    124) die "本轮超 ${ROUND_TIMEOUT_MIN} 分钟被 kill（规格 §11：超时打回 ready-for-agent，不算该 issue 失败）" 1 ;;
    *)   die "本轮失败 exit=$rc（详见 $LOG）" "$rc" ;;
  esac
}

cmd_install() {
  local unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$unit_dir"
  # Type=oneshot 本身就不允许同一 unit 重叠启动（systemd 保证），poll.lock 再兜一层
  cat > "$unit_dir/lightkey-autopilot.service" <<EOF
# 生成物，勿手改：bash scripts/autopilot/ctl.sh install
[Unit]
Description=LightKey issue-autopilot 单轮
# 桌面/交互会话里跑要能访问用户级凭据与网络
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash $HERE/ctl.sh run-once
TimeoutStartSec=$(( ROUND_TIMEOUT_MIN * 60 + 120 ))
Nice=10
IOSchedulingClass=idle
EOF
  cat > "$unit_dir/lightkey-autopilot.timer" <<'EOF'
# 生成物，勿手改：bash scripts/autopilot/ctl.sh install
[Unit]
Description=LightKey issue-autopilot 每 15 分钟一轮

[Timer]
OnBootSec=2min
OnCalendar=*:0/15
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF
  info "已写 unit → $unit_dir/lightkey-autopilot.{service,timer}"
  info "启用（这步归你，本脚本不擅自启用）："
  info "  systemctl --user daemon-reload && systemctl --user enable --now lightkey-autopilot.timer"
  info "  loginctl enable-linger $USER   # 想让无人登录时也跑（服务器/长期开机的机器要）"
  info "二选一：装了 timer 就别再 ctl.sh start（两者靠 poll.lock 不会打架，但会互相排队浪费轮次）"
}

cmd_uninstall() {
  systemctl --user disable --now lightkey-autopilot.timer 2>/dev/null || true
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/lightkey-autopilot."{service,timer}
  systemctl --user daemon-reload 2>/dev/null || true
  info "已卸 timer（常驻 loop 若还在跑需另用 ctl.sh stop）"
}

case "${1:-}" in
  start)     shift; cmd_start "${1:-$INTERVAL_DEFAULT}" ;;
  stop)      cmd_stop ;;
  restart)   shift; local_iv="${1:-$INTERVAL_DEFAULT}"; cmd_stop; sleep 1; cmd_start "$local_iv" ;;
  run-once)  shift; cmd_run_once "$@" ;;
  status)    shift; exec bash "$HERE/status.sh" "$@" ;;
  tail)      [[ -f "$LOG" ]] && exec tail -n 50 -F "$LOG" || die "没有日志 $LOG（循环从未跑过）" 2 ;;
  install)   cmd_install ;;
  uninstall) cmd_uninstall ;;
  _loop)     shift; cmd_loop "$@" ;;
  *)         sed -n '/^# 用法:/,/^set -uo/p' "$HERE/ctl.sh" | grep '^#' | sed 's/^# \{0,2\}//'; exit 2 ;;
esac
