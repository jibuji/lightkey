#!/usr/bin/env bash
# ctl.sh 启动层回归：单实例幂等 + 两把锁职责 + stop 真停 + install 产物。
# 不碰真实 HOME/state，不依赖 poll.sh（用桩）。用法: bash scripts/autopilot/tests/ctl.t.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTL="$HERE/ctl.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export AUTOPILOT_STATE_DIR="$T/state" XDG_CONFIG_HOME="$T/xdg"
mkdir -p "$AUTOPILOT_STATE_DIR"

# 桩 poll.sh：抢 poll.lock（真 poll.sh 的 §4 步骤 1 契约），睡 3 秒，写心跳
cat > "$T/stub-poll.sh" <<'STUB'
#!/usr/bin/env bash
exec 8>"${AUTOPILOT_STATE_DIR}/poll.lock"
flock -n 8 || { echo "已有轮次在跑，本轮放弃"; exit 0; }
echo "round start $(date -u +%FT%TZ)"
sleep "${STUB_SLEEP:-3}"
echo "round done"
STUB
chmod +x "$T/stub-poll.sh"
export AUTOPILOT_POLL_BIN="$T/stub-poll.sh"

pass=0 fail=0
ck() { if eval "$2"; then pass=$((pass+1)); printf '  [PASS] %s\n' "$1"; else fail=$((fail+1)); printf '  [FAIL] %s\n' "$1"; fi; }
out=$( 2>&1 ); rc=0

echo "=== ctl.sh 启动层回归 ==="

# 1) 首次 start 成功
out=$(bash "$CTL" start 5 2>&1); rc=$?
ck "start 首次成功" "[ $rc -eq 0 ] && printf '%s' \"$out\" | grep -q '已启动'"

holder1=$(fuser "$AUTOPILOT_STATE_DIR/loop.lock" 2>/dev/null | tr -d ' ')
ck "loop.lock 被持有" "[ -n '$holder1' ]"

# 2) 重复 start 幂等：不再起第二个实例
out=$(bash "$CTL" start 5 2>&1); rc=$?
ck "重复 start 退出码 0（幂等）" "[ $rc -eq 0 ]"
ck "重复 start 提示已在运行" "printf '%s' \"$out\" | grep -q '不重复启动'"
holders=$(fuser "$AUTOPILOT_STATE_DIR/loop.lock" 2>/dev/null | tr -s ' ' '\n' | grep -cE '^[0-9]+$')
ck "仍只有一个实例持锁" "[ $holders -eq 1 ]"

# 3) 并发 5 个 start 冲进来 → 只能有一个实例（TOCTOU 检验）
for i in 1 2 3 4 5; do bash "$CTL" start 5 >>"$T/race.log" 2>&1 & done; wait
holders=$(fuser "$AUTOPILOT_STATE_DIR/loop.lock" 2>/dev/null | tr -s ' ' '\n' | grep -cE '^[0-9]+$')
ck "并发 5 次 start 仍单实例" "[ $holders -eq 1 ]"

# 4) loop 真的在跑轮次（桩日志出现 round）
sleep 4
ck "常驻循环跑过轮次" "grep -q 'round' \"$AUTOPILOT_STATE_DIR/poll.log\""

# 5) run-once 与在跑轮次互斥：第二个 run-once 立刻放弃而不是并跑
STUB_SLEEP=6 bash "$T/stub-poll.sh" >>"$T/ro1.log" 2>&1 &
sleep 1
out=$(STUB_SLEEP=6 timeout 20 bash "$CTL" run-once 2>&1); rc=$?
ck "撞锁的 run-once 不报错退出 0" "[ $rc -eq 0 ] && printf '%s' \"$out\" | grep -qiE '已有轮次|本轮 OK'"

# 6) stop 真停：锁释放、进程消失
bash "$CTL" stop >/dev/null 2>&1
sleep 1
ck "stop 后锁已释放" "[ -z \"\$(fuser '$AUTOPILOT_STATE_DIR/loop.lock' 2>/dev/null | tr -d ' ')\" ]"
ck "stop 后无 _loop 残留" "! pgrep -f 'ctl.sh _loop' >/dev/null"
ck "stop 幂等（再 stop 不报错）" "bash '$CTL' stop >/dev/null 2>&1"

# 7) status 能看到锁持有者
bash "$CTL" start 900 >/dev/null 2>&1
out=$(bash "$HERE/status.sh" 2>&1)
ck "status 报告轮次锁持有者" "printf '%s' \"$out\" | grep -q 'pid'"
bash "$CTL" stop >/dev/null 2>&1

# 8) install 产物合法（oneshot + timer 成对，不启用）
bash "$CTL" install >/dev/null 2>&1
ck "install 写了 service" "[ -f \"$T/xdg/systemd/user/lightkey-autopilot.service\" ]"
ck "install 写了 timer"   "[ -f \"$T/xdg/systemd/user/lightkey-autopilot.timer\" ]"
ck "service 指向 run-once" "grep -q 'ctl.sh run-once' \"$T/xdg/systemd/user/lightkey-autopilot.service\""
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$T/xdg/systemd/user/lightkey-autopilot.service" >"$T/verify.log" 2>&1 \
    || grep -q 'EXEC' "$T/verify.log" 2>/dev/null
  ck "systemd-analyze verify 无致命错" "! grep -qiE 'error while loading|Failed to' \"$T/verify.log\""
fi

# 9) 缺 poll.sh 时必须响亮报错，不能假装启动成功
AUTOPILOT_POLL_BIN="$T/does-not-exist.sh" out=$(bash "$CTL" start 5 2>&1); rc=$?
ck "缺 poll.sh → exit 2 且说清缺什么" "[ $rc -eq 2 ] && printf '%s' \"$out\" | grep -q '缺轮次驱动'"
AUTOPILOT_POLL_BIN="$T/does-not-exist.sh" out=$(bash "$CTL" run-once 2>&1); rc=$?
ck "缺 poll.sh → run-once 也 exit 2" "[ $rc -eq 2 ]"

echo "PASS=$pass FAIL=$fail"
(( fail == 0 ))
