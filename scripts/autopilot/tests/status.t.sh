#!/usr/bin/env bash
# status.sh 的离线回归：假 gh + 假 HOME，不碰真实凭据、不联网。
# 用法: bash scripts/autopilot/tests/status.t.sh
set -uo pipefail
S="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/status.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/home/.config/lightkey-autopilot" "$T/home/.local/state/lightkey-autopilot"

cat > "$T/bin/gh" <<'GH'
#!/usr/bin/env bash
case "$*" in
  *"--json body,title,labels"*)
    [[ -n "${FAKE_GH_FAIL:-}" ]] && exit 1
    printf '%s\t%s\t- last-ok: %s\n' "${FAKE_TITLE:-hb}" "${FAKE_LABELS:-}" "${FAKE_LASTOK:-}" ;;
  *"run list"*) [[ -n "${FAKE_WD:-}" ]] && printf 'completed\t%s\t%s\tautopilot-watchdog\n' "${FAKE_CONCL:-success}" "$FAKE_WD" ;;
  *"agent-working"*) printf '#173 在做的活\n' ;;
  *) printf '\n' ;;
esac
GH
chmod +x "$T/bin/gh"
printf 'host_id = "test-host"\ntracking_issue = 999\n' > "$T/home/.config/lightkey-autopilot/host.toml"
echo "round ok" > "$T/home/.local/state/lightkey-autopilot/poll.log"

iso() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }
pass=0 fail=0
t() { # <用例名> <期望退出码> <期望 verdict> [env=...]...
  local name="$1" expect="$2" expect_v="$3"; shift 3
  local out code verdict
  out=$(env HOME="$T/home" PATH="$T/bin:$PATH" "$@" bash "$S" 2>&1); code=$?
  verdict=$(printf '%s' "$out" | grep -o 'verdict=[A-Z]*' | head -1 | cut -d= -f2)
  if [[ "$code" == "$expect" && "$verdict" == "$expect_v" ]]; then
    pass=$((pass+1)); printf '  [PASS] %-34s exit=%s %s\n' "$name" "$code" "$verdict"
  else
    fail=$((fail+1)); printf '  [FAIL] %-34s exit=%s/%s 期望 %s/%s\n' "$name" "$code" "$verdict" "$expect" "$expect_v"
  fi
}

echo "=== status.sh 回归（心跳契约 + 看门狗健康 + 退出码） ==="
t "新鲜心跳 → ALIVE"            0 ALIVE   FAKE_LASTOK="$(iso '-10 minutes')" FAKE_WD="$(iso '-10 minutes')"
t "心跳 90 分 → SUSPECT"         1 SUSPECT FAKE_LASTOK="$(iso '-90 minutes')" FAKE_WD="$(iso '-10 minutes')"
t "看门狗 3h 没跑 → SUSPECT"     1 SUSPECT FAKE_LASTOK="$(iso '-10 minutes')" FAKE_WD="$(iso '-180 minutes')"
t "无 last-ok 行 → SUSPECT"      1 SUSPECT FAKE_LASTOK=""                     FAKE_WD="$(iso '-10 minutes')"
t "last-ok 形状坏 → SUSPECT"     1 SUSPECT FAKE_LASTOK="yesterday"            FAKE_WD="$(iso '-10 minutes')"
t "last-ok 无时区 → SUSPECT"     1 SUSPECT FAKE_LASTOK="2026-09-09T03:12"     FAKE_WD="$(iso '-10 minutes')"
t "看门狗 failure → SUSPECT"     1 SUSPECT FAKE_LASTOK="$(iso '-10 minutes')" FAKE_WD="$(iso '-10 minutes')" FAKE_CONCL=failure
t "stale 标签在场 → SUSPECT"     1 SUSPECT FAKE_LASTOK="$(iso '-10 minutes')" FAKE_WD="$(iso '-10 minutes')" FAKE_LABELS=heartbeat-stale
t "[PAUSED] 陈旧 → PAUSED 不报"  0 PAUSED  FAKE_LASTOK="$(iso '-90 minutes')" FAKE_TITLE="hb [PAUSED]" FAKE_WD="$(iso '-10 minutes')"
t "gh view 失败 → BROKEN"        2 BROKEN  FAKE_LASTOK="$(iso '-10 minutes')" FAKE_WD="$(iso '-10 minutes')" FAKE_GH_FAIL=1
rm "$T/home/.config/lightkey-autopilot/host.toml"
t "host.toml 缺失 → BROKEN"      2 BROKEN  FAKE_LASTOK="$(iso '-10 minutes')"
printf 'host_id = "test-host"\ntracking_issue = 999\n' > "$T/home/.config/lightkey-autopilot/host.toml"
rm "$T/bin/gh"
t "gh 不可用 → BROKEN"           2 BROKEN  FAKE_LASTOK="$(iso '-10 minutes')"

echo "PASS=$pass FAIL=$fail"
(( fail == 0 ))
