#!/usr/bin/env bash
# issue-autopilot 公共层（规格 workflows/issue-autopilot.md §16 实现清单的支撑件）
#
# 职责：host.toml 解析、状态目录/日志、ISO 时间、每日配额计数器、runs 落盘路径、
# 脱敏。只定义函数，source 无副作用（回归见 tests/poll.t.sh）。
#
# 运行时依赖刻意收敛为 bash + coreutils + git + gh（Windows Git Bash 同形可跑；
# jq/python 不进运行时 —— 它们在 Git Bash 默认不存在，A14）。
# shellcheck shell=bash disable=SC2317

AP_CONF_DEFAULT="$HOME/.config/lightkey-autopilot/host.toml"

ap_conf_path() { printf '%s\n' "${AUTOPILOT_CONF:-$AP_CONF_DEFAULT}"; }

ap_state_dir() { printf '%s\n' "${AUTOPILOT_STATE_DIR:-$HOME/.local/state/lightkey-autopilot}"; }

# 仓库根：优先 AUTOPILOT_REPO_DIR；否则按 source 者位置推（poll.sh/probe 在 scripts/autopilot/ 下）
ap_repo_dir() {
  if [[ -n "${AUTOPILOT_REPO_DIR:-}" ]]; then printf '%s\n' "$AUTOPILOT_REPO_DIR"; return 0; fi
  local d="${BASH_SOURCE[1]}"
  d="$(cd "$(dirname "$d")/../.." && pwd)" && printf '%s\n' "$d"
}

# 取 host.toml 标量（去引号）；键不存在输出空串并返回 1
ap_conf_get() { # <key>
  local conf v
  conf="$(ap_conf_path)"
  [[ -f "$conf" ]] || return 1
  v=$(grep -m1 "^[[:space:]]*$1[[:space:]]*=" "$conf" | tail -1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//' | tr -d '\r')
  v="${v%\"}"; v="${v#\"}"
  printf '%s\n' "$v"
  [[ -n "$v" ]]
}

# 取 host.toml 数组键（claimed_capabilities 等），逐元素一行
ap_conf_list() { # <key>
  local conf
  conf="$(ap_conf_path)"
  [[ -f "$conf" ]] || return 1
  grep -m1 "^[[:space:]]*$1[[:space:]]*=" "$conf" | sed 's/^[^=]*=//' \
    | tr -d '[]"' | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$'
}

ap_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ap_now_epoch() { date -u +%s; }

# 轮次日志：交互 run-once 时 stderr + poll.log 双写；被 ctl 重定向时（非 tty）只走 stderr，
# 由 ctl 的重定向落 poll.log，避免双写。
ap_log() {
  local line
  line="[$(ap_now_iso)] $*"
  printf '%s\n' "$line" >&2
  if [[ -t 2 ]]; then printf '%s\n' "$line" >>"$(ap_state_dir)/poll.log"; fi
}

# ---- 每日配额计数器（§11：每日 implement 启动 3；本地唯一允许的状态之一） --------
# 文件两行：`date <UTC日期>` 与 `implement_started <n>`。文本而非 JSON：status.sh 直接
# head 展示，且运行时不引 jq 依赖。

ap_quota_file() { printf '%s\n' "$(ap_state_dir)/quota-$(date -u +%F).json"; }

ap_quota_read() { # → 实现次数（0 起）；跨日自动归零
  local f today n
  f="$(ap_quota_file)"; today=$(date -u +%F)
  n=0
  if [[ -f "$f" ]]; then
    [[ "$(sed -n 's/^date //p' "$f" | head -1)" == "$today" ]] \
      && n=$(sed -n 's/^implement_started //p' "$f" | head -1)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
  fi
  printf '%s\n' "$n"
}

ap_quota_inc() { # 计数 +1 落盘（poll.lock 已保证单写者）
  local f n
  f="$(ap_quota_file)"; n=$(( $(ap_quota_read) + 1 ))
  printf 'date %s\nimplement_started %s\n' "$(date -u +%F)" "$n" >"$f"
  printf '%s\n' "$n"
}

# ---- runs/ 落盘（§11：stdout jsonl 保留 30 天） ---------------------------------

ap_runs_dir() { printf '%s\n' "$(ap_state_dir)/runs"; }

# 清 30 天前的 runs 子目录（按目录名里的 ts 无法判，按 mtime）
ap_runs_gc() {
  local d
  [[ -d "$(ap_runs_dir)" ]] || return 0
  find "$(ap_runs_dir)" -mindepth 1 -maxdepth 1 -type d -mtime +30 \
    | while IFS= read -r d; do rm -rf "$d"; ap_log "runs gc：清理 $(basename "$d")"; done
}

# ---- 脱敏（§12.6：gh token / OPENAI_API_KEY 值 / 常见 sk- key 不进 runs/*.jsonl）--

ap_redact_stream() { # stdin → stdout
  sed -E 's/ghp_[A-Za-z0-9]{20,}/ghp_REDACTED/g
          s/gho_[A-Za-z0-9]{20,}/gho_REDACTED/g
          s/ghs_[A-Za-z0-9]{20,}/ghs_REDACTED/g
          s/(OPENAI_API_KEY[=: ][^[:space:]"'"'"']*)/OPENAI_API_KEY=REDACTED/g
          s/sk-[A-Za-z0-9_-]{16,}/sk-REDACTED/g'
}

ap_redact_file() { ap_redact_stream <"$1" >"$1.tmp" && mv "$1.tmp" "$1"; }

# ---- 杂项 ------------------------------------------------------------------------

ap_epoch_of() { # <ISO-8601 带 Z> → epoch；非法输出空
  local t
  t=$(date -u -d "$1" +%s 2>/dev/null) || return 1
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2} ]] || return 1
  printf '%s\n' "$t"
}

ap_human_age() { # <epoch_past> → "3d2h" / "45m" / "12s"
  local d=$(( $(ap_now_epoch) - $1 ))
  if (( d >= 86400 )); then printf '%dd%dh\n' $(( d / 86400 )) $(( (d % 86400) / 3600 ))
  elif (( d >= 3600 )); then printf '%dh%dm\n' $(( d / 3600 )) $(( (d % 3600) / 60 ))
  elif (( d >= 60 )); then printf '%dm\n' $(( d / 60 ))
  else printf '%ds\n' "$d"; fi
}
