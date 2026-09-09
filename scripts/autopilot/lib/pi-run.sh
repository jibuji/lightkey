#!/usr/bin/env bash
# issue-autopilot 子进程层（规格 workflows/issue-autopilot.md §11.1 / §12.8-9）
#
# **全仓唯一允许出现 --provider/--model/--thinking 的地方**（§16）：值只从
# host.toml 取（A13），不读 ~/.pi/agent/settings.json 默认值。
# 硬约束（成码，不是注释）：
#   - env -u OPENAI_API_KEY 起 pi（实测嵌套默认 provider 必 401，§12.8）
#   - --approve 必给（否则 AGENTS.md / 项目 skills 不加载 → agent 绕过交付纪律，§12.9）
#   - 子进程 setsid 独立进程组（预算 kill 按组杀，绝不误伤 poll.sh 自己）+ 9>&-
#     不继承轮次锁 fd（§4.1：否则 fuser 误报多实例）
#   - 超预算 kill：--mode json 顶层 usage 是累计值、部分 provider 只在收尾报 →
#     取历史 max 判断（§11.1）
#   - resume 档 = implement 档（§11.1：同难度任务不因续跑降档）
# shellcheck shell=bash disable=SC2317

source_once() { [[ "$(type -t "$1" 2>/dev/null)" == function ]] || source "$2"; }
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_once ap_conf_get    "$_here/common.sh"
source_once ap_log         "$_here/common.sh"
source_once ap_runs_dir    "$_here/common.sh"
source_once ap_redact_file "$_here/common.sh"

PI_BIN="${PI_BIN:-pi}"
AP_MONITOR_CB=""   # 可选：监控循环每 30s 调一次（poll.sh 用它做 10 分钟心跳戳更新）

# 组装本次实际生效的旗标层参数 → "provider model thinking"（缺配置返回 1）
ap_pi_flags() { # <phase: triage|implement|resume>
  local p="$1" prov model think
  prov=$(ap_conf_get provider) || { ap_log "host.toml 缺 provider"; return 1; }
  case "$p" in
    triage)    model=$(ap_conf_get model_triage) || model=""; think=$(ap_conf_get thinking_triage) || think="" ;;
    implement|resume) model=$(ap_conf_get model_implement) || model=""; think=$(ap_conf_get thinking_implement) || think="" ;;
    *) ap_log "未知 phase=$p"; return 1 ;;
  esac
  [[ -n "$model" ]] || { ap_log "host.toml 缺 model（phase=$p）"; return 1; }
  printf '%s %s %s\n' "$prov" "$model" "${think:-off}"
}

# jsonl 里累计 token 的历史 max（宽松形状：抽不到 → 空 = 不杀，墙钟兜底）
ap_usage_max() { # <jsonl-file>
  grep -oE '"(totalTokens|total_tokens|outputTokens|output_tokens)"[[:space:]]*:[[:space:]]*[0-9]+' "$1" 2>/dev/null \
    | grep -oE '[0-9]+$' | sort -n | tail -1
}

# 运行一个有界 LLM 任务。
#   $1 phase  $2 issue 号或 "-"  $3 prompt 文件  $4 墙钟秒  [$5 工作目录]
# 结果全局：AP_RC / AP_USAGE_MAX / AP_OUT（jsonl 路径）
# AP_RC 专属码：124=墙钟超时（issue 打回 ready-for-agent，§11）
#               125=预算 kill（同样打回 ready-for-agent，§11）
ap_pi_run() {
  local phase="$1" issue="$2" prompt="$3" tmo="$4" cwd="${5:-}"
  local flags prov model think out dir ts meta pid u budget rc
  flags=$(ap_pi_flags "$phase") || { AP_RC=2; return 2; }
  read -r prov model think <<< "$flags"
  [[ -n "$cwd" ]] || cwd=$(ap_repo_dir)

  if [[ "$issue" == "-" ]]; then dir="$(ap_runs_dir)/misc"; else dir="$(ap_runs_dir)/$issue"; fi
  mkdir -p "$dir/sessions"
  ts=$(date -u +%Y%m%d-%H%M%S)
  out="$dir/$ts.jsonl"
  budget=$(ap_conf_get budget_implement_tokens || echo 0)

  # 首行 = 可复现记录（§11.1：这坨是谁、以什么档位写的）
  printf '{"autopilot_meta":{"phase":"%s","issue":"%s","run":"%s","provider":"%s","model":"%s","thinking":"%s","budget_tokens":"%s","ts":"%s"}\n' \
    "$phase" "$issue" "${AP_RUN_ID:-}" "$prov" "$model" "$think" "$budget" "$(ap_now_iso)" >"$out"

  ap_log "pi 起跑 phase=$phase issue=$issue model=$model thinking=$think timeout=${tmo}s out=$out"

  # setsid：独立进程组（预算 kill 才能整组杀而不伤 poll.sh）；timeout 兜墙钟
  ( cd "$cwd" && exec setsid timeout -k 30 "$tmo" \
      env -u OPENAI_API_KEY "$PI_BIN" -p --mode json --approve \
      --provider "$prov" --model "$model" --thinking "${think:-off}" \
      --session-dir "$dir/sessions" -- "$(cat "$prompt")" ) >>"$out" 2>&1 9>&- &
  pid=$!
  echo "$pid" >"$dir/child.pid"   # 泄漏/掉单时校验按组杀（poll.sh kill_child_of）

  AP_USAGE_MAX=0; AP_RC=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 30 9>&- || true
    kill -0 "$pid" 2>/dev/null || break
    u=$(ap_usage_max "$out"); [[ -n "$u" ]] && AP_USAGE_MAX="$u"
    [[ -n "$AP_MONITOR_CB" ]] && "$AP_MONITOR_CB"
    if [[ "$budget" =~ ^[0-9]+$ ]] && (( budget > 0 )) && (( AP_USAGE_MAX > budget )); then
      ap_log "预算超限 kill：usage=$AP_USAGE_MAX > budget=$budget（issue=$issue）"
      kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      sleep 5; kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      AP_RC=125
      break
    fi
  done
  if (( AP_RC == 0 )); then
    wait "$pid" || AP_RC=$?
  else
    wait "$pid" 2>/dev/null || true
  fi
  u=$(ap_usage_max "$out"); [[ -n "$u" ]] && AP_USAGE_MAX="$u"

  printf '{"autopilot_end":{"exit":"%s","usage_max":"%s","ts":"%s"}}\n' \
    "$AP_RC" "$AP_USAGE_MAX" "$(ap_now_iso)" >>"$out"
  rm -f "$dir/child.pid"
  ap_redact_file "$out"
  AP_OUT="$out"
  ap_log "pi 退出 phase=$phase issue=$issue rc=$AP_RC usage_max=$AP_USAGE_MAX"
  return "$AP_RC"
}
