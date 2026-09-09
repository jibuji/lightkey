#!/usr/bin/env bash
# issue-autopilot 循环本体（规格 workflows/issue-autopilot.md §4；补充拍板 #29）
#
# 一轮 = 总开关 → 轮次锁 →（last-ok 心跳先行）→ 磁盘 → 探测 → 收尾扫描（回收
# 优先于开工）→ 分诊 → 恢复 → 认领+实现 → PR → 心跳整写。
#
# §12 十条安全不变量在此成码（不是写在文档里就算）：
#  1 永不 wontfix/关闭分诊对象/duplicate/.out-of-scope（关闭只发生在「PR 已合并」收尾）
#  2 永不 push 非 autopilot/* ref（§12.7 refs diff 校验）
#  3 needs-human 与 [PAUSED] 只能由人解除（本脚本从不改 tracking 标题；恢复=检测到
#    OWNER/MEMBER 回复，不是自己撤销）
#  4 不触碰真实 ~/.lightkey 与 daemon socket（只读 GitHub + worktree + 临时目录）
#  5 denylist 命中即不 auto-merge（ap_pr_setup_merge）
#  6 密钥进 runs 前过 redact（ap_redact_file）
#  7 子进程结束后校验 refs/标签/PR（越界 → 回滚 + needs-human）
#  8 env -u OPENAI_API_KEY 起 pi（pi-run.sh 成码）
#  9 --approve 必给（pi-run.sh 成码）
# 10 每轮先写 last-ok 再干其他（hb_touch 是第一个 gh 写动作）
#
# 用法：bash scripts/autopilot/poll.sh（由 ctl.sh run-once / timer / cron 调；
#       人工验收用 DRY_RUN=1 —— 只分诊分析 + 跳账 + 心跳，不开 PR 不动标签不认领）
set -uo pipefail

# ---- PATH（§13.5：cron 不继承交互 shell 的 PATH） --------------------------------
for d in "$HOME/.cargo/bin" "$HOME/.local/bin" "/usr/local/bin"; do
  case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH" ;; esac
done
export PATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
export AUTOPILOT_REPO_DIR="$REPO"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
# shellcheck source=lib/labels.sh
source "$HERE/lib/labels.sh"
# shellcheck source=lib/heartbeat.sh
source "$HERE/lib/heartbeat.sh"
# shellcheck source=lib/pi-run.sh
source "$HERE/lib/pi-run.sh"
# shellcheck source=lib/pr.sh
source "$HERE/lib/pr.sh"

STATE_DIR="$(ap_state_dir)"
mkdir -p "$STATE_DIR/runs"
AP_TMP=$(mktemp -d); trap 'rm -rf "$AP_TMP"' EXIT
export AP_TMP

DRY_RUN="${DRY_RUN:-0}"
ROUND_TIMEOUT_MIN="${AUTOPILOT_ROUND_TIMEOUT_MIN:-60}"
QUOTA_DAILY_IMPL=3
QUOTA_TRIAGE_PER_ROUND=3
IMPL_RETRY_MAX=2
DISK_MIN_GIB=15
LEAK_STALE_S=$((2 * 3600))
DEGRADE_AFTER_S=$((7 * 86400))
AP_RUN_ID="r-$(date -u +%Y%m%d-%H%M)"
ROUND_START=$(ap_now_epoch)
ROUND_RC=0
HB_LINES=""
HB_NEW_SKIPS=""
RECLAIM_CANDIDATE=""    # sweep 发现的泄漏认领（attempt 未尽），交认领阶段重起
RECLAIM_WHY=""
declare -a CAP_TRUE=() # 探测为真的能力

# 模板渲染：SUBS 关联数组的 {{PLACEHOLDER}} 替换（调度器拼全文，禁令进 prompt 不靠 agent 自觉）
render_prompt() { # <template> <out>
  local t k
  t=$(cat "$1")
  for k in "${!SUBS[@]}"; do t=${t//\{\{$k\}\}/${SUBS[$k]}}; done
  printf '%s' "$t" >"$2"
}

round_fail() { ROUND_RC=1; HB_LINES+="- !! $1"$'\n'; ap_log "FAIL: $1"; }
hb_line()   { HB_LINES+="- $1"$'\n'; }
round_left_s() { echo $(( ROUND_TIMEOUT_MIN * 60 - ( $(ap_now_epoch) - ROUND_START ) )); }

# 心跳整写（§4 步骤 7；无论成败必须写。定义前置：磁盘门的提前退出路径也要调它）
hb_finish() {
  local body_all ledger merged
  body_all=$(hb_body_read "$TRACKING") || { ap_log "心跳整写前读 body 失败"; ROUND_RC=2; return; }
  ledger=$(hb_ledger_lines "$body_all")
  merged=$(hb_ledger_merge "$ledger" "${HB_NEW_SKIPS:-}")
  HB_LEDGER=$(printf '%s' "$merged" | sed '/^$/d')
  HB_RESULT="- 结论: $([[ "$DRY_RUN" == 1 ]] && printf 'DRY_RUN（只分诊/跳账/心跳，不动标签不开 PR 不认领） · '\
)$([[ $ROUND_RC == 0 ]] && echo OK || echo "PARTIAL/FAIL（见 !! 行）")"
  HB_QUOTA_LINE="implement-today $(ap_quota_read)/$QUOTA_DAILY_IMPL · round-timeout ${ROUND_TIMEOUT_MIN}m · disk ${AVAIL_GIB} GiB"
  hb_render_full "$body_all" >"$AP_TMP/hb.md"
  hb_body_write "$TRACKING" "$AP_TMP/hb.md" || { ap_log "心跳整写失败（gh issue edit）"; ROUND_RC=2; return; }
  local hook; hook=$(ap_conf_get alert_webhook || true)
  if [[ -n "$hook" && $ROUND_RC != 0 ]]; then
    printf '{"text":"autopilot %s 轮次 %s 非 OK（见 #%s）"}' "$HOST_ID" "$AP_RUN_ID" "$TRACKING" \
      | timeout 10 curl -sf -X POST -H 'Content-Type: application/json' -d @- "$hook" >/dev/null 2>&1 \
      || ap_log "webhook 告警失败（best-effort）"
  fi
}

INVARIANTS='1. 永不 wontfix / 关闭 issue / 标 duplicate / 写 .out-of-scope/
2. 只允许 push refs/heads/autopilot/*；永不 --force；永不碰 main 或他人分支
3. needs-human 与 [PAUSED] 只能由人解除
4. 绝不触碰真实 ~/.lightkey 数据目录与 daemon socket；测试只用临时目录 / file:// 模拟存储
5. denylist 命中即不 auto-merge；release-build 能力恒 false，永不能发版
6. 密钥 / fixture 密码不进仓库、不进 issue 正文、不进 runs
7. 子进程结束后校验 refs / 标签 / PR；越界即回滚 + needs-human
8. 凭据只从 host.toml 显式传 provider/model（不依赖环境继承）
9. --approve 必给（交付纪律必须加载）
10. 任何不确定 → 打 needs-human，不要猜'

# ---- 配置（§1：一切从 host.toml） ------------------------------------------------

HOST_ID=$(ap_conf_get host_id) || { ap_log "host.toml 缺 host_id —— 循环不可能跑"; exit 2; }
TRACKING=$(ap_conf_get tracking_issue)
[[ "$TRACKING" =~ ^[0-9]+$ ]] || { ap_log "host.toml 缺 tracking_issue —— 无法写心跳"; exit 2; }
HB_HOST="$HOST_ID"; HB_WEBHOOK=$([[ -n "$(ap_conf_get alert_webhook || true)" ]] && echo on || echo off)
cd "$REPO"   # 先进仓：gh 隐式仓参数（repo view 等）依赖 cwd 在仓内（systemd 单元 cwd=/，实测暴露）
REPO_PATH=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null) \
  || { ap_log "gh 不可用（repo view 失败）"; exit 2; }

# ---- 1. 轮次锁（§4.1） ----------------------------------------------------------

exec 9>"$STATE_DIR/poll.lock"
flock -n 9 || { ap_log "另一轮在跑（poll.lock），本轮退出 0"; exit 0; }
ap_log "=== 轮次 $AP_RUN_ID 开始 host=$HOST_ID dry_run=$DRY_RUN ==="

# ---- 0. 总开关（§4 步骤 0；§12.3 [PAUSED] 只能由人解除 → 本脚本从不写标题） -------

TITLE=$(gh issue view "$TRACKING" --json title --jq .title 2>/dev/null) || {
  ap_log "读 tracking issue #$TRACKING 失败"; exit 2
}
if [[ "$TITLE" == *"[PAUSED]"* ]]; then
  hb_touch "$TRACKING" 1 || { ap_log "心跳写入失败（[PAUSED] 路径）"; exit 2; }
  ap_log "标题含 [PAUSED] —— 人主动暂停，本轮只写心跳后退出"
  exit 0
fi

# ---- 2. last-ok 心跳先行（§12.10：每轮第一个写入动作，失败路径也必须先走到这） ----

hb_touch "$TRACKING" || { ap_log "心跳写入失败（gh issue edit）—— 禁止静默继续"; exit 2; }

# ---- 磁盘门（§11：< 15 GiB 整轮不启动） ------------------------------------------

AVAIL_GIB=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
if (( AVAIL_GIB < DISK_MIN_GIB )); then
  round_fail "磁盘余量 ${AVAIL_GIB} GiB < ${DISK_MIN_GIB} GiB，整轮不启动（§11）"
  hb_finish; exit 0
fi
# （磁盘门为 0 号例外：其余阶段缺盘时 phase 内自行跳过）

# ---- 3. 能力探测（§7 fail-closed） -----------------------------------------------

PROBE_JSON=$(bash "$HERE/probe-capabilities.sh" 2>>"$STATE_DIR/poll.log") || PROBE_JSON=""
for c in rust-workspace frontend-vitest tauri-shell windows-cross-check wsl2-desktop-e2e release-build; do
  printf '%s' "$PROBE_JSON" | grep -q "\"$c\":true" && CAP_TRUE+=("$c")
done
cap_ok() { local c; for c in "${CAP_TRUE[@]:-}"; do [[ "$c" == "$1" ]] && return 0; done; return 1; }
[[ ${#CAP_TRUE[@]} -gt 0 ]] || round_fail "探测全 false（fail-closed）：${PROBE_JSON:-（探测脚本失败）}"

# ---- 4. 收尾扫描（§4 步骤 2：回收优先于开工） ------------------------------------

sweep() {
  local n line title created body labels assignee stamp_host stamp_run stamp_attempt stamp_hb
  while IFS=$'\t' read -r n created title; do
    [[ "$n" == "$TRACKING" ]] && continue
    body=$(gh issue view "$n" --json body,assignees --jq '[.body, ((.assignees // [])[0].login // "")] | @tsv' 2>/dev/null) || continue
    labels=$(ap_issue_labels "$n")
    tsv=$(ap_comments_tsv "$n")

    # PR 状态（分支名 = 认领命名空间）
    local pr_n="" pr_state=""
    read -r pr_n pr_state <<< "$(gh pr list --state all --head "autopilot/$n" --json number,state --jq '.[0] | [(.number//0), (.state//"-")] | @tsv' 2>/dev/null)"

    # 人类抢单：assignee 非空（非 bot）或戳后出现 OWNER/MEMBER 的 "mine"
    local stamp_created
    stamp_created=$(printf '%s\n' "$tsv" | awk -F "$AP_C_SEP" '$4 ~ /^## AGENT-WORKING/ {t=$3} END{print t}')
    if [[ -n "$(printf '%s' "$body" | cut -f2)" ]] \
       || { [[ -n "$stamp_created" ]] && ap_mine_after "$tsv" "$stamp_created"; }; then
      ap_log "#$n 被人类抢单 —— abort 残留子进程（若有）、摘 agent-working、现场保留、永不重开"
      kill_child_of "$n"
      ap_label_remove "$n" agent-working
      ap_label_add "$n" ready-for-human
      gh issue comment "$n" --body "> *This was generated by AI during triage.*

检测到人工接管（assignee / \`mine\`）：autopilot 放手，现场（分支 \`autopilot/$n\`）保留。" >/dev/null 2>&1
      hb_line "#$n 被人类抢单，已放手（现场保留）"
      continue
    fi

    if [[ "$pr_state" == MERGED ]]; then
      ap_log "#$n PR #$pr_n 已合并 —— 清标签/关单/删分支/收 worktree"
      ap_label_remove "$n" agent-working
      gh issue view "$n" --json state --jq .state | grep -qx OPEN \
        && ap_issue_close "$n" "PR #$pr_n 已合并（squash），循环收尾关单。"
      git push origin --delete "autopilot/$n" >/dev/null 2>&1 || true
      cleanup_worktree "$n"
      hb_line "#$n PR #$pr_n 合并 → 已关单、分支/worktree 已清"
      continue
    fi

    if [[ "$pr_state" == CLOSED ]]; then
      ap_log "#$n PR #$pr_n 被驳回 —— 摘 agent-working 打 needs-human，保留分支与 worktree（驳回理由不落盘 agent 只会重犯）"
      ap_label_remove "$n" agent-working; ap_label_add "$n" needs-human
      post_needs_human "$n" "PR #$pr_n 被驳回" "驳回原因是什么？要我如何修改再提？"
      hb_line "#$n PR 被驳回 → needs-human（分支保留）"
      continue
    fi

    # 认领中途失败兑底：无戳无 PR（如换标签后才在 run_implement 里被拒）
    # → 退回 ready-for-agent（没开始过活，不算 attempt、不弹 needs-human）。
    if [[ -z "$pr_n" && -z "$stamp_created" ]]; then
      ap_log "#$n 认领无戳（claim 中途失败）→ 退回 ready-for-agent"
      ap_label_remove "$n" agent-working; ap_label_add "$n" ready-for-agent
      hb_line "#$n 认领无戳 → 退回 ready-for-agent"
      continue
    fi

    # 泄漏判定：checks 红 / 无 PR 且戳 2h 无心跳
    local leak=0 why=""
    if [[ -n "$pr_n" && "$pr_state" == OPEN ]]; then
      local states; states=$(gh pr checks "$pr_n" --json state --jq '[.[].state] | join(",")' 2>/dev/null)
      [[ "$states" == *fail* ]] && { leak=1; why="PR checks 红（$states）"; }
    else
      local hb_epoch stamp_last
      stamp_last=$(printf '%s\n' "$tsv" | awk -F "$AP_C_SEP" '$4 ~ /^## AGENT-WORKING/ {b=$4} END{print b}' | sed -n 's/.*last-heartbeat: //p')
      hb_epoch=$(ap_epoch_of "$stamp_last" 2>/dev/null) || hb_epoch=0
      if (( hb_epoch > 0 && ( $(ap_now_epoch) - hb_epoch ) > LEAK_STALE_S )); then
        leak=1; why="无 PR 且认领戳 last-heartbeat 超 ${LEAK_STALE_S}s"
      fi
    fi

    if (( leak )); then
      kill_child_of "$n"
      local attempt; attempt=$(stamp_attempt_of "$tsv")
      if (( attempt < IMPL_RETRY_MAX )) && (( $(ap_quota_read) < QUOTA_DAILY_IMPL )); then
        ap_log "#$n 认领泄漏（$why）→ 待重起（attempt $((attempt+1))/$IMPL_RETRY_MAX）"
        RECLAIM_CANDIDATE="$n"; RECLAIM_WHY="$why"
      else
        ap_log "#$n 认领泄漏（$why）且 attempt/quota 尽 → needs-human"
        ap_label_remove "$n" agent-working; ap_label_add "$n" needs-human
        post_needs_human "$n" "认领泄漏：$why" "重试已尽（attempt $attempt/$IMPL_RETRY_MAX）或配额尽，是否人工接手？"
        hb_line "#$n 泄漏 → needs-human（$why）"
      fi
    fi
  done < <(gh issue list --state open --label agent-working --limit 50 --json number,createdAt,title \
             --jq '.[] | [.number, .createdAt, .title] | @tsv' 2>/dev/null)
}

stamp_attempt_of() { ap_stamp_latest "$1" >/dev/null && ap_stamp_latest "$1" | sed -n '3p' || echo 1; }
kill_child_of() { # 泄漏/抢单时杀残留子进程（setsid 组，pid 记录在 runs/<n>/child.pid）
  local f="$STATE_DIR/runs/$1/child.pid" p
  [[ -f "$f" ]] || return 0
  p=$(cat "$f" 2>/dev/null)
  if [[ "$p" =~ ^[0-9]+$ ]] && kill -0 "$p" 2>/dev/null; then
    kill -TERM "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true
    sleep 2; kill -KILL "-$p" 2>/dev/null || true
    ap_log "#$1 残留子进程 pid=$p 已杀"
  fi
  rm -f "$f"
}
cleanup_worktree() { # <n>
  local wt="$REPO/.autopilot/worktrees/$1"
  [[ -d "$wt" ]] && git worktree remove --force "$wt" >/dev/null 2>&1 || true
  git fetch --prune origin >/dev/null 2>&1 || true
  git branch -D "autopilot/$1" >/dev/null 2>&1 || true
}
post_needs_human() { # <n> <卡在哪> <问题>
  cat >"$AP_TMP/nh.md" <<EOF
## NEEDS-HUMAN [$HOST_ID/$AP_RUN_ID]
**卡在哪**：$2（阶段：autopilot 轮次）
**需要你决定**：$3
**已尝试与证据**：见 runs/（$HOST_ID 上 \`scripts/autopilot/status.sh\` 可查轮次日志）
**现场**：branch \`autopilot/$1\`（若有），worktree 保留
**配额**：attempt $(stamp_attempt_of "$(ap_comments_tsv "$1")")/$IMPL_RETRY_MAX（耗尽后不再自动续跑）
EOF
  gh issue comment "$1" --body-file "$AP_TMP/nh.md" >/dev/null 2>&1
}

if [[ "$DRY_RUN" == 1 ]]; then
  ap_log "DRY_RUN=1：跳过收尾扫描（§15：只分诊分析 + 跳账 + 心跳）"
else
  sweep
fi

# ---- 5. 7 天全宿主否定降级（§6；终结性判定由超时+全宿主否定共同触发） ------------

degrade_ready_for_human() {
  local body_all ledger all_hosts n issue_line hosts ready_since rs_epoch
  body_all=$(hb_body_read "$TRACKING")
  ledger=$(hb_ledger_lines "$body_all")
  [[ -n "$ledger" ]] || return 0
  all_hosts=$(hb_ledger_hosts "$ledger")
  while IFS=$'\t' read -r n created title; do
    [[ "$n" == "$TRACKING" ]] && continue
    hosts=$(hb_ledger_hosts_for "$n" "$ledger")
    [[ -n "$hosts" ]] || continue
    # 7 天时钟：ready-for-agent 标签最近一次打上的时间（timeline，可从 GitHub 全量重建）
    ready_since=$(ap_ready_since "$REPO_PATH" "$n")
    [[ -n "$ready_since" ]] || continue
    rs_epoch=$(ap_epoch_of "$ready_since") || continue
    (( $(ap_now_epoch) - rs_epoch > DEGRADE_AFTER_S )) || continue
    local covered=1 h
    for h in $all_hosts; do printf '%s\n' "$hosts" | grep -qx "$h" || covered=0; done
    (( covered )) || continue
    [[ "$(ap_issue_labels "$n")" == *ready-for-agent* ]] || continue
    ap_log "#$n 全宿主否定超 7 天 → 降级 ready-for-human（§6）"
    ap_label_remove "$n" ready-for-agent; ap_label_add "$n" ready-for-human
    gh issue comment "$n" --body "> *This was generated by AI during triage.*

**全宿主否定超时降级（§6）**：本 issue \`ready-for-agent\` 已停留 > 7 天，且所有在册宿主（$(
      printf '%s\n' "$all_hosts" | paste -sd'、' -)）都因能力不足跳过：$(
      printf '%s\n' "$ledger" | grep "^skipped #$n " | sed 's/^skipped /- /' | paste -sd'
' -)。
需要其中一台机器补齐能力（按上述 missing），或由人直接接手。" >/dev/null 2>&1
    hb_line "#$n 全宿主否定超 7 天 → ready-for-human"
  done < <(gh issue list --state open --label ready-for-agent --limit 50 --json number,createdAt,title \
             --jq '.[] | [.number, .createdAt, .title] | @tsv' 2>/dev/null)
}
[[ "$DRY_RUN" == 1 ]] || degrade_ready_for_human

# ---- 6. 分诊（§4 步骤 3；§5 权限白名单；每轮最多 3 个，最旧优先） -------------------

triage_phase() {
  local done_n=0 n created title labels_before labels_after body prompt_out flags diff violations
  while IFS=$'\t' read -r n created title; do
    [[ "$n" == "$TRACKING" ]] && continue
    (( done_n >= QUOTA_TRIAGE_PER_ROUND )) && break
    (( $(round_left_s) < 300 )) && { hb_line "分诊中断：轮次墙钟余量不足"; break; }
    labels_before=$(ap_issue_labels "$n")
    [[ -z "$labels_before" || ",$labels_before," == *",needs-triage,"* ]] || continue
    body=$(gh issue view "$n" --json body --jq .body 2>/dev/null)
    declare -A SUBS=(
      [ISSUE_NUMBER]="$n" [ISSUE_TITLE]="$title" [ISSUE_BODY]="$body"
      [INVARIANTS]="$INVARIANTS"
      [DRY_RUN_BLOCK]=$([[ "$DRY_RUN" == 1 ]] && printf '**DRY_RUN 模式**：本轮只分析——在最终回复里输出你将写的 Triage Notes / 判定 / brief（含 Needs: 行），**不要执行任何 gh 写操作**（不评论、不改标签）。' || true)
    )
    render_prompt "$HERE/prompts/triage.md" "$AP_TMP/prompt-$n.md"
    local tmo=$(( $(round_left_s) < 900 ? $(round_left_s) : 900 ))
    ap_pi_run triage "$n" "$AP_TMP/prompt-$n.md" "$tmo" "$REPO" || true
    # §5 双闸的代码侧：diff 标签，白名单外的改动 → 回滚
    labels_after=$(ap_issue_labels "$n")
    diff=$(ap_label_diff "$labels_before" "$labels_after")
    violations=$(ap_label_violations "$diff")
    if [[ -n "$diff" ]]; then
      if [[ -n "$violations" || "$DRY_RUN" == 1 ]]; then
        ap_log "#$n 分诊标签越权（$violations）→ 回滚到 ${labels_before:-（无）}"
        # 回滚 = 恢复 before 快照
        local l
        while IFS= read -r l; do [[ -n "$l" ]] && ap_label_remove "$n" "${l:1}"; done <<< "$(printf '%s\n' "$labels_after" | tr ',' '\n')"
        while IFS= read -r l; do [[ -n "$l" ]] && ap_label_add "$n" "$l"; done <<< "$(printf '%s\n' "$labels_before" | tr ',' '\n')"
        if [[ "$DRY_RUN" != 1 ]]; then
          ap_label_add "$n" needs-human
          post_needs_human "$n" "分诊标签越权：$violations" "是否人工分诊本 issue？"
        fi
        hb_line "分诊 #$n 标签越权已回滚（$violations）"
      else
        hb_line "分诊 #$n → ${labels_after}"
      fi
    else
      hb_line "分诊 #$n 分析完成（标签未变：DRY_RUN 或 agent 无动作）"
    fi
    done_n=$((done_n + 1))
  done < <(gh issue list --state open --limit 50 --json number,createdAt,title,labels \
             --jq '.[] | select((.labels | length) == 0 or any(.labels[]; .name == "needs-triage")) | [.number, .createdAt, .title] | @tsv' 2>/dev/null | sort -t$'\t' -k2)
}
triage_phase

# ---- 7. 恢复（§4 步骤 4；§8：OWNER/MEMBER 回复才恢复，attempt 不重置） -----------

restore_phase() {
  local n created title tsv anchor reply reply_body stamp_attempt
  while IFS=$'\t' read -r n created title; do
    [[ "$n" == "$TRACKING" ]] && continue
    tsv=$(ap_comments_tsv "$n")
    anchor=$(ap_nh_anchor_time "$tsv") || continue
    reply=$(ap_owner_reply_after "$tsv" "$anchor") || continue
    # 前置检查：配额/墙钟不满足就不换标签（换了却跑不起来 = 卡在 agent-working 无戳无 PR）
    if (( $(ap_quota_read) >= QUOTA_DAILY_IMPL )) || (( $(round_left_s) < 600 )); then
      ap_log "#$n 有裁决但本轮实现槽不可用（配额/墙钟），恢复延后"
      hb_line "#$n 恢复延后：配额/墙钟不足（needs-human 保留）"
      continue
    fi
    reply_body=$(ap_body_unescape "$(printf '%s' "$reply" | awk -F "$AP_C_SEP" '{print $2}')" | sed 's/^[[:space:]]*//')
    local auto_line=""
    [[ "$reply_body" =~ ^AUTOPILOT:\ (.*)$ ]] && auto_line="${BASH_REMATCH[1]}"
    stamp_attempt=$(stamp_attempt_of "$tsv")
    ap_log "#$n 维护者已裁决 → 恢复续跑（attempt $stamp_attempt/$IMPL_RETRY_MAX 不重置）"
    ap_label_remove "$n" needs-human; ap_label_add "$n" agent-working
    hb_line "#$n NEEDS-HUMAN 已被裁决，恢复续跑（attempt $stamp_attempt/$IMPL_RETRY_MAX）"
    run_implement "$n" "resume" "$auto_line" "$reply_body" "$stamp_attempt"
    return # 并发=1（§11）：恢复即本轮唯一实现槽
  done < <(gh issue list --state open --label needs-human --limit 50 --json number,createdAt,title \
             --jq '.[] | [.number, .createdAt, .title] | @tsv' 2>/dev/null | sort -t$'\t' -k2)
}
[[ "$DRY_RUN" == 1 ]] || restore_phase

# ---- 8. 认领 + 实现 + PR（§4 步骤 5-6；§6 选单与幂等） ----------------------------

run_implement() { # <n> <phase: implement|resume> [auto_line] [reply_body] [attempt]
  local n="$1" phase="$2" auto_line="${3:-}" reply_body="${4:-}" attempt="${5:-1}"
  local wt="$REPO/.autopilot/worktrees/$n" branch="autopilot/$n"
  local prompt="$AP_TMP/prompt-$n.md" stamp_id="" tick=0

  # 配额（§11：每日 implement 启动 3）
  if (( $(ap_quota_read) >= QUOTA_DAILY_IMPL )); then
    hb_line "认领 #$n 未起：今日配额用尽（$QUOTA_DAILY_IMPL/$QUOTA_DAILY_IMPL）"
    return 2
  fi
  local tmo=$(( $(round_left_s) - 300 )); (( tmo < 300 )) && { hb_line "实现 #$n 未起：墙钟不足"; return 2; }

  # 现场：worktree（幂等：已有则复用，分支存在则续其上）
  git fetch origin >/dev/null 2>&1 || true
  if [[ ! -d "$wt" ]]; then
    if git ls-remote --exit-code origin "refs/heads/$branch" >/dev/null 2>&1; then
      git worktree add "$wt" -B "$branch" "origin/$branch" >/dev/null 2>&1 \
        || git worktree add "$wt" -B "$branch" origin/main >/dev/null 2>&1 || true
    else
      git worktree add "$wt" -b "$branch" origin/main >/dev/null 2>&1 || true
    fi
  fi
  [[ -d "$wt" ]] || { round_fail "worktree 建不起来：$wt"; return 1; }

  # 认领戳（§8 格式；后续每 ~10 分钟覆盖式更新 last-heartbeat）
  cat >"$AP_TMP/stamp.md" <<EOF
## AGENT-WORKING [$HOST_ID/$(date -u +%Y-%m-%dT%H:%MZ)]
- run-id: $AP_RUN_ID
- host: $HOST_ID
- branch: $branch
- worktree: $wt
- attempt: $attempt/$IMPL_RETRY_MAX
- last-heartbeat: $(ap_now_iso)
EOF
  stamp_id=$(ap_comment_post "$n" "$AP_TMP/stamp.md") || true

  # prompt（调度器拼全文，禁令在场，不靠 agent 自觉）
  local brief; brief=$(issue_brief "$n")
  declare -A SUBS=(
    [ISSUE_NUMBER]="$n"
    [ISSUE_TITLE]=$(gh issue view "$n" --json title --jq .title 2>/dev/null)
    [ISSUE_BODY]=$(gh issue view "$n" --json body --jq .body 2>/dev/null)
    [WORKTREE]="$wt" [BRANCH]="$branch" [RUN_ID]="$AP_RUN_ID" [ATTEMPT]="$attempt"
    [CAPABILITIES]=$(printf '%s ' "${CAP_TRUE[@]:-（fail-closed：无）}")
    [BRIEF]="$brief" [INVARIANTS]="$INVARIANTS"
    [AUTOPILOT_REPLY]="${auto_line:-（无注入行——维护者回复原文见 issue 评论，自行阅读）}"
    [NEEDS_HUMAN_NOTE]="${reply_body:-（上次卡点见 NEEDS-HUMAN 评论）}"
  )
  render_prompt "$HERE/prompts/$phase.md" "$prompt"

  # refs 白名单基线（§12.7）
  git ls-remote origin | ap_refs_parse >"$AP_TMP/refs_before"

  # 心跳戳更新回调（每 ~10 分钟）
  stamp_tick_update() {
    tick=$((tick + 1))
    (( tick % 20 == 0 )) || return 0
    [[ -n "$stamp_id" ]] || return 0
    sed "s/^- last-heartbeat: .*/- last-heartbeat: $(ap_now_iso)/" "$AP_TMP/stamp.md" >"$AP_TMP/stamp.md.new" \
      && mv "$AP_TMP/stamp.md.new" "$AP_TMP/stamp.md" \
      && ap_comment_edit "$stamp_id" "$AP_TMP/stamp.md"
  }
  AP_MONITOR_CB=stamp_tick_update

  ap_quota_inc >/dev/null
  export CARGO_TARGET_DIR="$REPO/target"   # §11：与主仓共享编译缓存
  ap_pi_run "$phase" "$n" "$prompt" "$tmo" "$wt" || true
  AP_MONITOR_CB=""

  # §12.7 子进程结束后校验：refs / 标签 / PR
  git ls-remote origin | ap_refs_parse >"$AP_TMP/refs_after"
  local refs_bad; refs_bad=$(ap_refs_violations "$AP_TMP/refs_before" "$AP_TMP/refs_after")
  if [[ -n "$refs_bad" ]]; then
    ap_label_remove "$n" agent-working; ap_label_add "$n" needs-human
    post_needs_human "$n" "子进程推了白名单外的 ref：$refs_bad" "这些越界 push 如何处置（人工清/回滚）？"
    round_fail "#$n 越界 ref：$refs_bad"
    return 1
  fi
  local labels_now; labels_now=$(ap_issue_labels "$n")
  if [[ "$labels_now" != *agent-working* ]]; then
    ap_label_add "$n" agent-working
    hb_line "#$n 实现期标签被改动过，已纠正回 agent-working"
  fi

  # PR 阶段（§4 步骤 6；§10 auto-merge 闸门）
  local pr_n pr_state
  read -r pr_n pr_state <<< "$(gh pr list --state all --head "$branch" --json number,state --jq '.[0] | [(.number//0), (.state//"-")] | @tsv' 2>/dev/null)"
  if [[ -n "$pr_n" && "$pr_n" != 0 ]]; then
    case "$pr_state" in
      OPEN)
        local rc_merge=0
        ap_pr_setup_merge "$pr_n" "$n" || rc_merge=$?
        if (( rc_merge == 2 )); then
          ap_label_remove "$n" agent-working; ap_label_add "$n" needs-human
          gh issue comment "$n" --body "> *This was generated by AI during triage.*

PR #$pr_n 命中 denylist，不开 auto-merge，转人工评审（§10）。" >/dev/null 2>&1
          hb_line "PR #$pr_n 命中 denylist → needs-human"
        elif (( rc_merge == 1 )); then
          hb_line "PR #$pr_n 缺 Closes 行或不可读 → 不开 auto-merge（agent-working 保留）"
        else
          hb_line "认领 #$n（attempt $attempt/$IMPL_RETRY_MAX，PR #$pr_n）"
        fi ;;
      *) hb_line "#$n PR #$pr_n 状态 $pr_state（收尾扫描下轮处置）" ;;
    esac
    return 0
  fi

  # 无 PR：按退出码处置（§11：超时/预算 → 打回 ready-for-agent；失败 → attempt 规则）
  if [[ "$AP_RC" == 124 || "$AP_RC" == 125 ]]; then
    ap_label_remove "$n" agent-working; ap_label_add "$n" ready-for-agent
    gh issue comment "$n" --body "> *This was generated by AI during triage.*

本轮$([[ "$AP_RC" == 124 ]] && echo 墙钟超时 || echo 预算超限)，issue 打回 ready-for-agent（超时/超预算是宿主问题，不算活的失败，§11）。" >/dev/null 2>&1
    hb_line "#$n 超时/超预算打回 ready-for-agent（rc=$AP_RC）"
    return 0
  fi
  if (( attempt < IMPL_RETRY_MAX )); then
    ap_label_remove "$n" agent-working; ap_label_add "$n" ready-for-agent
    gh issue comment "$n" --body "> *This was generated by AI during triage.*

attempt $attempt/$IMPL_RETRY_MAX 未交付（rc=$AP_RC，无 PR），打回 ready-for-agent，下轮重试。" >/dev/null 2>&1
    hb_line "#$n attempt $attempt/$IMPL_RETRY_MAX 失败（rc=$AP_RC）→ 打回重试"
  else
    ap_label_remove "$n" agent-working; ap_label_add "$n" needs-human
    post_needs_human "$n" "attempt $IMPL_RETRY_MAX/$IMPL_RETRY_MAX 仍未交付（rc=$AP_RC，无 PR）" "是否人工接手本 issue？"
    hb_line "#$n 重试尽 → needs-human"
  fi
}

claim_phase() {
  # 并发 = 1（§11）：已有 agent-working 在跑（本轮 sweep 后仍存）→ 排队不并行
  local inflight; inflight=$(gh issue list --state open --label agent-working --limit 5 --json number \
    --jq '[.[] | select(.number != '"$TRACKING"')] | length' 2>/dev/null)
  if (( ${inflight:-0} > 0 )); then hb_line "已有 agent-working 在跑，本轮不认领（并发=1）"; return 0; fi
  # 实现槽可用性（§11）：不可用就不换标签 —— 换了却跑不起来 = 卡在 agent-working
  # 无戳无 PR（sweep 兜底只能被动收回，且配额尽时会被误判 needs-human）。
  if (( $(ap_quota_read) >= QUOTA_DAILY_IMPL )); then
    hb_line "本轮不认领：今日 implement 配额已用尽（$(ap_quota_read)/$QUOTA_DAILY_IMPL）"
    return 0
  fi
  if (( $(round_left_s) < 600 )); then
    hb_line "本轮不认领：墙钟余量不足（$(round_left_s)s）"
    return 0
  fi
  if [[ -n "$RECLAIM_CANDIDATE" ]]; then
    local attempt; attempt=$(stamp_attempt_of "$(ap_comments_tsv "$RECLAIM_CANDIDATE")")
    run_implement "$RECLAIM_CANDIDATE" implement "" "" "$((attempt + 1))"
    return 0
  fi
  local n created title needs c ok body blocked
  while IFS=$'\t' read -r n created title; do
    [[ "$n" == "$TRACKING" ]] && continue
    (( $(round_left_s) < 600 )) && break
    # 资格过滤（§6）：无 assignee ∧ 无 blocker ∧ attempt 未尽
    body=$(gh issue view "$n" --json body,assignees --jq '[.body, ((.assignees // [])[0].login // "")] | @tsv' 2>/dev/null) || continue
    [[ -z "$(printf '%s' "$body" | cut -f2)" ]] || continue
    blocked=$(gh api "repos/$REPO_PATH/issues/$n/dependencies/summary" --jq .blocked_by 2>/dev/null || true)
    [[ "$blocked" =~ ^[0-9]+$ ]] && (( blocked > 0 )) && continue
    printf '%s' "$body" | grep -q 'Blocked by:' && continue
    local attempt; attempt=$(stamp_attempt_of "$(ap_comments_tsv "$n")")
    (( attempt < IMPL_RETRY_MAX )) || continue
    # 能力覆盖（§6）：Needs: ⊆ 探测为真
    needs=$(issue_brief "$n" | grep -oE '^Needs: .*' | sed 's/^Needs: //' | tr ',' '\n' | tr -d ' ')
    if [[ -n "$needs" ]]; then
      ok=1
      while IFS= read -r c; do [[ -z "$c" ]] && continue; cap_ok "$c" || ok=0; done <<< "$needs"
      if (( ok == 0 )); then
        # 跳账（§6）：标签不动，只记台账
        local missing=""
        while IFS= read -r c; do cap_ok "$c" || missing+="$c,"; done <<< "$needs"
        ap_log "#$n 本宿主能力不足（$missing）→ 跳账（标签不动）"
        HB_NEW_SKIPS+="skipped #$n host=$HOST_ID missing=$(printf '%s' "$missing" | sed 's/,$//') at=$(ap_now_iso)"$'\n'
        continue
      fi
    fi
    # 写前重读（§6 步骤 1：跨机唯一 CAS 尝试）
    [[ "$(ap_issue_labels "$n")" == *ready-for-agent* ]] || continue
    ap_log "认领 #$n（写前重读通过）"
    ap_label_remove "$n" ready-for-agent; ap_label_add "$n" agent-working
    run_implement "$n" implement "" "" "$attempt"
    return 0
  done < <(gh issue list --state open --label ready-for-agent --limit 50 --json number,createdAt,title \
             --jq '.[] | [.number, .createdAt, .title] | @tsv' 2>/dev/null | sort -t$'\t' -k2)
}

# issue brief（含 Needs: 行）：先看正文，再看最新 triage brief 评论
issue_brief() { # <n>
  local body tsv best=""
  body=$(gh issue view "$n" --json body --jq .body 2>/dev/null)
  tsv=$(ap_comments_tsv "$n")
  printf '%s\n' "$body" | grep -q '^Needs: ' && { printf '%s\n' "$body"; return 0; }
  ap_body_unescape "$(printf '%s\n' "$tsv" | awk -F "$AP_C_SEP" '$4 ~ /Needs: / {b=$4} END{print b}')" | grep -B20 '^Needs: ' | tail -25
}

[[ "$DRY_RUN" == 1 ]] || claim_phase

hb_finish
ap_runs_gc
ap_log "=== 轮次 $AP_RUN_ID 结束 rc=$ROUND_RC ==="
exit "$ROUND_RC"
