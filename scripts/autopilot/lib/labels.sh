#!/usr/bin/env bash
# issue-autopilot 标签与评论层（规格 workflows/issue-autopilot.md §5 / §8）
#
# - gh 包装（真机用；回归用假 gh 顶在 PATH 前面即可）
# - 纯函数（戳解析 / OWNER 回复判定 / mine 抢单判定 / 标签 diff）供 tests/poll.t.sh 离线钉
# shellcheck shell=bash disable=SC2317

source_once() { [[ "$(type -t "$1" 2>/dev/null)" == function ]] || source "$2"; }
source_once ap_conf_path "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# ---- gh 包装 ----------------------------------------------------------------------

ap_issue_labels() { # <n> → 逗号分隔标签（无标签输出空）
  gh issue view "$1" --json labels --jq '.labels | map(.name) | join(",")' 2>/dev/null
}

ap_label_add() { # <n> <label>
  gh issue edit "$1" --add-label "$2" >/dev/null 2>&1 || ap_log "label add 失败 #$1 +$2（容忍继续）"
}

ap_label_remove() { # <n> <label>
  gh issue edit "$1" --remove-label "$2" >/dev/null 2>&1 || ap_log "label remove 失败 #$1 -$2（容忍继续）"
}

ap_issue_close() { # <n> <comment>
  gh issue close "$1" --comment "$2" >/dev/null 2>&1 || ap_log "issue close 失败 #$1（容忍继续）"
}

# 发评论 → 输出 comment id（从返回 URL 抠 #issuecomment-<id>）
ap_comment_post() { # <n> <body-file>
  local url
  url=$(gh issue comment "$1" --body-file "$2" 2>/dev/null) || return 1
  printf '%s\n' "$url" | grep -oE 'issuecomment-[0-9]+' | grep -oE '[0-9]+'
}

# 覆盖式更新指定 comment（§8：实现期每 10 分钟更新 last-heartbeat；绝不误编辑他人评论）
ap_comment_edit() { # <comment-id> <body-file>
  gh api "repos/$(gh repo view --json nameWithOwner --jq .nameWithOwner)/issues/comments/$1" \
    -X PATCH -F body=@"$2" >/dev/null 2>&1
}

# 取某 issue 的评论（升序）为「login␟assoc␟createdAt␟body」行集；body 的换行压成 \n 字面量
AP_C_SEP=$'\xe2\x90\x9f' # U+241F ␟（正文中出现概率≈0）
ap_comments_tsv() { # <n>
  gh issue view "$1" --json comments --jq \
    ".comments[] | [.author.login, .authorAssociation, .createdAt, (.body | gsub(\"\\n\"; \"\\\\n\"))] | join(\"\u241f\")"
}

# ---- 纯函数：戳解析（输入是上面 TSV 的 body 列；$(...) 已丢换行，用字面 \n 占位） ----

ap_body_unescape() { printf '%s' "$1" | sed 's/\\n/\n/g'; }

# 最新 AGENT-WORKING 戳 → 关键字段；无戳返回 1
# 输出 4 行：host / run-id / attempt 分子 / last-heartbeat（可缺省 "-"）
ap_stamp_latest() { # <tsv 行集>
  local line body stamp=""
  while IFS= read -r line; do
    body=$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $4}')
    [[ "$(ap_body_unescape "$body")" =~ ^##[[:space:]]AGENT-WORKING[[:space:]]\[ ]] && stamp="$body"
  done <<< "$1"
  [[ -n "$stamp" ]] || return 1
  local s; s=$(ap_body_unescape "$stamp")
  printf '%s\n%s\n%s\n%s\n' \
    "$(printf '%s' "$s" | sed -n 's/^## AGENT-WORKING \[\([^/]*\)\/.*\]$/\1/p')" \
    "$(printf '%s' "$s" | sed -n 's/^- run-id: //p')" \
    "$(printf '%s' "$s" | sed -n 's/^- attempt: \([0-9]*\)\/.*/\1/p')" \
    "$(printf '%s' "$s" | sed -n 's/^- last-heartbeat: //p' | tail -1)"
}

# 最新 NEEDS-HUMAN 锚点评论的 createdAt；无 → 返回 1
ap_nh_anchor_time() { # <tsv 行集>
  local line t=""
  while IFS= read -r line; do
    if [[ "$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $4}')" =~ ^##[[:space:]]NEEDS-HUMAN[[:space:]]\[ ]]; then
      t=$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $3}')
    fi
  done <<< "$1"
  [[ -n "$t" ]] && printf '%s\n' "$t"
}

# 「我方评论」特征（本循环 / /triage 免责声明产生）；用于把 OWNER 身份的机器人评论
# 与真正的人类回复区分开（本机 gh 账号 = OWNER，authorAssociation 不足以区分）
ap_is_our_comment() { # <body>
  local b; b=$(printf '%s' "$1" | head -1)
  [[ "$b" =~ ^##[[:space:]]AGENT-WORKING[[:space:]]\[ ]] \
    || [[ "$b" =~ ^##[[:space:]]NEEDS-HUMAN[[:space:]]\[ ]] \
    || [[ "$(ap_body_unescape "$1")" =~ \*[Tt]his[[:space:]]was[[:space:]]generated[[:space:]]by[[:space:]]AI ]]
}

# 锚点之后第一条 OWNER/MEMBER 人类回复 → 输出 "created␟body"；无 → 1
ap_owner_reply_after() { # <tsv 行集> <anchor-createdAt>
  local line when assoc body
  while IFS= read -r line; do
    when=$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $3}')
    assoc=$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $2}')
    body=$(printf '%s' "$line" | awk -F "$AP_C_SEP" '{print $4}')
    [[ "$when" > "$2" ]] || continue
    [[ "$assoc" == OWNER || "$assoc" == MEMBER ]] || continue
    ap_is_our_comment "$body" && continue
    printf '%s%s%s\n' "$when" "$AP_C_SEP" "$body"
    return 0
  done <<< "$1"
  return 1
}

# 认领戳之后出现 OWNER/MEMBER 人类评论含独立词 "mine" → 0（人抢单）
ap_mine_after() { # <tsv 行集> <stamp-createdAt>
  local reply
  reply=$(ap_owner_reply_after "$1" "$2") || return 1
  ap_body_unescape "$(printf '%s' "$reply" | awk -F "$AP_C_SEP" '{print $2}')" | grep -qw mine
}

# issue 的 ready-for-agent 标签最近一次打上时间（timeline API；降级时钟用它：
# 台账同 host+issue 只保最近一条（§6），撑不起 7 天时钟；timeline 从 GitHub 可全量重建，§9）
ap_ready_since() { # <repo-path> <n>
  gh api "repos/$1/issues/$2/timeline?per_page=100" --paginate --jq \
    '.[] | select(.event == "labeled" and .label.name == "ready-for-agent") | .created_at' 2>/dev/null | tail -1
}

# ---- 纯函数：标签白名单与 diff（§5） ----------------------------------------------

# /triage 分诊 agent 允许读写的标签闭集：四状态 + 既有类别
ap_triage_whitelisted() { # <label>
  case "$1" in
    needs-triage|needs-info|ready-for-agent|ready-for-human|bug|enhancement|documentation|question) return 0 ;;
    *) return 1 ;;
  esac
}

# before/after（逗号串）→ 变更行集（"+x" / "-y"），无变更输出空
ap_label_diff() { # <before-csv> <after-csv>
  local a b
  { tr ',' '\n' <<< "${1:-}"; } | grep -v '^$' | sort -u > /tmp/.ap_lbl_a.$$
  { tr ',' '\n' <<< "${2:-}"; } | grep -v '^$' | sort -u > /tmp/.ap_lbl_b.$$
  comm -13 /tmp/.ap_lbl_a.$$ /tmp/.ap_lbl_b.$$ | sed 's/^/+/' | grep -v '^+$'
  comm -23 /tmp/.ap_lbl_a.$$ /tmp/.ap_lbl_b.$$ | sed 's/^/-/' | grep -v '^-$'
  rm -f /tmp/.ap_lbl_a.$$ /tmp/.ap_lbl_b.$$
}

# diff 行集里出现白名单外的标签改动 → 输出越权行（非空即违规）
ap_label_violations() { # <diff 行集>
  local l
  while IFS= read -r l; do
    [[ -n "$l" ]] || continue
    ap_triage_whitelisted "${l:1}" || printf '%s\n' "$l"
  done <<< "$1"
}
