#!/usr/bin/env bash
# issue-autopilot 心跳层（规格 workflows/issue-autopilot.md §9）
#
# tracking issue 正文 = 人可读投影，唯一机器契约行 `- last-ok: <ISO-8601 UTC>`：
# 每轮最先写（§12.10），失败路径也要写；`<!-- human -->` 区整段保留（§9）。
# 跳账台账（§6 skipped-on-host）与 7 天全宿主否定的降级素材也住在这层。
# shellcheck shell=bash disable=SC2317

source_once() { [[ "$(type -t "$1" 2>/dev/null)" == function ]] || source "$2"; }
source_once ap_conf_path "$(dirname "${BASH_SOURCE[0]}")/common.sh"
source_once ap_log        "$(dirname "${BASH_SOURCE[0]}")/common.sh"

HB_STALE_MINUTES=45

hb_body_read() { gh issue view "$1" --json body --jq .body 2>/dev/null; }
hb_body_write() { gh issue edit "$1" --body-file "$2" >/dev/null 2>&1; }

# 本轮**第一个写入动作**（§12.10）：把 `- last-ok: <now>` 落进现有正文。
# 只动契约行；paused=1 时同时把首条「结论」行改为已暂停说明（§4 步骤 0）。
# 正文里没有任何 last-ok 行时在文末追加（首轮/被改坏时的自愈路径）。
hb_touch() { # <issue> [paused=0]
  local body out now
  body=$(hb_body_read "$1") || return 1
  now=$(ap_now_iso)
  out=$(printf '%s\n' "$body" | awk -v ts="$now" -v paused="${2:-0}" '
    BEGIN { done = 0 }
    /^- last-ok: / { if (!done) { print "- last-ok: " ts; done = 1; next } }
    paused == 1 && /^- 结论: / { print "- 结论: 已暂停（标题含 [PAUSED]，本轮不动任何 issue）"; next }
    { print }
    END { if (!done) print "- last-ok: " ts }')
  printf '%s\n' "$out" >"$AP_TMP/hb_touch.md"
  hb_body_write "$1" "$AP_TMP/hb_touch.md"
}

# ---- 跳账台账（§6） ---------------------------------------------------------------

# 台账行形状：`skipped #<n> host=<h> missing=<cap> at=<ISO>`
# 同一 host+issue 只保最近一条（防膨胀，§6）。
hb_ledger_lines() { # <body> → 台账行集
  awk '/^## skipped-on-host/{f=1;next} /^## /{f=0} f' <<< "$1" | grep '^skipped #'
}

hb_ledger_key() { printf '%s' "$1" | sed -n 's/^skipped #\([0-9]*\) host=\([^ ]*\) missing=.*/\1@\2/p'; }
hb_ledger_at()   { sed -n 's/.* at=//p'; }

# 追加/覆盖条目 → 新台账行集。existing 可为空；newlines 里同键也只留最后一条。
hb_ledger_merge() { # <existing-lines> <new-lines>  （同 key 新者胜）
  local existing="$1" new="$2" merged="" line key
  local -A newkeys=()
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    key=$(hb_ledger_key "$line"); [[ -n "$key" ]] && newkeys["$key"]=1
  done <<< "$new"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    key=$(hb_ledger_key "$line")
    [[ -n "$key" && -n "${newkeys[$key]:-}" ]] && continue
    merged+="$line"$'\n'
  done <<< "$existing"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    merged+="$line"$'\n'
  done <<< "$new"
  printf '%s' "$merged"
}

hb_ledger_hosts() { # <全部台账行集> → 去重 host 列表（"在册宿主"的操作定义：
                    # 出现过跳账的宿主集合；从未跑过的宿主不构成否定）
  printf '%s\n' "$1" | sed -n 's/^skipped #[0-9]* host=\([^ ]*\) missing=.*/\1/p' | sort -u
}

hb_ledger_hosts_for() { # <issue-n> <台账行集> → 跳过该 issue 的宿主集合
  printf '%s\n' "$2" | sed -n "s/^skipped #$1 host=\([^ ]*\) missing=.*/\1/p" | sort -u
}

hb_ledger_first_seen() { # <issue-n> <台账行集> → 该 issue 最早 at=（无输出空）
  printf '%s\n' "$2" | grep "^skipped #$1 " | hb_ledger_at | sort | head -1
}

# ---- 整段重写（§9 骨架） ----------------------------------------------------------
# 全局输入（poll.sh 在调用前置好；tests/poll.t.sh 同样直接置）：
#   HB_HOST / HB_RESULT(结论行) / HB_LINES(本轮区逐行) / HB_QUOTA_LINE
#   / HB_WEBHOOK(off|on) / HB_PAUSED(0|1)
hb_render_full() { # <existing-body> → stdout 新正文
  local human="" line
  human=$(sed -n '/^<!-- human -->/,/^<!-- \/human -->/p' <<< "$1")
  printf '# issue-autopilot — heartbeat%s   host=%s  last-run=%s  next≈（驱动方式决定）\n\n' \
    "$([[ "${HB_PAUSED:-0}" == 1 ]] && printf ' [PAUSED]')" "$HB_HOST" "$(ap_now_iso)"
  [[ -n "$human" ]] && printf '%s\n\n' "$human"
  printf '## 本轮\n%s\n' "${HB_RESULT:-}"
  while IFS= read -r line; do [[ -n "$line" ]] && printf '%s\n' "$line"; done <<< "${HB_LINES:-}"
  [[ -n "${HB_LINES:-}" ]] && printf '\n'
  printf '## 配额\n%s\n\n' "$HB_QUOTA_LINE"
  printf '## skipped-on-host\n%s\n' "${HB_LEDGER:-（无）}"
  printf '\n## 循环健康\n- last-ok: %s\n- 阈值 %sm · 告警 webhook: %s · host=%s\n' \
    "$(ap_now_iso)" "$HB_STALE_MINUTES" "${HB_WEBHOOK:-off}" "$HB_HOST"
}
