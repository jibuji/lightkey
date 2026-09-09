#!/usr/bin/env bash
# issue-autopilot PR 层（规格 workflows/issue-autopilot.md §10 / §12.2/5/7）
#
# denylist 路径闭集 + 版本闸门 + lockfile 大改阈值 + ref 白名单，纯逻辑可离线回归
# （tests/poll.t.sh）；gh/git 包装仅薄封装。
# shellcheck shell=bash disable=SC2317

source_once() { [[ "$(type -t "$1" 2>/dev/null)" == function ]] || source "$2"; }
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_once ap_log "$_here/common.sh"

# Cargo.lock 「大改」阈值（§10：路径闭集里的 `Cargo.lock 大改`；超出聚焦改动的
# 依赖翻搅视为范围蔓延，宁可人评）。改动行数（+/- 合计）> 该值即命中。
AP_LOCK_MAX_LINES=200

# ---- 纯逻辑：路径闭集 --------------------------------------------------------------

# stdin = 变更路径（一行一个）→ stdout = 命中的 denylist 规则（一行一个）
ap_denylist_path_hits() {
  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    case "$p" in
      .github/*|.github)                                    echo ".github/**" ;;
      crates/lk-app/*)                                      echo "crates/lk-app/**" ;;
      Cargo.toml)                 echo "Cargo.toml[workspace.package].version" ;;
      Cargo.lock)                        echo "Cargo.lock(大改候选:再看行数)" ;;
      frontend/package-lock.json)  echo "frontend/package-lock.json" ;;
      docs/decisions.md)                              echo "docs/decisions.md" ;;
      CONTEXT.md)                                          echo "CONTEXT.md" ;;
      AGENTS.md)                                            echo "AGENTS.md" ;;
      docs/adr/*)                                        echo "docs/adr/**" ;;
      docs/*)             echo "docs/**(规格权威文件,保守全禁)" ;;
    esac
  done
}

# 根 Cargo.toml 的 [workspace.package] version（stdin → stdout；无该节输出空）
ap_workspace_version() {
  awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version[[:space:]]*=/{print $3}' \
    | tr -d '"'
}

# 版本闸门（#34）：发布 tag 必须等于 workspace version → bump 属发版动作
ap_version_changed() { # <old-toml-file> <new-toml-file>
  local a b
  a=$(ap_workspace_version <"$1"); b=$(ap_workspace_version <"$2")
  [[ -n "$a" && "$a" != "$b" ]]
}

# ---- 纯逻辑：ref 白名单（§12.2/7） --------------------------------------------------

# stdin = `git ls-remote origin` 原文 → "sha ref" 行集
ap_refs_parse() { grep -E '^[0-9a-f]{40}[[:space:]]+refs/' | tr '\t' ' ' | awk '{print $1, $2}'; }

# 新增/变更的 ref 里凡不在 autopilot/<n> 命名空间 → 输出违规 "sha ref" 行（空=干净）
ap_refs_violations() { # <before-stdin> <after-stdin>   （两个参数都是文件路径）
  sort -k2 "$1" -o "$1.sort"; sort -k2 "$2" -o "$2.sort"
  join -j 2 -o 0,1.1,2.1 "$1.sort" "$2.sort" 2>/dev/null | awk '
    $2 != $3 { print $3, $1 }' | grep -vE 'autopilot/[0-9]+$' || true
  awk 'NR==FNR{b[$2]=1;next} !($2 in b){print $1, $2}' "$1.sort" "$2.sort" \
    | grep -vE 'autopilot/[0-9]+$' || true
  rm -f "$1.sort" "$2.sort"
}

# ---- 纯逻辑：PR 正文契约 --------------------------------------------------------

# Closes 行在 → 输出该 issue 号（§10：缺它不许开 auto-merge）
ap_pr_closes_target() { # <pr-body>
  printf '%s' "$1" | grep -oiE 'closes? #[0-9]+' | grep -oE '[0-9]+' | head -1
}

# PR 正文骨架（§10 必填四段；prompt 层把它拼进 implement/resume 提示词，由 agent 填实）
ap_pr_body_template() { # <issue-n>
  cat <<EOF
Closes #$1

## Spec 依据
（docs/<spec>.md §<节> + issue brief 摘要）

## 本机验证结果
（跑了哪些命令、通过与否、缺哪个能力——如实写，CI 绿 ≠ 本机验证过）

## 护栏命中
（denylist 判定结果：干净 / 命中哪些路径）

## NEEDS-HUMAN 历史
（无 / 卡过哪、怎么解的）
EOF
}

# ---- git/gh 包装 ----------------------------------------------------------------

# 变更路径集（相对仓库根，一行一个；删除/新增/修改都算）
ap_changed_paths() { # <base-ref> <head-ref>
  git diff --name-only "$1" "$2" 2>/dev/null
}

# denylist 全判定（路径 + 版本闸门 + lockfile 大改）→ stdout 命中说明（空=干净）
ap_denylist_check() { # <base-ref> <head-ref>
  local hits="" paths p
  paths=$(ap_changed_paths "$1" "$2")
  hits=$(printf '%s\n' "$paths" | ap_denylist_path_hits | sort -u)
  if printf '%s\n' "$paths" | grep -qx 'Cargo.toml'; then
    git show "$1:Cargo.toml" >"$AP_TMP/dl_base.toml" 2>/dev/null
    git show "$2:Cargo.toml" >"$AP_TMP/dl_head.toml" 2>/dev/null
    if ap_version_changed "$AP_TMP/dl_base.toml" "$AP_TMP/dl_head.toml"; then
      hits+=$'\n'"Cargo.toml workspace.package version 变更（#34 bump 属发版）"
    fi
  fi
  if printf '%s\n' "$paths" | grep -qx 'Cargo.lock'; then
    local n=0
    n=$(git diff --numstat "$1" "$2" -- Cargo.lock 2>/dev/null | awk '{a+=$1+$2} END{print a+0}')
    (( n > AP_LOCK_MAX_LINES )) && hits+=$'\n'"Cargo.lock 大改（${n} 行 > ${AP_LOCK_MAX_LINES}）"
  fi
  printf '%s' "$hits" | sed '/^$/d'
}

# PR 的 merge 决策 + 动作（§10 两道闸的合并闸门这一半）
ap_pr_setup_merge() { # <pr> <issue> [auto=1]
  local body hits
  body=$(gh pr view "$1" --json body --jq .body 2>/dev/null) || { ap_log "pr view 失败 #$1"; return 1; }
  if [[ -z "$(ap_pr_closes_target "$body")" ]]; then
    ap_log "PR #$1 缺 Closes 行 → 不开 auto-merge（§10）"
    return 1
  fi
  hits=$(ap_denylist_check "origin/main" "autopilot/$2")
  if [[ -n "$hits" ]]; then
    ap_log "PR #$1 命中 denylist：$hits → 不开 auto-merge，转 needs-human（§10）"
    return 2
  fi
  gh pr merge "$1" --auto --squash >/dev/null 2>&1 && ap_log "PR #$1 auto-merge ON（CI 全绿即 squash 合并）"
}
