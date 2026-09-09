#!/usr/bin/env bash
# poll.sh 及其 lib 的纯逻辑离线回归（规格 workflows/issue-autopilot.md §12/§5/§10/§11）
# 假 gh + 假工具链顶在 PATH 前，不联网、不碰真实凭据（与 status.t.sh/ctl.t.sh 同构，
# 不引 bats —— 零额外依赖，Windows Git Bash 同样能跑）。
# 用法: bash scripts/autopilot/tests/poll.t.sh
set -uo pipefail

AP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/home/.config/lightkey-autopilot" "$T/state" "$T/bin" "$T/repo/frontend/node_modules" "$T/repo/scripts"

pass=0 fail=0
t() { # <名> <期望0/1> <实际命令...>
  local name="$1" expect="$2"; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  if [[ $rc == $expect ]]; then pass=$((pass+1)); printf '  [PASS] %s\n' "$name"
  else fail=$((fail+1)); printf '  [FAIL] %s 期望=%s 实际=%s\n' "$name" "$expect" "$rc"; fi
}
teq() { # <名> <期望串> <实际串>
  if [[ "$2" == "$3" ]]; then pass=$((pass+1)); printf '  [PASS] %s\n' "$1"
  else fail=$((fail+1)); printf '  [FAIL] %s\n    期望: %q\n    实际: %q\n' "$1" "$2" "$3"; fi
}

# 被测 lib（source 无副作用）
export AUTOPILOT_STATE_DIR="$T/state"
export AUTOPILOT_CONF="$T/home/.config/lightkey-autopilot/host.toml"
export AUTOPILOT_REPO_DIR="$T/repo"
export AP_TMP="$T/tmp"; mkdir -p "$AP_TMP"
# shellcheck source=../lib/common.sh
source "$AP/lib/common.sh"
# shellcheck source=../lib/labels.sh
source "$AP/lib/labels.sh"
# shellcheck source=../lib/heartbeat.sh
source "$AP/lib/heartbeat.sh"
# shellcheck source=../lib/pr.sh
source "$AP/lib/pr.sh"

echo "=== poll/lib 纯逻辑回归 ==="

# ---- 1. host.toml 解析（common.sh） ----------------------------------------------
cat > "$AUTOPILOT_CONF" <<'EOF'
host_id = "linux-ws1"
claimed_capabilities = ["rust-workspace", "frontend-vitest"]
provider = "bailian-plan-personal"
budget_implement_tokens = 2000000
tracking_issue = 184
EOF
teq "conf_get 标量" "linux-ws1" "$(ap_conf_get host_id)"
teq "conf_get 缺键返回空" "" "$(ap_conf_get nope || true)"
teq "conf_get 整数" "2000000" "$(ap_conf_get budget_implement_tokens)"
teq "conf_list 数组" "rust-workspace frontend-vitest" "$(ap_conf_list claimed_capabilities | paste -sd' ' -)"

# ---- 2. 每日配额（common.sh） ------------------------------------------------------
teq "配额初始 0" "0" "$(ap_quota_read)"
ap_quota_inc >/dev/null; ap_quota_inc >/dev/null
teq "配额计数 2" "2" "$(ap_quota_read)"
rm -f "$(ap_quota_file)"
teq "配额文件没了归零" "0" "$(ap_quota_read)"

# ---- 3. 脱敏（common.sh，§12.6） --------------------------------------------------
teq "redact ghp_ token" 'token=ghp_REDACTED x' \
  "$(printf 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 x' | ap_redact_stream)"
teq "redact sk- key" 'key=sk-REDACTED' \
  "$(printf 'key=sk-abcdefghijklmnopqrst x=y' | grep -o 'key=sk-[A-Za-z0-9_-]*' | head -1 | sed 's/sk-[A-Za-z0-9_-]*/sk-REDACTED/')"

# ---- 4. denylist 路径闭集（pr.sh，§10） -------------------------------------------
teq "denylist .github" ".github/**" "$(printf '.github/workflows/x.yml\n' | ap_denylist_path_hits)"
teq "denylist 自身规格 workflows" "workflows/**(循环自身规格)" "$(printf 'workflows/issue-autopilot.md\n' | ap_denylist_path_hits)"
teq "denylist lk-app 已放开（#30）" "" "$(printf 'crates/lk-app/src/main.rs\n' | ap_denylist_path_hits)"
teq "denylist docs 全树保守禁" "docs/**(规格权威文件,保守全禁)" "$(printf 'docs/sync.md\n' | ap_denylist_path_hits)"
teq "denylist decisions" "docs/decisions.md" "$(printf 'docs/decisions.md\n' | ap_denylist_path_hits)"
teq "denylist 版本闸门候选" "Cargo.toml[workspace.package].version" "$(printf 'Cargo.toml\n' | ap_denylist_path_hits)"
teq "denylist 干净路径为空" "" "$(printf 'crates/lk-core/src/lib.rs\nfrontend/src/x.ts\n' | ap_denylist_path_hits)"

# ---- 5. 版本闸门（pr.sh，#34） -----------------------------------------------------
cat > "$AP_TMP/toml_old" <<'EOF'
[workspace.package]
version = "0.4.0"
edition = "2021"
EOF
cat > "$AP_TMP/toml_new" <<'EOF'
[workspace.package]
version = "0.4.1"
edition = "2021"
EOF
cat > "$AP_TMP/toml_new2" <<'EOF'
[workspace.package]
version = "0.4.0"
edition = "2021"
[dependencies]
foo = "1"
EOF
teq "workspace version 提取" '0.4.0' "$(ap_workspace_version < "$AP_TMP/toml_old")"
t  "版本变更被闸住" 0 ap_version_changed "$AP_TMP/toml_old" "$AP_TMP/toml_new"
t  "版本未变更放行" 1 ap_version_changed "$AP_TMP/toml_old" "$AP_TMP/toml_new2"

# ---- 6. ref 白名单（pr.sh，§12.2/7） ----------------------------------------------
printf '%s\n' '0000000000000000000000000000000000000001 refs/heads/main' \
             '0000000000000000000000000000000000000002 refs/heads/autopilot/170' > "$AP_TMP/rb"
printf '%s\n' '0000000000000000000000000000000000000009 refs/heads/main' \
             '0000000000000000000000000000000000000003 refs/heads/autopilot/170' \
             '0000000000000000000000000000000000000004 refs/heads/feature-x' \
             '0000000000000000000000000000000000000005 refs/heads/autopilot/171' > "$AP_TMP/ra"
viol=$(ap_refs_violations "$AP_TMP/rb" "$AP_TMP/ra")
teq "越权 ref：main 被改 + 新 feature-x" \
  "refs/heads/feature-x
refs/heads/main" \
  "$(printf '%s\n' "$viol" | awk '{print $2}' | sort | paste -sd'
' -)"

# ---- 7. PR 正文契约（pr.sh，§10） --------------------------------------------------
teq "Closes 解析" "170" "$(ap_pr_closes_target 'Closes #170

## Spec 依据
xx')"
teq "fixes 不在 closes 契约内" "" "$(ap_pr_closes_target '... fixes #171 ...')"
teq "无 Closes 为空" "" "$(ap_pr_closes_target 'nope')"

# ---- 8. 标签白名单 / diff / 越权（labels.sh，§5） ----------------------------------
t  "白名单内 needs-info"     0 ap_triage_whitelisted needs-info
t  "白名单内 bug"             0 ap_triage_whitelisted bug
t  "白名单外 agent-working"   1 ap_triage_whitelisted agent-working
t  "白名单外 wontfix"          1 ap_triage_whitelisted wontfix
diff=$(ap_label_diff "needs-triage,bug" "ready-for-agent,bug")
teq "diff 只报变化" "+ready-for-agent
-needs-triage" "$diff"
teq "白名单内改动不越权" "" "$(ap_label_violations "$diff")"
diff2=$(ap_label_diff "needs-triage" "agent-working,needs-triage")
teq "agent-working 即越权" "+agent-working" "$(ap_label_violations "$diff2")"

# ---- 9. 戳 / OWNER 回复 / mine 解析（labels.sh，§8） -------------------------------
S="$AP_C_SEP"
tsv="$(printf 'bot%sOWNER%s2026-09-08T10:00:00Z%s## AGENT-WORKING [linux-ws1/2026-09-08T10:00Z]\\n- run-id: r-170-x\\n- attempt: 1/2\\n- last-heartbeat: 2026-09-08T11:40Z' "$S" "$S" "$S")
$(printf 'jibuji%sOWNER%s2026-09-08T12:00:00Z%s## NEEDS-HUMAN [linux-ws1/r-170-x]\\n**卡在哪**：xx' "$S" "$S" "$S")"
teq "戳解析 host" "linux-ws1" "$(ap_stamp_latest "$tsv" | sed -n 1p)"
teq "戳解析 attempt" "1" "$(ap_stamp_latest "$tsv" | sed -n 3p)"
teq "NEEDS-HUMAN 锚点时间" "2026-09-08T12:00:00Z" "$(ap_nh_anchor_time "$tsv")"

tsv2="$tsv"$'\n'"$(printf 'jibuji%sOWNER%s2026-09-09T09:00:00Z%sAUTOPILOT: 改用方案 B' "$S" "$S" "$S")"
reply=$(ap_owner_reply_after "$tsv2" "2026-09-08T12:00:00Z")
teq "OWNER 回复识别（非我方标记）" "2026-09-09T09:00:00Z" "$(printf '%s' "$reply" | awk -F "$S" '{print $1}')"
teq "AUTOPILOT 注入行" "AUTOPILOT: 改用方案 B" "$(printf '%s' "$reply" | awk -F "$S" '{print $2}')"
tsv3="$tsv"$'\n'"$(printf 'jibuji%sNONE%s2026-09-09T10:00:00Z%s外部报告人回复不算恢复' "$S" "$S" "$S")"
t  "外部报告人回复不算" 1 ap_owner_reply_after "$tsv3" "2026-09-08T12:00:00Z"
tsv4="$tsv"$'\n'"$(printf 'jibuji%sOWNER%s2026-09-09T09:30:00Z%smine' "$S" "$S" "$S")"
t  "mine 抢单识别" 0 ap_mine_after "$tsv4" "2026-09-08T10:00:00Z"
tsv5="$tsv"$'\n'"$(printf 'jibuji%sOWNER%s2026-09-09T09:30:00Z%s## AGENT-WORKING [linux-ws1/续跑戳]（我方评论不算 mine）' "$S" "$S" "$S")"
t  "我方续戳不算 mine" 1 ap_mine_after "$tsv5" "2026-09-08T10:00:00Z"

# ---- 10. 跳账台账（heartbeat.sh，§6） ----------------------------------------------
body_old='# heartbeat
<!-- human -->
人读区保留
<!-- /human -->
## skipped-on-host
skipped #173 host=linux-ws1 missing=tauri-shell at=2026-09-02T00:00:00Z
skipped #175 host=win-desktop1 missing=rust-workspace at=2026-09-03T00:00:00Z

## 循环健康
- last-ok: 2026-09-08T00:00:00Z
'
teq "台账提取" "2" "$(hb_ledger_lines "$body_old" | wc -l)"
ledger=$(hb_ledger_lines "$body_old")
new1='skipped #173 host=linux-ws1 missing=tauri-shell at=2026-09-09T00:00:00Z'
merged=$(hb_ledger_merge "$ledger" "$new1")
teq "同 host+issue 只留最新" "skipped #173 host=linux-ws1 missing=tauri-shell at=2026-09-09T00:00:00Z" \
  "$(printf '%s\n' "$merged" | grep '#173 ')"
teq "合并后条目数 2" "2" "$(printf '%s\n' "$merged" | grep -c '^skipped #')"
teq "在册宿主集合" "linux-ws1 win-desktop1" "$(hb_ledger_hosts "$merged" | paste -sd' ' -)"
teq "#173 被跳宿主" "linux-ws1" "$(hb_ledger_hosts_for 173 "$merged" | paste -sd' ' -)"
teq "台账首见（诊断用途；降级时钟走 timeline，见 ap_ready_since）" "2026-09-02T00:00:00Z" "$(hb_ledger_first_seen 173 "$ledger")"

# ---- 11. 心跳整写（heartbeat.sh，§9 契约行） ----------------------------------------
HB_HOST=linux-ws1; HB_RESULT="- 结论: OK"; HB_LINES="- 认领: #170 (attempt 1/2)"
HB_QUOTA_LINE="implement-today 1/3 · round-timeout 60m · disk 41 GiB"; HB_WEBHOOK=off; HB_PAUSED=0
HB_LEDGER=$(printf '%s\n' "$merged" | sed '/^$/d')
new_body=$(hb_render_full "$body_old")
teq "契约行严格 ISO 形状（watchdog 正则可判）" "1" \
  "$(printf '%s\n' "$new_body" | grep -cE '^- last-ok: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')"
teq "human 区保留" "1" "$(printf '%s\n' "$new_body" | grep -c '人读区保留')"
teq "台账进正文" "1" "$(printf '%s\n' "$new_body" | grep -c 'skipped #175 host=win-desktop1')"

# ---- 12. probe-capabilities：全绿场景 + fail-closed（§7） ---------------------------
cat > "$T/repo/scripts/e2e_cross_subsystem.sh" <<'EOF'
#!/usr/bin/env bash
echo "PREFLIGHT-OK: ok"
exit 0
EOF
chmod +x "$T/repo/scripts/e2e_cross_subsystem.sh"
cat > "$T/bin/cargo" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == --version ]] && { echo "cargo 1.80"; exit 0; }
exit 0
EOF
cat > "$T/bin/node" <<'EOF'
#!/usr/bin/env bash
echo "v22"; exit 0
EOF
cat > "$T/bin/npm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$T/bin/pkg-config" <<'EOF'
#!/usr/bin/env bash
[[ "$2" == webkit2gtk-4.1 ]] && exit 0
exit 1
EOF
chmod +x "$T/bin"/*
pj=$(PATH="$T/bin:$PATH" bash "$AP/probe-capabilities.sh" 2>/dev/null | tail -1)
teq "probe host_id 注入" "1" "$(printf '%s' "$pj" | grep -c '"host_id":"linux-ws1"')"
teq "probe rust-workspace true" "1" "$(printf '%s' "$pj" | grep -c '"rust-workspace":true')"
teq "probe tauri-shell true" "1" "$(printf '%s' "$pj" | grep -c '"tauri-shell":true')"
teq "probe wsl2 true" "1" "$(printf '%s' "$pj" | grep -c '"wsl2-desktop-e2e":true')"
teq "probe windows-cross false（无 conda）" "1" "$(printf '%s' "$pj" | grep -c '"windows-cross-check":false')"
teq "probe release-build 恒 false" "1" "$(printf '%s' "$pj" | grep -c '"release-build":false')"
teq "probe 单行 JSON" "1" "$(PATH="$T/bin:$PATH" bash "$AP/probe-capabilities.sh" 2>/dev/null | wc -l)"

# fail-closed：没有工具链 → 一切 false
rm -f "$T/bin"/*
pj2=$(PATH="$T/emptybin" bash "$AP/probe-capabilities.sh" 2>/dev/null | tail -1)
teq "fail-closed 全 false" "0" "$(printf '%s' "$pj2" | grep -c ':true')"
mkdir -p "$T/emptybin"

echo "PASS=$pass FAIL=$fail"
(( fail == 0 ))
