#!/usr/bin/env bash
# issue-autopilot 能力探测（规格 workflows/issue-autopilot.md §7；补充拍板 #29）
#
# 契约：stdout 恰好一行 JSON，调度器只读它判能力：
#   {"host_id":"…","ok":true,"capabilities":{…6 项…},"missing_reasons":{…},
#    "disk_free_gib":41.2,"ts":"…"}
# 每项必须是**主动验证**（不许只看配置文件）；探测失败/超时 ⇒ 该能力 false（fail-closed，
# A7：claimed_capabilities 只是候选声明，探测不过即缺失）。
#
# 环境覆盖（测试用）：AUTOPILOT_CONF / AUTOPILOT_REPO_DIR / PATH（假 cargo/npm/wsl…）
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${AUTOPILOT_CONF:-$HOME/.config/lightkey-autopilot/host.toml}"
REPO="${AUTOPILOT_REPO_DIR:-$(cd "$HERE/../.." && pwd)}"

conf_get() {
  [[ -f "$CONF" ]] || return 1
  local v
  v=$(grep -m1 "^[[:space:]]*$1[[:space:]]*=" "$CONF" | tail -1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//' | tr -d '\r')
  v="${v%\"}"; v="${v#\"}"; printf '%s\n' "$v"; [[ -n "$v" ]]
}

HOST_ID=$(conf_get host_id) || HOST_ID="(unconfigured)"

# ---- 探测原语 --------------------------------------------------------------------

probe() { # <timeout-s> <cmd...> → 0/1
  timeout "$1" "${@:2}" >/dev/null 2>&1
}

CAP_BOOL() { # <cap> <0|1> <reason-if-false>
  CAPS["$1"]=${2}
  [[ "$2" == true ]] || { [[ -n "${3:-}" ]] && REASONS["$1"]="$3"; }
}

declare -A CAPS REASONS

# 1. rust-workspace：cargo 在 + `cargo test -p lk-core --no-run` 能过（真编译，非看文件）
if probe 900 cargo --version && (cd "$REPO" && probe 1800 cargo test -p lk-core --no-run -q); then
  CAP_BOOL rust-workspace true
else
  CAP_BOOL rust-workspace false "cargo 不可用或 cargo test -p lk-core --no-run 未过"
fi

# 2. frontend-vitest：node 在 + node_modules（或 npm ci 可成）+ 冒烟跑一轮
if probe 30 node --version && { [[ -d "$REPO/frontend/node_modules" ]] || (cd "$REPO/frontend" && probe 900 npm ci --silent); }; then
  if (cd "$REPO/frontend" && probe 900 npm test -- --run); then
    CAP_BOOL frontend-vitest true
  else
    CAP_BOOL frontend-vitest false "npm test --run 冒烟未过"
  fi
else
  CAP_BOOL frontend-vitest false "node 不可用且 node_modules 缺失 / npm ci 失败"
fi

# 3. tauri-shell：Linux 需 webkit2gtk + `cargo check -p lk-app`；探测脚本跑在哪个
#    运行时就验哪个运行时看到的工具链（A14：Git Bash 引擎看到的是原生 Windows 工具链）
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  if probe 1800 cargo check -p lk-app -q; then CAP_BOOL tauri-shell true
  else CAP_BOOL tauri-shell false "Windows 原生 cargo check -p lk-app 未过"; fi
else
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists webkit2gtk-4.1; then
    if (cd "$REPO" && probe 1800 cargo check -p lk-app -q); then CAP_BOOL tauri-shell true
    else CAP_BOOL tauri-shell false "cargo check -p lk-app 未过"; fi
  else
    CAP_BOOL tauri-shell false "webkit2gtk-4.1 not installed"
  fi
fi

# 4. windows-cross-check：conda env lightkey-mingw 在 + 交叉冒烟
MINGW_ENV=""
for d in "$HOME/miniconda3/envs/lightkey-mingw" "$HOME/anaconda3/envs/lightkey-mingw" \
         /opt/conda/envs/lightkey-mingw /usr/local/conda/envs/lightkey-mingw; do
  [[ -d "$d" ]] && MINGW_ENV="$d" && break
done
if command -v conda >/dev/null 2>&1 && [[ -z "$MINGW_ENV" ]]; then
  d=$(conda env list 2>/dev/null | awk '$1=="lightkey-mingw"{print $NF; exit}')
  [[ -n "$d" && "$d" != "lightkey-mingw" ]] && MINGW_ENV="$d"
fi
if [[ -n "$MINGW_ENV" ]] && (cd "$REPO" && PATH="$MINGW_ENV/bin:$PATH" probe 1800 cargo check --workspace --target x86_64-pc-windows-gnu -q); then
  CAP_BOOL windows-cross-check true
else
  CAP_BOOL windows-cross-check false "conda env lightkey-mingw 不存在或交叉 cargo check 未过"
fi

# 5. wsl2-desktop-e2e：E2E 脚本前置不 SKIP（--preflight-only：只跑前置，不执行本体）
if [[ -f "$REPO/scripts/e2e_cross_subsystem.sh" ]] \
   && out=$(timeout 300 bash "$REPO/scripts/e2e_cross_subsystem.sh" --preflight-only 2>&1); then
  if printf '%s\n' "$out" | grep -q '^SKIP:'; then
    CAP_BOOL wsl2-desktop-e2e false "$(printf '%s\n' "$out" | grep '^SKIP:' | head -1 | cut -c1-120)"
  else
    CAP_BOOL wsl2-desktop-e2e true
  fi
else
  CAP_BOOL wsl2-desktop-e2e false "e2e_cross_subsystem.sh 前置未通过或脚本缺失"
fi

# 6. release-build：仅 OWNER 手工，探测恒 false（§7 表；agent 永不可得）
CAP_BOOL release-build false "仅 OWNER 手工：探测恒为 false"

# ---- 输出（恰好一行 JSON） -------------------------------------------------------

DISK=$(df -BG --output=avail . 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)
[[ -n "$DISK" ]] || DISK=0

order=(rust-workspace frontend-vitest tauri-shell windows-cross-check wsl2-desktop-e2e release-build)
caps_json=""
reasons_json=""
sep=""
for c in "${order[@]}"; do
  caps_json+="$sep\"$c\":${CAPS[$c]}"
  [[ -n "${REASONS[$c]:-}" ]] && reasons_json+="$sep\"$c\":\"${REASONS[$c]}\""
  sep=","
done

# 声明 vs 探测（A7）：声明里没有、探测却有 → stderr 打警告（用探测结果）
if [[ -f "$CONF" ]]; then
  for c in $(grep -m1 '^[[:space:]]*claimed_capabilities' "$CONF" | sed 's/^[^=]*=//' | tr -d '[]"' | tr ',' '\n' | tr -d ' '); do
    [[ -n "$c" && "${CAPS[$c]:-false}" == false ]] \
      && printf 'warning: %s 声明了 %s 但探测不过（A7：以探测为准，能力缺失）\n' "$HOST_ID" "$c" >&2
  done
fi

printf '{"host_id":"%s","ok":true,"capabilities":{%s},"missing_reasons":{%s},"disk_free_gib":%s,"ts":"%s"}\n' \
  "$HOST_ID" "$caps_json" "$reasons_json" "$DISK" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
