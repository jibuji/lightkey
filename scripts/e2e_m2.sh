#!/usr/bin/env bash
# LightKey M2 授权门 E2E（docs/authorization-gate.md §7 / testing.md 第三层；
# CI 之外本地/手动运行）
#
# 场景：init → unlock → item add secret（NPM_TOKEN）→ rule add/list →
#       inject 规则命中（env 只含被授权 key、值只进子进程）→ inject 未命中
#       （headless 无审批界面 → 立即拒绝，非零退出码）→ inject 伪造 cwd 参数
#       → 拒绝 → audit 留痕（allowed/denied，无密钥值）→ 值披露（M2.9，
#       docs/value-disclosure.md）：无规则 item get → authz.denied 拒绝、
#       rule add --read 后静默放行、item export 恒弹窗（headless 拒绝）→
#       rule remove → 删除生效 + 审计。
#
# 用法：bash scripts/e2e_m2.sh [lk-binary-path]
set -u

LK="${1:-target/debug/lk}"
LK="$(cd "$(dirname "$LK")" && pwd)/$(basename "$LK")"
WORK="$(mktemp -d)"
PROJ="$(mktemp -d)"
trap 'rm -rf "$WORK" "$PROJ"' EXIT
export LIGHTKEY_HOME="$WORK"
export LK_JSON=0

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # check <desc> <expected_exit> <actual_exit>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望退出码 $2，实际 $3)"; fi
}

# 测试密钥运行时随机生成（fixture 密钥不进仓库）
MASTER_PW="e2e-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
SECRET_VALUE="sekrit-$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"

echo "== 1. init + unlock =="
"$LK" init --stdin >/dev/null 2>&1 <<<"$MASTER_PW"
check "init" 0 $?
echo "$MASTER_PW" | "$LK" unlock --stdin >/dev/null 2>&1
check "unlock" 0 $?

echo "== 2. secret 条目（key 名 → 值；值不可见、名可指名）=="
SECRET_ID="$("$LK" item add secret --name NPM_TOKEN --value "$SECRET_VALUE" --purpose 测试 | awk '{print $2}')"
check "add secret NPM_TOKEN" 0 $?
[ -n "$SECRET_ID" ] && ok "拿到条目 id" || bad "item add 未回传 id"

echo "== 3. rule add / list =="
"$LK" rule add "$PROJ" "npm *" --name publish NPM_TOKEN >/dev/null
check "rule add（命中 glob）" 0 $?
"$LK" rule add "$PROJ" "yarn deploy" --name deploy NPM_TOKEN >/dev/null
check "rule add（精确命令）" 0 $?
"$LK" rule add "$PROJ" "sh *" --name shell NPM_TOKEN >/dev/null
check "rule add（sh 通配，inject 测试用）" 0 $?
RULES="$("$LK" rule list)"
echo "$RULES" | grep -q publish && ok "rule list 含 publish" || bad "rule list 缺 publish"
echo "$RULES" | grep -q deploy && ok "rule list 含 deploy" || bad "rule list 缺 deploy"

echo "== 4. inject：规则命中 → env 只含被授权 key，值只进子进程 =="
OUT="$(cd "$PROJ" && "$LK" inject --keys NPM_TOKEN -- sh -c 'echo -n "$NPM_TOKEN"' 2>"$WORK/inject.err")"
check "inject 规则命中（exit 0）" 0 $?
if [ "$OUT" = "$SECRET_VALUE" ]; then
  ok "子进程 env 收到注入值（值只进子进程）"
else
  bad "子进程 env 值不符（got '$OUT'）"
fi
# lk 自身 stderr 不得含密钥值（只含状态信息）
if grep -q "$SECRET_VALUE" "$WORK/inject.err"; then
  bad "lk inject 自身输出泄漏密钥值"
else
  ok "lk inject 自身输出不含密钥值"
fi

echo "== 5. inject：headless 未命中规则 → 立即拒绝（非零退出码）=="
START=$(date +%s%N)
( cd "$PROJ" && "$LK" inject --keys NPM_TOKEN -- yarn publish >/dev/null 2>"$WORK/deny.err" )
CODE=$?
END=$(date +%s%N)
check "inject 未命中（headless）拒绝（exit 1）" 1 $CODE
if grep -q "无审批界面" "$WORK/deny.err"; then
  ok "拒绝原因 = 无审批界面（不阻塞）"
else
  bad "拒绝文案不符：$(cat "$WORK/deny.err")"
fi
ELAPSED_MS=$(( (END - START) / 1000000 ))
[ "$ELAPSED_MS" -lt 2000 ] && ok "无界面拒绝 <2s（不等待 30s）" || bad "无界面拒绝耗时 ${ELAPSED_MS}ms"

echo "== 6. inject：项目目录绑定——真实 cwd 不在规则项目内 → 拒绝 =="
( cd "$WORK" && "$LK" inject --keys NPM_TOKEN -- npm publish >/dev/null 2>&1 )
check "规则只在该项目目录下生效（cwd 在别处 → 拒绝，exit 1）" 1 $?

echo "== 7. audit：三层留痕 + 无密钥值 =="
AUDIT="$("$LK" audit)"
echo "$AUDIT" | grep -q "lk inject" && ok "审计含 inject 事件" || bad "审计缺 inject 事件"
ALLOWED_N=$("$LK" audit --json | jq '[.[] | select(.command | startswith("lk inject")) | select(.result == "allowed")] | length')
[ "${ALLOWED_N:-0}" -ge 1 ] && ok "审计含 allowed（规则命中）" || bad "审计缺 allowed"
DENIED_N=$("$LK" audit --json | jq '[.[] | select(.command | startswith("lk inject")) | select(.result == "denied")] | length')
[ "${DENIED_N:-0}" -ge 2 ] && ok "审计含 denied ×2（headless + 伪造 cwd）" || bad "审计 denied 数不符：$DENIED_N"
if grep -q "$SECRET_VALUE" "$WORK/audit.log" 2>/dev/null || "$LK" audit --json | grep -q "$SECRET_VALUE"; then
  bad "审计泄漏密钥值"
else
  ok "审计不含密钥值"
fi
"$LK" audit --verify >/dev/null 2>&1
check "审计 HMAC 链校验通过" 0 $?

echo "== 8. 值披露（M2.9）：headless 无规则 item get → authz.denied 拒绝 =="
( cd "$PROJ" && "$LK" item get "$SECRET_ID" >/dev/null 2>"$WORK/get.err" )
check "无规则 item get 拒绝（exit 1）" 1 $?
if grep -q "授权门拒绝" "$WORK/get.err"; then
  ok "拒绝文案提示 rule add --read 预授权"
else
  bad "拒绝文案不符：$(cat "$WORK/get.err")"
fi

echo "== 9. 值披露：rule add --read 后 item get 静默放行 =="
"$LK" rule add "$PROJ" --read --name read-token --keys NPM_TOKEN >/dev/null
check "rule add --read" 0 $?
GET_OUT="$(cd "$PROJ" && "$LK" item get "$SECRET_ID" --json 2>/dev/null | jq -r .value)"
if [ "$GET_OUT" = "$SECRET_VALUE" ]; then
  ok "读规则命中 → 静默放行（不弹窗返回明文值）"
else
  bad "读规则未放行或值不符：$GET_OUT"
fi
"$LK" rule list | grep -q "\[read\]" && ok "rule list 展示 [read] 能力" || bad "rule list 缺 capability 列"

echo "== 10. 值披露：item export 恒弹窗 → headless 拒绝（读规则不豁免）=="
( cd "$PROJ" && "$LK" item export "$SECRET_ID" -o "$WORK/out.bin" >/dev/null 2>"$WORK/export.err" )
check "export headless 拒绝（exit 1）" 1 $?
if grep -q "授权门拒绝" "$WORK/export.err"; then
  ok "export 被授权门拒绝（恒弹窗，规则不豁免）"
else
  bad "export 拒绝文案不符：$(cat "$WORK/export.err")"
fi

echo "== 11. 值披露审计：item.get allowed/denied 留痕 =="
GET_ALLOWED=$("$LK" audit --json | jq '[.[] | select(.command == "item.get") | select(.result == "allowed")] | length')
[ "${GET_ALLOWED:-0}" -ge 1 ] && ok "审计含 item.get allowed（规则命中）" || bad "审计缺 item.get allowed"
GET_DENIED=$("$LK" audit --json | jq '[.[] | select(.command == "item.get") | select(.result == "denied")] | length')
[ "${GET_DENIED:-0}" -ge 1 ] && ok "审计含 item.get denied（无规则拒绝）" || bad "审计缺 item.get denied"
EXPORT_DENIED=$("$LK" audit --json | jq '[.[] | select(.command == "item.export") | select(.result == "denied")] | length')
[ "${EXPORT_DENIED:-0}" -ge 1 ] && ok "审计含 item.export denied" || bad "审计缺 item.export denied"

echo "== 12. rule remove =="
RULE_ID="$("$LK" rule list | awk '/publish/{print $1}')"
"$LK" rule remove "$RULE_ID" >/dev/null
check "rule remove" 0 $?
"$LK" rule list | grep -q publish && bad "rule remove 未生效" || ok "rule remove 生效"

echo
echo "M2 E2E：$PASS 通过 / $FAIL 失败"
[ "$FAIL" = 0 ]
