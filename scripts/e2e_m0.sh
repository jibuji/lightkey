#!/usr/bin/env bash
# LightKey M0 单机闭环 E2E（docs/testing.md §1 第二层；CI 之外本地/手动运行）
#
# 场景：init → unlock → item add（四类各一）→ list/get → edit（CAS）→
#       delete（墓碑）→ export（附件往返）→ lock → unlock → audit 可见 →
#       恢复流程（恢复码 + 新主密码）→ 旧密码失效 / 数据完好
#
# 用法：bash scripts/e2e_m0.sh [lk-binary-path]
set -u

LK="${1:-target/debug/lk}"
LK="$(cd "$(dirname "$LK")" && pwd)/$(basename "$LK")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export LIGHTKEY_HOME="$WORK"
export LK_JSON=0

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # check <desc> <expected_exit> <actual_exit>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望退出码 $2，实际 $3)"; fi
}

# 测试密码运行时随机生成（fixture 密钥不进仓库）
MASTER_PW="e2e-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
NEW_PW="e2e-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"

echo "== 1. init =="
REC="$("$LK" init --stdin --json <<<"$MASTER_PW" | jq -r .recoveryCode)"
check "init 成功并返回恢复码" 0 $?
[ -n "$REC" ] && ok "恢复码已生成（${#REC} 字符）" || bad "恢复码为空"
echo "$REC" | grep -Eq '^[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}$' \
  && ok "恢复码格式 5×8 防混淆字符集" || bad "恢复码格式不符"

echo "== 2. unlock（错误/正确密码）=="
echo wrong-password | "$LK" unlock --stdin >/dev/null 2>&1
check "错误密码解锁被拒（exit 1）" 1 $?
echo "$MASTER_PW" | "$LK" unlock --stdin >/dev/null
check "正确密码解锁成功" 0 $?

echo "== 3. item add（四类各一）=="
ID_LOGIN="$("$LK" item add login --name GitHub --username octocat --password s3cr3t --uris https://github.com,https://gist.github.com | awk '{print $2}')"
check "add login" 0 $?
ID_NOTE="$("$LK" item add note --name 日记 --content '# 标题

正文内容' | awk '{print $2}')"
check "add note" 0 $?
ID_SECRET="$("$LK" item add secret --name 'API Key' --value sk-123456 --purpose 生产 --expires-at 2026-12-31 | awk '{print $2}')"
check "add secret" 0 $?
head -c 2621440 /dev/urandom > "$WORK/orig.bin"   # 2.5 MiB（3 分块）
ID_FILE="$("$LK" item add file --file "$WORK/orig.bin" --note 加密附件 | awk '{print $2}')"
check "add file" 0 $?

echo "== 4. list / get =="
LIST="$("$LK" item list)"
echo "$LIST" | grep -q "GitHub" && ok "list 含 login" || bad "list 缺 login"
echo "$LIST" | grep -q "日记" && ok "list 含 note" || bad "list 缺 note"
echo "$LIST" | grep -q "API Key" && ok "list 含 secret" || bad "list 缺 secret"
echo "$LIST" | grep -q "orig.bin" && ok "list 含 file" || bad "list 缺 file"
GET="$("$LK" item get "$ID_LOGIN")"
echo "$GET" | grep -q "octocat" && ok "get 返回 username" || bad "get 缺 username"

echo "== 5. edit（CAS）=="
R1="$("$LK" item get "$ID_LOGIN" --json | jq -r .revision)"
"$LK" item edit "$ID_LOGIN" --username newuser --expected-revision "$R1" >/dev/null
check "base revision 匹配时编辑成功" 0 $?
"$LK" item edit "$ID_LOGIN" --username stale --expected-revision "$R1" >/dev/null 2>&1
check "过期 base revision 触发 CAS 冲突（exit 1）" 1 $?
R2="$("$LK" item get "$ID_LOGIN" --json | jq -r .revision)"
"$LK" item edit "$ID_LOGIN" --username newuser2 --expected-revision "$R2" >/dev/null
check "刷新后重试收敛（last-write-wins）" 0 $?
"$LK" item get "$ID_LOGIN" --json | jq -r .username | grep -q newuser2 && ok "编辑已生效" || bad "编辑未生效"

echo "== 6. delete（墓碑）=="
"$LK" item delete "$ID_NOTE" >/dev/null
check "软删除成功" 0 $?
"$LK" item get "$ID_NOTE" --json | jq -e .deleted >/dev/null && ok "条目进入 deleted 态" || bad "deleted 标记缺失"
ls "$WORK" | grep -q "$ID_NOTE.tomb.lk" && ok "墓碑文件已写" || bad "墓碑文件缺失"
"$LK" item list | grep "日记" | grep -q "\[deleted\]" && ok "list 显示 deleted" || bad "list 未标 deleted"

echo "== 7. export（附件往返）=="
"$LK" item export "$ID_FILE" -o "$WORK/out.bin" >/dev/null
check "export 成功" 0 $?
cmp -s "$WORK/orig.bin" "$WORK/out.bin" && ok "附件往返一致（2.5 MiB）" || bad "附件不一致"

echo "== 8. lock / status =="
"$LK" lock >/dev/null && check "lock 成功" 0 $?
"$LK" status | grep -q "已锁定" && ok "status 显示已锁定" || bad "status 未锁定"
"$LK" item list >/dev/null 2>&1
check "锁定后条目操作被拒（exit 1）" 1 $?

echo "== 9. unlock → audit 可见 =="
echo "$MASTER_PW" | "$LK" unlock --stdin >/dev/null
AUDIT="$("$LK" audit)"
echo "$AUDIT" | grep -q "vault.init" && ok "审计含 vault.init" || bad "审计缺 vault.init"
echo "$AUDIT" | grep -q "item.put login <redacted>" && ok "审计含 item.put（已脱敏）" || bad "审计缺 item.put"
echo "$AUDIT" | grep -q "item.delete" && ok "审计含 item.delete" || bad "审计缺 item.delete"
"$LK" audit --verify | grep -q "验证通过" && ok "审计 HMAC 链验证通过" || bad "审计验证失败"

echo "== 10. 恢复流程（恢复码 + 新主密码）=="
"$LK" lock >/dev/null
printf "%s\n%s\n" "ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ" "$NEW_PW" | "$LK" recover --stdin >/dev/null 2>&1
check "错误恢复码被拒（exit 1）" 1 $?
NEW_REC="$(printf "%s\n%s\n" "$REC" "$NEW_PW" | "$LK" recover --stdin --json | jq -r .recoveryCode)"
check "正确恢复码恢复成功" 0 $?
[ -n "$NEW_REC" ] && [ "$NEW_REC" != "$REC" ] && ok "恢复码已轮换" || bad "恢复码未轮换"
echo "$MASTER_PW" | "$LK" unlock --stdin >/dev/null 2>&1
check "旧主密码失效（exit 1）" 1 $?
echo "$NEW_PW" | "$LK" unlock --stdin >/dev/null
check "新主密码解锁成功" 0 $?
"$LK" item get "$ID_LOGIN" --json | jq -r .username | grep -q newuser2 && ok "重加密后数据完好" || bad "数据丢失"
"$LK" item export "$ID_FILE" -o "$WORK/out2.bin" >/dev/null
cmp -s "$WORK/orig.bin" "$WORK/out2.bin" && ok "附件重加密后仍可解密" || bad "附件损坏"
"$LK" audit | grep -q "audit-key-rotation" && ok "审计含密钥轮换事件（旧钥签名）" || bad "审计缺轮换事件"

echo "== 11. 会话令牌生命周期 =="
ls "$WORK/session.token" >/dev/null 2>&1 && ok "解锁态存在令牌文件" || bad "令牌文件缺失"
"$LK" lock >/dev/null
ls "$WORK/session.token" >/dev/null 2>&1 && bad "锁定后令牌文件仍存在" || ok "锁定后令牌文件已删除"

echo
echo "结果：$PASS 通过 / $FAIL 失败"
[ "$FAIL" = 0 ]
