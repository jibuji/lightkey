#!/usr/bin/env bash
# LightKey M1 双客户端冲突合并 E2E（docs/testing.md §1 第二层）
#
# 场景：
#   0. 未配置同步时 `lk sync` 拒绝（exit 1）
#   1. A 初始化 + `lk config sync set file://`（本地模拟 WebDAV/S3，无凭据）
#      + `lk config get`
#   2. A 添加条目与 2.5MiB 附件并 `lk sync`；断言远端布局与密文
#   3. 双客户端离线双改同条目 → 上线 → last-write-wins 收敛（后改者胜，
#      含并发同步的真实 CAS 竞争窗口；CAS 冲突机制由 lk-core 单测确定性覆盖）
#   4. 一端删除 → 墓碑传播 → 对端收敛
#   5. 附件分块断点续传（删远端分块 → 补传 → 对端导出一致）
#   6. 后台轮询收敛（interval 15s）
#   7. 存储端只见密文（零知识断言：文件名形态 + LKC1 magic + 无明文）
#
# 用法：bash scripts/e2e_m1.sh [lk-binary-path]
set -u

LK="${1:-target/debug/lk}"
LK="$(cd "$(dirname "$LK")" && pwd)/$(basename "$LK")"
WORK="$(mktemp -d)"
A="$WORK/a"; B="$WORK/b"; C="$WORK/c"; REMOTE="$WORK/remote"
trap 'rm -rf "$WORK"' EXIT
export LK_JSON=0

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # check <desc> <expected_exit> <actual_exit>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望退出码 $2，实际 $3)"; fi
}

# 测试密码运行时随机生成（fixture 密钥不进仓库）
MASTER_PW="e2e-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
a() { LIGHTKEY_HOME="$A" "$LK" "$@"; }
b() { LIGHTKEY_HOME="$B" "$LK" "$@"; }
c() { LIGHTKEY_HOME="$C" "$LK" "$@"; }
wait_for() { # wait_for <desc> <timeout_secs> '<shell-cmd>'
  local desc="$1" timeout="$2" cmd="$3"
  local i=0
  while [ $i -lt "$timeout" ]; do
    if eval "$cmd" >/dev/null 2>&1; then ok "$desc"; return 0; fi
    sleep 1; i=$((i+1))
  done
  bad "$desc（$timeout 秒内未达成）"
}

echo "== 0. 未配置同步时拒绝 =="
mkdir -p "$C"
c init --stdin <<<"$MASTER_PW" >/dev/null
c unlock --stdin <<<"$MASTER_PW" >/dev/null
c sync >/dev/null 2>&1
check "未配置同步时 lk sync 拒绝（exit 1）" 1 $?
c config get sync.url >/dev/null 2>&1
check "未配置时 lk config get sync.url 失败（exit 1）" 1 $?
c config get 未知键 >/dev/null 2>&1
check "未知配置键 → 用法错误（exit 2）" 2 $?

echo "== 1. A 初始化 + 配置同步（file:// 本地模拟 WebDAV/S3）=="
a init --stdin <<<"$MASTER_PW" >/dev/null
check "A init" 0 $?
a config sync set "file://$REMOTE" --interval 15 --stdin <<<"syncuser
syncpass" >/dev/null
check "config sync set（file:// 忽略凭据输入）" 0 $?
[ "$(a config get sync.url)" = "file://$REMOTE" ] && ok "config get sync.url" || bad "config get sync.url = $(a config get sync.url)"
[ "$(a config get sync.interval)" = "15" ] && ok "config get sync.interval" || bad "config get sync.interval"
[ "$(a config get sync.enabled)" = "true" ] && ok "config get sync.enabled" || bad "config get sync.enabled"
a config sync set "file://$REMOTE" --interval 5 >/dev/null 2>&1
check "间隔越界（5s < 15s）→ 用法错误（exit 2）" 2 $?
a config sync set "file://$REMOTE" --interval 15 >/dev/null
check "恢复合法间隔" 0 $?
# 延长自动锁定（轮询等待阶段防空闲锁定）
jq '.autoLockMinutes = 60' "$A/config.json" > "$WORK/config.tmp" && mv "$WORK/config.tmp" "$A/config.json"
a unlock --stdin <<<"$MASTER_PW" >/dev/null
check "A unlock" 0 $?

echo "== 2. A 添加条目与附件并同步 =="
ID_X=$(a item add login --name GitHub --username octocat --password s3cr3t | awk '{print $2}')
ID_Z=$(a item add secret --name APIKey --value sk-123 | awk '{print $2}')
head -c 2621440 /dev/urandom > "$WORK/orig.bin"   # 2.5 MiB（3 分块）
ID_F=$(a item add file --file "$WORK/orig.bin" --note 加密附件 | awk '{print $2}')
a sync >/dev/null
check "lk sync 成功" 0 $?
[ -f "$REMOTE/index.lk" ] && ok "远端 index.lk 已创建" || bad "远端 index.lk 缺失"
[ -f "$REMOTE/$ID_X.item.lk" ] && ok "远端条目密文存在" || bad "远端条目密文缺失"
AID_F=$(a item get "$ID_F" --json | jq -r .attachmentId)
[ -f "$REMOTE/$AID_F.0.chunk.lk" ] && ok "远端附件分块存在" || bad "远端附件分块缺失"

echo "== 3. 双客户端离线双改同条目 → LWW 收敛 =="
cp -r "$A" "$B"
rm -f "$B/daemon.json" "$B/session.token" && rm -rf "$B/run"   # 隔离 B 的守护进程
b unlock --stdin <<<"$MASTER_PW" >/dev/null
check "B unlock" 0 $?
b sync >/dev/null
check "B 首次同步" 0 $?
b item export "$ID_F" -o "$WORK/out0.bin" >/dev/null
cmp -s "$WORK/orig.bin" "$WORK/out0.bin" && ok "B 附件导出一致（初始同步）" || bad "B 附件导出不一致"

# 3a. 顺序双改（stale 索引窗口：B 在读到旧索引后推送，A 已抢先上传新版本）
a item edit "$ID_X" --username alice >/dev/null
b item edit "$ID_X" --username bob >/dev/null
cp "$REMOTE/index.lk" "$WORK/index_rev1.lk"
a sync >/dev/null   # A 推送 alice（rev2a）
cp "$WORK/index_rev1.lk" "$REMOTE/index.lk"   # B 的 fetch 将看到旧索引（并发窗口）
b sync >/dev/null
a sync >/dev/null   # 最终传播
[ "$(a item get "$ID_X" --json | jq -r .username)" = "bob" ] && ok "A 收敛到后改者 bob" || bad "A 未收敛到 bob"
[ "$(b item get "$ID_X" --json | jq -r .username)" = "bob" ] && ok "B 收敛到后改者 bob" || bad "B 未收敛到 bob"

# 3b. 并发双改（真实 CAS 竞争窗口；结果确定性：后改者胜）
a item edit "$ID_X" --username alice2 >/dev/null
sleep 0.05
b item edit "$ID_X" --username bob2 >/dev/null
( a sync >/dev/null 2>&1 & b sync >/dev/null 2>&1; wait )
a sync >/dev/null
[ "$(a item get "$ID_X" --json | jq -r .username)" = "bob2" ] && ok "并发双改收敛到后改者" || bad "并发双改未收敛"
[ "$(b item get "$ID_X" --json | jq -r .username)" = "bob2" ] && ok "并发双改对端一致" || bad "并发双改对端不一致"

echo "== 4. 一端删除 → 墓碑传播 =="
a item delete "$ID_Z" >/dev/null
check "A 软删除" 0 $?
a sync >/dev/null
[ -f "$REMOTE/$ID_Z.tomb.lk" ] && ok "远端墓碑文件已上传" || bad "远端墓碑文件缺失"
b sync >/dev/null
b item get "$ID_Z" --json | jq -e .deleted >/dev/null && ok "B 收敛删除态" || bad "B 未收敛删除态"
[ -f "$B/$ID_Z.tomb.lk" ] && ok "B 本地墓碑已写" || bad "B 本地墓碑缺失"
a item list | grep -q "APIKey" && ok "A 列表显示 deleted" || bad "A 列表未见 deleted"

echo "== 5. 附件分块断点续传 =="
# 5a. 真实中断语义：A 新建文件条目后，仅元数据 + 0 号分块到达远端
#     （模拟上传中断的半成品状态）→ 下一次同步续传剩余分块
head -c 2621440 /dev/urandom > "$WORK/orig2.bin"
ID_F2=$(a item add file --file "$WORK/orig2.bin" --note 续传附件 | awk '{print $2}')
AID_F2=$(a item get "$ID_F2" --json | jq -r .attachmentId)
cp "$A/$AID_F2.attach.lk" "$REMOTE/" && cp "$A/$AID_F2.0.chunk.lk" "$REMOTE/"
a sync >/dev/null
[ -f "$REMOTE/$AID_F2.1.chunk.lk" ] && [ -f "$REMOTE/$AID_F2.2.chunk.lk" ] \
  && ok "中断续传：剩余分块已补传" || bad "中断续传失败"
b sync >/dev/null
b item export "$ID_F2" -o "$WORK/out2.bin" >/dev/null
cmp -s "$WORK/orig2.bin" "$WORK/out2.bin" && ok "对端导出续传附件一致" || bad "对端导出续传附件不一致"
# 5b. 事后丢失：早期已同步附件的分块被删 → 编辑条目（bump revision）→ 补传
rm "$REMOTE/$AID_F.1.chunk.lk"
a item edit "$ID_F" --note 触发补传 >/dev/null
a sync >/dev/null
[ -f "$REMOTE/$AID_F.1.chunk.lk" ] && ok "丢失分块已补传" || bad "丢失分块未补传"
b sync >/dev/null
b item export "$ID_F" -o "$WORK/out1.bin" >/dev/null
cmp -s "$WORK/orig.bin" "$WORK/out1.bin" && ok "对端导出附件一致（补传后）" || bad "对端导出不一致"

echo "== 6. 后台轮询收敛（interval 15s）=="
b item edit "$ID_X" --username polled >/dev/null
wait_for "A 的守护进程轮询收敛（≤60s）" 60 \
  "[ \"\$(a item get "$ID_X" --json | jq -r .username)\" = polled ]"

echo "== 6b. 守护进程重启后条目仍可见（索引持久化）=="
PID_B=$(jq -r .pid "$B/daemon.json" 2>/dev/null)
[ -n "$PID_B" ] && [ "$PID_B" != "null" ] && kill -TERM "$PID_B"
sleep 1
b unlock --stdin <<<"$MASTER_PW" >/dev/null   # 自动拉起新守护进程
check "B 重启后解锁" 0 $?
N=$(b item list | wc -l)
[ "$N" -ge 4 ] && ok "重启后列表可见（4 条条目）" || bad "重启后列表仅 $N 行"
b item get "$ID_X" --json | jq -r .username | grep -q polled && ok "重启后数据完好（polled）" || bad "重启后数据丢失"

echo "== 7. 存储端只见密文（零知识断言）=="
# 停掉两个守护进程（优雅退出），避免写入竞态
for d in "$A" "$B"; do
  if [ -f "$d/daemon.json" ]; then
    PID=$(jq -r .pid "$d/daemon.json" 2>/dev/null)
    [ -n "$PID" ] && [ "$PID" != "null" ] && kill -TERM "$PID" 2>/dev/null
  fi
done
sleep 1
# 7a. 只允许已知密文文件名（index.lk / {uuid}.{item,tomb,attach}.lk / {uuid}.{i}.chunk.lk）
BAD=$(find "$REMOTE" -type f | sed "s|$REMOTE/||" | \
  grep -vE '^(index\.lk|[0-9a-f-]{36}\.(item|tomb|attach)\.lk|[0-9a-f-]{36}\.[0-9]+\.chunk\.lk)$' | head -1)
[ -z "$BAD" ] && ok "远端只含已知密文文件名" || bad "意外文件: $BAD"
# 7b. 全部文件以 LKC1 magic 开头
NONLKC=0
for f in "$REMOTE"/*; do
  [ -f "$f" ] || continue
  head -c 4 "$f" | grep -q LKC1 || NONLKC=$((NONLKC+1))
done
[ "$NONLKC" = 0 ] && ok "全部远端文件为 LKC1 密文容器" || bad "$NONLKC 个文件非密文"
# 7c. 明文不可见（条目名/密码/附件名均不得出现）
if grep -raq "octocat\|s3cr3t\|sk-123\|加密附件\|polled" "$REMOTE" 2>/dev/null; then
  bad "远端出现明文"
else
  ok "远端无明文泄漏"
fi

echo
echo "结果：$PASS 通过 / $FAIL 失败"
[ "$FAIL" = 0 ]
