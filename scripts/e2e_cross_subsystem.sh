#!/usr/bin/env bash
# LightKey 跨子系统 E2E：WSL2 内 Linux `lk` ↔ Windows 桌面守护实例
# （docs/cross-subsystem.md §10 测试计划；依赖 M2.75 实现清单 §9 #1–5）
#
# 场景：前置检测（WSL2 + Windows 侧桌面包 + bridge 后端可用，否则 SKIP exit 0）
#       → 连接目标可见性（stderr「经 bridge」提示，§7.2）
#       → unlock → item list → 注入测试密钥（真实库，跑完即删）
#       → authz.evaluate 触发审批 → Linux 子进程收到注入 env
#       → 审计含 channel=wsl-bridge 事件且无密钥值 → 清理（delete/rule remove/lock）
#
# 审批模式（二选一，运行时明确打印当前模式）：
#   默认      交互模式：inject 未命中规则 → 第③层弹窗出现在 Windows GUI，
#             请在 30s 倒计时内点击批准（脚本会先打印提示再执行）。
#   --auto-approve  无人值守模式：先 rule add 命中规则（第②层白名单自动放行，
#             不弹窗），其余断言完全一致；适合 CI 外自动化回归。
#
# 主密码：Windows 侧真实库的主密码，交互输入（read -s 不回显），或经环境变量
#         LK_CROSS_MASTER_PW 提供（--auto-approve 无人值守时用）。
# 用法：bash scripts/e2e_cross_subsystem.sh [lk-binary-path] [--auto-approve]
#
# 事实来源（均已 grep 核实，勿臆造）：
#   - WSLInterop binfmt：/proc/sys/fs/binfmt_misc/WSLInterop（cross-subsystem.md §4#1）
#   - WSL2 内核串：uname -r 含 microsoft-standard-WSL2
#   - Windows 数据目录：%APPDATA%\lightkey\daemon.json
#     （crates/lk-daemon/src/dirs.rs → /mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey/）
#   - named pipe 名随机（\\.\pipe\lightkey-<user>-<rand8>，transport.rs），
#     端点一律从 daemon.json 读，脚本不硬编码管道名/端口
#   - lk.exe 已知安装位置：%LOCALAPPDATA%\LightKey\（cross-subsystem.md §7.2）
#   - bridge 后端选择环境变量：LIGHTKEY_BRIDGE=<lk.exe 路径>（§7.2）
set -u
set -o pipefail   # 管道中 lk 失败不得被 awk/grep 吞掉（断言真实性）

# ---------------------------------------------------------------- 参数解析
LK=""
AUTO=0
for arg in "$@"; do
  case "$arg" in
    --auto-approve) AUTO=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) if [ -z "$LK" ]; then LK="$arg"; else echo "多余参数：$arg" >&2; exit 2; fi ;;
  esac
done
LK="${LK:-target/debug/lk}"
# 二进制可能尚未构建（后续前置检测会给出明确 SKIP）；仅在存在时规范化绝对路径
if [ -e "$LK" ]; then
  LK="$(cd "$(dirname "$LK")" && pwd)/$(basename "$LK")"
fi

WORK="$(mktemp -d)"
PROJ="$WORK/proj"
trap 'rm -rf "$WORK"' EXIT
export LIGHTKEY_HOME="$WORK"   # 本地侧数据目录仅作兜底；bridge 模式下端点来自 Windows 侧
export LK_JSON=0

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # check <desc> <expected_exit> <actual_exit>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望退出码 $2，实际 $3)"; fi
}
skip() { # 前置不满足 → 干净跳过（CI 无 WSL 必须 exit 0）
  echo "SKIP: $1"
  echo "e2e_cross_subsystem：跳过（$1）"
  exit 0
}

# ---------------------------------------------------------------- 前置检测
# 1) 宿主必须是 WSL2（非 WSL1：无 interop 管道语义，规格 §1 非目标）
uname -r | grep -qi 'microsoft-standard-WSL2' \
  || skip "宿主不是 WSL2（uname -r=$(uname -r)）"
[ -e /proc/sys/fs/binfmt_misc/WSLInterop ] \
  || skip "WSLInterop 未启用（/proc/sys/fs/binfmt_misc/WSLInterop 不存在）"

# 2) Windows 侧 LightKey 数据目录（端点来源；§7.2 探测条件）
WIN_HOME="${LIGHTKEY_BRIDGE_HOME:-}"
if [ -z "$WIN_HOME" ]; then
  for d in /mnt/*/Users/*/AppData/Roaming/lightkey; do
    [ -f "$d/daemon.json" ] && WIN_HOME="$d" && break
  done
fi
[ -n "$WIN_HOME" ] && [ -f "$WIN_HOME/daemon.json" ] \
  || skip "Windows 侧未安装 LightKey 桌面应用（未找到 AppData/Roaming/lightkey/daemon.json；可用 LIGHTKEY_BRIDGE_HOME 指定）"

# 3) bridge 中继 lk.exe（§7.2 已知安装位置清单，与 lk-cli bridge_backend
#    KNOWN_EXE_DIRS / KNOWN_EXE_MACHINE_DIRS 对齐；Program Files 为 per-machine
#    安装兜底）
RELAY="${LIGHTKEY_BRIDGE:-}"
if [ -z "$RELAY" ]; then
  for c in /mnt/*/Users/*/AppData/Local/LightKey/lk.exe \
           /mnt/*/Users/*/AppData/Local/Programs/LightKey/lk.exe \
           /mnt/*/Users/*/AppData/Roaming/LightKey/lk.exe \
           /mnt/*/Program\ Files/LightKey/lk.exe; do
    [ -x "$c" ] && RELAY="$c" && break
  done
fi
[ -n "$RELAY" ] && [ -x "$RELAY" ] \
  || skip "未找到 Windows 侧 lk.exe（已查 %LOCALAPPDATA%\\LightKey\\、%APPDATA%\\LightKey\\ 与 Program Files；可用 LIGHTKEY_BRIDGE=<路径> 指定）"

# 4) Linux lk 二进制存在且已实现 bridge 后端（M2.75 §9 #2）。
#    依 §7.2「目标可见性」拍板：经 bridge 的每次调用必向 stderr 打
#    「经 bridge」提示行——以此区分旧二进制（静默走本地 daemon）。
#    SKIP/FAIL 边界是「bridge 后端已实现」而非「daemon 可达」：桌面应用
#    装了但守护实例未运行时，bridge.no_daemon 错误文本同样含 "bridge"，
#    本前置会照常通过（这正是设计意图——探测目标是区分旧二进制），后续
#    步骤对 daemon 未运行的失败输出会提示先启动桌面应用。
[ -x "$LK" ] || skip "lk 二进制不可执行：$LK（先 cargo build -p lk-cli）"
BRIDGE_NOTE="$(LIGHTKEY_BRIDGE="$RELAY" "$LK" status 2>&1 >/dev/null || true)"
printf '%s' "$BRIDGE_NOTE" | grep -q "bridge" \
  || skip "Linux lk 尚未实现 bridge 后端（status 无「经 bridge」提示，M2.75 待合入）"

echo "== 0. 前置就绪 =="
ok "WSL2 宿主 + WSLInterop 已启用"
ok "Windows 侧数据目录：$WIN_HOME"
ok "bridge 中继：$RELAY"
export LIGHTKEY_BRIDGE="$RELAY"

# 注入测试密钥名（真实库；跑完即删，值运行时随机生成不进仓库）
KEY_NAME="LK_E2E_CROSS"
SECRET_VALUE="sekrit-$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
mkdir -p "$PROJ"

if [ "$AUTO" = 1 ]; then
  [ -n "${LK_CROSS_MASTER_PW:-}" ] || { echo "错误：--auto-approve 需要环境变量 LK_CROSS_MASTER_PW 提供主密码" >&2; exit 2; }
  MASTER_PW="$LK_CROSS_MASTER_PW"
else
  printf "请输入 Windows 侧 LightKey 主密码（不回显）: "
  read -rs MASTER_PW
  echo
fi

echo "== 1. 连接目标可见性（§7.2：杜绝「以为在操作本地」）=="
STATUS_ERR="$(LIGHTKEY_BRIDGE="$RELAY" "$LK" status 2>&1 >/dev/null)"
printf '%s' "$STATUS_ERR" | grep -q "bridge" \
  && ok "status stderr 含「经 bridge」目标提示" || bad "status stderr 缺 bridge 提示：$STATUS_ERR"

echo "== 2. unlock（会话令牌仅存 lk 进程内存，§7.2）=="
echo "$MASTER_PW" | "$LK" unlock --stdin >/dev/null 2>"$WORK/unlock.err"
UNLOCK_RC=$?
check "unlock 经 bridge 成功" 0 "$UNLOCK_RC"
if [ "$UNLOCK_RC" -ne 0 ]; then
  echo "  提示：如报 bridge.no_daemon，请先启动 Windows 侧 LightKey 桌面应用（守护实例由其持有）再重试" >&2
  echo "  --- lk stderr ---" >&2
  sed 's/^/  /' "$WORK/unlock.err" >&2
fi

echo "== 3. item list（读 Windows 桌面应用的库）=="
LIST="$("$LK" item list 2>"$WORK/list.err")"
check "item list 成功" 0 $?
[ -n "$LIST" ] && ok "list 非空（跨子系统读库生效）" || ok "list 为空（新库亦属正常）"

echo "== 4. 注入测试密钥（真实库，跑完即删）=="
KEY_ID="$("$LK" item add secret --name "$KEY_NAME" --value "$SECRET_VALUE" --purpose e2e | awk '{print $2}')"
check "item add secret $KEY_NAME" 0 $?

echo "== 5. authz.evaluate → 注入（channel=wsl-bridge）=="
if [ "$AUTO" = 1 ]; then
  echo "（--auto-approve 模式：rule add 第②层白名单命中，自动放行，无弹窗）"
  # 显式 wsl://<发行版> 规范形：非交互环境下默认发行版解析必须拒绝
  # （cross-subsystem.md §7.4 回显确认），故用显式形态绕开确认而非跳过校验。
  # $PROJ 为 WSL 内路径（本脚本工作目录），规范形即 wsl://<distro><abs-path>。
  "$LK" rule add "wsl://${WSL_DISTRO_NAME:?WSL 发行版名未知}${PROJ}" "sh *" \
    --name e2e-cross "$KEY_NAME" >/dev/null 2>&1
  check "rule add（命中 sh *，免弹窗）" 0 $?
else
  echo ">>> 请注意 Windows 屏幕：即将弹出审批窗口（30s 倒计时），请点击「批准」。"
  sleep 2
fi
OUT="$(cd "$PROJ" && "$LK" inject --keys "$KEY_NAME" -- sh -c 'echo -n "$'"$KEY_NAME"'"' 2>"$WORK/inject.err")"
check "inject（经 bridge）exit 0" 0 $?
if [ "$OUT" = "$SECRET_VALUE" ]; then
  ok "Linux 子进程收到注入 env（值只进子进程）"
else
  bad "子进程 env 值不符（got '$OUT'）"
fi
if grep -q "$SECRET_VALUE" "$WORK/inject.err"; then
  bad "lk 自身 stderr 泄漏密钥值"
else
  ok "lk 自身输出不含密钥值"
fi

echo "== 6. 审计：channel=wsl-bridge 留痕 + 无密钥值 =="
AUDIT_JSON="$("$LK" audit --json)"
printf '%s' "$AUDIT_JSON" | grep -q "wsl-bridge" \
  && ok "审计含 channel=wsl-bridge 事件" || bad "审计缺 wsl-bridge 事件"
printf '%s' "$AUDIT_JSON" | grep -q "$SECRET_VALUE" \
  && bad "审计泄漏密钥值" || ok "审计不含密钥值"

echo "== 7. 清理（真实库不留痕）=="
if [ "$AUTO" = 1 ]; then
  RULE_ID="$("$LK" rule list | awk '/e2e-cross/{print $1}')"
  [ -n "$RULE_ID" ] && "$LK" rule remove "$RULE_ID" >/dev/null 2>&1
  "$LK" rule list | grep -q e2e-cross && bad "rule remove 未生效" || ok "规则已清理"
fi
"$LK" item delete "$KEY_ID" >/dev/null 2>&1
# 软删后 list 仍显示该行但带 [deleted] 标记（M0 语义）
"$LK" item list 2>/dev/null | grep "$KEY_NAME" | grep -q "\[deleted\]" \
  && ok "测试密钥已软删（墓碑待 30 天硬删，属正常语义）" || bad "测试密钥未删除"
"$LK" lock >/dev/null 2>&1 && ok "已锁定（会话结束）" || bad "lock 失败"

echo
if [ "$AUTO" = 1 ]; then
  echo "跨子系统 E2E（auto-approve）：$PASS 通过 / $FAIL 失败"
else
  echo "跨子系统 E2E（人工批准）：$PASS 通过 / $FAIL 失败"
fi
[ "$FAIL" = 0 ]
