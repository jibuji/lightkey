# LightKey WSL bridge 链路端到端实测报告（issue #32 第 0 步）

日期：2026-08-24　执行：ox-alpha（Windows 宿主 agent，自助无人类协助）

## 环境信息

```
Windows 版本: 10.0.26200.9168
wsl.exe --version: WSL 版本: 2.7.12.0 / 内核 6.18.33.2-2 / WSLg 1.0.73.2 / MSRDC 1.2.7214 / Direct3D 1.611.1 / DXCore 10.0.26100.1
发行版: Debian (VERSION 2)
Windows 侧 lk --version: lk 0.1.4（自建 target\release\lk.exe）
WSL 侧   lk --version: lk 0.1.4（自建 target/release/lk）
git log --oneline -1（同一 checkout，两侧分别构建）:
  9719862 chore(release): bump version to 0.1.4 (release v0.1.4)   （≥ b18b769 ✓）
LIGHTKEY_BRIDGE=/mnt/c/temp/lightkey/target/release/lk.exe（显式设置）
LIGHTKEY_BRIDGE_HOME=未设（数据目录在默认 %APPDATA%\lightkey）
```

库处理：原库已备份至 `%APPDATA%\lightkey.bak-20260824-185104` 后重建纯测试库
（用户授权），测试主密码经 `LK_CROSS_MASTER_PW` 环境变量提供，未入报告。

## §1 基线冒烟（Windows 本地）

```
rule add C:\lk-smoke "cmd *" --name smoke LK_SMOKE_FAKE  → rc=0，rule list 可见 smoke 行
item add secret LK_SMOKE_FAKE                            → rc=0
inject（cwd=C:\lk-smoke）cmd //c "echo %LK_SMOKE_FAKE%"
  stdout: fake-not-a-real-key   rc=0        ✓ #33 生效，非 no_cwd
反向对照（cwd=C:\）:
  stderr: lk inject: 已拒绝（无审批界面（未命中规则且桌面端未运行）） rc=1
  拒绝原因 = no_ui，非 no_cwd                                ✓ cwd 读得到但不匹配
#31 压测: 连续 status ×20 → OK: 20/20                        ✓
清理: rule remove + item delete 均 rc=0，rule list 空
```

## §2 主事件：E2E（bash scripts/e2e_cross_subsystem.sh target/release/lk --auto-approve）

```
== 0. 前置就绪 ==                    ✓ WSL2 + Interop / 数据目录 / bridge 中继
== 1. 连接目标可见性 ==              ✓ status stderr 含「→ 经 bridge 连接 Windows 桌面守护实例（版本 0.1.4）」
== 2. unlock 经 bridge ==            ✓
== 3. item list 跨子系统读库 ==      ✓ 非空
== 4. item add LK_E2E_CROSS ==       ✓
== 5. authz.evaluate → 注入 ==       ✓ rule add（wsl:// 规范形命中 sh *）✓ inject exit 0 ✓ env 值只进子进程 ✓ lk 输出无密钥值
== 6. 审计 ==                        ✓ 含 channel=wsl-bridge；不含密钥值
== 7. 清理 ==                        ✓ 规则移除 / 密钥 [deleted] 软删 / lock 成功

跨子系统 E2E（auto-approve）：17 通过 / 0 失败    EXIT=0
```

交互审批模式：本机无桌面壳，未覆盖（此类请求走 `no_ui` 拒绝路径，属预期）。

## §3 手工探针（WSL 内，LIGHTKEY_BRIDGE 显式指向新 lk.exe）

探针 A（~/proj，规则 `wsl://Debian/home/<user>/proj` + `sh *`）：
```
inject rc=0 out=fake-probe-value
audit --json --tail 10 | grep wsl-bridge → 连续多条 "channel": "wsl-bridge"   ✓
```
探针 B（cd /tmp，目录不匹配）：
```
stderr: lk inject: 已拒绝（无审批界面（未命中规则且桌面端未运行））
rc=1，拒绝原因 = no_ui ≠ no_cwd                                          ✓ PEB cwd 在 interop 下可读
```
探针 C：不需要（A 已通过，无归一化差异样本）。
清理：rule remove / item delete rc=0；`item list` 中 LK_PROBE_FAKE 为 `[deleted]`；
`rule list | grep probe` 无残留；lock 成功。

## 结论（§4 判定矩阵）

**矩阵行 1**：设计链路成立——interop 拉起 bridge 进程的 PEB UNC cwd → daemon 读取 →
`path_ns::canonical_project_dir` 归一化为 `wsl://<distro>/...` → 祖先匹配全通；
#31 压测 20/20。**建议关闭 #32，bridge 自证 cwd 方案无需实施。**

## 遗留异常清单

- 无链路类异常。唯一未覆盖项：交互审批弹窗路径（无桌面壳，no_ui 未覆盖）。
- 测试库为重建库；原真实库备份于 `%APPDATA%\lightkey.bak-20260824-185104`。
