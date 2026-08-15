# 高保真单页原型（设计评审用）

LightKey V1 前端的高保真可交互原型：单页静态 HTML/CSS/JS 三文件
（`index.html` + `styles.css` + `app.js`，零构建依赖）。

## 预览

```bash
cd docs/design/prototype
python3 -m http.server 8931        # 或任意静态服务器 / 直接双击 index.html
```

浏览器打开 `http://127.0.0.1:8931/index.html`。

- 默认进入**解锁页**，输入任意主密码 → 解锁进入主界面。
- 页面右下角有**原型导航栏**（评审工具，非产品 UI）可切换各屏幕、
  模拟 `lk inject` 审批弹窗、隐藏导航。
- 加 `?review=0` 隐藏导航栏（截图用）。

## 深链（截图 / 评审自动化）

| Hash | 屏幕 |
|------|------|
| `#unlock` | 解锁页 |
| `#vault` | 条目列表 + 详情 |
| `#item:<id>`（如 `#item:github`） | 指定条目详情 |
| `#rules` / `#settings` / `#audit` | 规则 / 设置 / 审计页 |
| `#approval` | 自动打开审批弹窗（30s 倒计时默认拒绝） |
| `#recovery` | 自动打开恢复码弹窗 |

示例：`http://127.0.0.1:8931/index.html?review=0#approval`

## 可交互范围

解锁/锁定 · 条目列表/搜索/筛选 · 详情（密码遮罩/显示/复制）· 新建/编辑/删除 ·
规则增删 · 设置开关 · 审计筛选 · 审批弹窗（真实 30s 倒计时、允许/拒绝/超时）·
恢复码展示/复制。

## 评审截图（agent_browser 采集，2026-08-15）

见 [`screenshots/`](screenshots/)：

1. `01-unlock.png` — 解锁页
2. `02-vault-list.png` — 条目列表
3. `03-item-detail.png` — 条目详情（遮罩态）
4. `04-rules.png` — 授权规则页
5. `05-settings.png` — 设置页
6. `06-audit.png` — 审计日志页
7. `07-approval.png` — 审批弹窗（倒计时中）
8. `08-recovery.png` — 恢复码（一次性展示）

评审流程（D14）：agent_browser 预览截图 → doubao-seed-2.1-turbo 视觉评审 →
lavish-axi 船长评审面 → 反馈回改 [`../spec.md`](../spec.md) 与原型。

## 说明

- 全部数据为**演示占位**（`app.js` 顶部 `DB`），不含任何真实密钥；
  符合 [testing.md](../../testing.md)「fixture 密钥不进仓库」纪律。
- 原型是设计交付物，**不是** `frontend/` 应用的一部分；M2 按
  [`../spec.md`](../spec.md) 以 React 实现真实界面。
- 设计 tokens 与 `spec.md` 一一对应（`styles.css` 顶部 `:root`）。
