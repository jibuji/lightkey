/**
 * Mock 初始库 —— 照搬 served 原型 app.js 的 v2 mock 数据字段形态
 * （login×3 / note×1 / secret×2 / file×2）。全部为演示占位，不含真实密钥
 * （testing.md「fixture 密钥不进仓库」）。
 */

import type { AuditEvent, AuthRule, Item, VaultSettings } from "../types";

export const MOCK_ITEMS: Item[] = [
  {
    id: "github",
    type: "login",
    name: "GitHub",
    revision: "2026-08-15T10:12:00Z",
    username: "dev@lightkey.dev",
    password: "ghp_demo_token_0000",
    uris: ["github.com"],
    custom: [{ name: "登录方式", value: "SSH key", hidden: false }],
  },
  {
    id: "deploy-note",
    type: "note",
    name: "部署手册",
    revision: "2026-08-15T09:40:00Z",
    content:
      "# 部署手册\n\n**发布前**检查：\n\n1. 构建 `cargo build --release`\n2. 运行 `cargo test`\n3. 打 tag 并推送\n\n> 生产环境禁止直接改库，走 PR。\n\n```bash\nsystemctl restart lk-daemon\n```\n\n示例：`lk vault unlock` 后执行 [发布脚本](https://example.com/release)。",
  },
  {
    id: "ntoken",
    type: "secret",
    name: "NPM_TOKEN",
    revision: "2026-08-14T10:00:00Z",
    value: "npm_demo_token_0000",
    purpose: "发布 npm 包（仅 rules 白名单命令注入）",
    expiresAt: "2027-01-01",
  },
  {
    id: "awskey",
    type: "secret",
    name: "AWS 生产只读",
    revision: "2026-08-12T16:05:00Z",
    value: "AKIAIOSFODNN7DEMO",
    purpose: "生产环境只读审计",
    expiresAt: "",
  },
  {
    id: "mail",
    type: "login",
    name: "公司邮箱",
    revision: "2026-08-12T14:30:00Z",
    username: "me@company.example",
    password: "demo_password_01",
    uris: ["mail.company.example"],
    custom: [],
  },
  {
    id: "router",
    type: "login",
    name: "家庭路由器",
    revision: "2026-08-10T08:30:00Z",
    username: "admin",
    password: "demo_password_02",
    uris: ["192.168.1.1"],
    custom: [],
  },
  {
    id: "fapiao",
    type: "file",
    name: "发票扫描件 2026-08",
    revision: "2026-08-14T21:00:00Z",
    note: "8 月报销用，原件在抽屉",
    size: "12.4 MB",
    fileType: "application/pdf",
    attachment: "fapiao-202608.pdf",
  },
  {
    id: "sshcfg",
    type: "file",
    name: "ssh_config 备份",
    revision: "2026-08-09T11:20:00Z",
    note: "2026-06 快照 · 含跳板机配置",
    size: "3.2 KB",
    fileType: "text/plain",
    attachment: "ssh_config.bak",
  },
];

export const MOCK_RULES: AuthRule[] = [
  { id: "r1", projectDir: "~/work/proj-a", command: "npm publish", keys: ["NPM_TOKEN"], created: "2026-08-14T10:00:00Z" },
  { id: "r2", projectDir: "~/work/proj-a", command: "cargo publish", keys: ["CARGO_REGISTRY_TOKEN"], created: "2026-08-14T10:05:00Z" },
  { id: "r3", projectDir: "~/work/proj-b", command: "aws s3 sync *", keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], created: "2026-08-15T09:00:00Z" },
];

export const MOCK_AUDIT: AuditEvent[] = [
  { ts: "10:24:33", starter: "zsh", target: "npm publish", dir: "~/work/proj-a", result: "allowed", note: "规则命中" },
  { ts: "10:22:10", starter: "claude", target: "bash -c curl …", dir: "~/work/proj-c", result: "denied", note: "默认拒绝" },
  { ts: "10:18:02", starter: "code", target: "git push", dir: "~/work/proj-a", result: "allowed", note: "规则命中" },
  { ts: "09:58:47", starter: "claude", target: "npm publish", dir: "~/work/proj-b", result: "timeout", note: "审批超时(30s)" },
  { ts: "09:41:12", starter: "lk", target: "vault.unlock", dir: "—", result: "allowed", note: "解锁成功" },
  { ts: "09:12:03", starter: "zsh", target: "git push", dir: "~/work/proj-d", result: "denied", note: "默认拒绝" },
];

export const MOCK_SETTINGS: VaultSettings = {
  autoLockMin: "5",
  bioGrace: true,
  syncUrl: "webdavs://dav.example.com/lightkey",
  pollSec: "60",
  retention: "永久",
};

/** mock 解锁主密码（演示用；真实实现由 Argon2id 派生校验，见 crypto.md） */
export const MOCK_MASTER_PASSWORD = "demo-password";

/** 演示恢复码（一次性展示；真实为高熵 40 字符，见 recovery.md） */
export const DEMO_RECOVERY_CODE = "J4QZ7 K8TW2 MPD9V XHC7G N3RFX 5AJKQ M2P8D 9VXH7";
