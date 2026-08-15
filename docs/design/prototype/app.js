/* LightKey 高保真原型交互 —— 演示用 mock 数据，非真实实现
   存储类型 v2（2026-08-15 定案）：login / note(Markdown) / secret / file */
"use strict";

/* ---------- 图标 ---------- */
const I = {
  lock: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  eye: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  copy: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  edit: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  file: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"/><path d="M14 2v6h6"/></svg>',
  fileText: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  key: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  download: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  paperclip: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>',
  terminal: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
  folder: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  check: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></svg>',
};

/* ---------- Mock 数据（全部为演示占位，不含真实密钥） ---------- */
const DB = {
  items: [
    { id: "github", type: "login", name: "GitHub", revision: "2026-08-15T10:12:00Z",
      username: "dev@lightkey.dev", password: "ghp_demo_token_0000", uris: ["github.com"],
      custom: [ { name: "登录方式", value: "SSH key", hidden: false } ] },
    { id: "deploy-note", type: "note", name: "部署手册", revision: "2026-08-15T09:40:00Z",
      content: "# 部署手册\n\n**发布前**检查：\n\n1. 构建 `cargo build --release`\n2. 运行 `cargo test`\n3. 打 tag 并推送\n\n> 生产环境禁止直接改库，走 PR。\n\n```bash\nsystemctl restart lk-daemon\n```\n\n示例：`lk vault unlock` 后执行 [发布脚本](https://example.com/release)。" },
    { id: "ntoken", type: "secret", name: "NPM_TOKEN", revision: "2026-08-14T10:00:00Z",
      value: "npm_demo_token_0000", purpose: "发布 npm 包（仅 rules 白名单命令注入）", expiresAt: "2027-01-01" },
    { id: "awskey", type: "secret", name: "AWS 生产只读", revision: "2026-08-12T16:05:00Z",
      value: "AKIAIOSFODNN7DEMO", purpose: "生产环境只读审计", expiresAt: "" },
    { id: "mail", type: "login", name: "公司邮箱", revision: "2026-08-12T14:30:00Z",
      username: "me@company.example", password: "demo_password_01", uris: ["mail.company.example"], custom: [] },
    { id: "router", type: "login", name: "家庭路由器", revision: "2026-08-10T08:30:00Z",
      username: "admin", password: "demo_password_02", uris: ["192.168.1.1"], custom: [] },
    { id: "fapiao", type: "file", name: "发票扫描件 2026-08", revision: "2026-08-14T21:00:00Z",
      note: "8 月报销用，原件在抽屉", size: "12.4 MB", fileType: "application/pdf", attachment: "fapiao-202608.pdf" },
    { id: "sshcfg", type: "file", name: "ssh_config 备份", revision: "2026-08-09T11:20:00Z",
      note: "2026-06 快照 · 含跳板机配置", size: "3.2 KB", fileType: "text/plain", attachment: "ssh_config.bak" },
  ],
  rules: [
    { id: "r1", projectDir: "~/work/proj-a", command: "npm publish", keys: ["NPM_TOKEN"], created: "2026-08-14T10:00:00Z" },
    { id: "r2", projectDir: "~/work/proj-a", command: "cargo publish", keys: ["CARGO_REGISTRY_TOKEN"], created: "2026-08-14T10:05:00Z" },
    { id: "r3", projectDir: "~/work/proj-b", command: "aws s3 sync *", keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], created: "2026-08-15T09:00:00Z" },
  ],
  audit: [
    { ts: "10:24:33", starter: "zsh", target: "npm publish", dir: "~/work/proj-a", result: "allowed", note: "规则命中" },
    { ts: "10:22:10", starter: "claude", target: "bash -c curl …", dir: "~/work/proj-c", result: "denied", note: "默认拒绝" },
    { ts: "10:18:02", starter: "code", target: "git push", dir: "~/work/proj-a", result: "allowed", note: "规则命中" },
    { ts: "09:58:47", starter: "claude", target: "npm publish", dir: "~/work/proj-b", result: "timeout", note: "审批超时(30s)" },
    { ts: "09:41:12", starter: "lk", target: "vault.unlock", dir: "—", result: "allowed", note: "解锁成功" },
    { ts: "09:12:03", starter: "zsh", target: "git push", dir: "~/work/proj-d", result: "denied", note: "默认拒绝" },
  ],
  settings: {
    autoLockMin: "5", bioGrace: true, syncUrl: "webdavs://dav.example.com/lightkey", pollSec: "60",
    retention: "永久",
  },
};

/* ---------- 状态 ---------- */
const state = {
  screen: "unlock",        // unlock | vault
  page: "items",           // items | rules | settings | audit
  filter: "all",
  afilter: "all",
  search: "",
  selectedId: "github",
  revealed: false,
  toastTimer: null,
};

const $ = (sel) => document.querySelector(sel);

/* ---------- 屏幕切换 ---------- */
function showScreen(name) {
  state.screen = name;
  document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
  document.getElementById(`screen-${name}`).classList.add("active");
  if (name === "vault") renderVault();
}

function setPage(page) {
  state.page = page;
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  document.getElementById(`page-${page}`).classList.add("active");
  document.querySelectorAll(".nav-item[data-page]").forEach((b) =>
    b.classList.toggle("active", b.dataset.page === page));
  renderPage(page);
}

/* ---------- 存储类型 v2 元信息 ---------- */
const TYPE_META = {
  login:  { cls: "login",  icon: I.globe,    label: "登录", sub: (it) => it.username || "—" },
  note:   { cls: "note",   icon: I.fileText, label: "笔记", sub: (it) => mdSnippet(it.content) },
  secret: { cls: "secret", icon: I.key,      label: "密钥",
            sub: (it) => it.purpose || (it.value ? `••••${it.value.slice(-4)}` : "—") },
  file:   { cls: "file",   icon: I.file,     label: "文件",
            sub: (it) => [it.size, it.fileType].filter(Boolean).join(" · ") || "—" },
};

/* ---------- Markdown：高亮 / 只读渲染 / 片段 ---------- */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function mdHighlight(src) {
  let inFence = false;
  return String(src || "").split("\n").map((raw) => {
    const fence = raw.match(/^```(\w*)/);
    if (fence) { inFence = !inFence; return `<span class="tk-fence">${esc(raw)}</span>`; }
    if (inFence) return `<span class="tk-code">${esc(raw)}</span>`;
    const h = raw.match(/^(#{1,3})\s+(.*)$/);
    if (h) return `<span class="tk-h">${h[1]} ${esc(h[2])}</span>`;
    const q = raw.match(/^(>\s?)(.*)$/);
    if (q) return `<span class="tk-q">${q[1]}${esc(q[2])}</span>`;
    const ul = raw.match(/^([-*+]|\d+\.)\s+(.*)$/);
    if (ul) return `<span class="tk-list">${ul[1]}</span> ${mdInline(ul[2])}`;
    return mdInline(raw);
  }).join("\n") + "\n";
}

function mdInline(s) {
  let l = esc(s);
  l = l.replace(/`([^`]+)`/g, '<span class="tk-i">`$1`</span>');
  l = l.replace(/\*\*([^*]+)\*\*/g, '<span class="tk-b">**$1**</span>');
  l = l.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<span class="tk-l">[$1]($2)</span>');
  return l;
}

function mdRender(md) {
  const lines = String(md || "").split("\n");
  let html = "", inFence = false, fenceBuf = [], listBuf = [];
  const flushList = () => { if (listBuf.length) { html += "<ul>" + listBuf.join("") + "</ul>"; listBuf = []; } };
  for (const raw of lines) {
    if (raw.trim() === "" && !inFence) { flushList(); continue; }
    const fence = raw.match(/^```(\w*)/);
    if (fence) {
      if (inFence) { html += `<pre class="md-code"><code>${fenceBuf.join("\n")}</code></pre>`; fenceBuf = []; inFence = false; }
      else inFence = true;
      continue;
    }
    if (inFence) { fenceBuf.push(esc(raw)); continue; }
    const h = raw.match(/^(#{1,3})\s+(.*)$/);
    if (h) { flushList(); html += `<h${h[1].length}>${mdRenderInline(h[2])}</h${h[1].length}>`; continue; }
    const q = raw.match(/^>\s?(.*)$/);
    if (q) { flushList(); html += `<blockquote>${mdRenderInline(q[1])}</blockquote>`; continue; }
    const ul = raw.match(/^[-*+]\s+(.*)$/);
    if (ul) { listBuf.push(`<li>${mdRenderInline(ul[1])}</li>`); continue; }
    flushList();
    html += `<p>${mdRenderInline(raw)}</p>`;
  }
  if (inFence) html += `<pre class="md-code"><code>${fenceBuf.join("\n")}</code></pre>`;
  flushList();
  return html || `<p class="empty">（空笔记）</p>`;
}

function mdRenderInline(s) {
  let l = esc(s);
  l = l.replace(/`([^`]+)`/g, "<code>$1</code>");
  l = l.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  l = l.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  l = l.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
  return l;
}

function mdSnippet(md) {
  return String(md || "").replace(/```[\w]*\n?/g, "").replace(/[#>*`\-\[\]()]/g, "")
    .replace(/\s+/g, " ").trim().slice(0, 24);
}

/* ---------- 渲染：条目列表 ---------- */
function filteredItems() {
  const q = state.search.trim().toLowerCase();
  return DB.items.filter((it) => {
    if (state.filter !== "all" && it.type !== state.filter) return false;
    if (!q) return true;
    const hay = [
      it.name, it.username || "", (it.uris || []).join(" "),
      it.purpose || "", it.value || "", it.content || "", it.note || "",
      it.attachment || "", it.fileType || "",
    ].join(" ").toLowerCase();
    return hay.includes(q);
  });
}

function renderList() {
  const wrap = $("#item-list");
  const items = filteredItems();
  if (!items.length) {
    wrap.innerHTML = `<div class="empty">
      <div style="color:var(--fg-2);font-size:32px">${state.search ? "🔍" : "🗝️"}</div>
      <div>${state.search ? "未找到匹配条目" : "还没有条目，添加第一条吧"}</div>
      ${state.search ? "" : '<button class="btn btn-primary btn-sm" data-act="add">新建条目</button>'}
    </div>`;
    return;
  }
  wrap.innerHTML = items.map((it) => {
    const m = TYPE_META[it.type] || TYPE_META.login;
    return `<button class="item ${it.id === state.selectedId ? "selected" : ""}" data-id="${it.id}">
      <span class="item-icon ${m.cls}">${m.icon}</span>
      <span class="item-body">
        <span class="item-name">${esc(it.name)}</span>
        <span class="item-sub">${esc(m.sub(it)) || "—"}</span>
      </span>
    </button>`;
  }).join("");
  wrap.querySelectorAll(".item").forEach((el) =>
    el.addEventListener("click", () => selectItem(el.dataset.id)));
  const add = wrap.querySelector('[data-act="add"]');
  if (add) add.addEventListener("click", () => openItemModal());
}

function selectItem(id) {
  state.selectedId = id;
  renderList();
  renderDetail();
  // 堆叠布局（≤900px）下详情在列表下方：点击条目后滚入视口，避免"详情不跟随"观感
  if (window.innerWidth <= 900) {
    const detailEl = $("#detail");
    if (detailEl) detailEl.scrollIntoView({ behavior: "auto", block: "start" });
  }
}

/* ---------- 渲染：详情（按类型分组字段） ---------- */
function renderDetail() {
  const it = DB.items.find((x) => x.id === state.selectedId);
  const el = $("#detail");
  if (!it) { el.innerHTML = ""; return; }
  const m = TYPE_META[it.type] || TYPE_META.login;
  const maskValue = (v) => state.revealed ? esc(v) : "••••••••••••";
  const revealBtn = `<button class="icon-btn" data-act="reveal" title="${state.revealed ? "隐藏" : "显示"}">${I.eye}</button>`;

  let body = "";
  if (it.type === "login") {
    body = `
      <div class="section-title">登录信息</div>
      <div class="field-row">
        <div><div class="field-row-label">用户名</div>
          <div class="field-row-value"><span class="mono">${esc(it.username)}</span>
          <button class="icon-btn" data-act="copy-username" title="复制用户名">${I.copy}</button></div>
        </div>
      </div>
      <div class="field-row">
        <div><div class="field-row-label">密码</div>
          <div class="field-row-value">
            <span class="${state.revealed ? "mono" : "mask"}">${maskValue(it.password)}</span>
            ${revealBtn}
            <button class="icon-btn" data-act="copy-password" title="复制密码">${I.copy}</button>
          </div>
        </div>
      </div>
      ${it.uris?.length ? `<div class="section-title">站点</div>
        ${it.uris.map((u) => `<div class="uri-row">${I.globe} ${esc(u)}</div>`).join("")}` : ""}
      ${it.custom?.length ? `<div class="section-title">自定义字段</div>
        ${it.custom.map((c) => `
          <div class="field-row">
            <div><div class="field-row-label">${esc(c.name)}</div>
              <div class="field-row-value"><span class="${c.hidden ? "mask" : ""}">${c.hidden ? "••••••••" : esc(c.value)}</span>
              ${c.hidden ? `<button class="icon-btn" data-act="copy-custom">${I.copy}</button>` : ""}</div>
            </div>
          </div>`).join("")}` : ""}`;
  } else if (it.type === "note") {
    body = `
      <div class="section-title">笔记内容（Markdown）</div>
      <div class="md-render">${mdRender(it.content)}</div>`;
  } else if (it.type === "secret") {
    body = `
      <div class="section-title">密钥信息</div>
      <div class="field-row">
        <div><div class="field-row-label">密钥值</div>
          <div class="field-row-value">
            <span class="${state.revealed ? "mono" : "mask"}">${maskValue(it.value)}</span>
            ${revealBtn}
            <button class="icon-btn" data-act="copy-value" title="复制密钥值">${I.copy}</button>
          </div>
        </div>
      </div>
      <div class="field-row">
        <div><div class="field-row-label">用途</div>
          <div class="field-row-value">${esc(it.purpose || "—")}</div>
        </div>
      </div>
      <div class="field-row">
        <div><div class="field-row-label">过期时间</div>
          <div class="field-row-value">${it.expiresAt ? `${esc(it.expiresAt)} <span style="color:var(--fg-2)">（到期后不再自动注入）</span>` : "无过期时间"}</div>
        </div>
      </div>`;
  } else if (it.type === "file") {
    body = `
      <div class="section-title">文件信息</div>
      <div class="field-row">
        <div><div class="field-row-label">备注</div>
          <div class="field-row-value">${esc(it.note || "—")}</div>
        </div>
      </div>
      <div class="field-row">
        <div><div class="field-row-label">大小</div>
          <div class="field-row-value">${esc(it.size || "—")}</div>
        </div>
      </div>
      <div class="field-row">
        <div><div class="field-row-label">类型</div>
          <div class="field-row-value"><span class="key-tag">${esc(it.fileType || "—")}</span></div>
        </div>
      </div>
      <div class="section-title">附件（加密存储 · 上限 50MB）</div>
      <div class="attachment-row">${I.paperclip} ${esc(it.attachment || "—")}
        <span style="color:var(--fg-2)">${esc(it.size || "")}</span>
        <button class="icon-btn" data-act="download" title="下载（原型为模拟）">${I.download}</button>
      </div>`;
  }

  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-head">
        <span class="item-icon ${m.cls}">${m.icon}</span>
        <div>
          <h3 class="detail-title">${esc(it.name)}</h3>
          <div class="detail-sub">${m.label} · 修订于 ${it.revision.slice(0, 10)} · 存储端仅见密文</div>
        </div>
        <div class="detail-actions">
          <button class="icon-btn" data-act="edit" title="编辑">${I.edit}</button>
          <button class="icon-btn" data-act="delete" title="删除（软删除，30 天硬删）" style="color:var(--fg-1)">${I.trash}</button>
        </div>
      </div>
      ${body}
    </div>`;

  el.querySelector('[data-act="reveal"]')?.addEventListener("click", () => {
    state.revealed = !state.revealed;
    renderDetail();
  });
  el.querySelector('[data-act="edit"]')?.addEventListener("click", () => openItemModal(it.id));
  el.querySelector('[data-act="delete"]')?.addEventListener("click", () => confirmDelete(it.id));
  el.querySelector('[data-act="copy-username"]')?.addEventListener("click", () => copyText(it.username));
  el.querySelector('[data-act="copy-password"]')?.addEventListener("click", () => copyText(it.password));
  el.querySelector('[data-act="copy-value"]')?.addEventListener("click", () => copyText(it.value));
  el.querySelector('[data-act="copy-custom"]')?.addEventListener("click", () => copyText(it.custom[0]?.value || ""));
  el.querySelector('[data-act="download"]')?.addEventListener("click", () =>
    toast("原型演示：附件下载为模拟行为", "ok"));
}

/* ---------- 渲染：规则 / 设置 / 审计 ---------- */
function renderRules() {
  const wrap = $("#rule-list");
  if (!DB.rules.length) {
    wrap.innerHTML = `<div class="empty">还没有规则 · 一切请求默认拒绝</div>`;
    return;
  }
  wrap.innerHTML = DB.rules.map((r) => `
    <div class="rule-card">
      <div class="rule-head">
        <div>
          <div class="rule-cmd">${esc(r.command)}</div>
          <div class="rule-dir">${I.folder} ${esc(r.projectDir)}</div>
        </div>
        <button class="icon-btn" data-del="${r.id}" title="删除规则" style="color:var(--fg-1)">${I.trash}</button>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px">
        ${r.keys.map((k) => `<span class="key-tag">${esc(k)}</span>`).join("")}
      </div>
    </div>`).join("");
  wrap.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", () => {
      DB.rules = DB.rules.filter((r) => r.id !== b.dataset.del);
      toast("规则已删除（已写审计）", "ok");
      renderRules();
    }));
}

function renderSettings() {
  const s = DB.settings;
  $("#settings-body").innerHTML = `
    <div class="settings-group">
      <div class="settings-group-title">安全</div>
      <div class="setting-row">
        <div><div class="setting-label">自动锁定（空闲）</div><div class="setting-desc">锁屏或超时后自动锁定，密钥从内存擦除</div></div>
        <select class="select-input" data-set="autoLockMin">
          ${["1", "5", "15", "30", "60"].map((v) => `<option ${s.autoLockMin === v ? "selected" : ""}>${v} 分钟</option>`).join("")}
        </select>
      </div>
      <div class="setting-row">
        <div><div class="setting-label">生物识别宽限（Windows Hello）</div><div class="setting-desc">已信任设备宽限窗口内可直接解锁</div></div>
        <label class="switch"><input type="checkbox" data-set="bioGrace" ${s.bioGrace ? "checked" : ""}/><span class="track"></span></label>
      </div>
      <div class="setting-row">
        <div><div class="setting-label">审计日志保留</div><div class="setting-desc">默认永久保留 · 滚动保留将在后续版本提供</div></div>
        <span class="select-input" style="display:inline-block">永久</span>
      </div>
    </div>
    <div class="settings-group">
      <div class="settings-group-title">同步（BYO 存储）</div>
      <div class="setting-row">
        <div><div class="setting-label">存储地址</div><div class="setting-desc">WebDAV / S3 · 存储端只见密文</div></div>
        <input class="select-input" style="width:260px" value="${esc(s.syncUrl)}" />
      </div>
      <div class="setting-row">
        <div><div class="setting-label">轮询间隔</div><div class="setting-desc">变更发现靠轮询（无推送）：15s ~ 24h</div></div>
        <select class="select-input" data-set="pollSec">
          ${["15", "30", "60", "300", "900", "3600"].map((v) => `<option ${s.pollSec === v ? "selected" : ""}>${v} 秒</option>`).join("")}
        </select>
      </div>
    </div>`;
  $("#settings-body").querySelectorAll("[data-set]").forEach((c) =>
    c.addEventListener("change", () => toast("设置已保存", "ok")));
}

function renderAudit() {
  const rows = DB.audit.filter((a) => state.afilter === "all" || a.result === state.afilter);
  const tag = { allowed: "allowed", denied: "denied", timeout: "timeout" };
  $("#audit-list").innerHTML = rows.length ? rows.map((a) => `
    <div class="audit-row">
      <span class="audit-ts">${a.ts}</span>
      <div class="audit-main">
        <div class="audit-cmd">${esc(a.starter)} → ${esc(a.target)}</div>
        <div class="audit-meta">${esc(a.dir)} · ${esc(a.note)} · HMAC 校验通过</div>
      </div>
      <span class="result-tag result-${tag[a.result]}">${a.result === "allowed" ? "允许" : a.result === "denied" ? "拒绝" : "超时"}</span>
    </div>`).join("")
    : `<div class="empty">该筛选下暂无事件</div>`;
}

function renderPage(page) {
  if (page === "items") { renderList(); renderDetail(); }
  if (page === "rules") renderRules();
  if (page === "settings") renderSettings();
  if (page === "audit") renderAudit();
}

function renderVault() {
  setPage(state.page); // re-render current page
  $("#search-input").value = state.search;
}

/* ---------- 弹窗 ---------- */
function openModal(html, onMount) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="modal-overlay"><div class="modal">${html}</div></div>`;
  root.querySelector(".modal-overlay").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { closeModal(); document.removeEventListener("keydown", esc); }
  });
  onMount?.(root.querySelector(".modal"));
}
function closeModal() { $("#modal-root").innerHTML = ""; }

/* ---------- 新建 / 编辑条目（v2：四类类型选择 → 类型对应表单） ---------- */
const FILE_LIMIT = 50 * 1024 * 1024; // 50MB

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function openItemModal(id) {
  const it = id ? DB.items.find((x) => x.id === id) : null;
  const title = it ? "编辑条目" : "新建条目";
  const typeOrder = ["login", "note", "secret", "file"];
  const typeLabels = { login: "登录", note: "笔记", secret: "密钥", file: "文件" };
  let selFile = null; // 本次选择的新附件（原型内存态）

  openModal(`
    <h3 class="modal-title">${title}</h3>
    <p class="modal-desc">保存后写入加密库 · 乐观并发（CAS）</p>
    <div class="form-grid">
      <label class="field"><span class="field-label">名称</span>
        <span class="input-wrap"><input id="f-name" value="${it ? esc(it.name) : ""}" placeholder="例如：GitHub" /></span></label>
      <div class="field">
        <span class="field-label">类型</span>
        <div class="filters" id="f-type-chips" style="margin-bottom:0">
          ${typeOrder.map((t) => `<button type="button" class="chip ${it?.type === t ? "active" : (!it && t === "login" ? "active" : "")}" data-type="${t}" aria-label="类型：${typeLabels[t]}" title="类型：${typeLabels[t]}">${typeLabels[t]}</button>`).join("")}
        </div>
      </div>

      <div id="f-login-fields">
        <label class="field"><span class="field-label">用户名</span>
          <span class="input-wrap"><input id="f-username" value="${it?.username ? esc(it.username) : ""}" /></span></label>
        <label class="field"><span class="field-label">密码</span>
          <span class="input-wrap"><input id="f-password" type="text" value="${it?.password ? esc(it.password) : ""}" /></span></label>
        <label class="field"><span class="field-label">站点（URI）</span>
          <span class="input-wrap"><input id="f-uri" value="${it?.uris?.join(", ") || ""}" placeholder="example.com" /></span></label>
      </div>

      <div id="f-note-fields">
        <label class="field"><span class="field-label">Markdown 内容（语法高亮 · 不做预览）</span>
          <span class="md-wrap">
            <span class="md-hl" aria-hidden="true"></span>
            <textarea id="f-content" class="md-editor" spellcheck="false">${it?.content ? esc(it.content) : ""}</textarea>
          </span></label>
      </div>

      <div id="f-secret-fields">
        <label class="field"><span class="field-label">密钥值</span>
          <span class="input-wrap"><input id="f-value" type="text" value="${it?.value ? esc(it.value) : ""}" placeholder="例如：npm_demo_token_0000" /></span></label>
        <label class="field"><span class="field-label">用途</span>
          <span class="input-wrap"><input id="f-purpose" value="${it?.purpose ? esc(it.purpose) : ""}" placeholder="例如：发布 npm 包（仅白名单命令注入）" /></span></label>
        <label class="field"><span class="field-label">过期时间（可选）</span>
          <span class="input-wrap"><input id="f-expires" type="date" value="${it?.expiresAt ? esc(it.expiresAt) : ""}" /></span></label>
      </div>

      <div id="f-file-fields">
        <label class="field"><span class="field-label">附件（加密存储）</span>
          <span class="attach-box">
            <input type="file" id="f-file" style="display:none" />
            <button type="button" class="btn btn-ghost btn-sm" id="f-file-pick">选择文件…</button>
            <span id="f-file-info" class="attach-info">${it?.attachment ? `${esc(it.attachment)} · ${esc(it.size || "")}` : "未选择文件"}</span>
          </span>
          <span class="limit-hint">单文件上限 50MB · 文件本体独立加密，存储端不可见</span></label>
        <label class="field"><span class="field-label">备注</span>
          <span class="input-wrap"><input id="f-note" value="${it?.note ? esc(it.note) : ""}" placeholder="可选说明" /></span></label>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="cancel">取消</button>
      <button class="btn btn-primary" data-act="save">保存</button>
    </div>`, (modal) => {
    const chips = modal.querySelectorAll("#f-type-chips .chip");
    const groups = {
      login: modal.querySelector("#f-login-fields"),
      note: modal.querySelector("#f-note-fields"),
      secret: modal.querySelector("#f-secret-fields"),
      file: modal.querySelector("#f-file-fields"),
    };
    let currentType = it?.type || "login";
    const applyType = (t) => {
      currentType = t;
      chips.forEach((c) => c.classList.toggle("active", c.dataset.type === t));
      Object.entries(groups).forEach(([k, el]) => { el.style.display = k === t ? "" : "none"; });
      // 笔记类型使用宽版弹窗（Markdown 编辑区放大）；其余类型常规尺寸
      modal.classList.toggle("modal-wide", t === "note");
    };
    chips.forEach((c) => c.addEventListener("click", () => applyType(c.dataset.type)));
    applyType(currentType);

    // Markdown 编辑器：语法高亮层 + 滚动同步
    const ta = modal.querySelector("#f-content");
    const hl = modal.querySelector(".md-hl");
    const syncHl = () => {
      hl.innerHTML = mdHighlight(ta.value);
      hl.scrollTop = ta.scrollTop;
      hl.scrollLeft = ta.scrollLeft;
    };
    ta.addEventListener("input", syncHl);
    ta.addEventListener("scroll", () => { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; });
    // 编辑框可纵向拉伸：让高亮层随编辑框同步扩张，避免拉伸后新行无高亮/不可见
    if (typeof ResizeObserver !== "undefined") {
      new ResizeObserver(() => { ta.parentElement.style.height = ta.offsetHeight + "px"; }).observe(ta);
    }
    syncHl();

    // 文件附件：选择交互 + 50MB 上限
    const fileInput = modal.querySelector("#f-file");
    const fileInfo = modal.querySelector("#f-file-info");
    modal.querySelector("#f-file-pick").addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      if (f.size > FILE_LIMIT) {
        toast("超过 50MB 上限，已拒绝选择", "warn");
        fileInput.value = "";
        fileInfo.textContent = it?.attachment ? `${it.attachment} · ${it.size}` : "未选择文件";
        return;
      }
      selFile = { name: f.name, size: fmtSize(f.size), fileType: f.type || "application/octet-stream" };
      fileInfo.textContent = `${selFile.name} · ${selFile.size}`;
      toast(`已选择附件 ${f.name}（${selFile.size}）`, "ok");
    });

    modal.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
    modal.querySelector('[data-act="save"]').addEventListener("click", () => {
      const name = $("#f-name").value.trim();
      if (!name) { toast("请填写名称", "warn"); return; }
      const now = new Date().toISOString().slice(0, 19) + "Z";
      const base = { name, revision: now };
      let data;
      if (currentType === "login") {
        data = { ...base, type: "login",
          username: $("#f-username").value.trim(), password: $("#f-password").value.trim(),
          uris: $("#f-uri").value.split(",").map((s) => s.trim()).filter(Boolean),
          custom: it?.custom || [] };
        if (!data.username || !data.password) { toast("请填写用户名与密码", "warn"); return; }
      } else if (currentType === "note") {
        data = { ...base, type: "note", content: $("#f-content").value };
        if (!data.content.trim()) { toast("请填写笔记内容", "warn"); return; }
      } else if (currentType === "secret") {
        data = { ...base, type: "secret",
          value: $("#f-value").value.trim(), purpose: $("#f-purpose").value.trim(),
          expiresAt: $("#f-expires").value || "" };
        if (!data.value) { toast("请填写密钥值", "warn"); return; }
      } else {
        if (!selFile && !it?.attachment) { toast("请选择附件文件（上限 50MB）", "warn"); return; }
        data = { ...base, type: "file",
          note: $("#f-note").value.trim(),
          size: selFile ? selFile.size : it.size,
          fileType: selFile ? selFile.fileType : it.fileType,
          attachment: selFile ? selFile.name : it.attachment };
      }
      if (it) {
        Object.assign(it, data);
        toast("条目已保存（revisionDate 已更新）", "ok");
      } else {
        DB.items.unshift({ id: "it" + Math.random().toString(36).slice(2, 8), ...data });
        state.selectedId = DB.items[0].id;
        toast("条目已创建", "ok");
      }
      closeModal();
      renderList(); renderDetail();
    });
  });
}

function confirmDelete(id) {
  const it = DB.items.find((x) => x.id === id);
  openModal(`
    <h3 class="modal-title">删除「${esc(it.name)}」？</h3>
    <p class="modal-desc">这是软删除：写入墓碑并在 30 天后硬删；墓碑会随同步传播。</p>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="cancel">取消</button>
      <button class="btn btn-danger" data-act="del">删除</button>
    </div>`, (modal) => {
    modal.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
    modal.querySelector('[data-act="del"]').addEventListener("click", () => {
      DB.items = DB.items.filter((x) => x.id !== id);
      if (state.selectedId === id) state.selectedId = DB.items[0]?.id || null;
      closeModal();
      renderList(); renderDetail();
      toast("已软删除 · 30 天后硬删", "ok");
    });
  });
}

/* ---------- 新建规则 ---------- */
function openRuleModal() {
  openModal(`
    <h3 class="modal-title">新建授权规则</h3>
    <p class="modal-desc">规则入库加密 · 按项目目录绑定 · 仅授权最小 key 名集合</p>
    <div class="form-grid">
      <label class="field"><span class="field-label">项目目录</span>
        <span class="input-wrap"><input id="r-dir" placeholder="~/work/proj-a" /></span></label>
      <label class="field"><span class="field-label">命令</span>
        <span class="input-wrap"><input id="r-cmd" placeholder="npm publish" /></span></label>
      <label class="field"><span class="field-label">注入的 key 名（逗号分隔）</span>
        <span class="input-wrap"><input id="r-keys" placeholder="NPM_TOKEN, NPM_CONFIG_..." /></span></label>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="cancel">取消</button>
      <button class="btn btn-primary" data-act="save">创建</button>
    </div>`, (modal) => {
    modal.querySelector('[data-act="cancel"]').addEventListener("click", closeModal);
    modal.querySelector('[data-act="save"]').addEventListener("click", () => {
      const dir = $("#r-dir").value.trim();
      const cmd = $("#r-cmd").value.trim();
      const keys = $("#r-keys").value.split(",").map((s) => s.trim()).filter(Boolean);
      if (!dir || !cmd || !keys.length) { toast("请完整填写规则", "warn"); return; }
      DB.rules.push({
        id: "r" + Math.random().toString(36).slice(2, 6),
        projectDir: dir, command: cmd, keys,
        created: new Date().toISOString().slice(0, 19) + "Z",
      });
      closeModal(); renderRules();
      toast("规则已创建（已写审计）", "ok");
    });
  });
}

/* ---------- 审批弹窗（模拟 lk inject） ---------- */
let approvalTimer = null;
function openApproval(overrides) {
  const req = Object.assign({
    starter: "claude", dir: "~/work/proj-c", cmd: "npm publish", keys: ["NPM_TOKEN"],
  }, overrides || {});
  const R = 28, C = 2 * Math.PI * R;
  let remain = 30;
  if (approvalTimer) clearInterval(approvalTimer);

  openModal(`
    <div class="approval-dialog">
      <h3 class="modal-title">授权请求 · ${esc(req.starter)}</h3>
      <p class="modal-desc">Agent 请求在项目目录中执行命令并注入密钥（密钥值不会显示）</p>
      <div class="approval-source">
        <span class="approval-avatar">${I.terminal}</span>
        <div>
          <div style="font-weight:600">${esc(req.starter)}</div>
          <div style="color:var(--fg-2);font-size:var(--fs-xs)">${I.folder} ${esc(req.dir)}</div>
        </div>
      </div>
      <div class="approval-cmd-box">$ ${esc(req.cmd)}</div>
      <div class="approval-keys">${req.keys.map((k) => `<span class="key-tag">${esc(k)}</span>`).join("")}</div>
      <div class="approval-timer">
        <span class="ring-wrap">
          <svg width="44" height="44">
            <circle cx="22" cy="22" r="${R}" fill="none" stroke="var(--bg-3)" stroke-width="3"/>
            <circle id="ring" cx="22" cy="22" r="${R}" fill="none" stroke="var(--warning)" stroke-width="3"
              stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="0"/>
          </svg>
          <span class="ring-num" id="ring-num">30</span>
        </span>
        <span>超时默认<b style="color:var(--danger)">拒绝</b> · 剩余 <span id="secs">30</span> 秒</span>
      </div>
      <div class="modal-actions">
        <button class="btn btn-ghost" data-act="deny">拒绝</button>
        <button class="btn btn-primary" data-act="allow">允许本次</button>
      </div>
    </div>`, (modal) => {
    const ring = modal.querySelector("#ring");
    const num = modal.querySelector("#ring-num");
    const secs = modal.querySelector("#secs");
    approvalTimer = setInterval(() => {
      remain -= 1;
      if (remain <= 0) {
        clearInterval(approvalTimer);
        closeModal();
        toast(`已超时 · 默认拒绝（已写审计）`, "warn");
        pushAudit(req, "timeout");
        return;
      }
      ring.style.strokeDashoffset = (C * (1 - remain / 30)).toFixed(1);
      num.textContent = remain;
      secs.textContent = remain;
    }, 1000);
    modal.querySelector('[data-act="allow"]').addEventListener("click", () => {
      clearInterval(approvalTimer); closeModal();
      toast(`已允许：${req.cmd}（env 仅注入被批准 key）`, "ok");
      pushAudit(req, "allowed");
    });
    modal.querySelector('[data-act="deny"]').addEventListener("click", () => {
      clearInterval(approvalTimer); closeModal();
      toast(`已拒绝：${req.cmd}（已写审计）`, "warn");
      pushAudit(req, "denied");
    });
  });
}
function pushAudit(req, result) {
  const now = new Date();
  DB.audit.unshift({
    ts: now.toTimeString().slice(0, 8), starter: req.starter, target: req.cmd,
    dir: req.dir, result,
    note: result === "allowed" ? "弹窗审批" : result === "denied" ? "用户拒绝" : "审批超时(30s)",
  });
}

/* ---------- 恢复码 ---------- */
const DEMO_RECOVERY_CODE = "J4QZ7 K8TW2 MPD9V XHC7G N3RFX 5AJKQ M2P8D 9VXH7";
function openRecovery() {
  openModal(`
    <h3 class="modal-title">恢复码（仅展示一次）</h3>
    <p class="modal-desc">请立即抄存或存入你的密码管理器；应用不记忆、不再展示。</p>
    <div class="recovery-code">${DEMO_RECOVERY_CODE}</div>
    <div class="recovery-warn">${I.lock}
      <span>三通道（主密码 / 恢复码 / 已信任设备）全丢 = 数据不可恢复。
      恢复码 + Argon2id 派生信封密钥保护主密钥副本，可随库进 BYO 云。</span>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="copy">复制</button>
      <button class="btn btn-primary" data-act="done">我已保存</button>
    </div>`, (modal) => {
    modal.querySelector('[data-act="copy"]').addEventListener("click", () => copyText(DEMO_RECOVERY_CODE.replace(/ /g, "")));
    modal.querySelector('[data-act="done"]').addEventListener("click", () => {
      closeModal(); toast("恢复信封已生成并加密保存", "ok");
    });
  });
}

/* ---------- Toast / 复制 ---------- */
function toast(msg, kind) {
  const root = $("#toast-root");
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<span class="dot" style="background:${kind === "ok" ? "var(--success)" : "var(--warning)"}"></span>${esc(msg)}`;
  root.appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; el.style.transition = "opacity 300ms"; }, 2400);
  setTimeout(() => el.remove(), 2800);
}
function copyText(text) {
  const done = () => toast("已复制 · 30 秒后自动清除剪贴板", "ok");
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => done());
  } else { done(); }
}

/* ---------- 原型导航栏（评审工具） ---------- */
function buildNav() {
  if (new URLSearchParams(location.search).get("review") === "0") return;
  const root = $("#nav-root");
  root.innerHTML = `
    <div class="proto-nav">
      <span style="color:var(--fg-2)">原型导航</span>
      <button data-nav="unlock">解锁页</button>
      <button data-nav="vault">条目</button>
      <button data-nav="rules">规则</button>
      <button data-nav="settings">设置</button>
      <button data-nav="audit">审计</button>
      <span class="sep"></span>
      <button data-nav="recovery">恢复码</button>
      <button class="warn" data-nav="approval">模拟 lk inject 审批</button>
      <span class="sep"></span>
      <button data-nav="hide" style="color:var(--fg-2)">隐藏导航</button>
    </div>`;
  root.querySelectorAll("[data-nav]").forEach((b) =>
    b.addEventListener("click", () => {
      const n = b.dataset.nav;
      if (n === "hide") { root.innerHTML = ""; return; }
      if (n === "approval") { showScreen("vault"); openApproval(); return; }
      if (n === "recovery") { showScreen("vault"); openRecovery(); return; }
      if (n === "unlock") { state.revealed = false; showScreen("unlock"); return; }
      if (n === "vault") { state.page = "items"; state.filter = "all"; showScreen("vault"); return; }
      setPage(n);
    }));
}

/* ---------- 事件绑定 ---------- */
function bindEvents() {
  $("#unlock-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("#unlock-password").value;
    if (!v) { toast("请输入主密码", "warn"); return; }
    showScreen("vault");
    toast("库已解锁 · 密钥仅存于守护进程内存", "ok");
  });
  $("#btn-hello").addEventListener("click", () => toast("Windows Hello 宽限解锁（已信任设备）", "ok"));
  $("#btn-recovery").addEventListener("click", openRecovery);
  $("#btn-lock").addEventListener("click", () => {
    state.revealed = false;
    $("#unlock-password").value = "";
    showScreen("unlock");
    toast("已锁定 · 内存密钥已擦除", "ok");
  });
  $("#btn-add").addEventListener("click", () => openItemModal());
  $("#btn-rule-add").addEventListener("click", openRuleModal);
  $("#btn-sync").addEventListener("click", () => toast("同步完成：无变更（轮询 60s）", "ok"));
  $("#search-input").addEventListener("input", (e) => {
    state.search = e.target.value;
    renderList();
  });
  // 条目筛选：事件委托绑定在容器上（chips 为静态节点，委托防御任何重渲染场景）
  const itemFilters = $("#item-filters");
  if (itemFilters) itemFilters.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip || !itemFilters.contains(chip)) return;
    itemFilters.querySelectorAll(".chip").forEach((x) => x.classList.remove("active"));
    chip.classList.add("active");
    state.filter = chip.dataset.filter;
    renderList();
  });
  document.querySelectorAll("#page-audit .chip").forEach((c) =>
    c.addEventListener("click", () => {
      document.querySelectorAll("#page-audit .chip").forEach((x) => x.classList.remove("active"));
      c.classList.add("active");
      state.afilter = c.dataset.afilter;
      renderAudit();
    }));
  document.querySelectorAll("[data-toggle-password]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.togglePassword);
      input.type = input.type === "password" ? "text" : "password";
    }));
  document.querySelectorAll(".nav-item[data-page]").forEach((b) =>
    b.addEventListener("click", () => {
      state.page = b.dataset.page;
      setPage(b.dataset.page);
    }));
}

/* ---------- Hash 深链（截图自动化用） ---------- */
function applyHash() {
  const h = location.hash.replace(/^#/, "");
  if (!h) return;
  if (h === "unlock") { showScreen("unlock"); return; }
  if (h === "vault") { state.page = "items"; state.filter = "all"; showScreen("vault"); return; }
  if (h === "approval") { showScreen("vault"); openApproval(); return; }
  if (h === "recovery") { showScreen("vault"); openRecovery(); return; }
  const m = h.match(/^item:(.+)$/);
  if (m) {
    state.page = "items"; state.filter = "all";
    state.selectedId = m[1];
    showScreen("vault");
    return;
  }
  if (["rules", "settings", "audit"].includes(h)) { state.page = h; showScreen("vault"); }
}

/* ---------- 启动 ---------- */
document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  buildNav();
  applyHash();
  if (state.screen === "unlock") showScreen("unlock");
});
