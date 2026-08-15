/**
 * Markdown 轻量处理（照搬 served 原型 app.js 机制）：
 * - mdHighlight：编辑区语法高亮（tk-* token 层，不做预览/不做 WYSIWYG，
 *   spec §4 笔记定义）
 * - mdRender：只读渲染（详情页）
 * - mdSnippet：列表副行片段
 *
 * 覆盖语法子集：# 标题 / **粗** / *斜* / `行内码` / ```围栏 / > 引用 /
 * 无序与有序列表 / [链接](url)。输出 HTML 片段由调用方以
 * dangerouslySetInnerHTML 注入（输入先 esc，无 XSS 面）。
 */

function esc(s: string): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] ?? c),
  );
}

/** 编辑区高亮：逐行产出带 tk-* class 的 span */
export function mdHighlight(src: string): string {
  let inFence = false;
  return String(src || "")
    .split("\n")
    .map((raw) => {
      const fence = raw.match(/^```(\w*)/);
      if (fence) {
        inFence = !inFence;
        return `<span class="tk-fence">${esc(raw)}</span>`;
      }
      if (inFence) return `<span class="tk-code">${esc(raw)}</span>`;
      const h = raw.match(/^(#{1,3})\s+(.*)$/);
      if (h) return `<span class="tk-h">${h[1]} ${esc(h[2])}</span>`;
      const q = raw.match(/^(>\s?)(.*)$/);
      if (q) return `<span class="tk-q">${q[1]}${esc(q[2])}</span>`;
      const ul = raw.match(/^([-*+]|\d+\.)\s+(.*)$/);
      if (ul) return `<span class="tk-list">${ul[1]}</span> ${mdInline(ul[2])}`;
      return mdInline(raw);
    })
    .join("\n") + "\n";
}

function mdInline(s: string): string {
  let l = esc(s);
  l = l.replace(/`([^`]+)`/g, '<span class="tk-i">`$1`</span>');
  l = l.replace(/\*\*([^*]+)\*\*/g, '<span class="tk-b">**$1**</span>');
  l = l.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<span class="tk-l">[$1]($2)</span>');
  return l;
}

/** 只读渲染（详情页） */
export function mdRender(md: string): string {
  const lines = String(md || "").split("\n");
  let html = "";
  let inFence = false;
  let fenceBuf: string[] = [];
  let listBuf: string[] = [];
  const flushList = () => {
    if (listBuf.length) {
      html += "<ul>" + listBuf.join("") + "</ul>";
      listBuf = [];
    }
  };
  for (const raw of lines) {
    if (raw.trim() === "" && !inFence) {
      flushList();
      continue;
    }
    const fence = raw.match(/^```(\w*)/);
    if (fence) {
      if (inFence) {
        html += `<pre class="md-code"><code>${fenceBuf.join("\n")}</code></pre>`;
        fenceBuf = [];
        inFence = false;
      } else {
        inFence = true;
      }
      continue;
    }
    if (inFence) {
      fenceBuf.push(esc(raw));
      continue;
    }
    const h = raw.match(/^(#{1,3})\s+(.*)$/);
    if (h) {
      flushList();
      html += `<h${h[1].length}>${mdRenderInline(h[2])}</h${h[1].length}>`;
      continue;
    }
    const q = raw.match(/^>\s?(.*)$/);
    if (q) {
      flushList();
      html += `<blockquote>${mdRenderInline(q[1])}</blockquote>`;
      continue;
    }
    const ul = raw.match(/^[-*+]\s+(.*)$/);
    if (ul) {
      listBuf.push(`<li>${mdRenderInline(ul[1])}</li>`);
      continue;
    }
    flushList();
    html += `<p>${mdRenderInline(raw)}</p>`;
  }
  if (inFence) html += `<pre class="md-code"><code>${fenceBuf.join("\n")}</code></pre>`;
  flushList();
  return html || `<p class="empty">（空笔记）</p>`;
}

function mdRenderInline(s: string): string {
  let l = esc(s);
  l = l.replace(/`([^`]+)`/g, "<code>$1</code>");
  l = l.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  l = l.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  l = l.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
  return l;
}

/** 列表副行片段：去掉 Markdown 记号，取前 24 字 */
export function mdSnippet(md: string): string {
  return String(md || "")
    .replace(/```[\w]*\n?/g, "")
    .replace(/[#>*`\-\[\]()]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 24);
}
