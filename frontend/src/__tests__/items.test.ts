/**
 * 条目域模块单测（架构评审候选 #4）：直接打 `items/collection` 的模块
 * interface，不经 DOM / renderHook：
 *
 * - §6.2 可搜字段白名单：白名单字段命中、密钥明文值与笔记全文不命中；
 * - 类型过滤 chips；
 * - 加载编排：成功 / 失败返回判别式结果（issue #85：失败可区分于空库，
 *   不再用 null 表达）/ 刷新后选中保持；
 * - CAS 冲突处置：覆盖 = 同 id+draft 重发 update 且不带 expectedRevision；
 * - 表单↔草稿映射：itemToDraft 剥离 id/revision 的往返一致性。
 */

import { describe, expect, it, vi } from "vitest";
import {
  filterItems,
  itemToDraft,
  loadItems,
  overwriteConflict,
  resolveSelection,
  searchableText,
  stashConflict,
} from "../items/collection";
import type { Item, ItemDraft, ItemType } from "../types";
import type { ItemsIpc } from "../items/collection";

/* ---------- fixtures ---------- */

const login: Item = {
  type: "login",
  id: "it-login",
  name: "GitHub 登录",
  revision: "2026-08-15T00:00:00Z",
  username: "alice@example.com",
  password: "SUPER-SECRET-PASSWORD",
  uris: ["https://github.com", "gist.github.com"],
  custom: [],
};

const note: Item = {
  type: "note",
  id: "it-note",
  name: "恢复码备忘",
  revision: "2026-08-15T00:00:00Z",
  content: "全文内容 topsecret-note-body 不应被搜到",
};

const secret: Item = {
  type: "secret",
  id: "it-secret",
  name: "npm 发布令牌",
  revision: "2026-08-15T00:00:00Z",
  value: "npm_secret_value_0000",
  purpose: "发布 npm 包",
  expiresAt: "",
};

const file: Item = {
  type: "file",
  id: "it-file",
  name: "合同扫描件",
  revision: "2026-08-15T00:00:00Z",
  note: "2026 年度劳动合同",
  size: "1.2 MB",
  fileType: "application/pdf",
  attachment: "contract.pdf",
};

const items = [login, note, secret, file];

/** 轻量 stub ipc（内存语义，无延迟）。 */
function stubIpc(store: Item[], opts?: { failList?: boolean; failGet?: boolean }) {
  return {
    list: vi.fn(async () => {
      if (opts?.failList) throw new Error("session.invalid");
      return store.map((it) => ({ id: it.id, name: it.name, type: it.type, revision: it.revision }));
    }),
    get: vi.fn(async (id: string) => {
      if (opts?.failGet) throw new Error("item.not_found");
      const it = store.find((x) => x.id === id);
      if (!it) throw new Error("item.not_found");
      return structuredClone(it);
    }),
    update: vi.fn(async (_id: string, _draft: ItemDraft): Promise<Item> => {
      throw new Error("not wired in this stub");
    }),
  } satisfies ItemsIpc & Record<string, ReturnType<typeof vi.fn>>;
}

/* ---------- (a) 过滤/搜索 ---------- */

describe("searchableText（spec §6.2 可搜字段白名单）", () => {
  it("白名单字段命中：名称/用户名/域名/用途/文件备注与元数据", () => {
    expect(searchableText(login)).toContain("alice@example.com");
    expect(searchableText(login)).toContain("gist.github.com");
    expect(searchableText(secret)).toContain("发布 npm 包");
    expect(searchableText(file)).toContain("contract.pdf");
    expect(searchableText(file)).toContain("application/pdf");
    expect(searchableText(file)).toContain("劳动合同");
  });

  it("密钥明文值绝不入 haystack；笔记全文不入 haystack", () => {
    expect(searchableText(secret)).not.toContain("npm_secret_value_0000");
    expect(searchableText(note)).not.toContain("topsecret-note-body");
    // login 密码同样不可搜
    expect(searchableText(login)).not.toContain("SUPER-SECRET-PASSWORD");
  });

  it("haystack 七槽位占位布局与重构前逐字节一致：连续空格查询词行为不变", () => {
    // 重构前 hay 为定长七槽位 join(" ")，非本类型槽位为空串 → 字段间存在
    // 连续空格；含连续空格的查询词（搜索框只 trim 首尾）必须同样命中。
    // secret：name 与 purpose 之间隔两个空槽位 → 三连空格。
    expect(filterItems([secret], "all", "令牌   发布")).toHaveLength(1);
    // 单空格 / 双连空格不命中——与重构前一致
    expect(filterItems([secret], "all", "令牌 发布")).toHaveLength(0);
    expect(filterItems([secret], "all", "令牌  发布")).toHaveLength(0);
  });
});

describe("filterItems（类型 chips + 查询词）", () => {
  it("类型过滤：只留命中类型的条目；all 放行全部", () => {
    expect(filterItems(items, "login", "").map((i) => i.id)).toEqual(["it-login"]);
    expect(filterItems(items, "file", "").map((i) => i.id)).toEqual(["it-file"]);
    expect(filterItems(items, "all", "")).toHaveLength(4);
  });

  it("查询词按白名单过滤且大小写不敏感；明文值不命中", () => {
    expect(filterItems(items, "all", "GITHUB").map((i) => i.id)).toEqual(["it-login"]);
    expect(filterItems(items, "all", "ALICE@EXAMPLE.COM").map((i) => i.id)).toEqual(["it-login"]);
    // 明文值 / 笔记全文不可作为搜索依据
    expect(filterItems(items, "all", "npm_secret_value_0000")).toHaveLength(0);
    expect(filterItems(items, "all", "topsecret-note-body")).toHaveLength(0);
  });

  it("搜索叠加类型 chips：先筛类型再匹配查询词", () => {
    expect(filterItems(items, "secret", "npm").map((i) => i.id)).toEqual(["it-secret"]);
    // "npm" 只命中 secret 的名称/用途，不因 login 无关而出现
    expect(filterItems(items, "login", "npm")).toHaveLength(0);
  });

  it("空结果返回空数组（空态由组件渲染）", () => {
    expect(filterItems(items, "all", "不存在的关键词")).toEqual([]);
  });
});

/* ---------- (b) 加载编排 ---------- */

describe("loadItems（list → 逐个 get 全量；失败为可区分判别式结果）", () => {
  it("成功：对每个 summary 调 get 并返回全量条目", async () => {
    const ipc = stubIpc(items);
    const res = await loadItems(ipc);
    expect(ipc.list).toHaveBeenCalledTimes(1);
    expect(ipc.get).toHaveBeenCalledTimes(4);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.items.map((it) => it.id)).toEqual(items.map((it) => it.id));
  });

  it("list 失败 → { ok:false, error }（不抛出；失败可区分于空库）", async () => {
    const ipc = stubIpc([], { failList: true });
    const res = await loadItems(ipc);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect((res.error as Error).message).toBe("session.invalid");
  });

  it("任一 get 失败 → 整轮失败 { ok:false }（与原 Promise.all 语义一致）", async () => {
    const ipc = stubIpc(items, { failGet: true });
    await expect(loadItems(ipc)).resolves.toMatchObject({ ok: false });
  });

  it("list 返回非数组（v0.1.11 错配形状）→ 失败且错因保留，不吞成空库", async () => {
    // 适配器漏解包时 list() 透传 ItemListResult 包装对象：旧实现吞成
    // null → 「还没有条目」表象；判别式结果必须让形状错配可区分。
    const ipc = stubIpc([]);
    ipc.list.mockResolvedValue({ items: [] } as unknown as Awaited<ReturnType<typeof ipc.list>>);
    const res = await loadItems(ipc);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect((res.error as Error).message).toContain("map is not a function");
  });
});

describe("resolveSelection（刷新后选中保持）", () => {
  it("原选中仍在结果中则保持", () => {
    expect(resolveSelection(items, "it-secret")).toBe("it-secret");
  });

  it("原选中已被删除则选第一个；空结果为 null", () => {
    expect(resolveSelection(items, "it-gone")).toBe("it-login");
    expect(resolveSelection([], "it-login")).toBeNull();
    expect(resolveSelection([], null)).toBeNull();
  });
});

/* ---------- (c) CAS 冲突处置 ---------- */

describe("CAS 冲突处置（stashConflict + overwriteConflict）", () => {
  it("覆盖 = 用暂存的同 id+draft 重发 update，且不带 expectedRevision", async () => {
    const updated = { ...login, name: "覆盖后的名字" };
    const ipc = stubIpc([]);
    ipc.update.mockResolvedValue(updated);
    const conflict = stashConflict(login.id, itemToDraft({ ...login, name: "我的编辑" }));

    await expect(overwriteConflict(ipc, conflict)).resolves.toBe(updated);
    expect(ipc.update).toHaveBeenCalledTimes(1);
    expect(ipc.update).toHaveBeenCalledWith(login.id, conflict.draft);
    // 关键语义：不带 options（expectedRevision），否则永远覆不上去
    expect(ipc.update.mock.calls[0]).toHaveLength(2);
  });

  it("失败原样上抛（toast 等 DOM 行为留在组件）", async () => {
    const ipc = stubIpc([]);
    ipc.update.mockRejectedValue(new Error("network"));
    const conflict = stashConflict("it-x", {} as ItemDraft);
    await expect(overwriteConflict(ipc, conflict)).rejects.toThrow("network");
  });
});

/* ---------- (d) 表单↔草稿映射 ---------- */

describe("itemToDraft（Item → ItemDraft 纯转换）", () => {
  const stripIdRev = (it: Item): Record<string, unknown> =>
    Object.fromEntries(Object.entries(it).filter(([k]) => k !== "id" && k !== "revision"));

  it("剥离 id/revision，其余字段逐类型保真", () => {
    for (const it of items) {
      const draft = itemToDraft(it);
      expect(draft).not.toHaveProperty("id");
      expect(draft).not.toHaveProperty("revision");
      expect(draft).toEqual(stripIdRev(it));
    }
  });

  it("转换是纯函数：不修改入参", () => {
    const snapshot = structuredClone(file);
    itemToDraft(file);
    expect(file).toEqual(snapshot);
  });
});

/* ---------- (e) 行为保持差分：重构前 VaultPage 内联实现 vs 条目域模块 ---------- */

/**
 * 重构前（base 3206e04）VaultPage 内联过滤逻辑的逐行忠实复刻——含定长七槽位
 * join(" ") 的 haystack 与 `.toLowerCase()` 时机。模块行为必须与其逐输入一致
 * （最高约束：VaultPage 行为零变化）。组件调用边界传入的 q 恒为已小写化文本
 * （`search.trim().toLowerCase()`），差分两侧同此约定。
 */
function legacyVaultPageFilter(
  all: Item[],
  filter: "all" | ItemType,
  q: string,
): Item[] {
  return all.filter((it) => {
    if (filter !== "all" && it.type !== filter) return false;
    if (!q) return true;
    const hay = [
      it.name,
      it.type === "login" ? it.username : "",
      it.type === "login" ? it.uris.join(" ") : "",
      it.type === "secret" ? it.purpose : "",
      it.type === "file" ? it.note : "",
      it.type === "file" ? it.attachment : "",
      it.type === "file" ? it.fileType : "",
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

/** mulberry32：可复现的确定性随机源。 */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("与重构前 VaultPage 内联实现的差分等价（行为零变化）", () => {
  // 含连续空格/大小写混合/跨类型关键词的字段值池；密钥明文刻意与其他类型的
  // 可搜词重叠，验证白名单语义在差分下同样成立。
  const POOL = [
    "GitHub 登录", "alice@example.com", "gist.github.com", "SUPER-SECRET-PASSWORD",
    "恢复码备忘", "topsecret-note-body", "npm 发布令牌", "npm_secret_value_0000",
    "发布 npm 包", "合同扫描件", "contract.pdf", "application/pdf", "2026 年度劳动合同",
    "A  B", "trailing ", " leading", "UPPER lower", "多  重  空格", "x", "",
  ];

  const pick = (r: () => number): string => POOL[Math.floor(r() * POOL.length)];

  function randomItem(r: () => number, i: number): Item {
    const base = { id: `gen-${i}`, revision: `rev-${i}` };
    switch (Math.floor(r() * 4)) {
      case 0:
        return {
          type: "login", ...base,
          name: pick(r), username: pick(r), password: pick(r),
          uris: [pick(r), pick(r)], custom: [],
        };
      case 1:
        return { type: "note", ...base, name: pick(r), content: pick(r) };
      case 2:
        return {
          type: "secret", ...base,
          name: pick(r), value: pick(r), purpose: pick(r), expiresAt: "",
        };
      default:
        return {
          type: "file", ...base,
          name: pick(r), note: pick(r), size: "1 KB",
          fileType: pick(r), attachment: pick(r),
        };
    }
  }

  it("searchableText 与旧七槽位 haystack 逐字节一致（全类型 × 随机字段）", () => {
    const r = rng(0x4c4b);
    for (let i = 0; i < 400; i++) {
      const it = randomItem(r, i);
      const legacy = (
        [
          it.name,
          it.type === "login" ? it.username : "",
          it.type === "login" ? it.uris.join(" ") : "",
          it.type === "secret" ? it.purpose : "",
          it.type === "file" ? it.note : "",
          it.type === "file" ? it.attachment : "",
          it.type === "file" ? it.fileType : "",
        ] as string[]
      ).join(" ").toLowerCase();
      expect(searchableText(it).toLowerCase()).toBe(legacy);
    }
  });

  it("filterItems 与旧内联过滤在 200 轮随机输入下结果序列完全一致", () => {
    const r = rng(0x51ce);
    const filters: ("all" | ItemType)[] = ["all", "login", "note", "secret", "file"];
    for (let round = 0; round < 200; round++) {
      const store = Array.from({ length: 8 }, (_, i) => randomItem(r, i));
      // 查询词从池中拼 1~3 片，保留原始大小写与内部空格；组件边界会统一
      // 小写化（`search.trim().toLowerCase()`），差分按同一调用边界喂两侧。
      const parts = Array.from({ length: 1 + Math.floor(r() * 3) }, () => pick(r));
      const rawQuery = parts.join(r() < 0.5 ? " " : "   ");
      const q = rawQuery.trim().toLowerCase();
      const f = filters[Math.floor(r() * filters.length)];
      const legacyIds = legacyVaultPageFilter(store, f, q).map((i) => i.id);
      const moduleIds = filterItems(store, f, q).map((i) => i.id);
      expect(moduleIds).toEqual(legacyIds);
    }
  });
});
