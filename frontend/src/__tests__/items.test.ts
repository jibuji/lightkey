/**
 * 条目域模块单测（架构评审候选 #4）：直接打 `items/collection` 的模块
 * interface，不经 DOM / renderHook：
 *
 * - §6.2 可搜字段白名单：白名单字段命中、密钥明文值与笔记全文不命中；
 * - 类型过滤 chips；
 * - 加载编排：成功 / 失败置 null（调用方据此清空列表）/ 刷新后选中保持；
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
import type { Item, ItemDraft } from "../types";
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

describe("loadItems（list → 逐个 get 全量）", () => {
  it("成功：对每个 summary 调 get 并返回全量条目", async () => {
    const ipc = stubIpc(items);
    const full = await loadItems(ipc);
    expect(ipc.list).toHaveBeenCalledTimes(1);
    expect(ipc.get).toHaveBeenCalledTimes(4);
    expect(full).not.toBeNull();
    expect(full!.map((it) => it.id)).toEqual(items.map((it) => it.id));
  });

  it("list 失败 → 返回 null（不抛出）", async () => {
    const ipc = stubIpc([], { failList: true });
    await expect(loadItems(ipc)).resolves.toBeNull();
  });

  it("任一 get 失败 → 整轮失败返回 null（与原 Promise.all 语义一致）", async () => {
    const ipc = stubIpc(items, { failGet: true });
    await expect(loadItems(ipc)).resolves.toBeNull();
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
