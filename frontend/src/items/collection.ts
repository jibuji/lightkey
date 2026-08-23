/**
 * 条目域模块（架构评审候选 #4）：从 ui-vault 组件闭包抽出的条目集合行为。
 *
 * 纯 TS module：零 React import、零 Cordis 注册，VaultPage 直接 import；
 * 每块行为均可不经 DOM 直接单测（`__tests__/items.test.ts`）。
 *
 * - 加载编排：`loadItems`（list → 逐个 get 取全量；任一步失败返回 null，
 *   由调用方置空数组）+ `resolveSelection`（刷新后选中保持：原选中仍在
 *   结果中则保持，否则选第一个；空结果为 null）；
 * - 过滤/搜索：`filterItems` + spec §6.2 可搜字段白名单 `searchableText`
 *   （名称 / 用户名 / 域名(login uris) / 用途(secret purpose) / 文件备注与
 *   元数据(note/attachment/fileType)；**绝不含密钥明文值与笔记全文**）；
 * - CAS 冲突处置：`stashConflict` + `overwriteConflict`（覆盖 = 用暂存的
 *   同 id+draft 重发 update、不带 expectedRevision——覆盖语义即放弃前置
 *   revision 校验）；
 * - 表单↔草稿映射：`itemToDraft`（Item → ItemDraft 纯转换；表单双向绑定
 *   留在组件）。
 */

import type { LightKeyIpc } from "../ipc/types";
import type { Item, ItemDraft, ItemType } from "../types";

/** 列表筛选值（"all" = 全部类型）。 */
export type ItemFilterValue = "all" | ItemType;

/* ---------- (b) 加载编排 ---------- */

/**
 * 条目域用到的 IPC 子集（结构化最小依赖，测试可用轻量 stub 替身）。
 */
export type ItemsIpc = Pick<LightKeyIpc, "list" | "get" | "update">;

/**
 * 加载编排：`ipc.list()` 后逐个 `ipc.get(id)` 取全量条目。
 *
 * 任一步失败返回 null（不抛出）；调用方据此置空数组——与原 VaultPage
 * 行为一致：失败只清空列表，不动当前选中。
 */
export async function loadItems(
  ipc: Pick<ItemsIpc, "list" | "get">,
): Promise<Item[] | null> {
  try {
    const summaries = await ipc.list();
    return await Promise.all(summaries.map((s) => ipc.get(s.id)));
  } catch {
    return null;
  }
}

/**
 * 刷新后选中保持规则：原 selectedId 仍在结果中则保持，否则选第一个；
 * 结果为空时无选中。
 */
export function resolveSelection(
  items: Item[],
  previousSelectedId: string | null,
): string | null {
  if (previousSelectedId && items.some((it) => it.id === previousSelectedId)) {
    return previousSelectedId;
  }
  return items[0]?.id ?? null;
}

/* ---------- (a) 过滤/搜索（spec §6.2 可搜字段白名单） ---------- */

/**
 * §6.2 安全决策的显式白名单：允许进入搜索 haystack 的字段。
 *
 * 名称 / 用户名 / 域名(login uris) / 用途(secret purpose) / 文件备注与
 * 元数据(file note/attachment/fileType)。**密钥明文值与笔记全文绝不入列**。
 * 返回未小写化的拼接串（大小写折叠由 `filterItems` 统一处理）。
 */
export function searchableText(item: Item): string {
  switch (item.type) {
    case "login":
      return [item.name, item.username, item.uris.join(" ")].join(" ");
    case "note":
      // 笔记全文不可搜（spec §6.2）：仅名称入 haystack
      return item.name;
    case "secret":
      // 密钥明文 value 永不可搜：仅名称与用途入 haystack
      return [item.name, item.purpose].join(" ");
    case "file":
      return [item.name, item.note, item.attachment, item.fileType].join(" ");
  }
}

/**
 * 列表过滤：先按类型 chips（"all" 放行全部），再按查询词命中白名单字段。
 * query 大小写不敏感（调用方传防抖后的原文或已小写化文本均可）。
 */
export function filterItems(
  items: Item[],
  filter: ItemFilterValue,
  query: string,
): Item[] {
  const q = query.toLowerCase();
  return items.filter((it) => {
    if (filter !== "all" && it.type !== filter) return false;
    if (!q) return true;
    return searchableText(it).toLowerCase().includes(q);
  });
}

/* ---------- (c) CAS 冲突处置 ---------- */

/** CAS 冲突暂存：冲突发生时冻结的编辑目标与草稿。 */
export interface ConflictStash {
  id: string;
  draft: ItemDraft;
}

/** 冲突时暂存 {id, draft}，供用户在「覆盖 / 取消」间抉择。 */
export function stashConflict(id: string, draft: ItemDraft): ConflictStash {
  return { id, draft };
}

/**
 * 覆盖处置：用暂存的同 id+draft 重发 update，且**不带 expectedRevision**
 * （带前置校验就永远覆不上去）。成功返回更新后的条目，失败原样上抛
 * （toast 文案等 DOM 行为留在组件）。
 */
export async function overwriteConflict(
  ipc: Pick<ItemsIpc, "update">,
  conflict: ConflictStash,
): Promise<Item> {
  return ipc.update(conflict.id, conflict.draft);
}

/* ---------- (d) 表单↔草稿映射（纯转换；双向绑定留组件） ---------- */

/**
 * 按具体条目类型剥去 id/revision（分布式，保住各类型的专属字段——
 * `types.ts` 的 `ItemDraft` 是对并集整体 Omit，会塌缩掉 login/note 等
 * 的差异化字段，故此处独立求型）。
 */
export type ItemDraftOf<T extends Item> = T extends unknown
  ? Omit<T, "id" | "revision">
  : never;

/** Item → ItemDraft 纯转换（剥去 id/revision），作表单初值来源。 */
export function itemToDraft<T extends Item>(item: T): ItemDraftOf<T> {
  const { id: _id, revision: _revision, ...draft } = item;
  // 分布式条件类型无法被 TS 从 rest rest 展开直接证明，此处收窄安全
  return draft as ItemDraftOf<T>;
}
