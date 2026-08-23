# LightKey

轻钥（LightKey）：个人密钥/私密信息管理工具，客户端全开源（MIT）。
本文件是唯一上下文的统一词汇表；设计决策见 `docs/decisions.md`。

## Language

### 条目域

**条目集合**:
一次解锁会话内加载进前端的全量条目快照，是列表类型筛选与搜索的唯一输入。
_Avoid_: 条目缓存, items 数组

**条目草稿**:
表单产出、尚无 id 与 revision 的条目载荷（`ItemDraft`）；新建直接入库，
编辑经乐观并发（CAS）提交。
_Avoid_: 表单数据, item 载荷

**可搜字段白名单**:
允许进入搜索 haystack 的显式字段集合——名称 / 用户名 / 域名(login uris) /
用途(secret purpose) / 文件备注与元数据；密钥明文值与笔记全文绝不入列
（spec §6.2 安全决策）。
_Avoid_: 全文索引, 全文搜索
