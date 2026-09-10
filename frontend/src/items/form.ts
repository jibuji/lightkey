/**
 * 表单域共享模块（issue #176）：ui-vault 与 ui-quick-save 两个插件的
 * secret 表单逐字文案 + 名称校验纯函数，抽取为单一共享来源
 * （decisions #27「零复制」——独立服务插件形态追认后，文案共享源收口）。
 *
 * 纯 TS module：零 React import、零 Cordis 注册，两个插件直接 import；
 * 校验纯函数可不经 DOM 直接单测（`__tests__/form.test.ts`）。
 * 只收口两插件共享的逐字项，不扩面到其他插件/表单组件。
 */

/** 名称校验错误文案（trim 后为空时提示）。 */
export const SECRET_NAME_ERROR = "请填写名称";

/** 用途字段占位符（secret 表单，两插件逐字共享）。 */
export const SECRET_PURPOSE_PLACEHOLDER = "例如：发布 npm 包（仅白名单命令注入）";

/**
 * 名称校验（可单测）：trim 后为空 → 返回错误文案；合法 → null。
 * 文案值即 `SECRET_NAME_ERROR`——改文案只动定义处，两插件引用同一导出。
 */
export function validateSecretName(name: string): string | null {
  return name.trim() ? null : SECRET_NAME_ERROR;
}