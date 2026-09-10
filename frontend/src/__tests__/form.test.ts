/**
 * 表单域共享模块单测（issue #176）：直接打 `items/form` 的模块
 * interface，不经 DOM / renderHook：
 *
 * - 名称校验纯函数：trim 后为空（空串 / 纯空白）→ 错误文案；合法 → null；
 * - 文案常量值钉死：两插件（ui-vault / ui-quick-save）引用同一导出，
 *   改文案只动定义处（decisions #27 零复制收口——若值变了说明有人改了
 *   定义处，测试会先行咬住）。
 */

import { describe, expect, it } from "vitest";
import {
  SECRET_NAME_ERROR,
  SECRET_PURPOSE_PLACEHOLDER,
  validateSecretName,
} from "../items/form";

describe("validateSecretName（名称 trim 后为空 → 错误文案）", () => {
  it("空串 → 「请填写名称」", () => {
    expect(validateSecretName("")).toBe("请填写名称");
  });

  it("纯空白 → 错误文案（trim 语义）", () => {
    expect(validateSecretName("   ")).toBe("请填写名称");
    expect(validateSecretName("\t\n ")).toBe("请填写名称");
  });

  it("合法名称 → null", () => {
    expect(validateSecretName("GitHub Token")).toBeNull();
  });

  it("首尾空白但不为空 → null（无隐式 trim 改写）", () => {
    expect(validateSecretName("  api_key  ")).toBeNull();
  });
});

describe("共享文案常量（修改只动定义处）", () => {
  it("名称校验错误文案", () => {
    expect(SECRET_NAME_ERROR).toBe("请填写名称");
  });

  it("用途占位符（两插件 secret 表单逐字共享）", () => {
    expect(SECRET_PURPOSE_PLACEHOLDER).toBe("例如：发布 npm 包（仅白名单命令注入）");
  });
});