/**
 * vitest 全局 setup：启用 React act 环境（渲染测试用）。
 */

(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;
