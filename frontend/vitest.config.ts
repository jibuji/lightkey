import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// 测试配置（vitest；jsdom 环境——localStorage/document 用于偏好持久化与主题 tokens）
export default defineConfig({
  plugins: [react()],
  // 协议契约测试经 `?raw` 读取 Rust 权威源（crates/lk-core/src/ipc.rs）——
  // crates/ 位于 frontend/ 根之外，Vite 默认 fs.allow 会拒绝；仅放宽测试
  // 侧（生产 vite.config.ts 不受影响，不随包导出 crates/）。
  server: {
    fs: {
      allow: [".."],
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    setupFiles: ["src/__tests__/setup.ts"],
  },
});
