import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// 测试配置（vitest；jsdom 环境——localStorage/document 用于偏好持久化与主题 tokens）
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    setupFiles: ["src/__tests__/setup.ts"],
  },
});
