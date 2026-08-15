import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 开发时通过 devUrl (localhost:1420) 加载前端；
// 端口必须与 crates/lk-app/tauri.conf.json 的 devUrl 一致。
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/crates/**", "**/docs/**"],
    },
  },
  build: {
    target: "es2021",
    outDir: "dist",
  },
});
