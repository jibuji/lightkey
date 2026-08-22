/**
 * formatProjectDir 单元测试（cross-subsystem.md §7.4/§7.5 展示层）。
 *
 * 守护进程侧已归一化为 `wsl://...` 再下发；前端只处理该前缀，
 * 不做 UNC（\\wsl.localhost）归一化——那是 lk-core::path_ns 的职责。
 */
import { describe, expect, it } from "vitest";
import { formatProjectDir } from "../utils/projectDir";

describe("formatProjectDir", () => {
  it("wsl:// 规范形追加 (WSL) 标注", () => {
    expect(formatProjectDir("wsl://Debian/home/u/p")).toBe("wsl://Debian/home/u/p (WSL)");
    expect(formatProjectDir("wsl://Ubuntu-22.04/root/proj")).toBe(
      "wsl://Ubuntu-22.04/root/proj (WSL)",
    );
  });

  it("wsl:// 发行版根目录（rest 为空）同样标注", () => {
    expect(formatProjectDir("wsl://Debian/")).toBe("wsl://Debian/ (WSL)");
  });

  it("无发行版段的非规范形原样展示、不误标", () => {
    expect(formatProjectDir("wsl://")).toBe("wsl://");
    expect(formatProjectDir("wsl:///etc")).toBe("wsl:///etc");
  });

  it("常规 Windows 路径原样", () => {
    expect(formatProjectDir("C:\\Users\\u\\p")).toBe("C:\\Users\\u\\p");
    expect(formatProjectDir("D:/work/proj-a")).toBe("D:/work/proj-a");
  });

  it("~ 及其他字符串原样", () => {
    expect(formatProjectDir("~/work/proj-a")).toBe("~/work/proj-a");
    expect(formatProjectDir("/home/u/p")).toBe("/home/u/p");
    expect(formatProjectDir("")).toBe("");
  });

  it("UNC 归一化是守护进程职责：前端不处理 \\wsl.localhost 输入（仅原样透传）", () => {
    // 守护进程侧 path_ns 已把该输入转为 wsl://... 后才下发；前端收到
    // 未归一化的 UNC 字符串时不猜测、原样展示
    expect(formatProjectDir("\\\\wsl.localhost\\Debian\\home\\u\\p")).toBe(
      "\\\\wsl.localhost\\Debian\\home\\u\\p",
    );
  });
});
