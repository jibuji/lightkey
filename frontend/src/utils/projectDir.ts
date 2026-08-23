/**
 * projectDir 展示格式化（cross-subsystem.md §7.4/§7.5）。
 *
 * 守护进程侧已把 UNC 路径归一化为规范形 `wsl://<distro>/<rest>` 再下发
 * （归一化在 lk-core::path_ns 执行），前端只处理 `wsl://` 前缀字符串：
 * 命中时按 `wsl://<distro>/<rest> (WSL)` 展示并标注 (WSL)，让用户一眼
 * 看出这是 WSL 侧目录；其余形态（常规 Windows 绝对路径、~、其他字符串）
 * 原样返回——纯展示函数，不上报、不改事件结构。
 */

/** 规范形前缀（守护进程侧 lk-core::path_ns 下发的唯一 WSL 形态）。 */
const WSL_PREFIX = "wsl://";

/**
 * 把 projectDir 原始值格式化为展示文案。
 *
 * - `wsl://Debian/home/u/p` → `wsl://Debian/home/u/p (WSL)`
 * - `C:\Users\u\p` / `~/work/proj-a` / 其他字符串 → 原样
 */
export function formatProjectDir(raw: string): string {
  if (!raw.startsWith(WSL_PREFIX)) return raw;
  // 规范形要求 <distro> 段非空：`wsl://Debian/home/u/p` ✓；`wsl://`、
  // `wsl:///etc` 无发行版段，视为非规范形，原样展示不误标
  const distro = raw.slice(WSL_PREFIX.length).split("/", 1)[0];
  if (!distro) return raw;
  return `${raw} (WSL)`;
}
