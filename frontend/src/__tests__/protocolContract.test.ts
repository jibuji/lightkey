/**
 * 协议契约双向对齐测试（issue #85/#86 事故类：跨语言协议漂移）。
 *
 * 断言 `frontend/src/ipc/protocol.ts` 与 Rust 权威源
 * `crates/lk-core/src/ipc.rs` 的线协议常量**逐值双向相等**：
 * RPC 方法名（M_*）、通知名（NOTIFY_*）、字符串错误码（MSG_*）、
 * 审计通道值（CHANNEL_*）与通道承载方法清单（CHANNEL_BEARING_METHODS）。
 *
 * 另钉死 `src/events.ts`（D 层事件总线契约）里与线协议同名的类型级
 * 字面量键（item.changed / session.unlocked / session.locked /
 * authz.request）——它们必须恰好等于 NOTIFICATIONS 值，事件总线侧不得
 * 出现既有的通知名之外的同名事件，也不得缺一个通知。
 *
 * 任何一侧新增 / 改名 / 删值而不同步，本测试即在 CI（npm test）变红，
 * 而不是等用户在客户端看到空列表或形状错配。
 *
 * Rust 源经 Vite `?raw` 读取（vitest 直接读文件；`vite/client` 已声明
 * `*?raw` 类型，无需 Node 类型依赖）。crates/ 在 frontend/ 根外，读取需
 * vitest.config.ts 的 `server.fs.allow: [".."]`。
 */
import { describe, expect, it } from "vitest";

import {
  CHANNELS,
  CHANNEL_BEARING_METHODS,
  ERROR_CODES,
  METHODS,
  NOTIFICATIONS,
} from "../ipc/protocol";

/** Rust 权威源文件（相对本测试文件的仓库根路径）。 */
import ipcRs from "../../../crates/lk-core/src/ipc.rs?raw";

/** D 层事件总线契约源（events.ts 的类型级字面量键）。 */
import eventsTs from "../events.ts?raw";

/** 解析全部 `pub const NAME: &str = "VALUE";` 常量。 */
function parseStrConsts(src: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /pub const ([A-Z][A-Z0-9_]*): &str = "([^"]*)";/g;
  for (const m of src.matchAll(re)) out.set(m[1], m[2]);
  return out;
}

/** 解析 CHANNEL_BEARING_METHODS 常量引用的 M_* 并解析为方法名字符串。 */
function parseChannelBearing(src: string, methods: Map<string, string>): string[] {
  const m = src.match(/pub const CHANNEL_BEARING_METHODS: &\[&str\] = &\[(.*?)\];/s);
  if (!m) return [];
  const refs = m[1].match(/M_[A-Z0-9_]+/g) ?? [];
  return refs.map((r) => methods.get(r)!).sort();
}

/** 解析 events.ts 的 `interface Events { … }` 模块增强里的字面量事件键。 */
function parseEventBusKeys(src: string): string[] {
  const m = src.match(/interface Events \{([\s\S]*?)\n  \}/);
  const body = m?.[1] ?? "";
  return [...body.matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

const sorted = (xs: readonly string[]) => [...xs].sort();

describe("protocol contract (协议契约)", () => {
  const consts = parseStrConsts(ipcRs);

  const rustMethods = new Map([...consts].filter(([k]) => /^M_/.test(k)));
  const rustMsg = new Map([...consts].filter(([k]) => /^MSG_/.test(k)));
  const rustNotify = new Map([...consts].filter(([k]) => /^NOTIFY_/.test(k)));
  const rustChannels = new Map([...consts].filter(([k]) => /^CHANNEL_/.test(k)));

  it("every &str const in ipc.rs is classified (methods / notify / msg / channel)", () => {
    const classified = new Set([
      ...rustMethods.keys(),
      ...rustMsg.keys(),
      ...rustNotify.keys(),
      ...rustChannels.keys(),
    ]);
    expect(classified).toEqual(new Set(consts.keys()));
  });

  it("METHODS mirrors M_* bidirectionally", () => {
    expect(sorted([...rustMethods.values()])).toEqual(sorted(Object.values(METHODS)));
    expect(Object.keys(METHODS).length).toBe(rustMethods.size);
  });

  it("NOTIFICATIONS mirrors NOTIFY_* bidirectionally", () => {
    expect(sorted([...rustNotify.values()])).toEqual(sorted(Object.values(NOTIFICATIONS)));
    expect(Object.keys(NOTIFICATIONS).length).toBe(rustNotify.size);
  });

  it("ERROR_CODES mirrors MSG_* bidirectionally", () => {
    expect(sorted([...rustMsg.values()])).toEqual(sorted(Object.values(ERROR_CODES)));
    expect(Object.keys(ERROR_CODES).length).toBe(rustMsg.size);
  });

  it("CHANNELS mirrors CHANNEL_* bidirectionally", () => {
    expect(sorted([...rustChannels.values()])).toEqual(sorted(Object.values(CHANNELS)));
    expect(Object.keys(CHANNELS).length).toBe(rustChannels.size);
  });

  it("CHANNEL_BEARING_METHODS matches the Rust const list", () => {
    expect(parseChannelBearing(ipcRs, rustMethods)).toEqual(sorted(CHANNEL_BEARING_METHODS));
    // 且全部来自 METHODS——不在契约内的方法不会携带 channel
    expect(
      CHANNEL_BEARING_METHODS.every((v) => (Object.values(METHODS) as readonly string[]).includes(v)),
    ).toBe(true);
  });

  it("events.ts wire-backed event keys mirror NOTIFICATIONS", () => {
    const notifyValues = Object.values(NOTIFICATIONS) as readonly string[];
    const eventKeys = parseEventBusKeys(eventsTs);
    // 事件总线侧（D 层本地 emit/on 键）凡与线协议通知同名者，须恰好等于
    // NOTIFICATIONS——无缺失、无多出的同名事件（events.ts 头注释的承诺）。
    const wireKeys = [...new Set(eventKeys.filter((k) => notifyValues.includes(k)))];
    expect(sorted(wireKeys)).toEqual(sorted(notifyValues));
  });
});
