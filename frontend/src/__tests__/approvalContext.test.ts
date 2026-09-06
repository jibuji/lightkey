/**
 * 审批帧单一解析器单测（issue #147：审批帧携带门事实 + 前端单一解析器）。
 *
 * 钉住：`parseApprovalContext` 把帧解析成唯一事实对象 ApprovalContext，
 * `rememberable` 由 subKind + writeAction + needsUnlock **纯派生**（不进
 * 协议）；规则负载构造（buildRememberRule / buildReauthorizeRule）与按钮
 * 渲染消费**同一**解析产物；旧帧（缺 subKind）下 rememberable 恒 false
 * ——spec 唯一行为修正（「记住」按钮不再渲染）。
 */

import { describe, expect, it } from "vitest";

import type { AuthzRequestPayload } from "../events";
import {
  buildReauthorizeRule,
  buildRememberRule,
  exeBasename,
  parseApprovalContext,
  parseApprovalKind,
  parseApprovalSubKind,
  parseFingerprintMismatch,
  parseWriteAction,
} from "../plugins/approvalContext";

/** 最小合法帧（inject 形态；daemon 帧恒带 challenge/needsUnlock）。 */
function frame(overrides: Partial<AuthzRequestPayload> = {}): AuthzRequestPayload {
  return {
    requestId: "req-1",
    starter: "claude",
    projectDir: "/work/proj-a",
    command: "npm publish",
    keys: ["NPM_TOKEN"],
    challenge: "chal-1",
    needsUnlock: false,
    ...overrides,
  };
}

describe("parseApprovalKind / parseApprovalSubKind（白名单严格解析）", () => {
  it("kind：合法值透传；未知/缺失/非字符串 → unknown（防御渲染先例）", () => {
    expect(parseApprovalKind("inject")).toBe("inject");
    expect(parseApprovalKind("read")).toBe("read");
    expect(parseApprovalKind("export")).toBe("export");
    expect(parseApprovalKind("rule")).toBe("rule");
    expect(parseApprovalKind("write")).toBe("write");
    expect(parseApprovalKind("telemetry")).toBe("unknown");
    expect(parseApprovalKind(undefined)).toBe("unknown");
    expect(parseApprovalKind(42)).toBe("unknown");
  });

  it("subKind：只接受白名单精确值；缺失/畸形/未知 → null（旧帧信号）", () => {
    expect(parseApprovalSubKind("rule.add")).toBe("rule.add");
    expect(parseApprovalSubKind("rule.remove")).toBe("rule.remove");
    expect(parseApprovalSubKind("item.put")).toBe("item.put");
    expect(parseApprovalSubKind("item.delete")).toBe("item.delete");
    expect(parseApprovalSubKind("rule.add ")).toBeNull(); // 不 trim：精确匹配
    expect(parseApprovalSubKind("item.putx")).toBeNull();
    expect(parseApprovalSubKind(undefined)).toBeNull(); // read/export/inject 帧
    expect(parseApprovalSubKind(null)).toBeNull();
    expect(parseApprovalSubKind(42)).toBeNull();
  });
});

describe("parseApprovalContext（唯一事实对象；rememberable 纯派生）", () => {
  it("inject 帧：无 subKind、不可记、不可重授权", () => {
    const c = parseApprovalContext(frame({ kind: "inject" }));
    expect(c.kind).toBe("inject");
    expect(c.subKind).toBeNull();
    expect(c.rememberable).toBe(false);
    expect(c.reauthorizable).toBe(false);
    expect(c.isRuleRemove).toBe(false);
    expect(c.isWriteDelete).toBe(false);
  });

  it("read 帧：rememberable=true（解锁态）；needsUnlock → false（#23 锁态无记住）", () => {
    const unlocked = parseApprovalContext(
      frame({ kind: "read", command: "item.get", keys: ["API_TOKEN"] }),
    );
    expect(unlocked.rememberable).toBe(true);
    const locked = parseApprovalContext(
      frame({ kind: "read", command: "item.get", keys: ["API_TOKEN"], needsUnlock: true }),
    );
    expect(locked.rememberable).toBe(false);
    expect(locked.needsUnlock).toBe(true);
  });

  it("export 帧：恒不可记（规则不豁免导出），锁态解锁态一致", () => {
    for (const needsUnlock of [false, true]) {
      const c = parseApprovalContext(
        frame({ kind: "export", command: "item.export", needsUnlock }),
      );
      expect(c.rememberable).toBe(false);
    }
  });

  it("rule 帧：subKind 派生 isRuleRemove；规则操作本身即持久动作 → 不可记", () => {
    const add = parseApprovalContext(
      frame({ kind: "rule", command: "rule.add pub", subKind: "rule.add" }),
    );
    expect(add.isRuleRemove).toBe(false);
    expect(add.rememberable).toBe(false);
    const remove = parseApprovalContext(
      frame({ kind: "rule", command: "rule.remove pub", subKind: "rule.remove" }),
    );
    expect(remove.isRuleRemove).toBe(true);
    expect(remove.rememberable).toBe(false);
  });

  it("write put 帧：create/update 按 subKind+writeAction 可记（#137 最小授权输入）", () => {
    for (const writeAction of ["create", "update"] as const) {
      const c = parseApprovalContext(
        frame({
          kind: "write",
          command: `item.put API_TOKEN`,
          keys: ["API_TOKEN"],
          subKind: "item.put",
          writeAction,
        }),
      );
      expect(c.isWriteDelete).toBe(false);
      expect(c.writeAction).toBe(writeAction);
      expect(c.rememberable).toBe(true);
    }
  });

  it("write put 帧 writeAction 畸形/缺失：不可记（宁可不记，不超发全类授权）", () => {
    for (const writeAction of [undefined, null, "delete", 42]) {
      const c = parseApprovalContext(
        frame({
          kind: "write",
          command: "item.put API_TOKEN",
          keys: ["API_TOKEN"],
          subKind: "item.put",
          writeAction: writeAction as never,
        }),
      );
      expect(c.rememberable).toBe(false);
    }
  });

  it("write delete 帧：isWriteDelete=true，恒不可记（任何规则不豁免）", () => {
    const c = parseApprovalContext(
      frame({
        kind: "write",
        command: "item.delete API_TOKEN",
        keys: ["API_TOKEN"],
        subKind: "item.delete",
        writeAction: null,
      }),
    );
    expect(c.isWriteDelete).toBe(true);
    expect(c.rememberable).toBe(false);
  });

  it("旧帧（kind=write 缺 subKind）：rememberable 恒 false——spec 唯一行为修正", () => {
    // 旧守护进程帧：writeAction 在场也不可记（不再渲染可点但必失败的按钮）
    const old = parseApprovalContext(
      frame({
        kind: "write",
        command: "item.put API_TOKEN",
        keys: ["API_TOKEN"],
        writeAction: "create",
      }),
    );
    expect(old.subKind).toBeNull();
    expect(old.rememberable).toBe(false);
    // 旧帧的 delete 语义不可恢复（启发式已删）——isWriteDelete 恒 false
    const oldDelete = parseApprovalContext(
      frame({ kind: "write", command: "item.delete API_TOKEN", keys: ["API_TOKEN"] }),
    );
    expect(oldDelete.isWriteDelete).toBe(false);
    expect(oldDelete.rememberable).toBe(false);
  });

  it("指纹失配帧：reauthorizable=true；畸形失配信息 → 防御回退普通 inject", () => {
    const ok = parseApprovalContext(
      frame({
        kind: "inject",
        fingerprintMismatch: { resolvedExePath: "C:\\bin\\npm.cmd", sha256Short: "a1b2c3d4" },
      }),
    );
    expect(ok.reauthorizable).toBe(true);
    expect(ok.fingerprintMismatch).toEqual({
      resolvedExePath: "C:\\bin\\npm.cmd",
      sha256Short: "a1b2c3d4",
    });
    // needsUnlock（#140 锁态二次审批）→ 不可重授权（临时 vault 无法持久化规则）
    const locked = parseApprovalContext(
      frame({
        kind: "inject",
        needsUnlock: true,
        fingerprintMismatch: { resolvedExePath: "/usr/bin/npm", sha256Short: "a1b2c3d4" },
      }),
    );
    expect(locked.reauthorizable).toBe(false);
    for (const bad of [null, "oops", {}, { resolvedExePath: "", sha256Short: "a1b2c3d4" }]) {
      const c = parseApprovalContext(
        frame({ kind: "inject", fingerprintMismatch: bad as never }),
      );
      expect(c.reauthorizable).toBe(false);
      expect(c.fingerprintMismatch).toBeNull();
    }
  });

  it("完整 64 位哈希 → sha256Short 截断到 8 位（UI 硬保证不展示完整值）", () => {
    const c = parseApprovalContext(
      frame({
        kind: "inject",
        fingerprintMismatch: {
          resolvedExePath: "/usr/bin/npm",
          sha256Short: "abcdef0123456789",
        },
      }),
    );
    expect(c.fingerprintMismatch!.sha256Short).toBe("abcdef01");
  });
});

describe("buildRememberRule / buildReauthorizeRule（与渲染消费同一解析产物）", () => {
  it("read：capability=read、keys=[条目名]、command 恒空", () => {
    const f = frame({ kind: "read", command: "item.get", keys: ["API_TOKEN"] });
    const c = parseApprovalContext(f);
    expect(buildRememberRule(f, c)).toEqual({
      projectDir: "/work/proj-a",
      name: "read-API_TOKEN",
      command: "",
      keys: ["API_TOKEN"],
      capability: "read",
    });
  });

  it("write put：capability=write + actions=[帧内 writeAction 当前动作]（#137）", () => {
    for (const writeAction of ["create", "update"] as const) {
      const f = frame({
        kind: "write",
        command: "item.put API_TOKEN",
        keys: ["API_TOKEN"],
        subKind: "item.put",
        writeAction,
      });
      expect(buildRememberRule(f, parseApprovalContext(f))).toEqual({
        projectDir: "/work/proj-a",
        name: "write-API_TOKEN",
        command: "",
        keys: ["API_TOKEN"],
        capability: "write",
        actions: [writeAction],
      });
    }
  });

  it("不可记组合 → null：export / delete / 锁态 / 旧帧 / writeAction 缺失 / 空keys", () => {
    const exportFrame = frame({ kind: "export", command: "item.export" });
    expect(buildRememberRule(exportFrame, parseApprovalContext(exportFrame))).toBeNull();
    const deleteFrame = frame({
      kind: "write",
      command: "item.delete API_TOKEN",
      keys: ["API_TOKEN"],
      subKind: "item.delete",
    });
    expect(buildRememberRule(deleteFrame, parseApprovalContext(deleteFrame))).toBeNull();
    const lockedRead = frame({
      kind: "read",
      command: "item.get",
      keys: ["API_TOKEN"],
      needsUnlock: true,
    });
    expect(buildRememberRule(lockedRead, parseApprovalContext(lockedRead))).toBeNull();
    const oldWrite = frame({
      kind: "write",
      command: "item.put API_TOKEN",
      keys: ["API_TOKEN"],
      writeAction: "create",
    });
    expect(buildRememberRule(oldWrite, parseApprovalContext(oldWrite))).toBeNull();
    const noAction = frame({
      kind: "write",
      command: "item.put API_TOKEN",
      keys: ["API_TOKEN"],
      subKind: "item.put",
    });
    expect(buildRememberRule(noAction, parseApprovalContext(noAction))).toBeNull();
    const emptyKeys = frame({ kind: "read", command: "item.get", keys: [] });
    expect(buildRememberRule(emptyKeys, parseApprovalContext(emptyKeys))).toBeNull();
  });

  it("重新授权：command/name = exe basename、fingerprint 仅 exePath（#136/§5.4）", () => {
    const f = frame({
      kind: "inject",
      fingerprintMismatch: {
        resolvedExePath: "C:\\Program Files\\nodejs\\npm.cmd",
        sha256Short: "a1b2c3d4",
      },
    });
    const c = parseApprovalContext(f);
    expect(buildReauthorizeRule(f, c)).toEqual({
      projectDir: "/work/proj-a",
      name: "fp-npm.cmd",
      command: "npm.cmd",
      keys: ["NPM_TOKEN"],
      capability: "inject",
      fingerprint: { exePath: "C:\\Program Files\\nodejs\\npm.cmd" },
    });
  });

  it("重新授权不可用 → null：非失配帧 / 锁态 / 畸形失配信息", () => {
    const plain = frame({ kind: "inject" });
    expect(buildReauthorizeRule(plain, parseApprovalContext(plain))).toBeNull();
    const locked = frame({
      kind: "inject",
      needsUnlock: true,
      fingerprintMismatch: { resolvedExePath: "/usr/bin/npm", sha256Short: "a1b2c3d4" },
    });
    expect(buildReauthorizeRule(locked, parseApprovalContext(locked))).toBeNull();
    const bad = frame({ kind: "inject", fingerprintMismatch: "oops" as never });
    expect(buildReauthorizeRule(bad, parseApprovalContext(bad))).toBeNull();
  });
});

describe("既有解析辅助（迁移自 approval.tsx，行为不变）", () => {
  it("parseWriteAction：只接受 create/update", () => {
    expect(parseWriteAction("create")).toBe("create");
    expect(parseWriteAction("update")).toBe("update");
    expect(parseWriteAction("delete" as never)).toBeNull();
    expect(parseWriteAction(undefined)).toBeNull();
    expect(parseWriteAction(null)).toBeNull();
  });

  it("parseFingerprintMismatch：shape 校验 + 超长截断", () => {
    expect(
      parseFingerprintMismatch({ resolvedExePath: "/usr/bin/npm", sha256Short: "a1b2c3d4" }),
    ).toEqual({ resolvedExePath: "/usr/bin/npm", sha256Short: "a1b2c3d4" });
    expect(parseFingerprintMismatch({ resolvedExePath: "", sha256Short: "a1b2c3d4" })).toBeNull();
    expect(parseFingerprintMismatch("oops" as never)).toBeNull();
    expect(
      parseFingerprintMismatch({
        resolvedExePath: "/usr/bin/npm",
        sha256Short: "abcdef0123456789",
      })!.sha256Short,
    ).toBe("abcdef01");
  });

  it("exeBasename：跨 Windows/Linux 分隔符", () => {
    expect(exeBasename("C:\\Program Files\\nodejs\\npm.cmd")).toBe("npm.cmd");
    expect(exeBasename("/usr/bin/npm")).toBe("npm");
    expect(exeBasename("npm.cmd")).toBe("npm.cmd");
  });
});
