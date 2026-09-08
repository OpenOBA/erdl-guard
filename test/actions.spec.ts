import { describe, it, expect } from "vitest";
import {
  SIMPLE_ACTIONS,
  simplifyRule,
  simplifyRules,
  createMcpGuard,
} from "../src/index.js";
import { DO_DECISIONS, GUARD_ALLOWED_DECISIONS } from "@openoba/rulsynor-core";

describe("simplifyRule()", () => {
  it("maps block → DENY (Ring 0)", () => {
    const r = simplifyRule(
      {
        name: "SEC-001-block-rm-rf",
        when: {
          logic: "AND",
          conditions: [{ field: "tool.args.command", operator: "contains", value: "rm -rf" }],
        },
        action: "block",
      },
      0,
    );
    expect(r.action.decision).toBe("DENY");
    expect(r.action.ring).toBe(0);
    expect(r.enabled).toBe(true);
    expect(r.category).toBe("security");
  });

  it("maps allow → ALLOW (Ring 3)", () => {
    const r = simplifyRule({ name: "x", when: { conditions: [] }, action: "allow" }, 0);
    expect(r.action.decision).toBe("ALLOW");
    expect(r.action.ring).toBe(3);
  });

  it("maps ask → REQUEST_HUMAN (Ring 2)", () => {
    const r = simplifyRule({ name: "x", when: { conditions: [] }, action: "ask" }, 0);
    expect(r.action.decision).toBe("REQUEST_HUMAN");
    expect(r.action.ring).toBe(2);
  });

  it("maps escalate → ESCALATE (Ring 2)", () => {
    const r = simplifyRule({ name: "x", when: { conditions: [] }, action: "escalate" }, 0);
    expect(r.action.decision).toBe("ESCALATE");
    expect(r.action.ring).toBe(2);
  });

  it("every verb maps to a decision anchored in DO_DECISIONS and GUARD_ALLOWED_DECISIONS", () => {
    for (const { decision } of Object.values(SIMPLE_ACTIONS)) {
      expect(DO_DECISIONS).toContain(decision);
      expect(GUARD_ALLOWED_DECISIONS).toContain(decision);
    }
  });
});

describe("simplifyRules() + createMcpGuard() end-to-end", () => {
  it("blocks a tool call with a lightweight block rule", () => {
    const rules = simplifyRules([
      {
        name: "SEC-001-block-rm-rf",
        when: {
          logic: "AND",
          conditions: [
            { field: "tool.name", operator: "eq", value: "bash" },
            { field: "tool.args.command", operator: "contains", value: "rm -rf" },
          ],
        },
        action: "block",
      },
    ]);
    const guard = createMcpGuard(rules);
    expect(guard.evaluate("bash", { command: "rm -rf /" }).decision).toBe("DENY");
    expect(guard.evaluate("bash", { command: "echo hi" }).decision).toBe("ALLOW");
  });
});

describe("routing edge cases", () => {
  it("block wins over allow regardless of rule order (ring precedence)", () => {
    // allow listed FIRST (lower priority), block listed SECOND — block (Ring 0) still wins.
    const rules = simplifyRules([
      { name: "allow-bash", when: { conditions: [{ field: "tool.name", operator: "eq", value: "bash" }] }, action: "allow" },
      { name: "block-rm-rf", when: { conditions: [{ field: "tool.args.command", operator: "contains", value: "rm -rf" }] }, action: "block" },
    ]);
    const guard = createMcpGuard(rules);
    expect(guard.evaluate("bash", { command: "rm -rf /" }).decision).toBe("DENY");
    expect(guard.evaluate("bash", { command: "echo hi" }).decision).toBe("ALLOW");
  });

  it("passes through the OR logic", () => {
    const r = simplifyRule(
      {
        name: "x",
        when: {
          logic: "OR",
          conditions: [
            { field: "tool.name", operator: "eq", value: "bash" },
            { field: "tool.name", operator: "eq", value: "sh" },
          ],
        },
        action: "block",
      },
      0,
    );
    expect(r.conditionLogic).toBe("OR");
    expect(r.conditions.length).toBe(2);
  });

  it("respects a custom category", () => {
    const r = simplifyRule(
      { name: "x", when: { conditions: [] }, action: "block", category: "compliance" },
      0,
    );
    expect(r.category).toBe("compliance");
  });

  it("auto-numbers priority by rule order", () => {
    const rules = simplifyRules([
      { name: "a", when: { conditions: [] }, action: "block" },
      { name: "b", when: { conditions: [] }, action: "block" },
      { name: "c", when: { conditions: [] }, action: "block" },
    ]);
    expect(rules.map((r) => r.priority)).toEqual([10, 20, 30]);
  });
});
