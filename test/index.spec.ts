import { describe, it, expect } from "vitest";
import { protect, GuardBlockedError, createMcpGuard } from "../src/index.js";
import { parseErdlDocument, BLOCKING_DECISIONS } from "@openoba/rulsynor-core";
import type { RuleDefinition } from "@openoba/rulsynor-core";

function rule(overrides: Partial<RuleDefinition> = {}): RuleDefinition {
  return {
    id: "SEC-001-test",
    name: "SEC-001-test",
    description: "test rule",
    category: "security",
    conditions: [{ field: "tool.name", operator: "eq", value: "bash" }],
    conditionLogic: "AND",
    action: { decision: "DENY", reason: "blocked", ring: 0 },
    priority: 10,
    enabled: true,
    ...overrides,
  };
}

const bashTool = {
  name: "bash",
  description: "run shell",
  async call(args: Record<string, unknown>) {
    return `executed: ${args.command}`;
  },
};

const yaml = (then: string) => `
protocol: "erdl/v2"
version: "2.1.0"
metadata:
  name: "test"
  category: security
rules:
  - name: "SEC-001-block-rm-rf"
    description: "block rm -rf"
    category: security
    priority: 10
    ring: 0
    when:
      logic: AND
      conditions:
        - field: "tool.name"
          operator: eq
          value: "bash"
        - field: "tool.args.command"
          operator: contains
          value: "rm -rf"
    then: ${then}
    message: "blocked"
`;

describe("protect()", () => {
  it("blocks a DENY rule (YAML-loaded)", async () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const [guarded] = protect([bashTool], rules);
    await expect(guarded.call({ command: "rm -rf /" })).rejects.toBeInstanceOf(GuardBlockedError);
  });

  it("allows a non-matching call", async () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const [guarded] = protect([bashTool], rules);
    await expect(guarded.call({ command: "echo hi" })).resolves.toBe("executed: echo hi");
  });

  it("allows when there are no rules", async () => {
    const [guarded] = protect([bashTool], []);
    await expect(guarded.call({ command: "rm -rf /" })).resolves.toBe("executed: rm -rf /");
  });

  it("carries decision and reason on GuardBlockedError", async () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const [guarded] = protect([bashTool], rules);
    try {
      await guarded.call({ command: "rm -rf /" });
      expect.unreachable("should have blocked");
    } catch (e) {
      expect(e).toBeInstanceOf(GuardBlockedError);
      const err = e as GuardBlockedError;
      expect(err.decision).toBe("DENY");
      expect(err.message).toBe("blocked");
    }
  });
});

describe("blocking decisions", () => {
  for (const decision of BLOCKING_DECISIONS) {
    it(`${decision} blocks`, async () => {
      const [guarded] = protect(
        [bashTool],
        [rule({ action: { decision: decision as never, reason: "x", ring: 0 } })],
      );
      await expect(guarded.call({ command: "ls" })).rejects.toBeInstanceOf(GuardBlockedError);
    });
  }

  it("ALLOW does not block", async () => {
    const [guarded] = protect(
      [bashTool],
      [rule({ action: { decision: "ALLOW", reason: "x", ring: 3 } })],
    );
    await expect(guarded.call({ command: "ls" })).resolves.toBe("executed: ls");
  });
});

describe("unless exemption", () => {
  it("allows when unless matches", async () => {
    const { rules } = parseErdlDocument(`
protocol: "erdl/v2"
version: "2.1.0"
metadata:
  name: "test"
  category: security
rules:
  - name: "SEC-001-block-bash"
    description: "block bash except echo"
    category: security
    priority: 10
    ring: 0
    when:
      logic: AND
      conditions:
        - field: "tool.name"
          operator: eq
          value: "bash"
    then: DENY
    message: "blocked"
    unless:
      logic: AND
      conditions:
        - field: "tool.args.command"
          operator: starts_with
          value: "echo"
`);
    const [guarded] = protect([bashTool], rules);
    await expect(guarded.call({ command: "echo hi" })).resolves.toBe("executed: echo hi");
    await expect(guarded.call({ command: "rm -rf /" })).rejects.toBeInstanceOf(GuardBlockedError);
  });
});

describe("createMcpGuard()", () => {
  it("evaluates DENY for a blocked tool call", () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const guard = createMcpGuard(rules);
    expect(guard.evaluate("bash", { command: "rm -rf /" }).decision).toBe("DENY");
  });

  it("evaluates ALLOW for an allowed tool call", () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const guard = createMcpGuard(rules);
    expect(guard.evaluate("bash", { command: "echo hi" }).decision).toBe("ALLOW");
  });

  it("guard() throws on a blocking decision", async () => {
    const { rules } = parseErdlDocument(yaml("DENY"));
    const guard = createMcpGuard(rules);
    await expect(
      guard.guard("bash", { command: "rm -rf /" }, async () => "ran"),
    ).rejects.toBeInstanceOf(GuardBlockedError);
  });
});
