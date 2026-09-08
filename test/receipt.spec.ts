import { describe, it, expect } from "vitest";
import { buildReceipt, createMcpGuard } from "../src/index.js";
import { parseErdlDocument } from "@openoba/rulsynor-core";

const yaml = `
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
    then: DENY
    message: "blocked"
`;

describe("buildReceipt()", () => {
  it("builds a full Decision Object (RFC-002 v1.5) with audit.hash", () => {
    const { rules } = parseErdlDocument(yaml);
    const guard = createMcpGuard(rules);
    const result = guard.evaluate("bash", { command: "rm -rf /" });

    const receipt = buildReceipt({
      toolName: "bash",
      toolArgs: { command: "rm -rf /" },
      rules,
      result,
      actionTaken: "blocked",
    });

    expect(receipt.spec).toBe("decision-object-v1.5");
    expect(receipt.audit.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.audit.preimage_version).toBe("erdl-do-v1.5-hash-flat");
    expect(receipt.result.decision).toBe("DENY");
    expect(receipt.evaluation.total_matched).toBeGreaterThanOrEqual(1);
  });

  it("chains via previousAuditHash", () => {
    const { rules } = parseErdlDocument(yaml);
    const guard = createMcpGuard(rules);
    const result = guard.evaluate("bash", { command: "rm -rf /" });

    const first = buildReceipt({
      toolName: "bash",
      toolArgs: { command: "rm -rf /" },
      rules,
      result,
      actionTaken: "blocked",
    });
    const second = buildReceipt({
      toolName: "bash",
      toolArgs: { command: "rm -rf /" },
      rules,
      result,
      actionTaken: "blocked",
      previousAuditHash: first.audit.hash,
    });

    expect(second.audit.previous_hash).toBe(first.audit.hash);
    expect(second.audit.hash).not.toBe(first.audit.hash);
  });

  it("anchors the DO policy to the rule's actual ring / then / when (no defaulted placeholder)", () => {
    const { rules } = parseErdlDocument(yaml);
    const guard = createMcpGuard(rules);
    const result = guard.evaluate("bash", { command: "rm -rf /" });

    const receipt = buildReceipt({
      toolName: "bash",
      toolArgs: { command: "rm -rf /" },
      rules,
      result,
      actionTaken: "blocked",
    });

    const policy = receipt.policies[0] as Record<string, unknown>;
    // ring must reflect the rule's declared Ring 0, not the Ring-3 fallback.
    expect(policy.ring).toBe(0);
    // then must reflect the rule's decision.
    expect(policy.then).toBe("DENY");
    // when must be the canonical S-expression of the rule's condition.
    expect(policy.when).toEqual({
      and: [
        { eq: [{ field: "tool.name" }, "bash"] },
        { contains: [{ field: "tool.args.command" }, "rm -rf"] },
      ],
    });
  });
});
