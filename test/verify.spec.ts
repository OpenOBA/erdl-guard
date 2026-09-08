import { describe, it, expect } from "vitest";
import { buildReceipt, createMcpGuard, verifyReceipt } from "../src/index.js";
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

function makeReceipt() {
  const { rules } = parseErdlDocument(yaml);
  const guard = createMcpGuard(rules);
  const result = guard.evaluate("bash", { command: "rm -rf /" });
  return buildReceipt({
    toolName: "bash",
    toolArgs: { command: "rm -rf /" },
    rules,
    result,
    actionTaken: "blocked",
  });
}

describe("verifyReceipt()", () => {
  it("verifies an untampered receipt", () => {
    const receipt = makeReceipt();
    expect(verifyReceipt(receipt).valid).toBe(true);
  });

  it("detects a tampered decision", () => {
    const receipt = makeReceipt();
    receipt.result.decision = "ALLOW";
    expect(verifyReceipt(receipt).valid).toBe(false);
  });

  it("detects a tampered reason", () => {
    const receipt = makeReceipt();
    receipt.result.reason = "forged";
    expect(verifyReceipt(receipt).valid).toBe(false);
  });

  it("detects a tampered audit.hash", () => {
    const receipt = makeReceipt();
    receipt.audit.hash = "sha256:" + "0".repeat(64);
    expect(verifyReceipt(receipt).valid).toBe(false);
  });
});
