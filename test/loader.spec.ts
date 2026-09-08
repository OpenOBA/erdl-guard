import { describe, it, expect } from "vitest";
import { loadRules, createMcpGuard } from "../src/index.js";

const lightweightYaml = `
rules:
  - name: "SEC-001-block-rm-rf"
    when:
      logic: AND
      conditions:
        - field: "tool.name"
          operator: eq
          value: "bash"
        - field: "tool.args.command"
          operator: contains
          value: "rm -rf"
    action: block
`;

const fullYaml = `
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

describe("loadRules()", () => {
  it("loads lightweight rules (action verbs) and translates them", () => {
    const rules = loadRules(lightweightYaml);
    expect(rules).toHaveLength(1);
    expect(rules[0].action.decision).toBe("DENY");
    expect(rules[0].action.ring).toBe(0);
  });

  it("loads full ERDL rules (then decisions) as-is", () => {
    const rules = loadRules(fullYaml);
    expect(rules).toHaveLength(1);
    expect(rules[0].action.decision).toBe("DENY");
  });

  it("returns [] for empty input", () => {
    expect(loadRules("")).toEqual([]);
    expect(loadRules("rules: []")).toEqual([]);
  });

  it("loadRules + createMcpGuard end-to-end", () => {
    const guard = createMcpGuard(loadRules(lightweightYaml));
    expect(guard.evaluate("bash", { command: "rm -rf /" }).decision).toBe("DENY");
    expect(guard.evaluate("bash", { command: "echo hi" }).decision).toBe("ALLOW");
  });
});
