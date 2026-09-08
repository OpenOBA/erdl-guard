import { describe, it, expect } from "vitest";
import { tool } from "ai";
import { wrapVercelAITools, GuardBlockedError } from "../src/index.js";
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

const bashTool = tool({
  description: "Run a shell command",
  parameters: {
    type: "object",
    properties: { command: { type: "string" } },
    required: ["command"],
  },
  execute: async ({ command }) => `executed: ${command}`,
});

const { rules } = parseErdlDocument(yaml);
const wrapped = wrapVercelAITools({ bash: bashTool }, rules);

describe("wrapVercelAITools()", () => {
  it("blocks a DENY tool call (real Vercel AI SDK tool)", async () => {
    await expect(
      wrapped.bash.execute({ command: "rm -rf /" } as never),
    ).rejects.toBeInstanceOf(GuardBlockedError);
  });

  it("allows a non-matching tool call", async () => {
    await expect(
      wrapped.bash.execute({ command: "echo hi" } as never),
    ).resolves.toBe("executed: echo hi");
  });

  it("preserves description and parameters", () => {
    expect(wrapped.bash.description).toBe("Run a shell command");
    expect(wrapped.bash.parameters).toBeDefined();
  });
});
