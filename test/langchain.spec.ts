import { describe, it, expect } from "vitest";
import { tool } from "@langchain/core/tools";
import { wrapLangChainTools, GuardBlockedError } from "../src/index.js";
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

const bashTool = tool(
  async ({ command }: { command: string }) => `executed: ${command}`,
  {
    name: "bash",
    description: "Run a shell command",
    schema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
  },
);

const { rules } = parseErdlDocument(yaml);
const wrapped = wrapLangChainTools({ bash: bashTool }, rules);

describe("wrapLangChainTools()", () => {
  it("blocks a DENY tool call (real LangChain tool)", async () => {
    await expect(wrapped.bash.invoke({ command: "rm -rf /" })).rejects.toBeInstanceOf(
      GuardBlockedError,
    );
  });

  it("allows a non-matching tool call", async () => {
    await expect(wrapped.bash.invoke({ command: "echo hi" })).resolves.toBe("executed: echo hi");
  });

  it("preserves name and description", () => {
    expect(wrapped.bash.name).toBe("bash");
    expect(wrapped.bash.description).toBe("Run a shell command");
  });
});
