// Quickstart: guard an agent's tool calls with ERDL Guard in a few lines.
import { loadRules, protect, GuardBlockedError } from "../dist/index.js";

// 1. Write rules — lightweight verbs (block/allow/ask/escalate).
const rules = loadRules(`
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
`);

// 2. Your tool.
const bashTool = {
  name: "bash",
  description: "Run a shell command",
  async call(args) {
    return `executed: ${args.command}`;
  },
};

// 3. Wrap it with the guard.
const [guardedBash] = protect([bashTool], rules);

// 4. Use it — dangerous calls are blocked, safe calls pass.
try {
  await guardedBash.call({ command: "rm -rf /" });
} catch (e) {
  if (e instanceof GuardBlockedError) {
    console.log("✓ blocked:", e.message, "| decision:", e.decision);
  }
}

console.log("✓ allowed:", await guardedBash.call({ command: "echo hello" }));
