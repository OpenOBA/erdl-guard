import { readFileSync } from "node:fs";
import { parseErdlDocument } from "@openoba/rulsynor-core";
import { protect, GuardBlockedError } from "../dist/index.js";

const yamlText = readFileSync(new URL("./rules.yaml", import.meta.url), "utf-8");
const { rules } = parseErdlDocument(yamlText);

const bashTool = {
  name: "bash",
  description: "Run a shell command",
  async call(args) {
    return `executed: ${args.command}`;
  },
};

const [guardedBash] = protect([bashTool], rules);

// Case 1 — blocked
try {
  await guardedBash.call({ command: "rm -rf /" });
  console.log("❌ UNEXPECTED: rm -rf was not blocked");
} catch (e) {
  if (e instanceof GuardBlockedError) {
    console.log("✅ blocked:", JSON.stringify(e.message), "| decision:", e.decision);
  } else {
    throw e;
  }
}

// Case 2 — allowed
const result = await guardedBash.call({ command: "echo hello" });
console.log("✅ allowed:", result);
