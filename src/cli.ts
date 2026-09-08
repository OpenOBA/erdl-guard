#!/usr/bin/env node
import { loadErdlFile } from "@openoba/rulsynor-core";
import type { DecisionObject } from "@openoba/rulsynor-core";
import { existsSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createMcpGuard, buildReceipt, startMcpProxy, verifyReceipt } from "./index.js";
import { buildBlockRule, dumpRuleYaml } from "./rule-gen.js";

const DEFAULT_RULES = `protocol: "erdl/v2"
version: "2.1.0"
metadata:
  name: "erdl-guard"
  description: "Default ERDL Guard rules"
  category: security
rules:
  - name: "SEC-001-block-rm-rf"
    description: "Block destructive rm -rf in bash"
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
    message: "Destructive command blocked"
`;

function usage(): void {
  console.log(`erdl-guard — deterministic authorization for AI agent tool calls

Usage:
  erdl-guard init                           create ./erdl/rules.yaml with default rules
  erdl-guard rule generate <tool> <prompt>  generate a block rule for a tool + keyword
  erdl-guard run <tool> <args-json>         evaluate a tool call against ./erdl/rules.yaml
  erdl-guard serve <upstream> <port>        start the MCP proxy (default http://localhost:9001, 3001)
  erdl-guard receipts verify <file>          verify a receipt's hash chain offline (use - for stdin)
`);
}

function cmdInit(): void {
  if (!existsSync("erdl")) mkdirSync("erdl", { recursive: true });
  const target = join("erdl", "rules.yaml");
  if (existsSync(target)) {
    console.log(`${target} already exists — not overwriting.`);
    return;
  }
  writeFileSync(target, DEFAULT_RULES, "utf-8");
  console.log(`Created ${target}`);
}

function cmdRuleGenerate(tool: string, prompt: string): void {
  const keyword = prompt.trim().replace(/^(block|阻止|阻断)\s+/i, "");
  const rule = buildBlockRule(tool, keyword);
  console.log(dumpRuleYaml(rule));
  console.log("# append the above to ./erdl/rules.yaml");
}

function cmdRun(tool: string, argsJson: string): void {
  const rulesFile = join("erdl", "rules.yaml");
  if (!existsSync(rulesFile)) {
    console.error(`No ${rulesFile} — run 'erdl-guard init' first.`);
    process.exit(1);
  }
  let args: Record<string, unknown>;
  try {
    args = JSON.parse(argsJson || "{}");
  } catch {
    console.error(`Invalid args JSON: ${argsJson}`);
    process.exit(1);
  }
  const doc = loadErdlFile(rulesFile);
  const guard = createMcpGuard(doc.rules);
  const started = performance.now();
  const result = guard.evaluate(tool, args);
  const receipt = buildReceipt({
    toolName: tool,
    toolArgs: args,
    rules: doc.rules,
    result,
    actionTaken: result.decision === "ALLOW" ? "allowed" : "blocked",
    evaluationDurationMs: Math.round(performance.now() - started),
  });
  console.log(JSON.stringify(receipt, null, 2));
}

function cmdServe(upstream: string, port: number): void {
  const rulesFile = join("erdl", "rules.yaml");
  if (!existsSync(rulesFile)) {
    console.error(`No ${rulesFile} — run 'erdl-guard init' first.`);
    process.exit(1);
  }
  const doc = loadErdlFile(rulesFile);
  try {
    startMcpProxy({ rules: doc.rules, upstream, port });
  } catch (e) {
    console.error((e as Error).message);
    process.exit(1);
  }
  console.log(`erdl-guard MCP proxy listening on http://localhost:${port} → ${upstream}`);
}

function cmdReceiptsVerify(file: string): void {
  let doObject: unknown;
  try {
    doObject = JSON.parse(readFileSync(file === "-" ? 0 : file, "utf-8"));
  } catch {
    console.error(`Cannot read/parse Decision Object from ${file === "-" ? "stdin" : file}`);
    process.exit(1);
  }
  const result = verifyReceipt(doObject as DecisionObject);
  console.log(result.valid ? "✓ valid" : "✗ INVALID");
  if (!result.valid) {
    console.log(`  claimed: sha256:${result.expected}`);
    console.log(`  actual:  sha256:${result.actual}`);
    process.exit(1);
  }
}

const [, , cmd, ...rest] = process.argv;
switch (cmd) {
  case "init":
    cmdInit();
    break;
  case "rule":
    cmdRuleGenerate(rest[0] ?? "", rest.slice(1).join(" "));
    break;
  case "run":
    cmdRun(rest[0] ?? "", rest[1] ?? "{}");
    break;
  case "serve":
    cmdServe(rest[0] ?? "http://localhost:9001", Number(rest[1] ?? 3001));
    break;
  case "receipts":
    cmdReceiptsVerify(rest[1] ?? "-");
    break;
  default:
    usage();
    process.exit(cmd ? 1 : 0);
}
