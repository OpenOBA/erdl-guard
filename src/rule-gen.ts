import * as yaml from "js-yaml";

/**
 * Pure rule-generation helpers for the CLI — no I/O, no top-level side effects,
 * so they are directly testable (cli.ts runs its command switch at import time
 * and must not be imported by tests).
 */

/**
 * Build a block rule for `erdl-guard rule generate`. Values are serialized with
 * `dumpRuleYaml` (js-yaml) so keywords containing quotes/colons/newlines cannot
 * break out of the YAML (no hand-rolled template literal).
 */
export function buildBlockRule(tool: string, keyword: string): Record<string, unknown> {
  return {
    name: `SEC-002-block-${tool}`,
    description: `Block ${keyword} in ${tool}`,
    category: "security",
    priority: 20,
    ring: 0,
    when: {
      logic: "AND",
      conditions: [
        { field: "tool.name", operator: "eq", value: tool },
        { field: "tool.args.command", operator: "contains", value: keyword },
      ],
    },
    then: "DENY",
    message: `${keyword} blocked`,
  };
}

/** Serialize a single rule as a YAML list item (for appending to `./erdl/rules.yaml`). */
export function dumpRuleYaml(rule: Record<string, unknown>): string {
  return yaml.dump([rule], { indent: 2 }).trim();
}
