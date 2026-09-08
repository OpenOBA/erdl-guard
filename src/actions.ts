import type { RuleDefinition, RuleCondition, Decision, RingLevel } from "@openoba/rulsynor-core";

/**
 * Simple action vocabulary for lightweight users. Each verb maps to a deterministic
 * guard decision + ring, anchored to `GUARD_ALLOWED_DECISIONS` (the Ring 0–3 subset).
 *
 * This is a facade — the verbs are NOT a second decision enum; they translate to the
 * authoritative `DO_DECISIONS` values and the engine runs unchanged.
 */
export const SIMPLE_ACTIONS = {
  block: { decision: "DENY", ring: 0 },
  allow: { decision: "ALLOW", ring: 3 },
  ask: { decision: "REQUEST_HUMAN", ring: 2 },
  escalate: { decision: "ESCALATE", ring: 2 },
} as const satisfies Record<string, { decision: Decision; ring: RingLevel }>;

export type SimpleAction = keyof typeof SIMPLE_ACTIONS;

/**
 * Derive a machine-friendly rule id from its name — mirrors `deriveId` in
 * `@openoba/rulsynor-core` (`erdl-loader.ts`), so lightweight rules get the
 * same normalized id (`SEC-001-block-rm-rf` → `sec_001_block_rm_rf`) as full
 * `then` rules parsed by `parseErdlDocument`.
 */
function deriveId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/** A lightweight rule: `name` + `when` + a simple `action` verb (no decision/ring burden). */
export interface LightweightRule {
  name: string;
  description?: string;
  when: {
    logic?: "AND" | "OR";
    conditions: RuleCondition[];
  };
  action: SimpleAction;
  category?: RuleDefinition["category"];
}

/**
 * Translate a lightweight rule into a full RuleDefinition: map the `action` verb to a
 * decision + ring, and auto-fill category (default `security`), priority (by order), and
 * `enabled: true`. The `when` block is passed through unchanged.
 */
export function simplifyRule(rule: LightweightRule, index: number): RuleDefinition {
  const { decision, ring } = SIMPLE_ACTIONS[rule.action];
  return {
    id: deriveId(rule.name),
    name: rule.name,
    description: rule.description ?? `${rule.action}: ${rule.name}`,
    category: rule.category ?? "security",
    conditions: rule.when.conditions,
    conditionLogic: rule.when.logic ?? "AND",
    action: { decision, reason: rule.description ?? `${rule.action}: ${rule.name}`, ring },
    priority: (index + 1) * 10,
    enabled: true,
  };
}

export function simplifyRules(rules: LightweightRule[]): RuleDefinition[] {
  return rules.map((rule, index) => simplifyRule(rule, index));
}
