import { parseErdlDocument } from "@openoba/rulsynor-core";
import type { RuleDefinition } from "@openoba/rulsynor-core";
import * as yaml from "js-yaml";
import { simplifyRules } from "./actions.js";
import type { LightweightRule } from "./actions.js";

interface RawRuleDoc {
  rules?: Array<Record<string, unknown>>;
}

/**
 * Load rules from a YAML document, auto-detecting the format:
 * - rules with `action` (a simple verb) → lightweight format, translated via `simplifyRules`
 * - rules with `then` (a decision type) → full ERDL format, parsed via `parseErdlDocument`
 *
 * One entry point for both formats — lightweight users write `action: block`, advanced
 * users write `then: DENY`, and `loadRules` handles both.
 */
export function loadRules(yamlText: string): RuleDefinition[] {
  const doc = yaml.load(yamlText) as RawRuleDoc | null;
  if (!doc || !Array.isArray(doc.rules) || doc.rules.length === 0) {
    return [];
  }
  const isLightweight = doc.rules.some((r) => typeof r.action === "string");
  if (isLightweight) {
    return simplifyRules(doc.rules as unknown as LightweightRule[]);
  }
  return parseErdlDocument(yamlText).rules;
}

export { yaml };
