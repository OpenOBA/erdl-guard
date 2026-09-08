import { buildDecisionObject, ruleWhenToExpr, toSExpr } from "@openoba/rulsynor-core";
import type {
  RuleDefinition,
  EvaluationResult,
  DecisionObject,
  DecisionObjectInput,
  GuardRuleDefinition,
} from "@openoba/rulsynor-core";

export interface ReceiptOptions {
  toolName: string;
  toolArgs: Record<string, unknown>;
  rules: RuleDefinition[];
  result: EvaluationResult;
  actionTaken: string;
  agentId?: string;
  sessionId?: string;
  runId?: string;
  step?: number;
  previousAuditHash?: string | null;
  evaluationDurationMs?: number;
}

/**
 * Re-shape an engine `RuleDefinition` (flat `conditions` + `action`) into the guard
 * rule shape `buildDecisionObject` expects (`when`/`then`/`ring`). The `when` is the
 * canonical S-expression of the rule's condition (the same tree the evaluator emits as
 * `matched_rules[].canonical_tree`), so the DO's `policies[]` carries the rule's actual
 * condition, decision, and ring — not a defaulted placeholder.
 */
function toGuardRule(r: RuleDefinition): GuardRuleDefinition {
  const whenTree = ruleWhenToExpr(r);
  return {
    id: r.id,
    name: r.name,
    priority: r.priority,
    ring: r.action.ring,
    when: whenTree ? toSExpr(whenTree) : undefined,
    then: r.action.decision,
  };
}

/**
 * Build a full Decision Object (RFC-002 v1.5 flat-hash) from a guard evaluation.
 * This is the tamper-evident audit record — `audit.hash` is JCS-canonicalized + SHA-256,
 * chainable via `previousAuditHash`.
 */
export function buildReceipt(opts: ReceiptOptions): DecisionObject {
  const input: DecisionObjectInput = {
    input: {
      runId: opts.runId ?? "erdl-guard",
      step: opts.step ?? 0,
      toolName: opts.toolName,
      toolArgs: opts.toolArgs,
      context: { tool: { name: opts.toolName, args: opts.toolArgs } },
      agentId: opts.agentId ?? "erdl-guard",
      sessionId: opts.sessionId ?? "erdl-guard",
      previousAuditHash: opts.previousAuditHash ?? null,
    },
    decision: opts.result.decision,
    actionTaken: opts.actionTaken,
    reason: opts.result.primaryReason ?? null,
    matchedRules: opts.result.matchedRules,
    totalEvaluated: opts.result.totalEvaluated,
    totalMatched: opts.result.totalMatched,
    rules: opts.rules.map(toGuardRule),
    evaluationDurationMs: opts.evaluationDurationMs ?? 0,
  };
  return buildDecisionObject(input);
}
