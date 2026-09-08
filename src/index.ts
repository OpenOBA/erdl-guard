import { Evaluator, BLOCKING_DECISIONS } from "@openoba/rulsynor-core";
import type { RuleDefinition, EvaluationResult, Decision } from "@openoba/rulsynor-core";

/**
 * Error thrown when the guard blocks a tool call. Carries the full EvaluationResult
 * so callers can surface the decision, matched rule, and reason to the user.
 */
export class GuardBlockedError extends Error {
  readonly decision: Decision;
  readonly result: EvaluationResult;

  constructor(result: EvaluationResult) {
    super(result.primaryReason ?? result.decision);
    this.name = "GuardBlockedError";
    this.decision = result.decision;
    this.result = result;
  }
}

/** A tool-callable object the guard can wrap. */
export interface ToolCall {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  call: (args: Record<string, unknown>, context?: Record<string, unknown>) => Promise<unknown>;
}

/**
 * Wrap tools with ERDL authorization. Each wrapped tool evaluates the given rules
 * against `{ tool: { name, args } }` before delegating to the original `call`.
 * Blocking decisions (DENY / CORRECT / REQUEST_HUMAN / EMERGENCY_HALT / ROLLBACK /
 * QUARANTINE) throw `GuardBlockedError`; everything else forwards.
 */
export function protect<T extends ToolCall>(tools: T[], rules: RuleDefinition[]): T[] {
  const evaluator = new Evaluator();
  return tools.map((tool) => {
    const guarded = {
      ...tool,
      async call(
        args: Record<string, unknown>,
        context: Record<string, unknown> = {},
      ): Promise<unknown> {
        const result = evaluator.evaluate(rules, {
          ...context,
          tool: { name: tool.name, args },
        });
        if ((BLOCKING_DECISIONS as readonly string[]).includes(result.decision)) {
          throw new GuardBlockedError(result);
        }
        return tool.call(args, context);
      },
    };
    return guarded as T;
  });
}

export { Evaluator, BLOCKING_DECISIONS, DO_DECISIONS, GUARD_ALLOWED_DECISIONS } from "@openoba/rulsynor-core";
export type { RuleDefinition, EvaluationResult, RuleCondition, Decision } from "@openoba/rulsynor-core";

export { createMcpGuard } from "./mcp.js";
export type { McpGuard } from "./mcp.js";

export { startMcpProxy } from "./proxy.js";
export type { McpProxyOptions } from "./proxy.js";

export { buildReceipt } from "./receipt.js";
export type { ReceiptOptions } from "./receipt.js";

export { verifyReceipt } from "./verify.js";
export type { VerifyResult } from "./verify.js";

export { wrapVercelAITools } from "./integrations/vercel-ai.js";
export type { VercelAIToolLike } from "./integrations/vercel-ai.js";

export { wrapLangChainTools } from "./integrations/langchain.js";
export type { LangChainToolLike } from "./integrations/langchain.js";

export { SIMPLE_ACTIONS, simplifyRule, simplifyRules } from "./actions.js";
export type { SimpleAction, LightweightRule } from "./actions.js";

export { loadRules } from "./loader.js";
