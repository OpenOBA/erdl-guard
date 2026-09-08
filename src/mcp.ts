import { Evaluator, BLOCKING_DECISIONS } from "@openoba/rulsynor-core";
import type { RuleDefinition, EvaluationResult } from "@openoba/rulsynor-core";
import { GuardBlockedError } from "./index.js";

/**
 * An in-process MCP `tools/call` guard. Evaluate ERDL rules against
 * `{ tool: { name, args } }` before the call is forwarded to the MCP server.
 *
 * The network form (a standalone MCP proxy endpoint per MCP spec 2026-07-28,
 * stateless, `_meta` protocolVersion) builds on this evaluate/guard primitive.
 */
export interface McpGuard {
  /** Evaluate rules against a tool call, returning the raw result. */
  evaluate(toolName: string, args: Record<string, unknown>): EvaluationResult;
  /** Guard a tool call; throws GuardBlockedError on a blocking decision. */
  guard<T>(toolName: string, args: Record<string, unknown>, handler: () => Promise<T>): Promise<T>;
}

export function createMcpGuard(rules: RuleDefinition[]): McpGuard {
  const evaluator = new Evaluator();
  const evaluate = (toolName: string, args: Record<string, unknown>): EvaluationResult =>
    evaluator.evaluate(rules, { tool: { name: toolName, args } });

  return {
    evaluate,
    async guard<T>(
      toolName: string,
      args: Record<string, unknown>,
      handler: () => Promise<T>,
    ): Promise<T> {
      const result = evaluate(toolName, args);
      if ((BLOCKING_DECISIONS as readonly string[]).includes(result.decision)) {
        throw new GuardBlockedError(result);
      }
      return handler();
    },
  };
}
