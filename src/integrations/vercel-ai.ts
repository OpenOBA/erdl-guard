import { createMcpGuard } from "../mcp.js";
import type { RuleDefinition } from "@openoba/rulsynor-core";

/** Minimal structural shape of a Vercel AI SDK tool (the `tool()` result). */
export interface VercelAIToolLike {
  description?: string;
  parameters?: unknown;
  execute: (args: Record<string, unknown>, options?: unknown) => unknown;
}

/**
 * Wrap a map of Vercel AI SDK tools with ERDL authorization. Each tool's `execute`
 * evaluates the rules against `{ tool: { name, args } }` before delegating to the
 * original `execute`; blocking decisions throw `GuardBlockedError`.
 *
 * This is a thin adapter over `createMcpGuard` — the deterministic engine and Decision
 * Object audit remain in `@openoba/rulsynor-core`.
 */
export function wrapVercelAITools<T extends Record<string, VercelAIToolLike>>(
  tools: T,
  rules: RuleDefinition[],
): T {
  const guard = createMcpGuard(rules);
  const wrapped = {} as Record<string, VercelAIToolLike>;
  for (const [name, tool] of Object.entries(tools)) {
    const originalExecute = tool.execute;
    wrapped[name] = {
      ...tool,
      execute: async (args: Record<string, unknown>, options?: unknown) => {
        await guard.guard(name, args ?? {}, async () => {});
        return originalExecute(args, options);
      },
    };
  }
  return wrapped as T;
}
