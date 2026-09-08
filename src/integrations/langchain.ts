import { createMcpGuard } from "../mcp.js";
import type { RuleDefinition } from "@openoba/rulsynor-core";

/** Minimal structural shape of a LangChain tool (the `tool()` result from @langchain/core/tools). */
export interface LangChainToolLike {
  name: string;
  description?: string;
  schema?: unknown;
  func: (input: unknown, config?: unknown) => unknown;
  [k: string]: unknown;
}

/**
 * Wrap a map of LangChain tools with ERDL authorization. Each tool's `func` (the raw
 * execution) evaluates the rules against `{ tool: { name, args } }` before delegating;
 * blocking decisions throw `GuardBlockedError`. Structured-tool inputs (objects) map to
 * `tool.args.*`; string inputs map to `tool.args.input`.
 */
export function wrapLangChainTools<T extends Record<string, LangChainToolLike>>(
  tools: T,
  rules: RuleDefinition[],
): T {
  const guard = createMcpGuard(rules);
  const wrapped = {} as Record<string, LangChainToolLike>;
  for (const [key, tool] of Object.entries(tools)) {
    const originalFunc = tool.func;
    const name = tool.name ?? key;
    const guardedFunc = async (input: unknown, config?: unknown) => {
      const args =
        input && typeof input === "object" ? (input as Record<string, unknown>) : { input };
      await guard.guard(name, args, async () => {});
      return originalFunc(input, config);
    };
    // Preserve the Runnable prototype (invoke/call are prototype methods, not own props).
    const wrappedTool = Object.create(Object.getPrototypeOf(tool)) as LangChainToolLike;
    Object.assign(wrappedTool, tool, { func: guardedFunc });
    wrapped[key] = wrappedTool;
  }
  return wrapped as T;
}
