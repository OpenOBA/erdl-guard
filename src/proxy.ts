import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { BLOCKING_DECISIONS } from "@openoba/rulsynor-core";
import type { RuleDefinition } from "@openoba/rulsynor-core";
import { createMcpGuard, GuardBlockedError } from "./index.js";

/**
 * MCP proxy (network form) per MCP spec 2026-07-28:
 *  - Streamable HTTP, stateless (no session, no initialize handshake).
 *  - Every request carries `MCP-Protocol-Version` header matching the body's
 *    `_meta.io.modelcontextprotocol/protocolVersion`.
 *  - `Mcp-Method` / `Mcp-Name` headers are required (mirrored from the JSON-RPC body).
 *
 * The proxy guards `tools/call` against ERDL rules, then forwards to the upstream
 * MCP server. Every other method is forwarded unchanged.
 */
export interface McpProxyOptions {
  rules: RuleDefinition[];
  /** Upstream MCP server base URL (e.g. http://localhost:9001). */
  upstream: string;
  port: number;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function jsonError(id: unknown, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
}

function header(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/** RFC 1918 private + loopback + link-local + CGNAT + metadata IPv4 prefixes. */
const BLOCKED_IPV4_PREFIXES = [
  '0.',
  '10.',
  '100.64.',
  '127.',
  '169.254.',
  '172.16.',
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
  '172.22.',
  '172.23.',
  '172.24.',
  '172.25.',
  '172.26.',
  '172.27.',
  '172.28.',
  '172.29.',
  '172.30.',
  '172.31.',
  '192.168.',
];

/** Loopback + cloud metadata hostnames. */
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'instance-data',
  'metadata.azure.internal',
]);

/**
 * Validate the upstream base URL. Always fails fast on a non-http(s) URL.
 * The private/loopback/metadata block (SSRF defense-in-depth) is OPT-IN via
 * `ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM=1` — the common case is a local MCP server,
 * so localhost must stay reachable by default.
 */
function validateUpstream(upstream: string): URL {
  let url: URL;
  try {
    url = new URL(upstream);
  } catch {
    throw new Error(`Invalid upstream URL: ${upstream}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Upstream protocol must be http(s), got "${url.protocol}"`);
  }
  if (process.env['ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM'] !== '1') return url;
  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host) || host === '::1') {
    throw new Error(
      `Upstream host "${host}" is blocked (SSRF guard); unset ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM to allow`,
    );
  }
  if (BLOCKED_IPV4_PREFIXES.some((p) => host.startsWith(p))) {
    throw new Error(
      `Upstream host "${host}" is a private/loopback address (SSRF guard); unset ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM to allow`,
    );
  }
  return url;
}

function forward(upstream: string, body: string, headers: Record<string, string>): Promise<string> {
  const url = new URL(upstream.endsWith("/") ? upstream + "mcp" : upstream + "/mcp");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
    signal: controller.signal,
  })
    .then((r) => {
      if (!r.ok) throw new Error(`Upstream responded ${r.status}`);
      return r.text();
    })
    .finally(() => clearTimeout(timeout));
}

export function startMcpProxy(options: McpProxyOptions) {
  // Fail fast at startup on an invalid/blocked upstream (don't start a proxy that can't forward).
  validateUpstream(options.upstream);
  const guard = createMcpGuard(options.rules);

  const server = createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");

    if (req.method !== "POST" || !req.url?.includes("/mcp")) {
      res.statusCode = 404;
      res.end(jsonError(null, -32601, "Method not found"));
      return;
    }

    // 2026-07-28: protocol version MUST be present as a header.
    const protocolVersion = header(req.headers["mcp-protocol-version"]);
    if (!protocolVersion) {
      res.statusCode = 400;
      res.end(jsonError(null, -32600, "Missing MCP-Protocol-Version header"));
      return;
    }

    let body: string;
    try {
      body = await readBody(req);
    } catch {
      res.statusCode = 400;
      res.end(jsonError(null, -32700, "Parse error"));
      return;
    }

    let json: {
      id?: unknown;
      method?: string;
      params?: Record<string, unknown>;
      _meta?: Record<string, unknown>;
    };
    try {
      json = JSON.parse(body);
    } catch {
      res.statusCode = 400;
      res.end(jsonError(null, -32700, "Parse error"));
      return;
    }

    // 2026-07-28: the header MUST match _meta.io.modelcontextprotocol/protocolVersion.
    const metaProtocolVersion = json._meta?.["io.modelcontextprotocol/protocolVersion"];
    if (typeof metaProtocolVersion === "string" && metaProtocolVersion !== protocolVersion) {
      res.statusCode = 400;
      res.end(
        jsonError(
          json.id,
          -32600,
          "HeaderMismatch: MCP-Protocol-Version does not match _meta.io.modelcontextprotocol/protocolVersion",
        ),
      );
      return;
    }

    const method = (json.method as string | undefined) ?? header(req.headers["mcp-method"]) ?? "";
    const toolName =
      (json.params?.name as string | undefined) ?? header(req.headers["mcp-name"]);

    // Guard tools/call before forwarding.
    if (method === "tools/call" && toolName) {
      const args = (json.params?.arguments as Record<string, unknown>) ?? {};
      try {
        await guard.guard(toolName, args, async () => {});
      } catch (e) {
        if (e instanceof GuardBlockedError) {
          res.statusCode = 403;
          res.end(jsonError(json.id, -32000, e.message));
          return;
        }
        // Non-blocking guard failure (e.g. a bad rule) — don't crash the handler.
        res.statusCode = 500;
        res.end(jsonError(json.id, -32603, "Guard evaluation failed"));
        return;
      }
    }

    // Forward to upstream.
    try {
      const upstreamBody = await forward(options.upstream, body, {
        "mcp-protocol-version": protocolVersion as string,
        "mcp-method": method,
        ...(toolName ? { "mcp-name": toolName } : {}),
      });
      res.statusCode = 200;
      res.end(upstreamBody);
    } catch {
      res.statusCode = 502;
      res.end(jsonError(json.id, -32000, "Upstream MCP server unreachable"));
    }
  });

  server.on("error", (err) => {
    console.error(`erdl-guard MCP proxy failed to listen on ${options.port}: ${(err as Error).message}`);
  });
  server.listen(options.port);
  return server;
}

export { BLOCKING_DECISIONS, validateUpstream };
