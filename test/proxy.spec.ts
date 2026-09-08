import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { startMcpProxy } from "../src/index.js";
import { validateUpstream } from "../src/proxy.js";
import { parseErdlDocument } from "@openoba/rulsynor-core";

const yaml = `
protocol: "erdl/v2"
version: "2.1.0"
metadata:
  name: "test"
  category: security
rules:
  - name: "SEC-001-block-rm-rf"
    description: "block rm -rf"
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
    message: "blocked"
`;

let upstream: Server;
let proxy: Server;
let upstreamPort: number;
let proxyPort: number;

beforeAll(async () => {
  // Mock upstream MCP server: echoes the method + tool name.
  upstream = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const json = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: json.id,
          result: { content: [{ type: "text", text: `upstream:${json.method}:${json.params?.name}` }] },
        }),
      );
    });
  });
  await new Promise<void>((r) => upstream.listen(0, () => r()));
  upstreamPort = (upstream.address() as { port: number }).port;

  const { rules } = parseErdlDocument(yaml);
  proxy = startMcpProxy({ rules, upstream: `http://localhost:${upstreamPort}`, port: 0 });
  await new Promise<void>((r) => proxy.once("listening", () => r()));
  proxyPort = (proxy.address() as { port: number }).port;
});

afterAll(async () => {
  await new Promise((r) => proxy.close(() => r()));
  await new Promise((r) => upstream.close(() => r()));
});

function call(body: Record<string, unknown>, headers: Record<string, string> = {}) {
  return fetch(`http://localhost:${proxyPort}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("startMcpProxy()", () => {
  it("blocks a tools/call that matches a DENY rule", async () => {
    const res = await call(
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "bash", arguments: { command: "rm -rf /" } } },
      { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "bash" },
    );
    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error).toBeTruthy();
  });

  it("forwards an allowed tools/call to the upstream", async () => {
    const res = await call(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "bash", arguments: { command: "echo hi" } } },
      { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "bash" },
    );
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.result.content[0].text).toBe("upstream:tools/call:bash");
  });

  it("rejects a request missing the protocol version header", async () => {
    const res = await call({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} });
    expect(res.status).toBe(400);
  });

  it("rejects a request where _meta protocolVersion mismatches the header", async () => {
    const res = await call(
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/list",
        params: {},
        _meta: { "io.modelcontextprotocol/protocolVersion": "2025-11-25" },
      },
      { "mcp-protocol-version": "2026-07-28" },
    );
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error.message).toContain("HeaderMismatch");
  });
});

describe("validateUpstream() (P2-3 SSRF guard)", () => {
  it("accepts http(s) URLs", () => {
    expect(validateUpstream("http://example.com").hostname).toBe("example.com");
    expect(validateUpstream("https://example.com:8443").hostname).toBe("example.com");
  });

  it("rejects non-http(s) protocols", () => {
    expect(() => validateUpstream("ftp://example.com")).toThrow(/http\(s\)/);
    expect(() => validateUpstream("file:///etc/passwd")).toThrow(/http\(s\)/);
  });

  it("rejects invalid URLs", () => {
    expect(() => validateUpstream("not a url")).toThrow(/Invalid upstream/);
  });

  it("blocks private/metadata hosts only when opt-in is enabled", () => {
    // By default (opt-in off), localhost is reachable (the common local-MCP case).
    expect(validateUpstream("http://localhost:9001").hostname).toBe("localhost");
    expect(validateUpstream("http://192.168.1.10").hostname).toBe("192.168.1.10");

    process.env.ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM = "1";
    try {
      expect(() => validateUpstream("http://169.254.169.254/latest/meta-data")).toThrow(
        /SSRF guard/,
      );
      expect(() => validateUpstream("http://10.0.0.1")).toThrow(/SSRF guard/);
      expect(() => validateUpstream("http://metadata.google.internal")).toThrow(/SSRF guard/);
      // public hosts still pass
      expect(validateUpstream("http://example.com").hostname).toBe("example.com");
    } finally {
      delete process.env.ERDL_GUARD_BLOCK_PRIVATE_UPSTREAM;
    }
  });
});
