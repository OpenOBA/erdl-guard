# ERDL Guard

> **Deterministic authorization for AI agent tool calls** — write ERDL rules, enforce them
> deterministically, in 5 lines of code.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![npm version](https://img.shields.io/npm/v/erdl-guard.svg)](https://www.npmjs.com/package/erdl-guard)
[![npm downloads](https://img.shields.io/npm/dw/erdl-guard.svg)](https://www.npmjs.com/package/erdl-guard)
[![Formally Verified](https://img.shields.io/badge/formally%20verified-Z3%20SMT-success.svg)](https://github.com/OpenOBA/erdl-formal)

[English](https://github.com/OpenOBA/erdl-guard/blob/master/README.md) · [中文](https://github.com/OpenOBA/erdl-guard/blob/master/README.zh-CN.md)

ERDL Guard sits between an agent and the tools it can execute. It evaluates **tool name +
arguments** against deterministic ERDL policy, then allows, denies, corrects, escalates, or
routes to human approval — **before your handler runs**. It governs tool calls, not prompts.

Unlike probabilistic guardrails that use an LLM to filter another LLM, ERDL Guard is
**deterministic**: same tool call → same decision, every time, and every decision carries a
**tamper-evident receipt** you can verify offline.

---

## Table of contents

- [Understand it in 30 seconds](#understand-it-in-30-seconds)
- [Quick start](#quick-start)
- [Why ERDL Guard](#why-erdl-guard)
- [Rules](#rules)
- [Decisions](#decisions)
- [Receipts](#receipts)
- [Integration matrix](#integration-matrix)
- [Self-host](#self-host)
- [Community & peer review](#community--peer-review)
- [License](#license)

---

## Understand it in 30 seconds

ERDL Guard is a deterministic policy gateway between an agent and its tools. On every tool call,
Guard evaluates ERDL rules first, then decides allow / deny / correct / escalate / human-review;
every decision produces a content-addressed, hash-chained, independently recomputeable receipt.

```
┌─────────┐      ┌──────────────────┐      ┌────────────────┐
│  Agent  │ ───▶ │    ERDL Guard    │ ───▶ │   Tool layer   │
│ (LLM)   │      │  deterministic   │      │ bash / DB / API │
└─────────┘      │  policy eval     │      └────────────────┘
                 └────────┬─────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │   Decision Object   │
                │  JCS + SHA-256 chain │  ← tamper-evident · offline-verifiable
                └─────────────────────┘
```

**It does two things**: ① deterministic enforcement before a tool runs (no second LLM judging);
② leaves a compliance-grade receipt that any third party can recompute independently.

---

## Quick start

### See it in 5 seconds (no install)

```bash
npx erdl-guard run bash '{"command":"rm -rf /"}'
```

Outputs a Decision Object: `decision: DENY`, with `audit.hash: sha256:…` (JCS-canonicalized +
SHA-256) and `audit.previous_hash` chaining decisions together. That's what ERDL Guard does —
**blocks before the tool runs, and leaves a receipt**.

### Install

```bash
npm install erdl-guard
```

### Wire it up in 5 lines

```ts
import { loadRules, protect } from "erdl-guard";

const rules = loadRules(yamlText);        // load rules (full `then` or lightweight `action`)
const safeTools = protect(tools, rules);  // wrap tools with deterministic enforcement
const agent = createAgent({ tools: safeTools });
```

Pass `safeTools` to LangChain, LangGraph, Vercel AI SDK, OpenAI Agents, MCP adapters, Claude SDK,
Google ADK, Mastra, AutoGen, CrewAI, or your own tool runner.

### CLI smoke test

```bash
erdl-guard init                          # scaffold a sample ruleset
erdl-guard run <tool> '<argsJson>'       # trigger an evaluation, prints a Decision Object
erdl-guard receipts verify <file.json>   # verify a receipt's hash chain offline
```

---

## Why ERDL Guard

### For developers

- **Deterministic, not probabilistic.** Rule evaluation is a pure function — no model in the
  authorization path. Same tool call → same decision, every time.
- **A real expression language.** `when → then` rules compile to a 34-node expression tree —
  comparison, logic, quantifiers, arithmetic, time, and aggregation — not just
  `field + operator + value` triplets.
- **Zero-injection engine.** The SafeExpr closed expression-tree kernel evaluates with no `eval`
  and no injection surface.
- **Formally verified.** Property checks backed by SMT (Z3) in a companion formal-verification
  package.
- **Framework-agnostic.** One `protect(tools, rules)` wraps any tool runner; mainstream frameworks
  ship adapters.

### For security & compliance teams

- **Explainable, auditable.** Every decision is a Decision Object (RFC-002 v1.5) —
  content-addressed, hash-chained, independently verifiable offline. This is the decision-level,
  tamper-evident audit trail regulated enterprises require.
- **No LLM in the judgment path.** Authorization decisions are explainable, reproducible, and
  forensic — compliance-friendly.
- **Every decision is logged.** ALLOW / DENY / correct / escalate / human-review each carry an
  immutable receipt, satisfying 等保 / SOX / HIPAA / financial-audit retention requirements.
- **Vector-level verifiable.** 317 core vectors (78 audit-layer + 239 expression-layer); the 78
  audit-layer vectors are byte-verified by two independent third-party runners (Go, Python).

---

## Rules

Rules follow the ERDL rule schema (§4). A `when` compiles to an expression tree (§5), a `then` is
a decision type (§6). A rule document carries the `protocol` / `version` / `metadata` header (§2.1).

```yaml
protocol: "erdl/v2"
version: "2.1.0"
metadata:
  name: "guard-demo"
  category: security
rules:
  - name: "SEC-001-block-rm-rf"
    description: "Block destructive rm -rf in bash"
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
    message: "Destructive command blocked"
```

### Start simple: lightweight actions

Don't want to think about 13 decision types and rings? Write a verb instead — the routing layer
maps it to the right deterministic decision + ring for you:

| Verb | Maps to | Ring |
|---|---|:---:|
| `block` | DENY | 0 |
| `allow` | ALLOW | 3 |
| `ask` | REQUEST_HUMAN | 2 |
| `escalate` | ESCALATE | 2 |

```yaml
rules:
  - name: "block rm -rf"
    when:
      conditions:
        - field: "tool.args.command"
          operator: contains
          value: "rm -rf"
    action: block          # ← just a verb; `loadRules` translates it to DENY + Ring 0
```

The verbs are a facade over the 13-decision engine, not a second enum — the deterministic engine,
the Decision Object audit, and the full expression language all stay intact.

### Full expression power

The Simple projection (§5.2) covers 28 condition operators across 8 families — comparison
(`eq`/`ne`/`gt`/`gte`/`lt`/`lte`), list (`in`/`not_in`), string (`contains`/`not_contains`/`match`/
`starts_with`/`ends_with`), boundary-negation (`not_starts_with`/`not_ends_with`), existence
(`exists`/`not_exists`), length (`length_gt`/`length_gte`/`length_lt`/`length_lte`/`length_eq`),
range (`between`/`not_between`), and count (`count_gt`/`count_gte`/`count_lt`/`count_lte`) — plus
2 condition modifiers (`within`/`rate`), 30 operators total.

For tier ≥3 business rules, the Expression projection (§5.3) opens the full 34-node tree —
quantifiers (`all`/`any`/`none`), arithmetic (`add`/`sub`/`mul`/`div`/`round`), time
(`days_between`, `date_add`), and aggregation — which simple `field + operator + value` guards
cannot express.

---

## Decisions

`then` is one of the ERDL decision types (§6). Guard rules use the 9 guard-allowed decisions
(`GUARD_ALLOWED_DECISIONS` — Ring 0–2 actions plus the Ring 3 exception):

`ALLOW` · `CORRECT` · `DENY` · `EMERGENCY_HALT` · `ESCALATE` · `REQUEST_HUMAN` · `ROLLBACK` ·
`QUARANTINE` · `DELEGATE`

---

## Receipts

Every decision is written as a **Decision Object (RFC-002 v1.5)** — a content-addressed,
hash-chained, tamper-evident receipt:

```bash
erdl-guard run bash '{"command":"rm -rf /"}'
```

Outputs a Decision Object whose `audit.hash` is a `sha256:…` digest (JCS-canonicalized +
SHA-256) and whose `audit.previous_hash` chains decisions together. This is the decision-level,
tamper-evident, independently recomputable audit trail that regulated enterprises require.

Verify offline:

```bash
erdl-guard receipts verify <decision.json>
```

Anyone can recompute the hash and check chain integrity independently — without trusting ERDL
Guard itself.

---

## Integration matrix

**In-process adapters (TypeScript) — implemented and tested:**

| Runtime | Artifact | Status |
|---|---|---|
| Provider-agnostic tools | `protect(tools, rules)` | Canonical path |
| Vercel AI SDK | `erdl-guard/integrations/vercel-ai` | Implemented + tested |
| LangChain / LangGraph (JS) | `erdl-guard/integrations/langchain` | Implemented + tested |

**Cross-language (via the MCP proxy):**

Python frameworks (CrewAI · OpenAI Agents SDK · Pydantic AI) and .NET (Microsoft Agent
Framework) integrate through the language-agnostic `startMcpProxy` — deploy ERDL Guard as an MCP
gateway and every MCP-speaking agent is guarded regardless of its language.

### Which entry do I use?

| Your scenario | Use |
|---|---|
| TypeScript/JS agent (Vercel AI SDK / LangChain) | `wrapVercelAITools` / `wrapLangChainTools` |
| Any framework, in-process | `protect(tools, rules)` |
| Python / .NET / cross-language | `startMcpProxy` (MCP gateway) |
| Quick test | CLI: `erdl-guard run <tool> '<args>'` |
| Load rules (full `then` or lightweight `action`) | `loadRules(yamlText)` |

---

## Self-host

```bash
docker compose up
```

ERDL Guard now listens as an MCP gateway at `http://localhost:3001/mcp`. Any MCP agent can reach it:

```bash
curl -s http://localhost:3001/mcp \
  -H 'content-type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: bash' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"echo hello"}}}'
```

---

## Community & peer review

The ERDL engine powering ERDL Guard is backed by SMT (Z3) property checks in a companion
formal-verification package; the 78 audit-layer vectors are byte-verified by two independent
third-party runners (Go, Python). ERDL is submitted as RFC #2031 to the A2A project's official
discussion forum and is currently in community-discussion stage.

> Early peer review and design partners come from the A2A / OWASP agentic-security community.
> For named endorsements or a design-partner relationship, contact [support@openoba.com](mailto:support@openoba.com).

---

## License

- **ERDL Guard**: [MIT](./LICENSE).
- **The engine powering ERDL Guard** (`@openoba/rulsynor-core`): **BSL 1.1** (source-available,
  converts to GPL in 2030). Production-scale commercial use requires a commercial license.
