# ERDL Guard

> **为 AI Agent 工具调用提供确定性授权** —— 写 ERDL 规则，确定性执行，5 行代码接入。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Formally Verified](https://img.shields.io/badge/formally%20verified-Z3%20SMT-success.svg)](https://github.com/OpenOBA/erdl-formal)

ERDL Guard 位于 Agent 与它能执行的工具之间。它在**你的 handler 运行之前**，对"工具名 + 参数"做确定性的 ERDL 策略求值，然后放行、拒绝、纠正、上报、或转人工审批。**它管的是工具调用，不是 prompt。**

与"用 LLM 过滤 LLM"的概率式 guardrail 不同，ERDL Guard 是**确定性的**：相同的工具调用 → 永远相同的决策，且每个决策都附带一份可离线独立核验的**防篡改凭证（Receipt）**。

---

## 目录

- [30 秒看懂](#30-秒看懂)
- [快速开始](#快速开始)
- [为什么选 ERDL Guard](#为什么选-erdl-guard)
- [规则](#规则)
- [决策](#决策)
- [凭证（Receipts）](#凭证receipts)
- [集成矩阵](#集成矩阵)
- [自托管](#自托管)
- [社区与同行评审](#社区与同行评审)
- [许可](#许可)

---

## 30 秒看懂

ERDL Guard 是 Agent 与工具之间的一层确定性策略网关。Agent 每次调用工具，Guard 先求值 ERDL 规则，再决定放行 / 拒绝 / 纠正 / 上报 / 转人工；每一次决策都会产出一份内容寻址、哈希链式、可独立复核的凭证。

```
┌─────────┐      ┌──────────────────┐      ┌────────────────┐
│  Agent  │ ───▶ │    ERDL Guard    │ ───▶ │   工具执行层     │
│ (LLM)   │      │  确定性策略求值    │      │ bash / DB / API │
└─────────┘      └────────┬─────────┘      └────────────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │   Decision Object   │
                │  JCS + SHA-256 链    │  ← 防篡改 · 可离线独立复核
                └─────────────────────┘
```

**它解决两件事**：① 在工具执行前做确定性管控（不靠另一个 LLM 判断）；② 留下合规审计可用的、可被第三方独立重算的决策凭证。

---

## 快速开始

### 5 秒看效果（无需安装）

```bash
npx erdl-guard run bash '{"command":"rm -rf /"}'
```

输出一个 Decision Object：`decision: DENY`，附带 `audit.hash: sha256:…`（JCS 规范化 + SHA-256）与 `audit.previous_hash` 哈希链。这就是 ERDL Guard 干的事——**在工具跑起来之前挡掉，并留痕**。

### 安装

```bash
npm install erdl-guard
```

### 5 行代码接入

```ts
import { loadRules, protect } from "erdl-guard";

const rules = loadRules(yamlText);        // 加载规则（完整 then 或轻量 action）
const safeTools = protect(tools, rules);  // 用确定性策略包裹工具
const agent = createAgent({ tools: safeTools });
```

把 `safeTools` 传给 LangChain / LangGraph / Vercel AI SDK / OpenAI Agents / MCP 适配器 / Claude SDK / Google ADK / Mastra / AutoGen / CrewAI，或你自己的工具 runner。

### CLI 速测

```bash
erdl-guard init                          # 初始化示例规则集
erdl-guard run <tool> '<argsJson>'       # 触发一次求值，输出 Decision Object
erdl-guard receipts verify <file.json>   # 离线核验凭证哈希链
```

---

## 为什么选 ERDL Guard

### 给开发者

- **确定性，而非概率性。** 规则求值是纯函数——授权路径里没有模型。相同的工具调用 → 永远相同的决策。
- **真正的表达式语言。** `when → then` 规则编译为 34 节点表达式树——比较、逻辑、量词、算术、时间、聚合——不只是 `field + operator + value` 三段式。
- **零注入引擎。** SafeExpr 闭合表达式树内核求值，无 `eval`、无注入面。
- **形式化验证背书。** 配套形式化验证包用 SMT（Z3）做性质检查。
- **框架无关。** 一行 `protect(tools, rules)` 包住任何工具 runner；主流框架均有适配。

### 给安全与合规团队

- **可解释、可审计。** 每个决策都有一份 Decision Object（RFC-002 v1.5）——内容寻址、哈希链式、可离线独立复核。这是受监管企业要求的决策级防篡改审计链。
- **不依赖 LLM 判断。** 授权决策可解释、可复现、可取证——合规友好。
- **决策即留痕。** ALLOW / DENY / 纠正 / 上报 / 转人工，每次都有不可篡改的凭证，满足等保 / SOX / HIPAA / 金融审计留痕要求。
- **向量级可核验。** 317 个核心向量（78 审计层 + 239 表达式层）；78 个审计层向量由两个独立第三方 runner（Go、Python）逐字节验证通过。

---

## 规则

规则遵循 ERDL 规则 schema（§4）。`when` 编译为表达式树（§5），`then` 是决策类型（§6）。规则文档带 `protocol` / `version` / `metadata` 头（§2.1）。

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

### 从最简单的写起：轻量 action

不想记 13 种决策类型和 ring？写一个动词就行，路由层会自动映射到正确的确定性决策 + ring：

| 动词 | 映射到 | Ring |
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
    action: block          # ← 只是一个动词；loadRules 自动翻译为 DENY + Ring 0
```

动词是 13 决策引擎的 facade，不是第二个枚举——确定性引擎、Decision Object 审计、完整表达式语言全部保持不变。

### 完整表达式能力

Simple 投影（§5.2）覆盖 8 族 28 个条件操作符——比较（`eq`/`ne`/`gt`/`gte`/`lt`/`lte`）、列表（`in`/`not_in`）、字符串（`contains`/`not_contains`/`match`/`starts_with`/`ends_with`）、边界取反（`not_starts_with`/`not_ends_with`）、存在性（`exists`/`not_exists`）、长度（`length_gt`/`length_gte`/`length_lt`/`length_lte`/`length_eq`）、范围（`between`/`not_between`）、计数（`count_gt`/`count_gte`/`count_lt`/`count_lte`）——外加 2 个条件修饰符（`within`/`rate`），共 30 个操作符。

对于 tier ≥3 的业务规则，Expression 投影（§5.3）打开完整 34 节点树——量词（`all`/`any`/`none`）、算术（`add`/`sub`/`mul`/`div`/`round`）、时间（`days_between`、`date_add`）、聚合——这些是简单 `field + operator + value` guard 表达不了的。

---

## 决策

`then` 是 ERDL 决策类型之一（§6）。Guard 规则使用 9 个 guard 允许的决策（`GUARD_ALLOWED_DECISIONS` —— Ring 0–2 动作加 Ring 3 例外）：

`ALLOW` · `CORRECT` · `DENY` · `EMERGENCY_HALT` · `ESCALATE` · `REQUEST_HUMAN` · `ROLLBACK` · `QUARANTINE` · `DELEGATE`

---

## 凭证（Receipts）

每个决策都写成一份 **Decision Object（RFC-002 v1.5）**——内容寻址、哈希链式、防篡改凭证：

```bash
erdl-guard run bash '{"command":"rm -rf /"}'
```

输出的 Decision Object 的 `audit.hash` 是 `sha256:…` 摘要（JCS 规范化 + SHA-256），`audit.previous_hash` 把决策链在一起。这就是受监管企业要求的、决策级、防篡改、可独立重算的审计链。

离线核验：

```bash
erdl-guard receipts verify <decision.json>
```

任何人都能独立重算哈希、核验链完整性——不依赖 ERDL Guard 本身。

---

## 集成矩阵

**进程内适配器（TypeScript）——已实现并测试：**

| 运行时 | 制品 | 状态 |
|---|---|---|
| Provider 无关工具 | `protect(tools, rules)` | 标准路径 |
| Vercel AI SDK | `erdl-guard/integrations/vercel-ai` | 已实现 + 测试 |
| LangChain / LangGraph (JS) | `erdl-guard/integrations/langchain` | 已实现 + 测试 |

**跨语言（经 MCP proxy）：**

Python 框架（CrewAI · OpenAI Agents SDK · Pydantic AI）与 .NET（Microsoft Agent Framework）通过语言无关的 `startMcpProxy` 接入——把 ERDL Guard 部署为 MCP 网关，任何会讲 MCP 的 agent 都被罩住，与语言无关。

### 我该用哪个入口？

| 你的场景 | 用 |
|---|---|
| TypeScript/JS agent（Vercel AI SDK / LangChain） | `wrapVercelAITools` / `wrapLangChainTools` |
| 任意框架，进程内 | `protect(tools, rules)` |
| Python / .NET / 跨语言 | `startMcpProxy`（MCP 网关） |
| 快速测试 | CLI：`erdl-guard run <tool> '<args>'` |
| 加载规则（完整 `then` 或轻量 `action`） | `loadRules(yamlText)` |

---

## 自托管

```bash
docker compose up
```

ERDL Guard 即作为 MCP 网关在 `http://localhost:3001/mcp` 监听。任何 MCP agent 都能接：

```bash
curl -s http://localhost:3001/mcp \
  -H 'content-type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: bash' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"echo hello"}}}'
```

---

## 社区与同行评审

ERDL Guard 的引擎由配套形式化验证包做 SMT（Z3）性质检查；78 个审计层向量由两个独立第三方 runner（Go、Python）逐字节验证通过。ERDL 已作为 RFC #2031 提交至 A2A 官方讨论区，处于社区讨论阶段。

> 早期同行评审与设计合作伙伴来自 A2A / OWASP agentic-security 社区。如需具名背书或建立设计合作伙伴关系，请联系 [support@openoba.com](mailto:support@openoba.com)。

---

## 许可

- **ERDL Guard**：[MIT](./LICENSE)。
- **驱动 ERDL Guard 的引擎**（`@openoba/rulsynor-core`）：**BSL 1.1**（source-available，2030 年转为 GPL）。生产规模商业使用需商业授权。
