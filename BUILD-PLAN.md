# ERDL Guard — 构建计划

> 维护者：唐浩然（OpenOBA AI 执行官）
> 日期：2026-09-08
> 状态：Henry 已批「文档化后即可开始」，正式开工。

---

## 0. 一句话

`erdl-guard` = 复用 rulsynor-core 深引擎（Action Guard + 规则引擎 + Decision Object + SafeExpr），套一层「drop-in 工具授权 SDK + MCP proxy」的壳，锚定 ERDL 规范，主流框架 Tier 1 先做。

## 1. 铁律（开工前锁定）

1. **锚定 AUTH-* 权威源**：决策/运算符/节点/字段从 `AUTH-CODE-SCHEMA`（erdl-schema.ts）`import`，不复制枚举、不凭记忆写。
2. **复用不重写**：引擎依赖 `@openoba/rulsynor-core`（BSL 1.1，已发布 1.1.0），SDK 只做「壳」。
3. **MCP 按 2026-07-28 stateless**：无 session、`_meta` 带 protocolVersion、`Mcp-Method`/`Mcp-Name` 头。
4. **禁悬空数字**：30/13/34 等数字由 `.length` 派生。
5. **commit 信息空白**（Henry 指令）。

## 2. 架构（3 层）

```
第 1 层：protect(tools)  —— 框架无关，包住 tool 对象（地基）
第 2 层：MCP proxy  —— 最高杠杆（通用标准）
第 3 层：framework middleware —— Tier 1：Vercel/LangChain/OpenAI/CrewAI/MAF
```

## 3. 构建顺序（Phase）

| Phase | 内容 | 验收 |
|---|---|---|
| 0 | 产品定义 + 锚点 + 适配研究 | ✅ 已完成 |
| 1 | SDK 骨架：`protect(tools)` 复用引擎 | 一条 SEC 规则跑通（block rm -rf）|
| 2 | MCP proxy（stateless）| MCP tools/call 被拦截 |
| 3 | 演示 + 规则 CLI | 60 秒 demo + `erdl-guard init` |
| 4 | Tier 1 框架适配 | Vercel/LangChain/OpenAI/CrewAI/MAF |

## 4. 复用清单（rulsynor-core 已有，不重写）

| 组件 | rulsynor-core 位置 |
|---|---|
| 枚举（决策/运算符/节点）| `src/engine/erdl-schema.ts` |
| Action Guard（Ring 0-3）| `src/guard/` |
| 规则引擎（求值）| `src/engine/evaluator.ts` |
| Decision Object | `src/provenance.ts` + RFC-002 |
| SafeExpr（零注入）| `src/engine/safe-regex.ts` 等 |

## 5. 许可证

A 方案：SDK（erdl-guard）= MIT；引擎（@openoba/rulsynor-core）= BSL 1.1。SDK 是薄壳，引擎是依赖。
