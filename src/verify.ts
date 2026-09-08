import { canonicalize } from "json-canonicalize";
import { createHash } from "node:crypto";
import type { DecisionObject } from "@openoba/rulsynor-core";

export interface VerifyResult {
  valid: boolean;
  expected: string;
  actual: string;
}

/**
 * Verify a Decision Object's `audit.hash` (RFC-002 §7, flat-hash recomputation):
 * delete `audit.hash` (and `signature`/`signing_key_id`), JCS-canonicalize the preimage,
 * SHA-256 it, and compare against the claimed `audit.hash`.
 *
 * This is the independent recomputation that makes the receipt tamper-evident — the
 * exact inverse of `buildDecisionObject`'s flat-hash scheme.
 */
export function verifyReceipt(doObject: DecisionObject): VerifyResult {
  const preimage = structuredClone(doObject) as unknown as Record<string, unknown>;
  const audit = preimage.audit as Record<string, unknown>;
  delete audit.hash;
  delete preimage.signature;
  delete preimage.signing_key_id;

  const canonical = canonicalize(preimage);
  const actual = createHash("sha256").update(canonical).digest("hex");
  const expected = doObject.audit.hash.replace(/^sha256:/, "");

  return { valid: actual === expected, expected, actual };
}
