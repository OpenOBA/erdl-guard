/**
 * V-DO v1.5 conformance — erdl-guard `verifyReceipt` vs the authoritative
 * erdl-vectors Decision Object oracle (decision-object-vectors-v1.5.json).
 *
 * Proves that erdl-guard's hash recomputation (JCS RFC 8785 + SHA-256, unique
 * deletion point = audit.hash, RFC-002 §1.1) is byte-conformant with the 78
 * hash-layer vectors. It also documents the honest boundary: `verifyReceipt`
 * is HASH-ONLY — it does not implement the semantic/chain breach detection
 * (jurisdiction_mismatch / sod_violation / tree_snapshot_divergence /
 * chain_seq_gap / …), which is the full conforming runner's job (erdl-vectors
 * scripts/verify-v1.5.js), not erdl-guard's receipt verifier.
 *
 * Usage: node scripts/vdo-conformance.mjs [path-to-vectors.json]
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { verifyReceipt } from "../dist/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const defaultFixture = resolve(here, "../../erdl-vectors/decision-object-vectors-v1.5.json");
const fixture = process.argv[2] ?? defaultFixture;

const { vectors } = JSON.parse(readFileSync(fixture, "utf8"));

const HASH_LAYER_BREACHES = new Set(["hash_mismatch", "canary_mismatch"]);

let singleMatch = 0;
let singleHashBreach = 0;
let chainMatch = 0;
let chainHashBreach = 0;
let tamperPairs = 0;
let chainDos = 0;
const failures = [];
const semanticUnseen = [];

for (const v of vectors) {
  const exp = v.expected ?? {};

  // Shape 1: single decision_object
  if (v.decision_object) {
    const valid = verifyReceipt(v.decision_object).valid;
    const isHashBreach = HASH_LAYER_BREACHES.has(exp.breach);
    const expectValid = !isHashBreach; // MATCH + semantic breaches keep a valid hash
    if (valid === expectValid) {
      if (valid) singleMatch++;
      else singleHashBreach++;
    } else {
      failures.push(`${v.id}: valid=${valid}, expected.breach=${exp.breach ?? exp.type}`);
    }
    // semantic breach: hash is valid but a full runner flags it — document it
    if (valid && exp.breach && !HASH_LAYER_BREACHES.has(exp.breach)) {
      semanticUnseen.push(`${v.id}(${exp.breach})`);
    }
    continue;
  }

  // Shape 2: tamper pair (base_do + tampered_do)
  if (v.base_do && v.tampered_do) {
    const baseValid = verifyReceipt(v.base_do).valid;
    const tamperedValid = verifyReceipt(v.tampered_do).valid;
    if (baseValid && !tamperedValid) {
      tamperPairs++;
    } else {
      failures.push(`${v.id}: base=${baseValid}, tampered=${tamperedValid} (expect true/false)`);
    }
    continue;
  }

  // Shape 3: chain (array of DOs)
  if (Array.isArray(v.chain)) {
    const chainValid = v.chain.map((do_) => verifyReceipt(do_).valid);
    const invalidCount = chainValid.filter((x) => !x).length;
    chainDos += v.chain.length;

    if (exp.breach === "hash_mismatch") {
      // C02 single-tamper: at least one member hash-invalid is the CORRECT detection.
      if (invalidCount >= 1) chainHashBreach++;
      else failures.push(`${v.id}: expected tampered member, got all valid`);
    } else if (exp.type === "MATCH") {
      // C01 normal chain: all members hash-valid.
      if (invalidCount === 0) chainMatch++;
      else failures.push(`${v.id}: expected all valid, got ${invalidCount} invalid`);
    } else {
      // C03-C08 structural breach (chain_seq_gap / dangling / time_regression /
      // genesis / version / mode): each member hash is still valid; the breach is in
      // the chain STRUCTURE, which verifyReceipt (hash-only) does not check.
      semanticUnseen.push(`${v.id}(${exp.breach})`);
    }
    continue;
  }
}

console.log("=== erdl-guard verifyReceipt × V-DO v1.5 conformance ===\n");
console.log(`single-DO  (${singleMatch + singleHashBreach}) : ${singleMatch} hash-valid + ${singleHashBreach} hash-breach (canary) — all correct`);
console.log(`tamper-pair (${tamperPairs}) : base valid / tampered invalid — all correct`);
console.log(`chain hash-layer (${chainMatch + chainHashBreach}) : ${chainMatch} normal + ${chainHashBreach} single-tamper — all correct (${chainDos} DOs)`);
console.log(`\nFAILURES: ${failures.length}`);
failures.forEach((f) => console.log("  ✗ " + f));

console.log(`\n=== honest boundary (verifyReceipt is hash-only) ===`);
console.log(
  `semantic/structural breaches NOT detected by verifyReceipt (hash stays valid, needs full runner): ${semanticUnseen.length}`,
);
semanticUnseen.forEach((s) => console.log("  - " + s));

const pass = failures.length === 0;
console.log(`\n=> ${pass ? "PASS" : "FAIL"}: erdl-guard hash layer is byte-conformant with the V-DO oracle`);
process.exitCode = pass ? 0 : 1;
