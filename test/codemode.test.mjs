// Code Mode sandbox tests (run after `npm run build`).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { runCodeMode, DEFAULT_LIMITS } from "../dist/codemode/sandbox.js";

const sha = (t) => createHash("sha256").update(t, "utf8").digest("hex");
const host = {
  hash: async (t) => sha(t),
  verify: async (n) => ({ sequence: n, found: n < 1000, entry_hash: null, anchor_status: n % 2 ? "anchored" : "pending", txid: n % 2 ? "ab".repeat(32) : null, block_height: null }),
  verifyStatement: async () => ({ issuerSignatureValid: true, inclusionProofValid: true, receiptSignatureValid: true, valid: true }),
  anchor: async (n) => ({ sequence: n, anchor_status: n % 2 ? "anchored" : "pending", txid: null }),
};

test("checks many items in one run and returns only the exceptions", async () => {
  const docs = Array.from({ length: 500 }, (_, i) => ({ text: `doc ${i}`, expected: sha(`doc ${i}`) }));
  docs[123].expected = "0".repeat(64);
  const r = await runCodeMode(
    `const bad = [];
     for (const d of input) { if ((await lp.hash(d.text)) !== d.expected) bad.push(d.text); }
     return { checked: input.length, bad };`,
    docs,
    host
  );
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.result, { checked: 500, bad: ["doc 123"] });
  assert.equal(r.hostCalls, 500);
});

test("sandbox has no network, filesystem, process or require", async () => {
  const r = await runCodeMode(
    `return [typeof fetch, typeof require, typeof process, typeof XMLHttpRequest, typeof WebSocket, typeof Deno];`,
    null,
    host
  );
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.result, ["undefined", "undefined", "undefined", "undefined", "undefined", "undefined"]);
});

test("runaway code is stopped", async () => {
  const r = await runCodeMode(`while (true) {}`, null, host, { ...DEFAULT_LIMITS, timeoutMs: 300 });
  assert.equal(r.ok, false);
});

test("host-call budget is enforced by the host", async () => {
  const r = await runCodeMode(
    `for (let i = 0; i < 50; i++) await lp.verify(i); return "done";`,
    null,
    host,
    { ...DEFAULT_LIMITS, maxHostCalls: 10 }
  );
  assert.equal(r.ok, false);
  assert.match(r.error, /budget/);
});

test("lp.issue only plans: budget, duplicates and raw content", async () => {
  const r = await runCodeMode(
    `const out = [];
     const h = await lp.hash("caption");
     out.push(await lp.issue({ precomputed_sha256: h, aiSystemId: "gpt", deployerName: "Acme", contentCategory: "SYNTHETIC_TEXT" }));
     out.push(await lp.issue({ precomputed_sha256: h, aiSystemId: "gpt", deployerName: "Acme", contentCategory: "SYNTHETIC_TEXT" }));
     out.push(await lp.issue({ artifact: "raw text", aiSystemId: "gpt", deployerName: "Acme", contentCategory: "SYNTHETIC_TEXT" }));
     for (let i = 0; i < 5; i++) out.push(await lp.issue({ precomputed_sha256: await lp.hash("x" + i), aiSystemId: "gpt", deployerName: "Acme", contentCategory: "SYNTHETIC_TEXT" }));
     return out.map((o) => o.planned ? "planned" : o.reason);`,
    null,
    host,
    { ...DEFAULT_LIMITS, maxPlannedIssues: 3 }
  );
  assert.equal(r.ok, true, r.error);
  assert.equal(r.result[0], "planned");
  assert.match(r.result[1], /duplicate/);
  assert.match(r.result[2], /precomputed_sha256/);
  assert.equal(r.result.filter((x) => x === "planned").length, 3);
  assert.ok(r.result.some((x) => /budget/.test(x)));
  assert.equal(r.planned.length, 3);
});

test("errors in generated code are reported, not thrown", async () => {
  const bad = await runCodeMode(`return (`, null, host);
  assert.equal(bad.ok, false);
  const thrown = await runCodeMode(`throw new Error("nope")`, null, host);
  assert.equal(thrown.ok, false);
  assert.match(thrown.error, /nope/);
});

test("large results are truncated", async () => {
  const r = await runCodeMode(`return "x".repeat(100000);`, null, host, { ...DEFAULT_LIMITS, maxResultChars: 100 });
  assert.equal(r.ok, true);
  assert.equal(r.truncated, true);
});
