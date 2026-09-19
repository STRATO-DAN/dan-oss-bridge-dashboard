// Audit tamper-evidence (hash-chain) + surfaced-failure tests. A plain JSONL file is filesystem-writable,
// so the security claim it can honestly make is tamper-EVIDENCE: any edit, reorder, insert, or mid-stream
// truncation must be DETECTABLE by re-verifying the chain. And a failed audit write must be SURFACED, not
// silently swallowed. Real temp dir, real fs, no mocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Audit } from "../src/audit.js";

async function withDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-audit-"));
  try {
    await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("hash-chain: a clean audit log verifies end to end", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir);
    await audit.record({ op: "message.post", result: "ok", principal: "agent-a", channel: "g", msgId: 1 });
    await audit.record({ op: "api", result: "deny", reason: "unauthenticated" });
    await audit.record({ op: "message.post", result: "ok", principal: "agent-b", channel: "g", msgId: 2 });
    const v = await Audit.verifyChain(path.join(dir, "audit.log"));
    assert.equal(v.ok, true);
    assert.equal(v.lines, 3);
  }));

test("hash-chain: editing a line's content is DETECTED", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir);
    await audit.record({ op: "message.post", result: "deny", principal: "agent-a", channel: "g", reason: "sender_spoof" });
    await audit.record({ op: "message.post", result: "ok", principal: "agent-a", channel: "g", msgId: 1 });
    const file = path.join(dir, "audit.log");
    const lines = (await fs.readFile(file, "utf8")).split("\n").filter(Boolean);
    // Rewrite the first line's content but keep its now-stale hash — exactly what a tamperer would do.
    const first = JSON.parse(lines[0]);
    first.principal = "someone-else";
    lines[0] = JSON.stringify(first);
    await fs.writeFile(file, lines.join("\n") + "\n", "utf8");
    const v = await Audit.verifyChain(file);
    assert.equal(v.ok, false);
    assert.equal(v.brokenAt, 0);
  }));

test("hash-chain: deleting a middle line (silent truncation) is DETECTED", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir);
    await audit.record({ op: "a", result: "ok" });
    await audit.record({ op: "b", result: "ok" });
    await audit.record({ op: "c", result: "ok" });
    const file = path.join(dir, "audit.log");
    const lines = (await fs.readFile(file, "utf8")).split("\n").filter(Boolean);
    // Drop the middle line — line 3's `prev` no longer matches its new predecessor's hash.
    await fs.writeFile(file, [lines[0], lines[2]].join("\n") + "\n", "utf8");
    const v = await Audit.verifyChain(file);
    assert.equal(v.ok, false);
    assert.equal(v.brokenAt, 1);
  }));

test("hash-chain: the tested security fields are still present on every line (consumers unaffected)", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir);
    await audit.record({ op: "message.post", result: "deny", principal: "agent-a", channel: "g", reason: "sender_spoof", msgId: 7 });
    const line = JSON.parse((await fs.readFile(path.join(dir, "audit.log"), "utf8")).trim());
    for (const k of ["ts", "op", "result", "principal", "channel", "msgId", "reason", "prev", "hash"]) {
      assert.ok(k in line, `line carries ${k}`);
    }
    assert.equal(line.result, "deny");
    assert.equal(line.reason, "sender_spoof");
  }));

test("write failures are SURFACED (writeFailures + lastError), never silently swallowed", () =>
  withDir(async (dir) => {
    // Point the audit at a path whose parent is a FILE, so audit.log can never be written (ENOTDIR).
    const blocker = path.join(dir, "blocker");
    await fs.writeFile(blocker, "x");
    const audit = new Audit(blocker); // this.file = blocker/audit.log → append always fails
    await audit.record({ op: "message.post", result: "ok", principal: "agent-a" });
    assert.equal(audit.writeFailures, 1, "a failed audit write is counted, not dropped");
    assert.ok(audit.lastError, "the error is retained for inspection");
  }));

test("drain() waits for a record() the caller never awaited — the fire-and-forget teardown race", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir);
    audit.record({ op: "message.post", result: "ok", principal: "agent-a", channel: "g", msgId: 1 }); // NOT awaited
    await audit.drain();
    const v = await Audit.verifyChain(path.join(dir, "audit.log"));
    assert.equal(v.ok, true);
    assert.equal(v.lines, 1, "the unawaited write landed before drain() resolved");
  }));
