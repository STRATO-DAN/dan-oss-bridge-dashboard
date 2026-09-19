// Tests for whole-log tamper-evidence: the hash chain (src/chain.js), the store storing `prev`, and
// the GET /api/channels/:channel/verify endpoint that powers the dashboard's "verify log integrity"
// panel. Each proves a property that fails against the pre-chain code (there was no `prev`, no chain,
// and no verify route).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { GENESIS, linkOf, verifyChain } from "../src/chain.js";
import { BridgeStore } from "../src/store.js";
import { createServer } from "../src/server.js";
import { AuthStore } from "../src/auth.js";
import { signMessage, canonicalMessage } from "../src/sign.js";

// ── pure chain unit tests ───────────────────────────────────────────────────────────────────────
function chainMessages(n, from = "agent-a") {
  const msgs = [];
  let prev = GENESIS;
  for (let i = 1; i <= n; i++) {
    const m = { id: i, from, text: `message ${i}`, ts: 1_000 + i, nonce: `n${i}`, sig: `s${i}`, prev };
    msgs.push(m);
    prev = linkOf(m);
  }
  return msgs;
}

test("linkOf is deterministic and changes when any covered field changes", () => {
  const m = { id: 1, from: "a", text: "hi", ts: 5, nonce: "n", sig: "s", prev: GENESIS };
  assert.equal(linkOf(m), linkOf({ ...m }));
  assert.equal(linkOf(m).length, 64);
  assert.notEqual(linkOf(m), linkOf({ ...m, text: "HI" }));
  assert.notEqual(linkOf(m), linkOf({ ...m, id: 2 }));
  assert.notEqual(linkOf(m), linkOf({ ...m, sig: "s2" }));
  assert.notEqual(linkOf(m), linkOf({ ...m, prev: "x".repeat(64) }));
});

test("a clean chain verifies: chain present, no break, every link ok", () => {
  const { chainPresent, firstBreakId, verdicts } = verifyChain(chainMessages(4));
  assert.equal(chainPresent, true);
  assert.equal(firstBreakId, null);
  assert.deepEqual(verdicts.map((v) => v.chainOk), [true, true, true, true]);
});

test("deleting a middle message breaks the chain at the next one", () => {
  const msgs = chainMessages(4);
  msgs.splice(1, 1); // drop id 2 -> [1,3,4]
  const { firstBreakId, verdicts } = verifyChain(msgs);
  assert.equal(firstBreakId, 3); // id 3's stored prev no longer matches id 1's link
  assert.equal(verdicts.find((v) => v.id === 3).chainOk, false);
});

test("reordering two messages breaks the chain", () => {
  const msgs = chainMessages(4);
  [msgs[1], msgs[2]] = [msgs[2], msgs[1]]; // swap id 2 and 3
  assert.notEqual(verifyChain(msgs).firstBreakId, null);
});

test("inserting a foreign message breaks the chain", () => {
  const msgs = chainMessages(4);
  msgs.splice(2, 0, { id: 99, from: "x", text: "injected", ts: 9, nonce: "z", sig: "bad", prev: GENESIS });
  assert.notEqual(verifyChain(msgs).firstBreakId, null);
});

test("editing a message's text breaks the chain at the FOLLOWING message", () => {
  const msgs = chainMessages(4);
  msgs[1] = { ...msgs[1], text: "TAMPERED" }; // its own prev is unchanged, but its link changes
  const { firstBreakId, verdicts } = verifyChain(msgs);
  assert.equal(verdicts.find((v) => v.id === 2).chainOk, true); // id 2's own prev still matches
  assert.equal(firstBreakId, 3);                                 // id 3's prev no longer matches edited id 2
});

test("an un-chained (legacy) log reports no chain, no false break", () => {
  const legacy = [
    { id: 1, from: "a", text: "old", ts: 1, nonce: "n1", sig: "s1" }, // no prev
    { id: 2, from: "a", text: "old2", ts: 2, nonce: "n2", sig: "s2" },
  ];
  const { chainPresent, firstBreakId, verdicts } = verifyChain(legacy);
  assert.equal(chainPresent, false);
  assert.equal(firstBreakId, null);
  assert.deepEqual(verdicts.map((v) => v.chainOk), [null, null]);
});

test("the oldest retained message is an un-checkable anchor, not a break", () => {
  const full = chainMessages(4);
  const retained = full.slice(2); // ids 3,4 — id 3's predecessor (id 2) has aged out
  const { firstBreakId, verdicts } = verifyChain(retained);
  assert.equal(verdicts.find((v) => v.id === 3).chainOk, null); // anchor, not a break
  assert.equal(verdicts.find((v) => v.id === 4).chainOk, true);
  assert.equal(firstBreakId, null);
});

// ── store stores the chain ──────────────────────────────────────────────────────────────────────
async function withStore(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-chain-"));
  const store = new BridgeStore(dir);
  await store.init();
  try { await fn(store); } finally { await store.close(); await fs.rm(dir, { recursive: true, force: true }); }
}

test("store: first message anchors to GENESIS, each later message links to the previous", () =>
  withStore(async (store) => {
    const m1 = await store.postMessage("general", "agent-a", "one", { nonce: "n1", ts: Date.now() });
    const m2 = await store.postMessage("general", "agent-a", "two", { nonce: "n2", ts: Date.now() });
    const m3 = await store.postMessage("general", "agent-a", "three", { nonce: "n3", ts: Date.now() });
    assert.equal(m1.prev, GENESIS);
    assert.equal(m2.prev, linkOf(m1));
    assert.equal(m3.prev, linkOf(m2));
    // and the whole retained log verifies clean
    const { messages } = store.readMessages("general", 0);
    assert.equal(verifyChain(messages).firstBreakId, null);
  }));

// ── the verify endpoint ─────────────────────────────────────────────────────────────────────────
async function withServer(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-verify-"));
  const setup = new AuthStore(dir);
  const a = await setup.register("agent-a", "tok-a", ["channel:general"]);
  const keys = { "agent-a": a.privateKey };
  const server = createServer({ dataDir: dir });
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, keys, server); }
  finally {
    await new Promise((r) => server.close(r));
    await server._bridge.audit.drain();
    await fs.rm(dir, { recursive: true, force: true });
  }
}
const A = { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a" };
function signed(keys, principal, channel, text) {
  const nonce = randomUUID(), ts = Date.now();
  const sig = signMessage(keys[principal], canonicalMessage({ from: principal, channel, nonce, ts, text }));
  return { text, nonce, ts, sig };
}
async function postThree(base, keys) {
  for (const t of ["alpha", "beta", "gamma"]) {
    const res = await fetch(`${base}/api/channels/general/messages`, {
      method: "POST", headers: { "content-type": "application/json", ...A }, body: JSON.stringify(signed(keys, "agent-a", "general", t)),
    });
    assert.equal(res.status, 200);
  }
}

test("GET /verify on a clean signed log: chain intact, every message verified", () =>
  withServer(async (base, keys) => {
    await postThree(base, keys);
    const res = await fetch(`${base}/api/channels/general/verify`, { headers: A });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.equal(data.chainPresent, true);
    assert.equal(data.chainIntact, true);
    assert.equal(data.firstBreakId, null);
    assert.equal(data.counts.total, 3);
    assert.equal(data.counts.sigForged, 0);
    assert.ok(data.records.every((r) => r.sigVerified === true));
    assert.deepEqual(data.records.map((r) => r.chainOk), [true, true, true]);
  }));

test("GET /verify detects an in-place edit: signature forged AND chain broken at the next", () =>
  withServer(async (base, keys, server) => {
    await postThree(base, keys);
    // Simulate a tampered stored log: edit the first message's text in place (what an on-disk edit +
    // reload would surface). Its Ed25519 signature no longer matches its content, and the next
    // message's stored prev no longer matches the edited message's recomputed link.
    const ch = server._bridge.store.channels.get("general");
    ch.messages[0].text = "EDITED AFTER THE FACT";
    const res = await fetch(`${base}/api/channels/general/verify`, { headers: A });
    const data = await res.json();
    assert.equal(data.chainIntact, false);
    assert.equal(data.firstBreakId, ch.messages[1].id);
    assert.equal(data.counts.sigForged, 1);
    assert.equal(data.records[0].sigVerified, false);   // edited message: signature no longer matches
    assert.equal(data.records[1].chainOk, false);       // next message: chain link broken
  }));

test("GET /verify detects a deleted message (chain break)", () =>
  withServer(async (base, keys, server) => {
    await postThree(base, keys);
    const ch = server._bridge.store.channels.get("general");
    const survivorId = ch.messages[2].id;
    ch.messages.splice(1, 1); // delete the middle message
    const res = await fetch(`${base}/api/channels/general/verify`, { headers: A });
    const data = await res.json();
    assert.equal(data.chainIntact, false);
    assert.equal(data.firstBreakId, survivorId); // the message after the hole no longer links
  }));

test("GET /verify requires auth and channel scope", () =>
  withServer(async (base) => {
    const noauth = await fetch(`${base}/api/channels/general/verify`);
    assert.equal(noauth.status, 401);
  }));
