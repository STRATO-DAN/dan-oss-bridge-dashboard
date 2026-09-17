// Real tests against BridgeStore itself — durable message identity, honest history-gap reporting,
// replay rejection, single-writer locking, and real EventEmitter-backed long-poll, all against a real
// temp data dir.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { BridgeStore, BridgeError } from "../src/store.js";

let _n = 0;
const nonce = () => `nonce-${++_n}`;

async function withStore(fn, opts) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-test-"));
  const store = new BridgeStore(dir, opts);
  await store.init();
  try {
    await fn(store, dir);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("postMessage assigns durable sequential ids per channel, starting at 1", () =>
  withStore(async (store) => {
    const m1 = await store.postMessage("general", "agent-1", "hello", { nonce: nonce() });
    const m2 = await store.postMessage("general", "agent-2", "hi back", { nonce: nonce() });
    assert.equal(m1.id, 1);
    assert.equal(m2.id, 2);
  }));

test("the server-established `from` is what gets stored, verbatim", () =>
  withStore(async (store) => {
    const m = await store.postMessage("general", "agent-7", "hi", { nonce: nonce() });
    assert.equal(m.from, "agent-7");
  }));

test("waitForMessages resolves immediately with already-buffered messages past sinceId", () =>
  withStore(async (store) => {
    await store.postMessage("general", "agent-1", "first", { nonce: nonce() });
    const result = await store.waitForMessages("general", 0, 1000);
    assert.equal(result.messages.length, 1);
    assert.equal(result.messages[0].text, "first");
  }));

test("waitForMessages genuinely blocks then resolves the moment a real message posts", () =>
  withStore(async (store) => {
    const waitPromise = store.waitForMessages("general", 0, 5000);
    const start = Date.now();
    setTimeout(() => store.postMessage("general", "agent-2", "delayed", { nonce: nonce() }), 150);
    const result = await waitPromise;
    const elapsed = Date.now() - start;
    assert.equal(result.messages[0].text, "delayed");
    assert.ok(elapsed < 1000, `expected resolve well before the 5000ms timeout, took ${elapsed}ms`);
  }));

test("waitForMessages resolves empty, honestly, when nothing arrives before the real timeout", () =>
  withStore(async (store) => {
    const result = await store.waitForMessages("general", 0, 200);
    assert.deepEqual(result.messages, []);
  }));

test("announcePresence + listPresence reports a real, freshly-announced principal as online", () =>
  withStore((store) => {
    store.announcePresence("general", "agent-1");
    const online = store.listPresence("general");
    assert.equal(online.length, 1);
    assert.equal(online[0].from, "agent-1");
    assert.ok(online[0].lastSeenMsAgo < 1000);
  }));

test("a principal that never announced never appears in listPresence", () =>
  withStore((store) => {
    assert.deepEqual(store.listPresence("general"), []);
  }));

test("listChannels reports real channel names, sorted", () =>
  withStore(async (store) => {
    await store.postMessage("zeta", "agent-1", "hi", { nonce: nonce() });
    await store.postMessage("alpha-channel", "agent-1", "hi", { nonce: nonce() });
    assert.deepEqual(store.listChannels(), ["alpha-channel", "zeta"]);
  }));

// ── security invariants ───────────────────────────────────────────────────────────────────────

test("INV-07/14: message ids are durable — a restart NEVER reuses an id", () =>
  withStore(async (store, dir) => {
    await store.postMessage("general", "a", "one", { nonce: nonce() });
    const m2 = await store.postMessage("general", "a", "two", { nonce: nonce() });
    assert.equal(m2.id, 2);
    await store.close(); // release the single-writer lock before the "restart"
    const restarted = new BridgeStore(dir);
    await restarted.init();
    try {
      const m3 = await restarted.postMessage("general", "a", "three", { nonce: nonce() });
      assert.equal(m3.id, 3, "id continued from the durable sequence, not reset to the array length");
    } finally {
      await restarted.close();
    }
  }));

test("INV-08: a cursor older than the oldest retained message reports a history gap, never a silent partial", () =>
  withStore(async (store) => {
    for (let i = 0; i < 5; i++) await store.postMessage("g", "a", `m${i}`, { nonce: nonce() });
    // retention keeps the last 3 (ids 3,4,5); id 1 and 2 have aged out.
    const gapped = store.readMessages("g", 1);
    assert.equal(gapped.gap, true);
    assert.equal(gapped.minRetainedId, 3);
    assert.equal(gapped.latestId, 5);
    const fresh = store.readMessages("g", 4);
    assert.equal(fresh.gap, false);
    assert.deepEqual(fresh.messages.map((m) => m.id), [5]);
    // sinceId 0 (a first read) is never a "gap".
    assert.equal(store.readMessages("g", 0).gap, false);
  }, { maxMessagesPerChannel: 3 }));

test("INV-06: a replayed nonce is rejected", () =>
  withStore(async (store) => {
    await store.postMessage("g", "a", "approve deployment", { nonce: "fixed-nonce" });
    await assert.rejects(
      () => store.postMessage("g", "a", "approve deployment", { nonce: "fixed-nonce" }),
      (e) => e instanceof BridgeError && e.code === "REPLAY",
    );
  }));

test("INV-06 (durable): a used nonce is STILL rejected after a restart — replay protection survives a bounce", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-nonce-restart-"));
  const a = new BridgeStore(dir);
  await a.init();
  try {
    await a.postMessage("g", "agent-1", "approve deployment", { nonce: "fixed-nonce" });
    await a.close(); // release the single-writer lock and simulate a hub restart
    const b = new BridgeStore(dir);
    await b.init();
    try {
      await assert.rejects(
        () => b.postMessage("g", "agent-1", "approve deployment", { nonce: "fixed-nonce" }),
        (e) => e instanceof BridgeError && e.code === "REPLAY",
        "a nonce used BEFORE the restart must still be rejected AFTER it (nonces persist to nonces.json)",
      );
    } finally {
      await b.close();
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a stale client timestamp is rejected", () =>
  withStore(async (store) => {
    await assert.rejects(
      () => store.postMessage("g", "a", "old", { nonce: nonce(), ts: Date.now() - 10 * 60_000 }),
      (e) => e instanceof BridgeError && e.code === "STALE",
    );
  }));

test("a post with no nonce is rejected (replay protection is mandatory)", () =>
  withStore(async (store) => {
    await assert.rejects(
      () => store.postMessage("g", "a", "no nonce"),
      (e) => e instanceof BridgeError && e.code === "NONCE_REQUIRED",
    );
  }));

test("concurrency: a data dir has a single writer — a second hub refuses to start", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-lock-"));
  const a = new BridgeStore(dir);
  await a.init();
  const b = new BridgeStore(dir);
  try {
    await assert.rejects(() => b.init(), (e) => e instanceof BridgeError && e.code === "HUB_LOCKED");
    await a.close(); // once the first releases, a new hub can take the dir
    const c = new BridgeStore(dir);
    await c.init();
    await c.close();
  } finally {
    await a.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
