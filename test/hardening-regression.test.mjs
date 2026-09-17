// Regression tests for the confirmed audit findings (B1–B10). Each one FAILS on the pre-fix code and
// PASSES after. Real temp dirs, real fs, real running servers — several use targeted fs fault-injection
// (delaying/ordering renames, counting fsyncs) to make an otherwise timing-dependent durability race
// deterministic. No mocks of the code under test, no new dependencies.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { Audit } from "../src/audit.js";
import { BridgeStore, BridgeError } from "../src/store.js";
import { createServer } from "../src/server.js";
import { AuthStore } from "../src/auth.js";
import { signMessage, canonicalMessage } from "../src/sign.js";
import { keyMatchesPrincipal } from "../public/app.js";

async function withDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-fix-"));
  try { await fn(dir); } finally { await fs.rm(dir, { recursive: true, force: true }); }
}
async function exists(f) { try { await fs.access(f); return true; } catch { return false; } }

// ── B1 HIGH — verifyChain() false-tampers after rotation; verifyDir() spans generations ─────────────
test("B1: a clean rotated audit log verifies ok across generations (single-file verify would false-flag it)", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir, { maxBytes: 50 }); // tiny cap: the 2nd record forces exactly one rotation
    await audit.record({ op: "a", result: "ok" });
    await audit.record({ op: "b", result: "ok" });
    assert.ok(await exists(path.join(dir, "audit.log.1")), "rotation must have happened");

    // The old behavior — verifying the CURRENT file alone — false-flags tamper, because audit.log's first
    // `prev` is the rotated file's tip, not null. This is exactly the bug the finding describes.
    const single = await Audit.verifyChain(path.join(dir, "audit.log"));
    assert.equal(single.ok, false, "single-file verify false-positives on a clean rotated log");

    // The fix: verify both generations as one continuous chain.
    const v = await Audit.verifyDir(dir);
    assert.equal(v.ok, true, "a clean rotated log must verify ok");
    assert.equal(v.lines, 2, "both generations' lines are counted as one chain");
    assert.equal(v.generations, 2);
    assert.equal(v.droppedGenerations, 0, "nothing dropped yet — both generations still on disk");
  }));

// ── B2 HIGH — concurrent posts must all be DURABLY on disk (serialized persist) ──────────────────────
test("B2: concurrent posts are all durably on disk — no acked message lost to a persist reorder", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-durable-"));
  const store = new BridgeStore(dir);
  await store.init();
  const origRename = fsp.rename;
  // Fault injection: force whichever channels.json snapshot is PARTIAL (missing the 2nd message) to land
  // LAST — the precise reorder that drops an already-acked message when persists run concurrently. With
  // the fix, persists are serialized so the partial snapshot is never even written concurrently.
  fsp.rename = async (from, to) => {
    if (path.basename(to) === "channels.json") {
      try {
        const snap = JSON.parse(await fsp.readFile(from, "utf8"));
        const n = snap?.g?.messages?.length ?? 0;
        if (n < 2) await new Promise((r) => setTimeout(r, 150)); // partial snapshot: force it to land last
      } catch { /* ignore — fall through */ }
    }
    return origRename(from, to);
  };
  try {
    await Promise.all([
      store.postMessage("g", "a", "one", { nonce: "n1" }),
      store.postMessage("g", "a", "two", { nonce: "n2" }),
    ]);
    // Assert the DURABLE file, not in-memory state.
    const onDisk = JSON.parse(await fsp.readFile(path.join(dir, "channels.json"), "utf8"));
    const ids = onDisk.g.messages.map((m) => m.id).sort((x, y) => x - y);
    assert.deepEqual(ids, [1, 2], "both acked messages must be durably on disk — neither dropped by a persist reorder");
    assert.equal(onDisk.g.seq, 2, "the durable seq matches the acked ids, so a restart never reissues one");
  } finally {
    fsp.rename = origRename;
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ── B3 HIGH — unauthenticated flood must not be able to write unbounded audit volume ────────────────
async function readAuditStable(dir, { settleMs = 250, timeoutMs = 4000 } = {}) {
  const file = path.join(dir, "audit.log");
  const deadline = Date.now() + timeoutMs;
  let last = -1;
  for (;;) {
    let n = 0;
    try { n = (await fs.readFile(file, "utf8")).split("\n").filter(Boolean).length; } catch { n = 0; }
    if (n === last && n > 0) break;
    last = n;
    if (Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, settleMs));
  }
  let lines = [];
  try { lines = (await fs.readFile(file, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { /* none */ }
  return lines;
}

test("B3: an unauthenticated flood is rate-limited BEFORE it audits — audit volume is capped, not amplified", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-flood-"));
  const server = createServer({ dataDir: dir, unauthBurst: 30, unauthRefillPerSec: 0 }); // no refill during the burst
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const N = 200;
    const results = await Promise.all(Array.from({ length: N }, () =>
      fetch(`${base}/api/channels/general/messages`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: "x", nonce: "n", ts: Date.now(), sig: "x" }),
      }).then((r) => r.status)));
    const n429 = results.filter((s) => s === 429).length;
    const n401 = results.filter((s) => s === 401).length;
    assert.ok(n429 > 100, `most of a ${N}-request unauth flood must be refused pre-audit (got ${n429} × 429)`);

    const lines = await readAuditStable(dir);
    const audited = lines.filter((l) => l.result === "deny" && l.reason === "unauthenticated").length;
    assert.ok(audited <= 35, `unauth audit volume must be capped near the burst limit, not one-per-request (audited ${audited} of ${N})`);
    assert.ok(audited <= n401 + 1, "an audited unauth line corresponds to a 401, never to a rate-limited 429");
  } finally {
    await new Promise((r) => server.close(r));
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 });
  }
});

// ── B4 MED-HIGH — a dropped generation is DETECTABLE via the rotation ledger ─────────────────────────
test("B4: dropping a generation is detectable — the rotation ledger counts generations that no longer survive", () =>
  withDir(async (dir) => {
    const audit = new Audit(dir, { maxBytes: 50 });
    await audit.record({ op: "a", result: "ok" }); // gen 1
    await audit.record({ op: "b", result: "ok" }); // rotation 1 → gen 2
    await audit.record({ op: "c", result: "ok" }); // rotation 2 → gen 3 (gen 1's file is evicted by 2-gen retention)

    let v = await Audit.verifyDir(dir);
    assert.equal(v.ok, true, "the surviving chain is still clean");
    assert.equal(v.generations, 3, "the ledger knows 3 generations have existed");
    assert.equal(v.generationsOnDisk, 2, "only 2 generations survive on disk");
    assert.equal(v.droppedGenerations, 1, "the evicted generation is DETECTABLE, not silent");

    // Now delete the retained previous generation outright (an attacker removing history).
    await fs.rm(path.join(dir, "audit.log.1"), { force: true });
    v = await Audit.verifyDir(dir);
    assert.equal(v.generations, 3, "the anchor still attests all 3 generations existed");
    assert.equal(v.droppedGenerations, 2, "the deletion of a whole generation is detectable");
  }));

// ── B5 MED — crash between rotation-rename and first append must not orphan the chain ────────────────
test("B5: a crash between rotation and the first append seeds the new chain from the rotated tip (no clean orphan)", () =>
  withDir(async (dir) => {
    const a1 = new Audit(dir);
    await a1.record({ op: "a", result: "ok" });
    await a1.record({ op: "b", result: "ok" });
    const logFile = path.join(dir, "audit.log");
    const tip = JSON.parse((await fs.readFile(logFile, "utf8")).split("\n").filter(Boolean).pop()).hash;

    // Simulate the crash: rotation renamed audit.log → audit.log.1, then the process died BEFORE the first
    // append recreated audit.log. On restart, audit.log is absent and audit.log.1 holds the chain.
    await fs.rename(logFile, `${logFile}.1`);
    assert.equal(await exists(logFile), false, "audit.log is absent, as after the crash");

    const a2 = new Audit(dir);
    await a2.record({ op: "c", result: "ok" }); // the first append after the crash
    const firstNew = JSON.parse((await fs.readFile(logFile, "utf8")).split("\n").filter(Boolean)[0]);
    assert.equal(firstNew.prev, tip, "the first post-crash line continues from the rotated tip, not a fresh null-rooted chain");
    const v = await Audit.verifyDir(dir);
    assert.equal(v.ok, true, "the chain is continuous across the crash boundary");
  }));

// ── B6 MED — a single message's text is capped (oversize → rejected, not an unbounded rewrite) ───────
test("B6 (store): an oversize message is rejected with TOO_LARGE, not accepted", () =>
  withDir(async (dir) => {
    const store = new BridgeStore(dir, { maxMessageBytes: 1024 });
    await store.init();
    try {
      await assert.rejects(
        () => store.postMessage("g", "a", "x".repeat(2000), { nonce: "n1" }),
        (e) => e instanceof BridgeError && e.code === "TOO_LARGE",
      );
      // a message within the cap still works
      const ok = await store.postMessage("g", "a", "ok", { nonce: "n2" });
      assert.equal(ok.id, 1);
    } finally { await store.close(); }
  }));

test("B6 (http): an oversize post is refused 413 TOO_LARGE", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-big-"));
  const setup = new AuthStore(dir);
  const a = await setup.register("agent-a", "tok-a", ["channel:general"]);
  const server = createServer({ dataDir: dir });
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const text = "y".repeat(20000); // over the 16 KiB default cap, still under the 256 KiB body limit
    const nonce = randomUUID(), ts = Date.now();
    const sig = signMessage(a.privateKey, canonicalMessage({ from: "agent-a", channel: "general", nonce, ts, text }));
    const res = await fetch(`${base}/api/channels/general/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a" },
      body: JSON.stringify({ text, nonce, ts, sig }),
    });
    assert.equal(res.status, 413);
    assert.equal((await res.json()).code, "TOO_LARGE");
  } finally {
    await new Promise((r) => server.close(r));
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ── B7 MED — long-poll holding is capped, and a socket timeout is set ────────────────────────────────
test("B7: over the held-poll cap a wait degrades to an immediate read, and a socket timeout is configured", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-hold-"));
  const setup = new AuthStore(dir);
  await setup.register("agent-a", "tok-a", ["channel:general"]);
  const server = createServer({ dataDir: dir, maxHeldPolls: 0 }); // cap 0 → never hold a long-poll
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.ok(server.timeout > 0, "a socket idle timeout must be set to reap stuck connections");
    const start = Date.now();
    // wait=1 on an empty channel would hold ~25s without the cap; with cap 0 it must return immediately.
    const res = await fetch(`${base}/api/channels/general/messages?sinceId=0&wait=1`, {
      headers: { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a" },
    }).then((r) => r.json());
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 2000, `over the held-poll cap the request must not hold the connection (took ${elapsed}ms)`);
    assert.equal(res.ok, true);
    assert.deepEqual(res.messages, []);
  } finally {
    await new Promise((r) => server.close(r));
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ── B8 LOW-MED — durable writes are fsync'd ──────────────────────────────────────────────────────────
test("B8: a durable store write is fsync'd (data + directory), not just written and renamed", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-sync-"));
  const origOpen = fsp.open;
  let syncs = 0;
  fsp.open = async (...args) => {
    const fh = await origOpen(...args);
    const realSync = fh.sync.bind(fh);
    fh.sync = async () => { syncs++; return realSync(); };
    return fh;
  };
  try {
    const store = new BridgeStore(dir);
    await store.init();
    await store.postMessage("g", "a", "durable", { nonce: "n1" });
    assert.ok(syncs > 0, "the durable write path must fsync (old code used writeFile+rename with no fsync)");
    await store.close();
  } finally {
    fsp.open = origOpen;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ── B9 LOW — a durable message's nonce is always persisted BEFORE the message ────────────────────────
test("B9: nonces.json is persisted before channels.json, so a durable message's nonce is never missing", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-order-"));
  const origRename = fsp.rename;
  const order = [];
  fsp.rename = async (from, to) => { order.push(path.basename(to)); return origRename(from, to); };
  try {
    const store = new BridgeStore(dir);
    await store.init();
    order.length = 0; // ignore any renames from init
    await store.postMessage("g", "a", "approve", { nonce: "n1" });
    const iNonce = order.indexOf("nonces.json");
    const iChannels = order.indexOf("channels.json");
    assert.ok(iNonce >= 0 && iChannels >= 0, "both files are persisted");
    assert.ok(iNonce < iChannels, "the nonce must be recorded before the message that used it (no replay-after-crash window)");
    await store.close();
  } finally {
    fsp.rename = origRename;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ── B10 LOW — a remembered signing key is reused only for the principal it belongs to ────────────────
test("B10: a stored signing key is reused only when it belongs to the entered principal", () => {
  assert.equal(keyMatchesPrincipal("agent-a", "agent-a"), true, "same principal → reuse the remembered key");
  assert.equal(keyMatchesPrincipal("agent-a", "agent-b"), false, "different principal → must NOT reuse agent-a's key when joining as agent-b");
  assert.equal(keyMatchesPrincipal(null, "agent-a"), false, "no remembered principal → no reuse");
  assert.equal(keyMatchesPrincipal("agent-a", ""), false, "no entered principal → no reuse");
});
