// Concurrency + audit-emission tests. "Multiple principals posting/long-polling at once" and "audit
// entries are actually written" are both real, previously-untested claims the hub makes implicitly —
// these prove them against a real running server, not a single-client happy path.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createServer } from "../src/server.js";
import { AuthStore } from "../src/auth.js";
import { signMessage, canonicalMessage } from "../src/sign.js";

async function withServer(n, fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-conc-"));
  const setup = new AuthStore(dir);
  const principals = {};
  for (let i = 0; i < n; i++) {
    const id = `agent-${i}`;
    const reg = await setup.register(id, `tok-${i}`, ["channel:general"]);
    principals[id] = { token: `tok-${i}`, key: reg.privateKey };
  }
  const server = createServer({ dataDir: dir });
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, principals, dir); }
  finally {
    await new Promise((r) => server.close(r));
    // Audit writes are fire-and-forget (never block the API response — see src/audit.js), so a
    // concurrent test can still have one in flight (creating/renaming a file inside `dir`) the instant
    // server.close() resolves. maxRetries/retryDelay is Node's own built-in handling for exactly this
    // kind of transient ENOTEMPTY/EBUSY race on a directory being torn down mid-write.
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 });
  }
}

function headers(id, tok) { return { "X-Bridge-Principal": id, "X-Bridge-Token": tok }; }
function signedBody(keys, id, channel, text) {
  const nonce = randomUUID(), ts = Date.now();
  return { text, nonce, ts, sig: signMessage(keys, canonicalMessage({ from: id, channel, nonce, ts, text })) };
}

// Audit writes are deliberately fire-and-forget (the server never awaits audit.record(), so a slow
// disk never blocks the API response) — so a test must poll for the line to land, the same way any
// real audit consumer tailing the file would, rather than assume it's there the instant the HTTP call
// resolves.
async function readAuditLines(dir, { timeoutMs = 2000 } = {}) {
  const file = path.join(dir, "audit.log");
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const raw = await fs.readFile(file, "utf8");
      const lines = raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
      if (lines.length > 0) return lines;
    } catch { /* not written yet */ }
    if (Date.now() > deadline) return [];
    await new Promise((r) => setTimeout(r, 10));
  }
}

test("CONCURRENCY: N principals posting to the same channel simultaneously all succeed with distinct, gap-free ids", () =>
  withServer(8, async (base, principals) => {
    const posts = Object.entries(principals).map(([id, p]) =>
      fetch(`${base}/api/channels/general/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers(id, p.token) },
        body: JSON.stringify(signedBody(p.key, id, "general", `hello from ${id}`)),
      }).then((r) => r.json()));
    const results = await Promise.all(posts);
    for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
    const ids = results.map((r) => r.message.id).sort((a, b) => a - b);
    assert.deepEqual(ids, Array.from({ length: 8 }, (_, i) => i + 1), "concurrent writers must never collide or skip an id — the single-writer lock serializes them");
    const senders = new Set(results.map((r) => r.message.from));
    assert.equal(senders.size, 8, "every message is attributed to its real, distinct authenticated sender");
  }));

test("CONCURRENCY: a long-poller waiting on the channel wakes for a message posted by a DIFFERENT concurrent principal", () =>
  withServer(2, async (base, principals) => {
    const [[watcherId, watcher], [posterId, poster]] = Object.entries(principals);
    const waitPromise = fetch(`${base}/api/channels/general/messages?sinceId=0&wait=1`, { headers: headers(watcherId, watcher.token) }).then((r) => r.json());
    await new Promise((r) => setTimeout(r, 150));
    const postRes = await fetch(`${base}/api/channels/general/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers(posterId, poster.token) },
      body: JSON.stringify(signedBody(poster.key, posterId, "general", "wake up")),
    }).then((r) => r.json());
    const start = Date.now();
    const woken = await waitPromise;
    assert.ok(Date.now() - start < 2000, "the long-poll must resolve promptly on arrival, not on its own timeout");
    assert.equal(woken.messages.length >= 1, true);
    assert.equal(woken.messages[woken.messages.length - 1].from, posterId);
    assert.equal(postRes.ok, true);
  }));

test("CONCURRENCY: many simultaneous long-pollers on the SAME channel all wake for one real post — no listener starves", () =>
  withServer(6, async (base, principals) => {
    const entries = Object.entries(principals);
    const [[posterId, poster], ...watchers] = entries;
    const waits = watchers.map(([id, p]) => fetch(`${base}/api/channels/general/messages?sinceId=0&wait=1`, { headers: headers(id, p.token) }).then((r) => r.json()));
    await new Promise((r) => setTimeout(r, 150));
    await fetch(`${base}/api/channels/general/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers(posterId, poster.token) },
      body: JSON.stringify(signedBody(poster.key, posterId, "general", "one post, many watchers")),
    });
    const results = await Promise.all(waits);
    for (const r of results) assert.ok(r.messages.length >= 1, "every simultaneous long-poller must be woken, none left hanging");
  }));

// ── audit emission is real, not just "the code calls audit.record()" ──────────────────────────────

test("AUDIT: a denied (unauthenticated) request really lands in audit.log, not just the HTTP response", () =>
  withServer(1, async (base, principals, dir) => {
    await fetch(`${base}/api/channels/general/messages`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "x", nonce: "n", ts: Date.now(), sig: "x" }),
    });
    const lines = await readAuditLines(dir);
    const entry = lines.find((l) => l.result === "deny" && l.reason === "unauthenticated");
    assert.ok(entry, "an unauthenticated attempt must leave a real audit trail");
    assert.equal(entry.principal, null, "no principal was ever established, so none is claimed");
  }));

test("AUDIT: a successful signed post really lands in audit.log with the server-established principal and message id", () =>
  withServer(1, async (base, principals, dir) => {
    const [id, p] = Object.entries(principals)[0];
    const res = await fetch(`${base}/api/channels/general/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers(id, p.token) },
      body: JSON.stringify(signedBody(p.key, id, "general", "audited post")),
    }).then((r) => r.json());
    const lines = await readAuditLines(dir);
    const entry = lines.find((l) => l.op === "message.post" && l.result === "ok");
    assert.ok(entry);
    assert.equal(entry.principal, id);
    assert.equal(entry.msgId, res.message.id, "the audited msgId is the REAL assigned id, not client input");
  }));

test("AUDIT: a rejected (spoofed sender) post really lands in audit.log as a deny", () =>
  withServer(1, async (base, principals, dir) => {
    const [id, p] = Object.entries(principals)[0];
    await fetch(`${base}/api/channels/general/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers(id, p.token) },
      body: JSON.stringify({ ...signedBody(p.key, id, "general", "spoof"), from: "someone-else" }),
    });
    const lines = await readAuditLines(dir);
    const entry = lines.find((l) => l.reason === "sender_spoof");
    assert.ok(entry, "a spoofing attempt must be audited under the REAL authenticated principal, not the claimed one");
    assert.equal(entry.principal, id);
  }));
