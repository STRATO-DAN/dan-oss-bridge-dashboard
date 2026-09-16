// HTTP-level tests: the review's five "breaking tests" plus the auth/authz/signing core, driven over
// real fetch against a real running hub. Each test uses its own isolated temp data dir and its own
// server. Every accepted post is signed with the principal's real Ed25519 key; the invariants are
// asserted against server behavior, not mocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createServer } from "../src/server.js";
import { AuthStore } from "../src/auth.js";
import { signMessage, canonicalMessage, verifyMessage } from "../src/sign.js";

async function withServer(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-http-"));
  const setup = new AuthStore(dir);
  const a = await setup.register("agent-a", "tok-a", ["channel:general"]);
  const b = await setup.register("agent-b", "tok-b", ["channel:general", "channel:secret"]);
  const keys = { "agent-a": a.privateKey, "agent-b": b.privateKey };
  const server = createServer({ dataDir: dir });
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, keys); }
  finally { await new Promise((r) => server.close(r)); await fs.rm(dir, { recursive: true, force: true }); }
}

const A = { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a" };
const B = { "X-Bridge-Principal": "agent-b", "X-Bridge-Token": "tok-b" };

// A correctly signed body for `principal` over `channel`/`text`.
function signed(keys, principal, channel, text, { nonce = randomUUID(), ts = Date.now() } = {}) {
  const sig = signMessage(keys[principal], canonicalMessage({ from: principal, channel, nonce, ts, text }));
  return { text, nonce, ts, sig };
}

function postMsg(base, channel, headers, body) {
  return fetch(`${base}/api/channels/${channel}/messages`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

test("INV-02: an unauthenticated post is denied (401), never accepted", () =>
  withServer(async (base) => {
    const res = await postMsg(base, "general", {}, { text: "hi", nonce: "n1", ts: Date.now(), sig: "x" });
    assert.equal(res.status, 401);
  }));

test("a bad token is denied (401)", () =>
  withServer(async (base) => {
    const res = await postMsg(base, "general", { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "wrong" }, { text: "hi", nonce: "n1", ts: Date.now(), sig: "x" });
    assert.equal(res.status, 401);
  }));

test("TEST A / INV-01: a caller cannot claim another principal's identity", () =>
  withServer(async (base, keys) => {
    const spoof = await postMsg(base, "general", A, { ...signed(keys, "agent-a", "general", "approve"), from: "agent-b" });
    assert.equal(spoof.status, 403);
    const ok = await postMsg(base, "general", A, signed(keys, "agent-a", "general", "hello"));
    assert.equal(ok.status, 200);
    const data = await ok.json();
    assert.equal(data.message.from, "agent-a", "server established the sender, not the caller");
  }));

test("TEST B / INV-03: a principal cannot use a channel outside its scope", () =>
  withServer(async (base, keys) => {
    const denied = await postMsg(base, "secret", A, signed(keys, "agent-a", "secret", "peek"));
    assert.equal(denied.status, 403);
    const allowed = await postMsg(base, "secret", B, signed(keys, "agent-b", "secret", "mine"));
    assert.equal(allowed.status, 200);
  }));

test("TEST C / INV-06: a replayed action message is rejected (409)", () =>
  withServer(async (base, keys) => {
    const body = signed(keys, "agent-a", "general", "approve deployment", { nonce: "replay-me" });
    assert.equal((await postMsg(base, "general", A, body)).status, 200);
    const replay = await postMsg(base, "general", A, body);
    assert.equal(replay.status, 409);
    assert.equal((await replay.json()).code, "REPLAY");
  }));

test("INV-10: a post with no signature is refused (400)", () =>
  withServer(async (base) => {
    const res = await postMsg(base, "general", A, { text: "unsigned", nonce: randomUUID(), ts: Date.now() });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).code, "SIG_REQUIRED");
  }));

test("INV-10: a bad signature, and a signature over different text, are refused (403)", () =>
  withServer(async (base, keys) => {
    const garbage = await postMsg(base, "general", A, { text: "x", nonce: randomUUID(), ts: Date.now(), sig: "AAAA" });
    assert.equal(garbage.status, 403);
    assert.equal((await garbage.json()).code, "BAD_SIGNATURE");
    // sign "reviewed", then submit "malicious" with that signature → canonical mismatch → refused.
    const s = signed(keys, "agent-a", "general", "reviewed");
    const swapped = await postMsg(base, "general", A, { ...s, text: "malicious" });
    assert.equal(swapped.status, 403);
  }));

test("INV-10: a stored message is independently verifiable via the principal's public key", () =>
  withServer(async (base, keys) => {
    await postMsg(base, "general", A, signed(keys, "agent-a", "general", "verifiable message"));
    const pub = await (await fetch(`${base}/api/principals/agent-a/pubkey`, { headers: A })).json();
    assert.equal(pub.ok, true);
    const read = await (await fetch(`${base}/api/channels/general/messages?sinceId=0`, { headers: A })).json();
    const msg = read.messages[0];
    assert.equal(verifyMessage(msg, "general", pub.publicKey), true, "receiver verifies authorship without trusting the hub");
    assert.equal(verifyMessage({ ...msg, text: msg.text + "!" }, "general", pub.publicKey), false, "any tampering is detected");
  }));

test("INV-09: presence is the authenticated principal — you cannot announce another agent online", () =>
  withServer(async (base) => {
    await fetch(`${base}/api/channels/general/presence`, { method: "POST", headers: { "content-type": "application/json", ...A }, body: "{}" });
    const data = await (await fetch(`${base}/api/channels/general/presence`, { headers: A })).json();
    assert.equal(data.online.length, 1);
    assert.equal(data.online[0].from, "agent-a");
  }));

test("cross-site browser requests are refused", () =>
  withServer(async (base, keys) => {
    const res = await postMsg(base, "general", { ...A, "Sec-Fetch-Site": "cross-site" }, signed(keys, "agent-a", "general", "csrf"));
    assert.equal(res.status, 403);
  }));

test("status lists only the channels the principal is authorized for", () =>
  withServer(async (base, keys) => {
    await postMsg(base, "general", B, signed(keys, "agent-b", "general", "g"));
    await postMsg(base, "secret", B, signed(keys, "agent-b", "secret", "s"));
    const aView = await (await fetch(`${base}/api/status`, { headers: A })).json();
    assert.deepEqual(aView.channels, ["general"], "agent-a must not see the `secret` channel it can't use");
    const bView = await (await fetch(`${base}/api/status`, { headers: B })).json();
    assert.deepEqual(bView.channels, ["general", "secret"]);
  }));
