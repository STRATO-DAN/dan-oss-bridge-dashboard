// Rotation survival: re-registering a principal must not retroactively break verification
// of messages signed before the rotation. Current key verifies new messages; the retired key
// verifies old ones; only messages no known key verifies count as forged.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createServer } from "../src/server.js";
import { AuthStore } from "../src/auth.js";
import { signMessage, canonicalMessage } from "../src/sign.js";

async function withServer(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-rotation-"));
  const setup = new AuthStore(dir);
  const a = await setup.register("agent-a", "tok-a", ["channel:general"]);
  const server = createServer({ dataDir: dir });
  await server._bridge.ready;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, setup, a.privateKey); }
  finally {
    await new Promise((r) => server.close(r));
    await server._bridge.audit.drain();
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function signed(privateKey, principal, channel, text) {
  const nonce = randomUUID();
  const ts = Date.now();
  const sig = signMessage(privateKey, canonicalMessage({ from: principal, channel, nonce, ts, text }));
  return { text, nonce, ts, sig };
}

function postMsg(base, channel, headers, body) {
  return fetch(`${base}/api/channels/${channel}/messages`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function getVerify(base, headers, channel) {
  const res = await fetch(`${base}/api/channels/${channel}/verify`, { headers });
  assert.equal(res.status, 200);
  return res.json();
}

test("ROTATION: messages signed before re-registration still verify after it", async () => {
  await withServer(async (base, setup, oldPrivateKey) => {
    const A1 = { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a" };
    // Pre-rotation message, signed with the original key.
    const first = await postMsg(base, "general", A1, signed(oldPrivateKey, "agent-a", "general", "before rotation"));
    assert.equal(first.status, 200);

    // Rotate: new token AND new signing key. Old key retires into historicalKeys.
    const before = setup.getPublicKey("agent-a");
    const rotated = await setup.register("agent-a", "tok-a2", ["channel:general"]);
    assert.notDeepEqual(rotated.publicKey, before, "rotation really issues a new signing key");

    // Post-rotation message, signed with the newest key.
    const A2 = { "X-Bridge-Principal": "agent-a", "X-Bridge-Token": "tok-a2" };
    const second = await postMsg(base, "general", A2, signed(rotated.privateKey, "agent-a", "general", "after rotation"));
    assert.equal(second.status, 200);

    const v = await getVerify(base, A2, "general");
    assert.equal(v.counts.total, 2);
    assert.equal(v.counts.sigForged, 0, "no legitimately signed message may read as forged after rotation");
    assert.ok(v.records.every((r) => r.sigVerified === true), "old and new messages both verify");
  });
});

test("ROTATION: getPublicKey still returns only the current key (unchanged contract)", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-rotation-"));
  try {
    const setup = new AuthStore(dir);
    const first = await setup.register("agent-a", "tok-a", ["channel:general"]);
    await setup.register("agent-a", "tok-b", ["channel:general"]);
    const history = setup.getVerificationKeys("agent-a");
    assert.equal(history.length, 2, "current + one retired key");
    assert.deepEqual(setup.getPublicKey("agent-a"), history[0], "getPublicKey is still the current key");
    assert.deepEqual(history[1], first.publicKey, "retired key preserved verbatim");
    assert.equal(setup.getVerificationKeys("nobody").length, 0);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
