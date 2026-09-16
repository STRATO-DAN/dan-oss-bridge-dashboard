// The signature primitive in isolation: canonical determinism, a real Ed25519 sign/verify roundtrip,
// tamper detection on every signed field, wrong-key rejection, and fail-closed behavior on garbage.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { canonicalMessage, signMessage, verifySignature, verifyMessage } from "../src/sign.js";

function keypair() {
  const kp = generateKeyPairSync("ed25519");
  return { pub: kp.publicKey.export({ format: "jwk" }), priv: kp.privateKey.export({ format: "jwk" }) };
}
const fields = { from: "agent-1", channel: "general", nonce: "nonce-1", ts: 1789000000000, text: "approve deployment" };

test("canonicalMessage is deterministic and unambiguous with newlines/quotes in text", () => {
  const a = canonicalMessage(fields);
  const b = canonicalMessage({ ...fields });
  assert.equal(a, b);
  // a text that tries to forge a field boundary produces a different canonical than moving the boundary
  const tricky = canonicalMessage({ ...fields, text: 'x","injected' });
  assert.notEqual(tricky, canonicalMessage({ ...fields, text: "x" }));
});

test("a valid signature verifies; a wrong public key does not", () => {
  const k = keypair(), other = keypair();
  const canonical = canonicalMessage(fields);
  const sig = signMessage(k.priv, canonical);
  assert.equal(verifySignature(k.pub, canonical, sig), true);
  assert.equal(verifySignature(other.pub, canonical, sig), false);
});

test("tampering with ANY signed field breaks verification", () => {
  const k = keypair();
  const sig = signMessage(k.priv, canonicalMessage(fields));
  for (const change of [
    { from: "agent-2" },
    { channel: "other" },
    { nonce: "nonce-2" },
    { ts: fields.ts + 1 },
    { text: "APPROVE deployment" },
  ]) {
    assert.equal(verifySignature(k.pub, canonicalMessage({ ...fields, ...change }), sig), false,
      `changing ${Object.keys(change)[0]} must break the signature`);
  }
});

test("verifyMessage checks a stored message against a public key", () => {
  const k = keypair();
  const ts = Date.now();
  const sig = signMessage(k.priv, canonicalMessage({ from: "agent-1", channel: "general", nonce: "n", ts, text: "hi" }));
  const stored = { id: 1, from: "agent-1", text: "hi", ts, nonce: "n", sig };
  assert.equal(verifyMessage(stored, "general", k.pub), true);
  assert.equal(verifyMessage({ ...stored, text: "hI" }, "general", k.pub), false, "a modified stored message fails");
  assert.equal(verifyMessage(stored, "wrong-channel", k.pub), false, "the wrong channel fails");
});

test("verify is fail-closed on garbage input, never throws", () => {
  const k = keypair();
  assert.equal(verifySignature(k.pub, "x", "not-base64url!!!"), false);
  assert.equal(verifySignature(null, "x", "AAAA"), false);
  assert.equal(verifySignature(k.pub, "x", ""), false);
  assert.equal(verifyMessage(null, "general", k.pub), false);
  assert.equal(verifyMessage({ from: "a" }, "general", k.pub), false); // no sig
});
