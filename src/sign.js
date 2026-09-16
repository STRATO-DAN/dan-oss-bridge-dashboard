// Independent message authenticity — Ed25519 signatures a receiver can verify WITHOUT trusting the
// hub. Token auth establishes the sender to the *server*; a signature lets Agent B verify Agent A
// directly, and makes tampering detectable end-to-end. Node stdlib crypto; the JWK key shape is the
// same one the browser's WebCrypto uses, so an agent, the CLI, and the dashboard all sign identically.
import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify } from "node:crypto";

// Canonical bytes a signature covers. A JSON array of primitives is deterministic across Node and
// browsers and unambiguous even when `text` (or a nonce) contains newlines or quotes — so there is no
// field-separator injection. `id` is NOT signed: the server assigns it, the client can't know it, and
// a receiver reconstructs the canonical form from the stored fields it already has.
export function canonicalMessage({ from, channel, nonce, ts, text }) {
  return JSON.stringify([String(from), String(channel), String(nonce), Number(ts), String(text)]);
}

/** Verify a base64url Ed25519 signature over `canonical` against a principal's public JWK. Fail-closed:
 *  any missing input, bad key, or malformed signature returns false, never throws. */
export function verifySignature(publicJwk, canonical, sigB64url) {
  try {
    if (!publicJwk || !sigB64url) return false;
    const key = createPublicKey({ key: publicJwk, format: "jwk" });
    return edVerify(null, Buffer.from(canonical, "utf8"), key, Buffer.from(String(sigB64url), "base64url"));
  } catch {
    return false;
  }
}

/** Produce a base64url Ed25519 signature (used by the `sign` CLI helper, receiver examples, and tests
 *  — the browser signs with WebCrypto's subtle.sign over the same canonical bytes). */
export function signMessage(privateJwk, canonical) {
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  return edSign(null, Buffer.from(canonical, "utf8"), key).toString("base64url");
}

/** Convenience for a receiver: verify a stored message came from `publicJwk` and wasn't modified.
 *  `channel` is supplied by the caller (it's the channel the message was read from). */
export function verifyMessage(message, channel, publicJwk) {
  if (!message || typeof message !== "object") return false;
  const canonical = canonicalMessage({ from: message.from, channel, nonce: message.nonce, ts: message.ts, text: message.text });
  return verifySignature(publicJwk, canonical, message.sig);
}
