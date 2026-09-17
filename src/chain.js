// [DAN] BRIDGE DASHBOARD — whole-log tamper-evidence via a per-message hash chain. Node stdlib only.
//
// Every message is ALREADY independently Ed25519-signed (see sign.js), which proves a single message's
// own content was not edited. It does NOT, on its own, detect a writer who DELETES, REORDERS, or INSERTS
// whole messages in a channel's stored log — the surviving signatures still verify. A hash chain closes
// that: each message stores `prev`, the SHA-256 of the message before it in the channel, so removing,
// reordering, or inserting any message makes the following message's stored `prev` disagree with the
// recomputed link — and `verify` reports exactly where.
//
// Two deliberate points, mirroring the CLI twin (dan-oss-bridge):
//  - The link binds the message's identity + content + its own signature + its link to the prior message
//    (prev, id, from, text, ts, nonce, sig). Editing a stored message breaks BOTH its Ed25519 signature
//    and the chain at the next message; deleting/reordering breaks the chain even though each surviving
//    signature still verifies on its own.
//  - The link does NOT feed the signature. Signatures stay exactly the canonicalMessage() form sign.js
//    already uses, so a message signed before chaining existed still verifies. Signature (authenticity)
//    and chain (whole-log integrity) are separate, composable layers.
//
// The hub is single-writer (one process holds the data-dir lock) and persists are serialized, so posts
// append in a total order and the chain is naturally linear — no extra locking is needed here (unlike the
// multi-writer CLI, where chaining is opt-in behind a file lock).
//
// Inherent limit (documented, not a bug): the chain proves nothing was changed WITHIN the messages it
// covers, but a channel retains only its most recent window — its oldest retained message's `prev` points
// at an aged-out message, so that message is an un-checkable ANCHOR, and truncating the newest messages
// leaves a shorter still-valid chain. Detecting a dropped head/tail needs an external anchor, out of scope
// for one local log. This is the same honest boundary the store already reports as `minRetainedId`/`gap`.
import { createHash } from "node:crypto";

// The `prev` of the very first message ever posted to a channel: 64 hex zeros ("nothing precedes this").
export const GENESIS = "0".repeat(64);

// One unambiguous byte string for a message's chained fields — a JSON array of primitives, deterministic
// and free of field-separator injection (same discipline as sign.js's canonicalMessage).
function canonical(prev, m) {
  return JSON.stringify([
    String(prev),
    Number(m.id),
    String(m.from),
    String(m.text),
    Number(m.ts),
    String(m.nonce ?? ""),
    String(m.sig ?? ""),
  ]);
}

/** The SHA-256 (hex) link OF a stored message — what the NEXT message records as its `prev`. Uses the
 *  message's own stored `prev` (empty string for a pre-chain/legacy message) so a writer and a verifier
 *  compute the identical value. */
export function linkOf(m) {
  const prev = typeof m.prev === "string" ? m.prev : "";
  return createHash("sha256").update(canonical(prev, m), "utf8").digest("hex");
}

/** Walk a channel's retained messages (oldest-first) and return per-message chain verdicts plus a
 *  whole-log summary. Pure: no I/O, no signature checks (the server layer adds those, since keys live in
 *  the auth store). `chainOk` is:
 *    - true  → this message's stored `prev` matches the recomputed link of the message before it
 *    - false → it does not (deletion / reorder / insertion / in-place edit); the first such id is the break
 *    - null  → not checkable: an un-chained (legacy) message, or the oldest retained message whose
 *              predecessor has aged out of the window (an honest anchor, not a break). */
export function verifyChain(messages) {
  let chainPresent = false;
  let firstBreakId = null;
  let expected = null; // the link the next chained message must carry as its `prev`
  const verdicts = [];
  for (const m of messages) {
    const hasPrev = typeof m.prev === "string" && m.prev.length > 0;
    let chainOk = null;
    if (hasPrev) {
      chainPresent = true;
      if (expected === null) {
        // First chained message in the retained window. If it anchors to GENESIS it is the true first
        // message ever and IS checkable; otherwise its predecessor aged out — an anchor, not a break.
        chainOk = m.prev === GENESIS ? true : null;
      } else {
        chainOk = m.prev === expected;
        if (!chainOk && firstBreakId === null) firstBreakId = m.id;
      }
    }
    verdicts.push({ id: m.id, chainOk });
    expected = linkOf(m); // compute this message's link for the next, chained or not
  }
  return { chainPresent, firstBreakId, verdicts };
}
