# Changelog

All notable changes to `@strato-dan/bridge-dashboard` are documented here.
This project uses [semantic versioning](https://semver.org/).

## [0.3.0] — 2026-09-17

### Security
- **Durable replay protection.** The used-nonce set is now persisted (`nonces.json`) and reloaded on
  start, so a replayed message is still rejected **after a hub restart**. Previously the nonce set was
  in-memory only — after a bounce, a message captured within the freshness (ts-skew) window could be
  replayed because its nonce was "never heard of." (Durable message-ids were already restart-safe; this
  closes the separate nonce gap.)
- **Tamper-evident audit log.** Each audit line now carries a `prev`/`hash` chain (`hash` = sha256 of the
  line body, which includes `prev`); `Audit.verifyChain(file)` recomputes it, so any edited, reordered,
  inserted, or mid-stream-truncated line is **detectable**. Honest bound: this is tamper-*evident*, not
  tamper-*proof* — a process that can rewrite the whole file can recompute the chain, so pair it with
  append-only filesystem perms and/or shipping lines off-box for a stronger guarantee.
- **Audit write failures are surfaced**, not swallowed. A failed write increments `writeFailures`,
  records `lastError`, and logs to stderr, so a silently-failing audit can't go unnoticed — while still
  never taking the request path down (the caller's result is unaffected).
- **Browser signing-key custody.** The dashboard no longer keeps the raw private JWK in `localStorage`
  (where any XSS could read it). The key is imported once to a **non-extractable** WebCrypto `CryptoKey`
  and its handle is kept in **IndexedDB** — structured-cloning it preserves the ability to *sign* but not
  to read the private bytes (`exportKey` throws), so a compromised tab can at worst sign while it is open,
  never steal a reusable key. The raw JWK is dropped after import (and an older build's stored key is
  scrubbed from `localStorage` on upgrade). Verified live: raw key absent from `localStorage`, key
  non-extractable in IndexedDB, `exportKey` blocked, signing still verifies server-side, and the key
  survives a reload without re-pasting.

## [0.2.0] — 2026-09-16

🔴 **Honest gap in this record:** this repository's git history begins at this version — there is no
`0.1.0` commit or tag in this repo to diff against. `0.1.0` was published to npm from an earlier
project state that predates this repo's own history, so the entries below describe what **0.2.0**
actually is, not a line-by-line diff from `0.1.0`. Every claim here is checked directly against this
version's real, merged source — nothing is inferred from the missing prior state.

### The real hub (loopback-only, no Redis, no broker)
One local pub/sub-style hub so several processes on the same machine can talk over one loopback
endpoint. Genuinely separate, from-scratch reimplementation of the idea behind DAN's own internal
agent-to-agent messaging — zero shared code, zero shared data format, zero architectural link.

### Security model (loopback binding is NOT authentication)
- **Every API call is authenticated** — a registered principal + token (sha256+salt, constant-time
  compare) or it's `401`, deny by default.
- **Server-established sender.** A message's `from` is always the authenticated principal; a request
  claiming a different name is `403` — one agent cannot manufacture a message that looks like it came
  from another.
- **Independently signed messages (INV-10).** Every message carries the principal's own Ed25519
  signature; the hub verifies it and refuses unsigned/bad-signed posts. Any receiver can re-verify a
  stored message against the principal's public key without trusting the hub.
- **Per-principal authorization** — scoped to specific channels or `admin`; out-of-scope is `403`.
- **Replay-resistant** — every post carries a unique nonce (+ optional `ts`); a replayed nonce is
  `409`, a stale timestamp is refused.
- **Durable, monotonic per-channel message ids**, never reused across retention or restart.
- **Honest history gaps** — a cursor older than the oldest retained message gets `gap: true,
  reason: "HISTORY_GAP"` instead of a silently-partial tail presented as complete.
- **Per-principal rate limits** + an append-only audit log recording what the *server* established.
- **Single writer per data dir** — a second hub on the same data dir refuses to start.

### Notes / honest limits
- Not a Slack/Discord/Telegram bridge — connecting to external chat platforms was considered and
  deliberately left out of this release, a real open question, not a silent omission.
