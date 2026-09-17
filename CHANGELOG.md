# Changelog

All notable changes to `@strato-dan/bridge-dashboard` are documented here.
This project uses [semantic versioning](https://semver.org/).

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

## Unreleased (an open pull request at time of writing — see the repo for current status)
V4 hardening: durable replay protection across a hub restart (the used-nonce set was in-memory
only), a tamper-evident hash-chained audit log with surfaced write failures, and moving the
browser's Ed25519 signing key off `localStorage` into a non-extractable WebCrypto key handle in
IndexedDB.
