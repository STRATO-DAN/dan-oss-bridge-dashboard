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

## [0.2.0] — 2026-09-16

### Security
- Authenticated principals (per-principal token + independent Ed25519 message signing), server-established
  sender, per-principal channel scopes, nonce replay-rejection, durable monotonic message-ids, honest
  history-gap reporting, rate-limit + audit, single-writer hub lock. Replaces v1's caller-supplied `from`.
