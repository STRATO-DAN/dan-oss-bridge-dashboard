# Changelog

All notable changes to `@strato-dan/bridge-dashboard` are documented here.
This project uses [semantic versioning](https://semver.org/).

## [0.4.0] — 2026-09-17

Cross-cutting polish pass — purely additive developer- and CI-ergonomics on top of the 0.3.x hub. No
behavior change to the existing `register` / `sign` subcommands or to any HTTP route, no change to the
auth model, and still **zero runtime dependencies** (Node standard library only). The full existing test
suite stays green.

### Added
- **Launcher flags on the no-arg hub (hand-rolled, no dependency).** `--version` prints the package
  version; `--help` prints usage (subcommands, environment variables, and the exit-code contract);
  `--json` prints the startup banner as one JSON object `{"url","port"}` instead of the human banner
  (and, being the scripting/CI path, does not open a browser). The human default banner is unchanged.
- **Ephemeral port.** `DAN_OSS_BRIDGE_DASHBOARD_PORT=0` now binds an OS-chosen free port; the actual
  bound port is reported (use `--json` to read it back). Any unset/non-numeric value still defaults to
  4875 exactly as before.
- **Documented 0 / 1 / 2 exit-code contract** (README + `--help`): `0` success, `1` runtime failure
  (e.g. port already in use — a one-line stderr message — or a `register` / `sign` error), `2` launcher
  usage error (an unrecognized option to the no-arg launcher). Startup failure on a busy port prints a
  one-line message on stderr and exits `1`.
- **`Makefile`** (portable to the `make` bundled with macOS, GNU Make 3.81): `make help`, `make test`
  (full suite), `make attack` (runs only the adversarial / security-regression tests — unauth `401`,
  identity-spoof `403`, out-of-scope `403`, replay `409`, unsigned `400`, bad-signature `403`,
  unauth-flood `429`, oversize `413`), `make demo` (end-to-end in a temp dir: register → boot → sign →
  POST → read back, then clean up), and `make bench` (post/read throughput over loopback).
- **`BENCHMARKS.md`** with real, reproducible post/read throughput numbers (`make bench`) and a machine
  note. Posts are durability-bound (each is `fsync`-persisted before it is acked); reads are in-memory.
- **README "Scriptable & CI" section** covering the launcher flags, the exit-code contract, the make
  targets, `make attack`, and a link to the benchmarks.

## [0.3.1] — 2026-09-17

Audit-hardening pass over the 0.3.0 durability/tamper-evidence work, before first publish of the 0.3.x
line. (0.3.0 was never published to npm; this is a separate version so the fixes below are a distinct,
reviewable set rather than a silent rewrite of 0.3.0's entry.) Every fix ships with a regression test that
fails on the pre-fix code and passes after (`test/hardening-regression.test.mjs`). Still zero runtime dependencies.

### Security / correctness
- **Audit chain verifies across rotation (no false tamper).** The hash-chain always spanned the rotation
  boundary (a new `audit.log`'s first `prev` is the rotated file's tip), but `verifyChain(file)` read a
  single file starting from `prev=null`, so a *clean* rotated log false-flagged as tampered. New
  `Audit.verifyDir(dir)` verifies `audit.log.1` then `audit.log` as one continuous chain and returns
  `ok:true` for a clean rotated log.
- **Durable, serialized message persistence.** `postMessage` mutated memory then did an unserialized
  whole-file read-modify-write; concurrent posts could let a slower rename of an older snapshot land last
  and drop an already-acked message (in-memory seq ahead of disk, id reissued after restart). The persist
  path is now serialized through an in-process write queue, so every acked message is durably on disk, in
  order, before the post resolves.
- **Unauthenticated flood no longer amplifies the audit log.** The per-principal rate limiter ran *after*
  authentication, so the `401` path — and its `audit.record` — ran unthrottled; a flood wrote one audit
  line per request, and via rotation/retention could evict real history. Unauthenticated requests are now
  rate-limited per client IP *before* they audit (over the cap → `429` with no audit line).
- **Dropped audit generations are detectable.** Two-generation retention discarded the chain root with no
  trace. A durable append-only rotation ledger (`audit.anchor`) records the tip of every generation as it
  is rotated out, so `verifyDir` can report `generations` vs `generationsOnDisk` / `droppedGenerations` —
  an evicted or deleted generation is now detectable rather than silent.
- **Crash between rotation and first append no longer orphans the chain.** If a crash landed after the
  rotation rename but before the first append (leaving `audit.log` absent), the next append started a fresh
  `prev=null` chain that verified clean in isolation. The chain tip is now seeded from `audit.log.1` when
  `audit.log` is absent, so the post-crash continuation links to the rotated tip.
- **Per-message size cap.** A single message's text is capped (16 KiB default); an oversize post is `413`
  `TOO_LARGE` instead of an unbounded, amplified whole-file rewrite.
- **Long-poll connection cap + socket timeout.** Concurrently-held long-polls are capped (over the cap a
  `wait` degrades to an immediate read), and an idle-socket timeout (~35s, past the 25s long-poll ceiling)
  reaps connections a client opens but never reads.
- **`fsync` on durable writes.** The store's atomic write-then-rename and the audit append now `fsync` the
  file and its parent directory (best-effort), so a crash right after a write doesn't lose a recorded line.
- **Nonce recorded before the message that used it.** `nonces.json` is now persisted before
  `channels.json`, so a crash between the two renames can at worst lose an un-acked message — never leave a
  durable message whose nonce was never written (which would allow a replay after restart).
- **Browser: a remembered signing key is reused only for its own principal.** The dashboard now records
  which principal the IndexedDB-held key belongs to and refuses to sign as a *different* entered principal
  with it, prompting for that principal's key instead.

### Docs
- `SECURITY.md` now documents two known, by-design limitations: public-key enumeration by any authenticated
  principal (`GET /api/principals/<id>/pubkey`), and the PID-reuse edge in the single-writer `hub.lock`.

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
