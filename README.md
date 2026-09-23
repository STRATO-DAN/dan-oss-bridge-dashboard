<div align="center">

<img src="assets/dan-mark.svg" alt="[DAN] BRIDGE DASHBOARD" width="84" height="84">

# [DAN] BRIDGE DASHBOARD

**One local hub so several processes can talk over one loopback endpoint — no Redis, no broker.**

[![CI](https://github.com/STRATO-DAN/dan-oss-bridge-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/STRATO-DAN/dan-oss-bridge-dashboard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@strato-dan/bridge-dashboard.svg)](https://www.npmjs.com/package/@strato-dan/bridge-dashboard)
[![runtime deps](https://img.shields.io/badge/runtime%20deps-0-2e9e56.svg)](#dependencies)
[![docs](https://img.shields.io/badge/docs-README-blue.svg)](#use)
[![license](https://img.shields.io/badge/license-MIT-informational.svg)](LICENSE)

</div>

> **⚡ Zero install · zero runtime dependencies.** No `npm install`, no build step, no broker to
> stand up — `npx @strato-dan/bridge-dashboard` runs it and `npm test` tests it. Pure Node standard
> library (Node ≥ 18). Full breakdown under [Dependencies](#dependencies).

One small local hub for wiring several processes on the same machine together — build scripts, dev
services, background workers, CLIs, or AI agents — so they can talk over one simple loopback
endpoint instead of you standing up Redis or a message broker just to pass messages around.

Post a message to a named channel. Read it back. Watch a channel and get new messages the instant
they arrive (a real long-poll, not a tight polling loop). See who else has announced presence.
Loopback only — nothing leaves your machine.

## Use

```bash
npx @strato-dan/bridge-dashboard
```

Opens at `http://127.0.0.1:4875` (loopback only). Identity is **authenticated, not typed**: mint a
principal + token once, scope it to the channels it may use, then talk as that principal.

```bash
# one-time: mint a principal and its token (shown once). --scope channel:* grants all channels.
npx @strato-dan/bridge-dashboard register agent-1 --scope channel:build-agents

# save your signing key once (register prints it), then post a SIGNED message AS that principal —
# the server stamps the sender and verifies your signature; `sign` builds the body for you.
echo '<private-jwk-from-register>' > agent-1.key.jwk
BODY=$(npx @strato-dan/bridge-dashboard sign --principal agent-1 --channel build-agents \
  --text "build finished, 42 tests green" --key-file agent-1.key.jwk)
curl -X POST http://127.0.0.1:4875/api/channels/build-agents/messages \
  -H 'X-Bridge-Principal: agent-1' -H 'X-Bridge-Token: <token>' \
  -H 'content-type: application/json' -d "$BODY"

# read (also authenticated)
curl 'http://127.0.0.1:4875/api/channels/build-agents/messages?sinceId=0' \
  -H 'X-Bridge-Principal: agent-1' -H 'X-Bridge-Token: <token>'

# long-poll: holds the request open until a NEW message arrives (or 25s pass)
curl 'http://127.0.0.1:4875/api/channels/build-agents/messages?sinceId=5&wait=1' \
  -H 'X-Bridge-Principal: agent-1' -H 'X-Bridge-Token: <token>'
```

## Scriptable & CI

Everything here is scriptable with plain, dependency-free tooling — no wrapper library, no config
file. The launcher understands a few hand-rolled flags (Node standard library only):

```bash
dan-oss-bridge-dashboard --version   # print the version, exit 0
dan-oss-bridge-dashboard --help      # usage: subcommands, env vars, exit codes; exit 0
dan-oss-bridge-dashboard --json      # startup banner as one JSON object {"url","port"} (no browser)
```

`--json` is the CI-friendly boot: it prints `{"url":"http://127.0.0.1:<port>","port":<port>}` on one
line and does not open a browser, so a script can capture the address it bound. Set
`DAN_OSS_BRIDGE_DASHBOARD_PORT=0` to have the OS pick a free port and read the real one back from that
JSON.

**Exit codes** (stable contract for scripts and CI):

| Code | Meaning |
|---|---|
| `0` | Success — including `--help` / `--version`. |
| `1` | Runtime failure — e.g. the port is already in use (a one-line message on stderr), or a `register` / `sign` error. |
| `2` | Launcher usage error — an unrecognized option was passed to the no-arg launcher. |

A `Makefile` wraps the common workflows (portable to the `make` that ships with macOS — GNU Make
3.81 — no dependencies):

```bash
make help     # list the targets
make test     # node --test test/*.test.mjs — the full suite
make attack   # run ONLY the adversarial / security-regression tests (see below)
make demo     # end-to-end in a temp dir: register → boot → sign → POST → read back, then clean up
make bench    # post/read throughput over loopback (see BENCHMARKS.md)
```

**Try the attacks: `make attack`.** It runs only the hostile-input tests and proves the hub holds:
unauthenticated post `401`, identity-spoof `403`, out-of-scope channel `403`, replayed nonce `409`,
unsigned post `400`, bad signature `403`, unauthenticated-flood rate-limit `429` (audit not amplified),
and oversize post `413`. All green.

**Throughput** is measured end-to-end over loopback with real numbers you can reproduce — see
[BENCHMARKS.md](BENCHMARKS.md) (`make bench`).

## What this is (and isn't)

This is a **genuinely separate, from-scratch reimplementation** of the idea behind DAN's own
internal agent-to-agent communication feature — built with zero shared code, zero shared data
format, and zero architectural link to that internal system. It exists so the underlying
capability (agents messaging and watching each other) is available as a real, standalone,
open-source tool, without exposing anything about DAN's own internal implementation.

It is **not** a Slack/Discord/Telegram bridge. Connecting to external chat platforms was
considered as a possible larger scope for this tool and was deliberately left out of this release
— a real, honest, unresolved question, not a silent omission. What's here is the core, genuinely
useful piece: a local pub/sub-style hub any process can talk to.

## Security model

Loopback binding limits *network* exposure, but it is **not** authentication — another local process,
or a web page open in your browser, can reach a loopback port too. So identity here is a **principal
the hub authenticates**, never a caller-supplied `from`:

- **Every API call is authenticated.** A request presents a registered principal + token
  (`X-Bridge-Principal` / `X-Bridge-Token`, or `Authorization: Bearer <principal>:<token>`); the hub
  verifies it (sha256+salt, constant-time compare) before anything happens. No credential → `401`,
  deny by default.
- **The sender is server-established.** A message's `from` is always the authenticated principal; a
  request that tries to post under a different name is refused (`403`). One agent cannot manufacture a
  message that looks like it came from another — the property a downstream LLM depends on when it
  reads "security-agent approved this."
- **Independently signed messages (INV-10).** Every message is signed with the principal's own Ed25519
  key — minted by `register`, the private key never leaving the operator. The hub verifies the signature
  and refuses an unsigned or bad-signed post (`400` / `403`), and any receiver can re-verify a stored
  message against the principal's public key (`GET /api/principals/<id>/pubkey`) — proving authorship and
  detecting tampering **without trusting the hub**.
- **Per-principal authorization.** A principal is scoped to the channels it may use (`--scope
  channel:foo`, `--scope channel:*`, `admin`); a channel outside that scope is `403`, and
  `/api/status` lists only the channels a principal may see.
- **Replay-resistant.** Every post carries a unique `nonce` (plus an optional `ts`); a replayed nonce
  is rejected (`409`) and a stale timestamp is refused — a captured "approve deployment" can't be
  re-submitted.
- **Durable message identity.** Ids are a durable per-channel sequence, monotonic and never reused
  across retention or restart, so cursors, dedup, and audit correlation stay sound.
- **Honest history gaps.** If a reader's cursor is older than the oldest retained message the response
  says so (`gap: true`, `reason: "HISTORY_GAP"`) instead of silently returning a partial tail as if it
  were the complete history.
- **Per-principal rate limits + an append-only audit log** (`audit.log`) that records what the
  *server* established — the authenticated principal and the decision — never a caller's claimed name.
- **Single writer per data dir.** A second hub on the same data dir refuses to start, so concurrent
  processes can't clobber each other's state.

Mint the first principal (until you do, the API denies everything, fail-closed):

```bash
npx @strato-dan/bridge-dashboard register agent-1 --scope channel:*
```

**Verifying a message without trusting the hub.** The private key stays with the operator; the hub only
ever holds public keys. A receiver fetches the sender's key (`GET /api/principals/<id>/pubkey`) and
re-verifies a stored message with the exported `verifyMessage(message, channel, publicKeyJwk)` from
`src/sign.js` — or in any language over the same canonical form, a JSON array
`[from, channel, nonce, ts, text]`. Tampering with any of those fields fails verification. The browser
UI signs the same way, via WebCrypto Ed25519, so a message posted from the dashboard is just as verifiable
as one from an agent.

## Verify log integrity

Per-message signatures prove that a *single* message's own content wasn't edited. On their own they do
**not** catch a writer who **deletes, reorders, or inserts** whole messages — the surviving signatures
still verify. So every stored message also carries `prev`, the SHA-256 of the message before it in the
channel: a hash chain. Break the order — remove a message, swap two, splice one in, or edit one in place
— and the following message's `prev` no longer matches, at an exact point.

`GET /api/channels/<channel>/verify` (authenticated + scoped) walks the channel and returns, per
message, whether its signature verifies and whether its chain link is intact, plus a channel-level
verdict (`chainIntact`, `firstBreakId`) and forged/unverifiable counts:

```bash
curl -H "X-Bridge-Principal: agent-1" -H "X-Bridge-Token: <token>" \
  http://127.0.0.1:4875/api/channels/general/verify
# { "ok": true, "chainPresent": true, "chainIntact": true, "firstBreakId": null,
#   "counts": { "total": 3, "sigForged": 0, "sigUnverifiable": 0 }, "records": [ ... ] }
```

The dashboard renders this as a **Verify log integrity** panel: a badge reading *chain intact — N
verified* (green) or *tampering detected at message #N* (coral, with a plain-English explanation), and
a ✓ / ⚠ mark on every message row so the exact tampered message stands out. It re-checks on join, when
new messages arrive, and on demand — turning "a bus that can prove its own log wasn't tampered with"
into something you can see, not just read.

The signature is unchanged by this — the chain link is not folded into it — so a message signed before
the chain existed still verifies; authenticity and log-integrity are independent, composable layers.
Honest limit: the chain can't detect a truncated head/tail (a shorter retained window stays internally
valid, and its oldest message is an un-checkable anchor — the same boundary reported as `minRetainedId`
/ `gap`); detecting a dropped head/tail needs an external anchor, out of scope for one local log.

## Honest limits

- **One machine, loopback only.** This is a local dev-time hub, not a distributed message bus. If
  you need agents on different machines to talk, you'd run this somewhere reachable to both and
  point them at it — not provided out of the box.
- **Presence is a heartbeat, not a live connection check.** An agent that crashes without a clean
  exit still shows "online" for up to 30 seconds after its last heartbeat.
- **Authenticated, but local-first.** Identity is a per-principal token you mint locally with
  `register` — no external identity service, no PKI, no multi-tenant server. It is the right strength
  for a local hub between agents on one machine (see [Security model](#security-model)); it is not a
  substitute for a real identity provider if you were to expose it beyond loopback (don't).
- Channel history is capped at the last 2000 messages per channel and persisted to a local JSON
  file — not a database, not meant for high-volume production traffic.

## When to use this

- **Best fit**: local processes or agents on one machine that need to post/read/watch shared
  channels during development — a CI job, a build script, and a couple of AI agents that need to
  coordinate, without standing up Redis or a message broker for it.
- **Best fit**: you want real push-on-arrival delivery (long-poll) instead of writing your own
  polling loop, on a local, authenticated, single-machine hub.

**Honest flip side**: this is not a distributed message bus — no cross-machine delivery, and no
durability guarantees beyond "the last 2000 messages per channel, in a local JSON file." Identity is
a local per-principal token, not a full identity provider or a public-key message-signing scheme (see
"Security model"). If you need agents on different machines or production-scale throughput, this
tool's own real scope stops well short of that; see "Honest limits" above.

## Examples

[`examples/two-agents-talking.mjs`](examples/two-agents-talking.mjs) uses `BridgeStore` directly
— no server, no UI — and shows the real long-poll delivery: the watcher's wait resolves the moment
a message posts, not on a fixed interval. A real run of it:

```console
$ node examples/two-agents-talking.mjs
agent-1 is watching, waiting for a message...
agent-2 posting a message...
agent-1's wait resolved after 202ms (well under the 5000ms timeout)
Messages delivered: [
  {
    id: 1,
    from: 'agent-2',
    text: 'build finished, 42 tests green',
    ts: 1789319551389
  }
]

Presence in this channel: [ { from: 'agent-1', lastSeenMsAgo: 202 } ]
```

The wait resolves in ~200 ms — the moment `agent-2` posts — not at the 5 s timeout. That gap is the
long-poll genuinely pushing on arrival rather than returning on a timer.

## Validated

Everything here was run locally against this exact code on Node 22 (supported: Node >= 18).

**Tests** — Node's built-in test runner, no `npm install` needed (zero runtime dependencies):

```console
$ npm test
> node --test test/*.test.mjs
...
# tests 77
# pass 77
# fail 0
```

**77 / 77 pass.** Beyond the behavioral tests (durable per-channel ids, the `EventEmitter`-backed
long-poll resolving the instant a message posts, presence, restart persistence) they assert the
security invariants directly — including the review's five "breaking tests": a caller cannot claim
another principal's identity (spoofed `from` → `403`); an unauthenticated post is denied (`401`) and
every accepted message has a server-established sender; a principal cannot use a channel outside its
scope (`403`); a replayed nonce is rejected (`409`); ids stay durable across a restart, a cursor into
aged-out history reports a gap, and a second hub on one data dir refuses to start. The signature layer
is covered end-to-end: an unsigned post is `400`, a bad or wrong-text signature is `403`, and a stored
message verifies (and detects tampering) against the principal's public key with no hub in the loop.

**HTTP round-trip** — a real run against the packaged server (`register`, then post / spoof / replay / read):

```console
# no credential → denied
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST .../channels/build-agents/messages \
    -H 'content-type: application/json' -d '{"text":"hi","nonce":"n1","ts":0,"sig":"x"}'
401

# authenticated + SIGNED (BODY built by `sign`) → the server stamps from=agent-1 and verifies the signature
$ BODY=$(dan-oss-bridge-dashboard sign --principal agent-1 --channel build-agents \
    --text "hello signed" --key-file agent-1.key.jwk)
$ curl -s -X POST .../channels/build-agents/messages \
    -H 'X-Bridge-Principal: agent-1' -H 'X-Bridge-Token: <token>' \
    -H 'content-type: application/json' -d "$BODY"
{"ok":true,"message":{"id":1,"from":"agent-1","text":"hello signed","ts":1789571790540,"nonce":"a8c7…","sig":"jS8KAuZTG37rAu_kNYSoDlLMk…"}}

# unsigned → refused; bad signature → refused; sender spoof → refused; replayed nonce → rejected
$ curl ... -d '{"text":"x","nonce":"u1","ts":...}'                 # no sig      -> 400 SIG_REQUIRED
$ curl ... -d '{"text":"x","nonce":"b1","ts":...,"sig":"AAAA"}'    # bad sig     -> 403 BAD_SIGNATURE
$ curl ... -d '{...,"from":"security-agent"}'                      # spoof from  -> 403
$ curl ... -d "$BODY"                                              # replay      -> 409
```

## Dependencies

**Runtime dependencies: none.** Pure Node standard library — nothing to install, no broker to run.

| | |
|---|---|
| **Runtime dependencies** | **0** — Node standard library only (`http`, `fs`, `crypto`, `events`) |
| **Install to run** | none — `npx @strato-dan/bridge-dashboard` |
| **Install to test** | none — `npm test` uses Node's built-in test runner |
| **Node** | ≥ 18 |
| **Dev-only** | `husky` — pulled in only if you clone to contribute; never needed to use the tool |

The long-poll delivery is Node's own `EventEmitter` — there's no message broker, no Redis, and no
dependency tree to resolve. `npx` fetches this one package and runs it.

## Project contents

| Path | What it is |
|---|---|
| `bin/dan-oss-bridge-dashboard.js` | CLI entry — `register <id> --scope …` mints a principal, or (no args) starts the hub + opens the UI. |
| `src/server.js` | The loopback-only HTTP server: authenticates every API call, establishes the sender, authorizes the channel, rate-limits, audits. |
| `src/auth.js` | Per-principal identity — token + Ed25519 keypair registration/verification (sha256+salt, constant-time), channel scopes. |
| `src/sign.js` | Ed25519 message signing — canonical form + verify, identical bytes for the CLI, agents, and the browser (WebCrypto). |
| `src/store.js` | `BridgeStore` — durable message ids, history-gap reporting, replay rejection, long-poll, single-writer lock. |
| `src/audit.js` | Append-only audit log of server-established facts. |
| `src/ratelimit.js` | Per-principal token-bucket rate limiter. |
| `public/` | The plain HTML/CSS/vanilla-JS channel UI (sends the principal token, handles history gaps). |
| `examples/` | Runnable example code using `BridgeStore` directly, no UI. |
| `test/` | Real unit + HTTP tests (`npm test`) — the security invariants and the five breaking tests. |

## FAQ

**Can two processes on different machines use this?** Only if you run the server somewhere both
machines can reach and point them at that address instead of `127.0.0.1` yourself — the tool binds
loopback-only by default and doesn't ship a way to expose itself beyond that; see "Honest limits."

**Is there message delivery guarantee if a watcher is offline when a message posts?** Yes, up to
the 2000-message-per-channel history cap — `waitForMessages` checks for already-buffered messages
past `sinceId` before ever registering a live listener, so a watcher that reconnects after being
offline still gets what it missed, not just future messages.

**Will this ever bridge to Slack/Discord/Telegram?** Genuinely undecided — see "What this is (and
isn't)" above. It's a real open question, not a roadmap commitment either way.

**Can a channel name contain anything?** No — channel names are validated against a strict allowlist
(`[A-Za-z0-9_-]{1,64}`, see `CHANNEL_RE` in `src/server.js`) before use. The sender is not a caller
field at all: it's the authenticated principal the server establishes from the credential, so a
message's `from` is always proof of who actually sent it (see "Security model").

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
for how to file an issue or submit a PR. Maintainers may use AI tools to help review
contributions — please don't include personal information in an issue, PR, or commit beyond
what's needed to describe the change.

## Releasing

See [RELEASING.md](RELEASING.md) —
the same version-bump/tag/publish process applies to every DAN-OSS tool, this one included.

## License

MIT (code) — see `LICENSE`. The "DAN" name and logo are trademarked — see `TRADEMARK.md`.

---

**[DAN] MEMORY SMASH** — which has its own, separate, internal agent-communication system — is
coming soon.
