// [DAN] BRIDGE DASHBOARD — the message store. A real, local, shared hub any authenticated principal
// posts to and reads from. Zero runtime deps.
//
// This layer stores only what the SERVER established: `from` is always the authenticated principal the
// server passes in, never a caller field. The store's own job is to make the record trustworthy as
// state — durable message identity, honest history-gap reporting, replay rejection, and a single
// writer per data dir so concurrent hubs can't silently clobber each other.
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { GENESIS, linkOf } from "./chain.js";

const PRESENCE_TTL_MS = 30_000;
const MAX_MESSAGES_PER_CHANNEL = 2000;
const MAX_CHANNELS = 512;        // a bounded number of channels — one principal can't create unbounded state.
const NONCE_TTL_MS = 10 * 60_000; // how long a used nonce is remembered for replay rejection.
const TS_SKEW_MS = 5 * 60_000;    // a message whose client ts is outside this window is rejected as stale.
export const MAX_MESSAGE_BYTES = 16 * 1024; // a single message's text is capped — an oversize post is 413,
                                            // not an unbounded whole-file rewrite (the store snapshots the
                                            // whole channel per post, so a 256 KiB message is O(n) per write).

/** Typed rejections the server maps to real status codes, instead of a generic 500. */
export class BridgeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export class BridgeStore {
  constructor(dataDir, opts = {}) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, "channels.json");
    this.lockFile = path.join(dataDir, "hub.lock");
    this.nonceFile = path.join(dataDir, "nonces.json"); // used nonces persist here so replay protection survives a restart
    // Production default is MAX_MESSAGES_PER_CHANNEL; overridable so tests can exercise retention and
    // the history-gap path without posting thousands of messages.
    this.maxMessages = Number.isInteger(opts.maxMessagesPerChannel) && opts.maxMessagesPerChannel > 0
      ? opts.maxMessagesPerChannel : MAX_MESSAGES_PER_CHANNEL;
    this.maxMessageBytes = Number.isInteger(opts.maxMessageBytes) && opts.maxMessageBytes > 0
      ? opts.maxMessageBytes : MAX_MESSAGE_BYTES;
    this.channels = new Map(); // name -> { messages: [], seq, minRetainedId, presence: Map(principal -> lastSeen) }
    this.events = new EventEmitter();
    this.events.setMaxListeners(0);
    this._nonces = new Map(); // nonce -> expiry ts (global; nonces are unique per post)
    this._holdsLock = false;
    this._persistTail = Promise.resolve(); // serializes the durable write path (one persist at a time, in order)
  }

  async init() {
    await fs.mkdir(this.dataDir, { recursive: true });
    await this.#acquireLock();
    try {
      const raw = JSON.parse(await fs.readFile(this.file, "utf8"));
      for (const [name, ch] of Object.entries(raw)) {
        const messages = Array.isArray(ch.messages) ? ch.messages : [];
        // Restore the durable sequence so a restart NEVER reuses an id (falls back to the max id seen,
        // or the count, for a channels.json written by an older, length-based version).
        const seq = Number.isInteger(ch.seq) ? ch.seq
          : messages.reduce((mx, m) => Math.max(mx, Number(m.id) || 0), 0) || messages.length;
        const minRetainedId = Number.isInteger(ch.minRetainedId) ? ch.minRetainedId
          : (messages.length ? Number(messages[0].id) || 0 : 0);
        this.channels.set(name, { messages, seq, minRetainedId, presence: new Map() });
      }
    } catch {
      // No saved state yet (or unreadable) — start empty rather than fail. A corrupt file does not
      // grant anyone authority; identity/authz live in principals.json, checked by the server.
    }
    // Restore the used-nonce set so replay protection SURVIVES a restart. Before this, `_nonces` was
    // purely in-memory: after a bounce, a message captured within the freshness window (ts-skew) could be
    // replayed because its nonce was "never heard of." We reload the still-live nonces (expired ones are
    // dropped on load — they'd be rejected as STALE by the ts window anyway) so a used nonce stays used.
    try {
      const now = Date.now();
      const saved = JSON.parse(await fs.readFile(this.nonceFile, "utf8"));
      if (Array.isArray(saved)) {
        for (const [nonce, exp] of saved) {
          if (typeof nonce === "string" && Number.isFinite(exp) && exp > now) this._nonces.set(nonce, exp);
        }
      }
    } catch {
      /* no saved nonces yet (or unreadable) — start with an empty set */
    }
  }

  async close() { await this.#releaseLock(); }

  // ── single-writer hub lock ────────────────────────────────────────────────────────────────────
  // Two hub processes on one data dir would each hold the whole store in memory and last-writer-wins
  // the file — silently losing messages and (before durable ids) reusing them. So a data dir has ONE
  // hub: we take an exclusive lock at startup and refuse to start a second, rather than pretend
  // fine-grained locking makes concurrent whole-file rewrites safe.
  async #acquireLock() {
    try {
      const fh = await fs.open(this.lockFile, "wx"); // O_EXCL: fails if the lock already exists
      await fh.write(String(process.pid));
      await fh.close();
      this._holdsLock = true;
      return;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
    // Lock exists — is the owner still alive? A stale lock (owner crashed) is reclaimed; a live one is honored.
    let ownerPid = 0;
    try { ownerPid = Number(await fs.readFile(this.lockFile, "utf8")) || 0; } catch { /* unreadable → treat as stale */ }
    let alive = false;
    if (ownerPid > 0) { try { process.kill(ownerPid, 0); alive = true; } catch { alive = false; } }
    if (alive) throw new BridgeError("HUB_LOCKED", `another hub (pid ${ownerPid}) is already running on ${this.dataDir}`);
    await fs.rm(this.lockFile, { force: true });
    const fh = await fs.open(this.lockFile, "wx");
    await fh.write(String(process.pid));
    await fh.close();
    this._holdsLock = true;
  }

  async #releaseLock() {
    if (!this._holdsLock) return;
    this._holdsLock = false;
    try {
      const owner = Number(await fs.readFile(this.lockFile, "utf8")) || 0;
      if (owner === process.pid) await fs.rm(this.lockFile, { force: true });
    } catch { /* already gone */ }
  }

  // Serialize the durable write path. Concurrent posts must not interleave the whole-file
  // read-modify-write: each post mutates memory synchronously (so ids are already distinct), but if their
  // persists ran concurrently a slower rename of an OLDER snapshot could land last and drop an
  // already-acked message — leaving the in-memory seq ahead of disk and reissuing that id after a restart.
  // Chaining the persists so they run one at a time, in submission order, guarantees every acked message
  // is durably on disk before postMessage resolves, and no stale snapshot ever clobbers a newer one.
  #enqueuePersist() {
    const run = () => this.#persist();
    this._persistTail = this._persistTail.then(run, run); // continue the chain even if a prior persist failed
    return this._persistTail;
  }

  async #persist() {
    // Persist the nonce set BEFORE the channel state: a message is only durable once its nonce is already
    // recorded, so a crash between the two renames can at worst lose an un-acked message — never leave a
    // durable message whose nonce was never written (which would let it be replayed after a restart).
    await this.#persistNonces();
    const plain = {};
    for (const [name, ch] of this.channels) plain[name] = { messages: ch.messages, seq: ch.seq, minRetainedId: ch.minRetainedId };
    await this.#atomicWrite(this.file, JSON.stringify(plain));
  }

  // Persist the still-live used-nonce set (expired entries dropped) so replay protection survives a
  // restart. Atomic write-then-rename, same as channels.json.
  async #persistNonces() {
    const now = Date.now();
    const live = [];
    for (const [nonce, exp] of this._nonces) if (exp > now) live.push([nonce, exp]);
    await this.#atomicWrite(this.nonceFile, JSON.stringify(live));
  }

  // Durable atomic replace: write a temp file, fsync its contents, rename it over the target, then fsync
  // the directory so the rename itself survives a crash. fsync is best-effort (not portable everywhere).
  async #atomicWrite(file, data) {
    const tmp = `${file}.${randomUUID()}.tmp`;
    const fh = await fs.open(tmp, "w", 0o600);
    try {
      await fh.writeFile(data, "utf8");
      try { await fh.sync(); } catch { /* fsync unsupported here — best effort */ }
    } finally {
      await fh.close();
    }
    await fs.rename(tmp, file);
    await this.#fsyncDir();
  }

  async #fsyncDir() {
    let fh;
    try {
      fh = await fs.open(this.dataDir, "r");
      await fh.sync();
    } catch {
      /* opening/fsyncing a directory is not portable (e.g. Windows) — best effort */
    } finally {
      if (fh) await fh.close().catch(() => {});
    }
  }

  #channel(name, { create } = { create: true }) {
    let ch = this.channels.get(name);
    if (ch) return ch;
    if (!create) return null;
    if (this.channels.size >= MAX_CHANNELS) {
      throw new BridgeError("TOO_MANY_CHANNELS", `channel limit reached (${MAX_CHANNELS}) — refusing to create ${JSON.stringify(name)}`);
    }
    ch = { messages: [], seq: 0, minRetainedId: 0, presence: new Map() };
    this.channels.set(name, ch);
    return ch;
  }

  listChannels() { return [...this.channels.keys()].sort(); }

  #sweepNonces(now) {
    if (this._nonces.size < 4096) return; // cheap: only sweep when the set has grown
    for (const [n, exp] of this._nonces) if (exp <= now) this._nonces.delete(n);
  }

  /** Append a message. `from` is the server-established principal (never a caller field). Requires a
   *  unique `nonce` and rejects a replayed one; rejects a client `ts` outside the allowed skew. The id
   *  is a durable per-channel sequence, so it is monotonic and never reused across retention/restart. */
  async postMessage(channelName, from, text, { nonce, ts, sig } = {}) {
    const now = Date.now();
    if (!nonce || typeof nonce !== "string" || nonce.length > 128) {
      throw new BridgeError("NONCE_REQUIRED", "a unique `nonce` is required (replay protection)");
    }
    // A single message's text is capped: the store snapshots the whole channel on every post, so an
    // oversize message is an amplified O(n) whole-file rewrite. Reject it (413) rather than accept it.
    if (Buffer.byteLength(String(text ?? ""), "utf8") > this.maxMessageBytes) {
      throw new BridgeError("TOO_LARGE", `message text exceeds the ${this.maxMessageBytes}-byte limit`);
    }
    // The stored `ts` is the client's own timestamp (the value the signature covers), so a message
    // stays independently verifiable after storage; it must still fall inside the freshness window.
    let tsNum = now;
    if (ts !== undefined && ts !== null) {
      const t = Number(ts);
      if (!Number.isFinite(t) || Math.abs(now - t) > TS_SKEW_MS) {
        throw new BridgeError("STALE", "message `ts` is outside the accepted freshness window");
      }
      tsNum = t;
    }
    this.#sweepNonces(now);
    const seen = this._nonces.get(nonce);
    if (seen && seen > now) throw new BridgeError("REPLAY", "duplicate/replayed message (nonce already used)");

    const ch = this.#channel(channelName);
    // Hash-chain link: this message commits to the one before it, so a later `verify` can prove no
    // message was deleted, reordered, or inserted (see chain.js). The very first message in a channel
    // anchors to GENESIS; every later one carries the link of the current last message. Computed here
    // under the single-writer hub lock + synchronous memory append, so the chain is naturally linear.
    const prev = ch.messages.length ? linkOf(ch.messages[ch.messages.length - 1]) : GENESIS;
    const message = { id: ++ch.seq, from, text, ts: tsNum, nonce, sig: sig ?? null, prev };
    ch.messages.push(message);
    if (ch.messages.length > this.maxMessages) {
      ch.messages.splice(0, ch.messages.length - this.maxMessages);
    }
    ch.minRetainedId = ch.messages.length ? ch.messages[0].id : ch.seq;
    this._nonces.set(nonce, now + NONCE_TTL_MS);
    await this.#enqueuePersist(); // serialized durable write — resolves only once THIS post is on disk
    this.events.emit(channelName, message);
    return message;
  }

  /** Read messages after `sinceId`, WITH honest history-gap reporting. If the caller's cursor points
   *  before the oldest retained id, `gap` is true and the caller is told to resync rather than silently
   *  receiving a partial tail as if it were complete. */
  readMessages(channelName, sinceId) {
    const ch = this.#channel(channelName, { create: false });
    if (!ch) return { messages: [], gap: false, minRetainedId: 0, latestId: 0 };
    const since = Number(sinceId) || 0;
    const gap = since > 0 && since < ch.minRetainedId;
    return {
      messages: ch.messages.filter((m) => m.id > since),
      gap,
      minRetainedId: ch.minRetainedId,
      latestId: ch.seq,
    };
  }

  /** Long-poll wrapper over readMessages: return immediately if there is anything new (or a gap to
   *  report), else wait up to timeoutMs for one real new message, then return a fresh read. */
  waitForMessages(channelName, sinceId, timeoutMs) {
    const first = this.readMessages(channelName, sinceId);
    if (first.messages.length > 0 || first.gap || timeoutMs <= 0) return Promise.resolve(first);
    return new Promise((resolve) => {
      const onMessage = () => { clearTimeout(timer); this.events.off(channelName, onMessage); resolve(this.readMessages(channelName, sinceId)); };
      const timer = setTimeout(() => { this.events.off(channelName, onMessage); resolve(this.readMessages(channelName, sinceId)); }, timeoutMs);
      this.events.on(channelName, onMessage);
    });
  }

  /** Presence is keyed on the server-established principal — a caller cannot announce another identity
   *  online, because the server passes the authenticated subject, not a `from` field. */
  announcePresence(channelName, principal) {
    const ch = this.#channel(channelName);
    ch.presence.set(principal, Date.now());
  }

  // Heartbeat-based, not a live connection: an agent that announced once then crashed shows online
  // until its TTL expires. A real, stated limit — not a pretended liveness check.
  listPresence(channelName) {
    const ch = this.#channel(channelName, { create: false });
    if (!ch) return [];
    const now = Date.now();
    const online = [];
    for (const [principal, lastSeen] of ch.presence) {
      if (now - lastSeen <= PRESENCE_TTL_MS) online.push({ from: principal, lastSeenMsAgo: now - lastSeen });
      else ch.presence.delete(principal);
    }
    return online.sort((a, b) => a.from.localeCompare(b.from));
  }
}
