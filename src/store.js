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

const PRESENCE_TTL_MS = 30_000;
const MAX_MESSAGES_PER_CHANNEL = 2000;
const MAX_CHANNELS = 512;        // a bounded number of channels — one principal can't create unbounded state.
const NONCE_TTL_MS = 10 * 60_000; // how long a used nonce is remembered for replay rejection.
const TS_SKEW_MS = 5 * 60_000;    // a message whose client ts is outside this window is rejected as stale.

/** Typed rejections the server maps to real status codes, instead of a generic 500. */
export class BridgeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export class BridgeStore {
  constructor(dataDir, opts = {}) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, "channels.json");
    this.lockFile = path.join(dataDir, "hub.lock");
    // Production default is MAX_MESSAGES_PER_CHANNEL; overridable so tests can exercise retention and
    // the history-gap path without posting thousands of messages.
    this.maxMessages = Number.isInteger(opts.maxMessagesPerChannel) && opts.maxMessagesPerChannel > 0
      ? opts.maxMessagesPerChannel : MAX_MESSAGES_PER_CHANNEL;
    this.channels = new Map(); // name -> { messages: [], seq, minRetainedId, presence: Map(principal -> lastSeen) }
    this.events = new EventEmitter();
    this.events.setMaxListeners(0);
    this._nonces = new Map(); // nonce -> expiry ts (global; nonces are unique per post)
    this._holdsLock = false;
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

  async #persist() {
    const plain = {};
    for (const [name, ch] of this.channels) plain[name] = { messages: ch.messages, seq: ch.seq, minRetainedId: ch.minRetainedId };
    const tmp = `${this.file}.${randomUUID()}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(plain), "utf8");
    await fs.rename(tmp, this.file);
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
    const message = { id: ++ch.seq, from, text, ts: tsNum, nonce, sig: sig ?? null };
    ch.messages.push(message);
    if (ch.messages.length > this.maxMessages) {
      ch.messages.splice(0, ch.messages.length - this.maxMessages);
    }
    ch.minRetainedId = ch.messages.length ? ch.messages[0].id : ch.seq;
    this._nonces.set(nonce, now + NONCE_TTL_MS);
    await this.#persist();
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
