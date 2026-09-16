// Per-principal identity for the bridge — the real trust root. Node stdlib only, zero runtime deps.
//
// WHY THIS EXISTS. A hub whose sender is a caller-supplied `from` string has not established that
// Agent A sent a message; it has accepted a label. Every security decision downstream (who may read
// a channel, whose name is on a message a downstream LLM then trusts) is only as real as the identity
// under it. So identity here is a PRINCIPAL the server authenticates before it will accept anything —
// never a field the caller sets.
//
// PORTABLE ON PURPOSE. This is an open-source, self-hostable tool: identity is a per-principal token
// any operator can mint locally (`bridge register`), with no dependency on any external identity
// system. Tokens are high-entropy random secrets, stored only as sha256(salt:token), compared in
// constant time. That is the right strength for a local hub authenticating machine agents; it is NOT
// a password KDF (tokens are not human passwords) and NOT a public-key signature scheme (independent,
// hub-less verification of a message's author is a separate, heavier layer — see README "Message
// signing").
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { createHash, timingSafeEqual, randomBytes, generateKeyPairSync } from "node:crypto";

const PRINCIPAL_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** A fresh, high-entropy principal token (256 bits, url-safe). The secret is shown to the operator
 *  once at registration and never stored in the clear. */
export function newToken() {
  return randomBytes(32).toString("base64url");
}

function hashToken(token, salt) {
  return createHash("sha256").update(`${salt}:${token}`, "utf8").digest("hex");
}

/** Normalize a scopes list to canonical capability strings. `channel:<name>` grants post+read on that
 *  channel; `channel:*` grants all channels; `admin` is reserved for privileged ops. Unknown/blank
 *  entries are dropped rather than silently widening authority. */
export function normalizeScopes(scopes) {
  const out = [];
  for (const raw of Array.isArray(scopes) ? scopes : []) {
    const s = String(raw || "").trim();
    if (s === "admin" || s === "channel:*") { out.push(s); continue; }
    const m = s.match(/^channel:([A-Za-z0-9_-]{1,64})$/);
    if (m) out.push(`channel:${m[1]}`);
  }
  return [...new Set(out)];
}

export class AuthStore {
  constructor(dataDir) {
    this.file = path.join(dataDir, "principals.json");
    this.dataDir = dataDir;
    this._principals = new Map(); // id -> { tokenHash, salt, scopes: string[] }
    this._mtimeMs = 0;
  }

  /** Load principals.json if it changed on disk since last read. Cheap to call per-request: a stat,
   *  and a parse only when the file actually changed (so `bridge register` in another process is
   *  picked up live, without restarting the hub). Missing/corrupt file → zero principals = deny all. */
  _refresh() {
    let st;
    try { st = fs.statSync(this.file); }
    catch { this._principals = new Map(); this._mtimeMs = 0; return; }
    if (st.mtimeMs === this._mtimeMs) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, "utf8"));
      const next = new Map();
      for (const [id, rec] of Object.entries(raw)) {
        if (!PRINCIPAL_RE.test(id) || !rec || typeof rec.tokenHash !== "string" || typeof rec.salt !== "string") continue;
        next.set(id, { tokenHash: rec.tokenHash, salt: rec.salt, scopes: normalizeScopes(rec.scopes), publicKey: rec.publicKey || null });
      }
      this._principals = next;
      this._mtimeMs = st.mtimeMs;
    } catch {
      // A corrupt principals.json must FAIL CLOSED (deny all), never fall back to trusting callers.
      this._principals = new Map();
      this._mtimeMs = st.mtimeMs;
    }
  }

  /** True when at least one principal is registered. The server uses this to tell a fresh operator
   *  exactly how to bootstrap, while still denying every unauthenticated call. */
  hasAnyPrincipal() { this._refresh(); return this._principals.size > 0; }

  /** Authenticate a presented (principalId, token). DENY-BY-DEFAULT: missing input, unknown id, or a
   *  bad token all return null — and the token is compared in constant time, never revealing which
   *  part failed. Returns the server-established subject { id, scopes } on success. */
  authenticate(principalId, token) {
    this._refresh();
    const id = String(principalId || "").trim();
    const tok = String(token || "");
    if (!PRINCIPAL_RE.test(id) || !tok) return null;
    const rec = this._principals.get(id);
    if (!rec) return null;
    const presented = Buffer.from(hashToken(tok, rec.salt), "hex");
    const stored = Buffer.from(rec.tokenHash, "hex");
    if (presented.length !== stored.length || !timingSafeEqual(presented, stored)) return null;
    return { id, scopes: rec.scopes, publicKey: rec.publicKey || null };
  }

  /** A principal's public signing key (JWK), for verifying message signatures independently of the hub. */
  getPublicKey(principalId) {
    this._refresh();
    const rec = this._principals.get(String(principalId || "").trim());
    return rec ? rec.publicKey || null : null;
  }

  /** Register or rotate a principal's token. Control-plane only (the `bridge register` CLI), never an
   *  HTTP route — a running hub exposes no endpoint that can mint identities. Atomic write. */
  async register(principalId, token, scopes) {
    const id = String(principalId || "").trim();
    if (!PRINCIPAL_RE.test(id)) throw new Error(`invalid principal id ${JSON.stringify(principalId)} — use [A-Za-z0-9_.-], 1-64 chars`);
    if (!token) throw new Error("a token is required");
    await fsp.mkdir(this.dataDir, { recursive: true });
    let current = {};
    try { current = JSON.parse(await fsp.readFile(this.file, "utf8")); } catch { /* first principal */ }
    const salt = randomBytes(16).toString("hex");
    // Each principal also gets an Ed25519 signing keypair: the PUBLIC key is stored (so the hub and any
    // receiver can verify this principal's messages); the PRIVATE key is returned once, to the operator,
    // and never persisted here.
    const kp = generateKeyPairSync("ed25519");
    const publicKey = kp.publicKey.export({ format: "jwk" });   // { kty, crv, x }
    const privateKey = kp.privateKey.export({ format: "jwk" }); // { kty, crv, x, d }
    current[id] = { tokenHash: hashToken(token, salt), salt, scopes: normalizeScopes(scopes), publicKey, createdAt: Date.now() };
    const tmp = `${this.file}.${randomBytes(6).toString("hex")}.tmp`;
    await fsp.writeFile(tmp, JSON.stringify(current, null, 2), { encoding: "utf8", mode: 0o600 });
    await fsp.rename(tmp, this.file);
    try { await fsp.chmod(this.file, 0o600); } catch { /* best effort on platforms without POSIX modes */ }
    return { id, scopes: normalizeScopes(scopes), publicKey, privateKey };
  }
}

/** Does this subject carry authority over `channel`? `channel:*` or `admin` → any channel; otherwise
 *  the exact `channel:<name>` capability must be present. Deny-by-default. */
export function mayUseChannel(subject, channel) {
  if (!subject || !Array.isArray(subject.scopes)) return false;
  return subject.scopes.includes("admin")
    || subject.scopes.includes("channel:*")
    || subject.scopes.includes(`channel:${channel}`);
}
