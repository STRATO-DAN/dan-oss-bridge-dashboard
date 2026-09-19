// Real local HTTP server, Node stdlib only — zero runtime dependencies.
//
// TRUST MODEL. Loopback binding limits network exposure but is NOT authentication — another local
// process, or a web page in the user's browser, can reach a loopback port too. So every /api request
// is authenticated to a PRINCIPAL before anything happens, and the message sender is whatever the
// server established from that credential — never a caller-supplied `from`. That is the difference
// between "agents are names that can send messages" and "agents are authenticated principals."
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BridgeStore, BridgeError } from "./store.js";
import { AuthStore, mayUseChannel } from "./auth.js";
import { Audit } from "./audit.js";
import { RateLimiter } from "./ratelimit.js";
import { canonicalMessage, verifySignature, verifyMessage } from "./sign.js";
import { verifyChain } from "./chain.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
};

function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [], size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 256 * 1024) { reject(new Error("request body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error("invalid JSON body")); }
    });
    req.on("error", reject);
  });
}

async function serveStatic(res, urlPath) {
  const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
  const resolved = path.resolve(PUBLIC_DIR, rel);
  if (resolved !== PUBLIC_DIR && !resolved.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403).end("forbidden"); return; }
  try {
    const data = await fs.readFile(resolved);
    res.writeHead(200, { "content-type": MIME[path.extname(resolved)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404).end("not found");
  }
}

const CHANNEL_RE = /^[A-Za-z0-9_-]{1,64}$/;

// DNS-rebinding guard — loopback-only hub; refuse any request whose Host isn't loopback so a web page
// the user visits can't rebind a hostname to 127.0.0.1 and drive the local hub.
function isLoopbackHost(hostHeader) {
  if (!hostHeader) return false;
  let host = String(hostHeader).trim().toLowerCase();
  if (host.startsWith("[")) host = host.slice(1, host.indexOf("]"));
  else host = host.replace(/:\d+$/, "");
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

// Establish the principal from the request. Never trusts a body field: identity is a credential
// (X-Bridge-Principal + X-Bridge-Token, or Authorization: Bearer <principal>:<token>) the server
// verifies. Returns the server-established subject { id, scopes } or null.
function authenticate(auth, req) {
  let principal = req.headers["x-bridge-principal"];
  let token = req.headers["x-bridge-token"];
  const authz = req.headers["authorization"];
  if ((!principal || !token) && typeof authz === "string" && authz.startsWith("Bearer ")) {
    const creds = authz.slice(7).trim();
    const i = creds.indexOf(":");
    if (i > 0) { principal = creds.slice(0, i); token = creds.slice(i + 1); }
  }
  return auth.authenticate(principal, token);
}

// CSRF / cross-site guard for the state-changing (POST) API. The custom auth header is itself the
// primary defense (a cross-origin page cannot set X-Bridge-Token, and we send no CORS headers), but
// we also refuse an explicit cross-site fetch metadata signal as defense in depth. Non-browser
// clients (agents, curl) send no Sec-Fetch-Site and are unaffected.
function isCrossSite(req) {
  const s = req.headers["sec-fetch-site"];
  return s === "cross-site" || s === "same-site";
}

const MAX_HELD_POLLS = 1024;      // cap concurrently-held long-poll connections (bounds sockets + listeners)
const SOCKET_TIMEOUT_MS = 35_000; // reap an idle socket ~10s past the 25s long-poll ceiling

export function createServer(cfg = {}) {
  const { dataDir } = cfg;
  const store = new BridgeStore(dataDir);
  const auth = new AuthStore(dataDir);
  const audit = new Audit(dataDir);
  const limiter = new RateLimiter({ capacity: 120, refillPerSec: 2 }); // burst 120, ~2/s sustained per principal
  // Unauthenticated requests carry no principal to scope a limit to, so they are capped per client IP
  // (loopback → one shared bucket) BEFORE their 401 + audit.record runs. Without this, an unauthenticated
  // flood writes one audit line per request — amplifying disk writes and, via retention/rotation, evicting
  // real audit history. Over the cap the request is refused (429) WITHOUT auditing, bounding unauth volume.
  const unauthLimiter = new RateLimiter({
    capacity: Number.isInteger(cfg.unauthBurst) ? cfg.unauthBurst : 60,
    refillPerSec: Number.isFinite(cfg.unauthRefillPerSec) ? cfg.unauthRefillPerSec : 1,
  });
  const maxHeldPolls = Number.isInteger(cfg.maxHeldPolls) && cfg.maxHeldPolls >= 0 ? cfg.maxHeldPolls : MAX_HELD_POLLS;
  let heldPolls = 0; // number of long-polls currently holding a connection open
  const ready = store.init();

  const server = http.createServer(async (req, res) => {
    await ready;
    const url = new URL(req.url, "http://127.0.0.1");
    if (!isLoopbackHost(req.headers.host)) { res.writeHead(403).end("forbidden"); return; }
    const p = url.pathname;

    // Static UI is public (plain HTML/CSS/JS); the API is not.
    if (!p.startsWith("/api/")) {
      if (req.method === "GET") return serveStatic(res, p);
      res.writeHead(404).end("not found");
      return;
    }

    if (req.method === "POST" && isCrossSite(req)) {
      audit.record({ op: "api", result: "deny", reason: "cross_site" });
      return sendJson(res, 403, { ok: false, reason: "cross-site request refused" });
    }

    // ── authenticate every API request (deny by default) ──────────────────────────────────────────
    const subject = authenticate(auth, req);
    if (!subject) {
      // Rate-limit the unauthenticated path per client IP BEFORE it audits, so a flood can't write (and
      // rotate away) unbounded audit volume. Over the cap → 429 with NO audit line.
      const ip = req.socket?.remoteAddress || "unknown";
      if (!unauthLimiter.take(ip)) {
        return sendJson(res, 429, { ok: false, reason: "rate limit exceeded — slow down" });
      }
      audit.record({ op: "api", result: "deny", reason: "unauthenticated" });
      const reason = auth.hasAnyPrincipal()
        ? "authentication required — send X-Bridge-Principal + X-Bridge-Token (or Authorization: Bearer <principal>:<token>)"
        : "no principals registered yet — run `dan-oss-bridge-dashboard register <id> --scope channel:*` to mint the first token";
      return sendJson(res, 401, { ok: false, reason });
    }
    if (!limiter.take(subject.id)) {
      audit.record({ op: "api", result: "deny", principal: subject.id, reason: "rate_limited" });
      return sendJson(res, 429, { ok: false, reason: "rate limit exceeded — slow down" });
    }

    try {
      if (p === "/api/status" && req.method === "GET") {
        // Only reveal channels this principal is authorized for — don't leak names outside its scope.
        const channels = store.listChannels().filter((c) => mayUseChannel(subject, c));
        return sendJson(res, 200, { ok: true, principal: subject.id, channels });
      }

      const messagesMatch = p.match(/^\/api\/channels\/([^/]+)\/messages$/);
      if (messagesMatch && CHANNEL_RE.test(messagesMatch[1])) {
        const channel = messagesMatch[1];
        if (!mayUseChannel(subject, channel)) {
          audit.record({ op: "message", result: "deny", principal: subject.id, channel, reason: "forbidden_channel" });
          return sendJson(res, 403, { ok: false, reason: `principal ${subject.id} is not authorized for channel ${channel}` });
        }
        if (req.method === "POST") {
          const body = await readBody(req);
          if (typeof body.text !== "string" || !body.text.trim()) return sendJson(res, 400, { ok: false, reason: "text is required" });
          // FINDING 09 fix: cheap size rejection BEFORE expensive Ed25519 verification —
          // otherwise an oversized body always pays verify cost before its inevitable 413.
          if (Buffer.byteLength(body.text, "utf8") > 16 * 1024) {
            audit.record({ op: "message.post", result: "deny", principal: subject.id, channel, reason: "too_large" });
            return sendJson(res, 413, { ok: false, reason: "message text exceeds the 16384-byte limit", code: "TOO_LARGE" });
          }
          // Identity is server-established: a `from` that isn't the caller's own principal is a
          // spoofing attempt and is refused outright (INV-01).
          if (body.from !== undefined && String(body.from) !== subject.id) {
            audit.record({ op: "message.post", result: "deny", principal: subject.id, channel, reason: "sender_spoof" });
            return sendJson(res, 403, { ok: false, reason: `cannot post as ${body.from} — messages are sent as the authenticated principal ${subject.id}` });
          }
          if (typeof body.nonce !== "string" || !body.nonce) return sendJson(res, 400, { ok: false, reason: "nonce is required (replay protection)", code: "NONCE_REQUIRED" });
          if (body.ts === undefined || body.ts === null) return sendJson(res, 400, { ok: false, reason: "ts is required (part of the signed payload)", code: "TS_REQUIRED" });
          // Every message must be SIGNED by the principal's key, and the signature is verified here so
          // a stored message can be verified again later by any receiver without trusting this hub
          // (INV-10). A missing or bad signature is refused — a signature is never decoration.
          if (typeof body.sig !== "string" || !body.sig) {
            audit.record({ op: "message.post", result: "deny", principal: subject.id, channel, reason: "sig_missing" });
            return sendJson(res, 400, { ok: false, reason: "sig is required — sign the canonical message with your principal's private key", code: "SIG_REQUIRED" });
          }
          const canonical = canonicalMessage({ from: subject.id, channel, nonce: body.nonce, ts: body.ts, text: body.text });
          if (!subject.publicKey || !verifySignature(subject.publicKey, canonical, body.sig)) {
            audit.record({ op: "message.post", result: "deny", principal: subject.id, channel, reason: "bad_signature" });
            return sendJson(res, 403, { ok: false, reason: "signature verification failed for this principal", code: "BAD_SIGNATURE" });
          }
          const message = await store.postMessage(channel, subject.id, body.text, { nonce: body.nonce, ts: body.ts, sig: body.sig });
          audit.record({ op: "message.post", result: "ok", principal: subject.id, channel, msgId: message.id });
          return sendJson(res, 200, { ok: true, message });
        }
        if (req.method === "GET") {
          const sinceId = Number(url.searchParams.get("sinceId")) || 0;
          // Cap concurrently-held long-polls: over capacity, degrade to an immediate read instead of
          // holding another connection (and EventEmitter listener) open under a long-poll flood.
          const hold = url.searchParams.get("wait") === "1" && heldPolls < maxHeldPolls;
          let result;
          if (hold) {
            heldPolls++;
            try { result = await store.waitForMessages(channel, sinceId, 25000); }
            finally { heldPolls--; }
          } else {
            result = await store.waitForMessages(channel, sinceId, 0);
          }
          // FINDING 07 fix: successful history reads are security events — a stolen token
          // reading history must leave forensic evidence, not a blind spot.
          audit.record({ op: "message.read", result: "ok", principal: subject.id, channel, sinceId });
          return sendJson(res, 200, {
            ok: true,
            messages: result.messages,
            latestId: result.latestId,
            minRetainedId: result.minRetainedId,
            // Honest history-gap signal: the caller's cursor is older than the oldest retained message,
            // so the returned tail is NOT the complete history after sinceId — resync from latestId.
            ...(result.gap ? { gap: true, reason: "HISTORY_GAP" } : {}),
          });
        }
      }

      // Whole-channel integrity audit: walk the retained log and report, per message, whether its
      // Ed25519 signature verifies AND whether its hash-chain link is intact — plus a channel-level
      // verdict and the first broken message id. Read-only; authenticated + scoped like every route.
      // This is the data the dashboard's "verify log integrity" panel renders.
      const verifyMatch = p.match(/^\/api\/channels\/([^/]+)\/verify$/);
      if (verifyMatch && CHANNEL_RE.test(verifyMatch[1]) && req.method === "GET") {
        const channel = verifyMatch[1];
        if (!mayUseChannel(subject, channel)) {
          audit.record({ op: "verify", result: "deny", principal: subject.id, channel, reason: "forbidden_channel" });
          return sendJson(res, 403, { ok: false, reason: `principal ${subject.id} is not authorized for channel ${channel}` });
        }
        const read = store.readMessages(channel, 0); // all retained messages, oldest-first
        const msgs = read.messages;
        const { chainPresent, firstBreakId, verdicts } = verifyChain(msgs);
        let sigForged = 0, sigUnverifiable = 0;
        const records = msgs.map((m, i) => {
          const publicKey = auth.getPublicKey(m.from);
          // A message whose sender has no registered key can't be authenticated by this hub — report it
          // honestly as unverifiable rather than silently "ok" or falsely "forged".
          const sigVerified = publicKey ? verifyMessage(m, channel, publicKey) : null;
          if (sigVerified === false) sigForged++;
          else if (sigVerified === null) sigUnverifiable++;
          return { id: m.id, from: m.from, ts: m.ts, sigVerified, chainOk: verdicts[i].chainOk };
        });
        const chainIntact = chainPresent ? firstBreakId === null : null;
        return sendJson(res, 200, {
          ok: true, channel,
          chainPresent, chainIntact, firstBreakId,
          minRetainedId: read.minRetainedId, latestId: read.latestId,
          counts: { total: records.length, sigForged, sigUnverifiable },
          records,
        });
      }

      const presenceMatch = p.match(/^\/api\/channels\/([^/]+)\/presence$/);
      if (presenceMatch && CHANNEL_RE.test(presenceMatch[1])) {
        const channel = presenceMatch[1];
        if (!mayUseChannel(subject, channel)) {
          audit.record({ op: "presence", result: "deny", principal: subject.id, channel, reason: "forbidden_channel" });
          return sendJson(res, 403, { ok: false, reason: `principal ${subject.id} is not authorized for channel ${channel}` });
        }
        if (req.method === "POST") {
          // Presence is announced for the authenticated principal — you cannot mark another agent online.
          store.announcePresence(channel, subject.id);
          audit.record({ op: "presence.announce", result: "ok", principal: subject.id, channel });
          return sendJson(res, 200, { ok: true, principal: subject.id });
        }
        if (req.method === "GET") {
          return sendJson(res, 200, { ok: true, online: store.listPresence(channel) });
        }
      }

      // A principal's public signing key, so a receiver can verify that principal's messages
      // independently of this hub (INV-10). Authenticated (any registered principal may fetch a key);
      // public keys are not secret, but reads stay behind the same auth boundary as everything else.
      const pubkeyMatch = p.match(/^\/api\/principals\/([^/]+)\/pubkey$/);
      if (pubkeyMatch && req.method === "GET") {
        const who = pubkeyMatch[1];
        const publicKey = auth.getPublicKey(who);
        if (!publicKey) return sendJson(res, 404, { ok: false, reason: `no principal ${who}` });
        return sendJson(res, 200, { ok: true, principal: who, publicKey });
      }

      res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: false, reason: "not found" }));
    } catch (err) {
      if (err instanceof BridgeError) {
        const status = { REPLAY: 409, STALE: 400, NONCE_REQUIRED: 400, TOO_MANY_CHANNELS: 429, TOO_LARGE: 413 }[err.code] || 400;
        audit.record({ op: "message.post", result: "deny", principal: subject.id, reason: err.code });
        return sendJson(res, status, { ok: false, reason: err.message, code: err.code });
      }
      // Never hand raw internals to the caller; log the shape, return a generic message.
      audit.record({ op: "api", result: "error", principal: subject.id, reason: err && err.message });
      return sendJson(res, 400, { ok: false, reason: "request could not be processed" });
    }
  });

  // Reap idle sockets past the long-poll ceiling so a client that opens connections and never reads can't
  // pin them open indefinitely (a long-poll answers at 25s, well before this 35s idle timeout fires).
  server.setTimeout(SOCKET_TIMEOUT_MS);
  server.on("close", () => { store.close().catch(() => {}); });
  server._bridge = { store, auth, audit, ready, get heldPolls() { return heldPolls; }, maxHeldPolls };
  return server;
}

export async function listen(port, dataDir) {
  const server = createServer({ dataDir });
  // Surface init failures (e.g. another hub already holds this data dir) BEFORE binding the port,
  // so the CLI can print a clean error instead of starting a half-broken second hub.
  await server._bridge.ready;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}
