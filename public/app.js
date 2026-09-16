// [DAN] BRIDGE DASHBOARD — real client logic, plain fetch + DOM. No framework, matches the other DAN-OSS
// tools. Long-polls /messages (server holds the request open until a new one arrives or 25s pass)
// instead of a tight interval loop — real near-live updates without websockets.
//
// Identity is authenticated: the client sends a registered principal + token on every request, and
// the server stamps the sender itself — this tab cannot post under a name it hasn't proven.
const $ = (id) => document.getElementById(id);

let channel = null;
let principal = null;
let token = null;
let signingKey = null; // imported WebCrypto Ed25519 private key (never leaves the browser)
let lastId = 0;
let polling = false;
let presenceTimer = null;
let sessionToken = 0; // bumped on every join so a previous channel's long-poll can be retired cleanly

// The token is a per-viewer convenience kept in this browser only; every access is guarded so a
// private window or blocked storage degrades to "you re-type it", never a crash.
const REMEMBER = "dan-oss-bridge-creds";
function loadCreds() {
  try {
    const c = JSON.parse(localStorage.getItem(REMEMBER) || "{}");
    if (c.principal) $("nameInput").value = c.principal;
    if (c.token) $("tokenInput").value = c.token;
    if (c.key) $("keyInput").value = c.key;
  } catch { /* storage unavailable — fields just start empty */ }
}
function saveCreds() {
  try { localStorage.setItem(REMEMBER, JSON.stringify({ principal, token, key: $("keyInput").value.trim() })); } catch { /* non-fatal */ }
}

function authHeaders() {
  return { "X-Bridge-Principal": principal || "", "X-Bridge-Token": token || "" };
}
function newNonce() {
  return (crypto.randomUUID && crypto.randomUUID()) || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// base64url of an ArrayBuffer (WebCrypto returns the signature as one).
function b64url(buf) {
  let s = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// The exact canonical form src/sign.js uses — a JSON array of primitives, identical bytes in the
// browser and on the server, so the server's Node verify accepts the browser's WebCrypto signature.
function canonical(from, ch, nonce, ts, text) {
  return JSON.stringify([String(from), String(ch), String(nonce), Number(ts), String(text)]);
}
async function importSigningKey(jwk) {
  return crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, { name: "Ed25519" }, false, ["sign"]);
}
async function signBody(ch, text) {
  const nonce = newNonce();
  const ts = Date.now();
  const data = new TextEncoder().encode(canonical(principal, ch, nonce, ts, text));
  const sig = b64url(await crypto.subtle.sign({ name: "Ed25519" }, signingKey, data));
  return { text, nonce, ts, sig };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function relativeTime(ms) {
  const diff = Date.now() - ms;
  if (diff < 45_000) return "just now";
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function setStatus(el, kind, text) {
  el.hidden = false;
  el.className = `status-line ${kind}`;
  el.textContent = text;
}

// GET with auth. Returns { status, data } so callers can react to 401/403/429, not just data.ok.
async function apiGet(url) {
  const res = await fetch(url, { headers: authHeaders() });
  const data = await res.json().catch(() => ({ ok: false }));
  return { status: res.status, data };
}
async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ ok: false }));
  return { status: res.status, data };
}

function appendMessages(messages) {
  const list = $("messageList");
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 60;
  if (list.querySelector(".empty-note")) list.innerHTML = "";
  for (const m of messages) {
    lastId = Math.max(lastId, m.id);
    const li = document.createElement("li");
    li.className = "message-row";
    const abs = new Date(m.ts).toLocaleString();
    li.innerHTML = `<span class="message-from">${escapeHtml(m.from)}</span><span class="message-meta hint" data-ts="${m.ts}" title="${escapeHtml(abs)}">${escapeHtml(relativeTime(m.ts))}</span><div class="message-text">${escapeHtml(m.text)}</div>`;
    list.appendChild(li);
  }
  if (nearBottom) list.scrollTop = list.scrollHeight;
}

// A server-reported history gap means our cursor is older than the oldest retained message: the tail
// we got is NOT complete, so jump the cursor forward and tell the reader rather than pretend otherwise.
function handleGap(data) {
  if (!data.gap) return false;
  lastId = Number(data.latestId) || lastId;
  const list = $("messageList");
  const note = document.createElement("li");
  note.className = "empty-note";
  note.textContent = "— older messages aged out of this channel's history; showing from here —";
  list.appendChild(note);
  return true;
}

async function loadInitialMessages(session) {
  const { status, data } = await apiGet(`/api/channels/${encodeURIComponent(channel)}/messages?sinceId=0`);
  if (session !== sessionToken) return; // a newer join/switch superseded this load
  if (!data.ok) { setStatus($("joinStatus"), "err", authError(status, data)); polling = false; return; }
  handleGap(data);
  if (data.messages.length > 0) appendMessages(data.messages);
  else if (!$("messageList").querySelector(".empty-note")) $("messageList").innerHTML = `<li class="empty-note">No messages yet — say something below.</li>`;
}

async function pollLoop(session) {
  while (polling && session === sessionToken) {
    try {
      const { status, data } = await apiGet(`/api/channels/${encodeURIComponent(channel)}/messages?sinceId=${lastId}&wait=1`);
      if (!polling || session !== sessionToken) return; // stopped, or switched channel mid-poll
      if (!data.ok) {
        if (status === 401 || status === 403) { setStatus($("joinStatus"), "err", authError(status, data)); polling = false; return; }
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      handleGap(data);
      if (data.messages.length > 0) appendMessages(data.messages);
    } catch {
      await new Promise((r) => setTimeout(r, 2000)); // honest backoff on a transient network hiccup
    }
  }
}

async function refreshPresence() {
  const { data } = await apiGet(`/api/channels/${encodeURIComponent(channel)}/presence`);
  const el = $("presenceList");
  if (!data.ok || !data.online || data.online.length === 0) {
    el.innerHTML = `<span class="presence-empty hint">Nobody else has announced presence yet.</span>`;
    return;
  }
  el.innerHTML = data.online.map((p) => `<span class="presence-pill"><span class="presence-dot"></span>${escapeHtml(p.from)}</span>`).join("");
}

async function refreshChannels() {
  const el = $("channelList");
  if (!el) return;
  try {
    const { data } = await apiGet("/api/status");
    const names = data.ok && Array.isArray(data.channels) ? data.channels : [];
    if (names.length === 0) { el.innerHTML = ""; return; }
    el.innerHTML = names
      .map((name) => `<button type="button" class="channel-item${name === channel ? " active" : ""}" data-channel="${escapeHtml(name)}">${escapeHtml(name)}</button>`)
      .join("");
  } catch {
    /* transient — leave the last-rendered list in place */
  }
}

function authError(status, data) {
  if (status === 401) return "Authentication failed — check the principal id and token (mint one with `register`).";
  if (status === 403) return data.reason || "Not authorized for this channel.";
  if (status === 429) return "Rate limited — slow down.";
  return data.reason || "Request failed.";
}

async function join() {
  const channelName = $("channelInput").value.trim();
  const principalValue = $("nameInput").value.trim();
  const tokenValue = $("tokenInput").value.trim();
  const keyValue = $("keyInput").value.trim();
  const status = $("joinStatus");

  if (!/^[A-Za-z0-9_-]{1,64}$/.test(channelName)) {
    setStatus(status, "err", "Channel name: letters, digits, - and _ only, up to 64 characters.");
    return;
  }
  if (!principalValue || !tokenValue || !keyValue) {
    setStatus(status, "err", "Enter your registered principal id, connection token, and signing key (all minted by `register`).");
    return;
  }
  let jwk;
  try { jwk = JSON.parse(keyValue); }
  catch { setStatus(status, "err", "Signing key must be the JSON JWK printed by `register`."); return; }
  try { signingKey = await importSigningKey(jwk); }
  catch { setStatus(status, "err", "Could not load the Ed25519 signing key in this browser — check the key value."); return; }

  channel = channelName;
  principal = principalValue;
  token = tokenValue;
  saveCreds();
  lastId = 0;
  polling = true;
  const session = ++sessionToken; // retires any previous channel's poll loop when switching

  $("roomLabel").textContent = channel;
  $("room").classList.add("active");
  $("messageList").innerHTML = ""; // drop the previous channel's messages when switching
  status.hidden = true;

  const pres = await postJson(`/api/channels/${encodeURIComponent(channel)}/presence`, {});
  if (session !== sessionToken) return;
  if (!pres.data.ok) { setStatus(status, "err", authError(pres.status, pres.data)); polling = false; return; }

  await loadInitialMessages(session);
  if (!polling) return;
  pollLoop(session);

  if (presenceTimer) clearInterval(presenceTimer);
  presenceTimer = setInterval(() => {
    postJson(`/api/channels/${encodeURIComponent(channel)}/presence`, {});
    refreshPresence();
    refreshChannels();
  }, 10000);
  refreshPresence();
  refreshChannels();
}

async function send() {
  const input = $("composeInput");
  const text = input.value.trim();
  if (!text || !channel) return;
  input.value = "";
  let body;
  try { body = await signBody(channel, text); }
  catch { setStatus($("joinStatus"), "err", "Could not sign the message — re-join with a valid signing key."); return; }
  const { status, data } = await postJson(`/api/channels/${encodeURIComponent(channel)}/messages`, body);
  if (!data.ok) setStatus($("joinStatus"), "err", authError(status, data));
}

$("joinBtn").addEventListener("click", join);
$("sendBtn").addEventListener("click", send);
$("composeInput").addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });

$("channelList").addEventListener("click", (e) => {
  const btn = e.target.closest(".channel-item");
  if (!btn || !btn.dataset.channel || btn.dataset.channel === channel) return;
  $("channelInput").value = btn.dataset.channel;
  join();
});

setInterval(() => {
  for (const el of document.querySelectorAll(".message-meta[data-ts]")) {
    el.textContent = relativeTime(Number(el.dataset.ts));
  }
}, 30_000);

loadCreds();
window.addEventListener("beforeunload", () => { polling = false; });
