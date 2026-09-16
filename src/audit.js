// Append-only audit log. Records what the SERVER established, never what the caller claimed — the
// `principal` field is always the authenticated subject (or null for a rejected unauthenticated
// attempt), never a caller-supplied `from`. That is the whole point: an audit trail that copies the
// client's own sender string is a record of claims, not of facts.
//
// Zero-dep, JSONL, one line per event. Light single-file rotation keeps it bounded (retention is part
// of the security model — an audit log that can grow without limit is its own denial-of-service).
//
// TAMPER-EVIDENCE (v0.4): each line carries `prev` (the previous line's hash) and `hash` = sha256(body),
// forming a hash-chain. `verifyChain()` recomputes it, so any edited, reordered, inserted, or
// mid-stream-truncated line is DETECTABLE. Honest bound: this is tamper-EVIDENT, not tamper-PROOF — a
// process with write access to the file can rewrite the whole chain from a point; pair with append-only
// filesystem perms and/or shipping lines off-box for a stronger guarantee. It is a real improvement over
// a plain file where silent edits leave no trace.
//
// FAILURES ARE SURFACED, not swallowed: a failed audit write increments `writeFailures`, records
// `lastError`, and logs to stderr — so "the thing documenting security events is quietly failing" cannot
// happen unnoticed — while still never taking the request path down (the caller's result is unaffected).
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const MAX_BYTES = 8 * 1024 * 1024; // rotate audit.log -> audit.log.1 past this; one generation kept.

export class Audit {
  constructor(dataDir) {
    this.file = path.join(dataDir, "audit.log");
    this._chain = Promise.resolve(); // serialize appends so lines never interleave
    this._prevHash = null; // running hash of the last written line (the chain tip)
    this._loaded = false; // have we read the existing tail to continue the chain across a restart?
    this.writeFailures = 0; // surfaced, never silently swallowed
    this.lastError = null;
  }

  /** Record one event. Server-established fields only:
   *  { op, result, principal?, channel?, msgId?, reason? }. `ts` is stamped here, server-side. */
  record(event) {
    // Chain the writes; a failure can never take the request path down, but it is SURFACED (counter +
    // lastError + stderr), never silently dropped — a broken audit is itself a security event.
    this._chain = this._chain
      .then(() => this.#append(event))
      .catch((err) => {
        this.writeFailures++;
        this.lastError = err;
        try {
          process.stderr.write(`[dan-oss-bridge] AUDIT WRITE FAILED (#${this.writeFailures}): ${err?.message || err}\n`);
        } catch {
          /* stderr unavailable — nothing more we can safely do */
        }
      });
    return this._chain;
  }

  async #ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    // Continue the chain across a restart: seed _prevHash from the last line already on disk.
    try {
      const raw = await fs.readFile(this.file, "utf8");
      const lines = raw.split("\n").filter(Boolean);
      const last = lines[lines.length - 1];
      if (last) {
        const parsed = JSON.parse(last);
        if (typeof parsed.hash === "string") this._prevHash = parsed.hash;
      }
    } catch {
      /* no file yet — the chain starts fresh */
    }
  }

  #buildLine(event) {
    // Server-established fields only, plus the chain link `prev`. This object is exactly what the hash
    // covers, and the written line is the same object plus `hash` — so a verifier strips `hash`, re-serializes
    // in the same key order, and recomputes.
    const body = {
      ts: Date.now(),
      op: event.op,
      result: event.result, // "ok" | "deny" | "error"
      principal: event.principal ?? null,
      channel: event.channel ?? null,
      msgId: event.msgId ?? null,
      reason: event.reason ?? null,
      prev: this._prevHash,
    };
    const hash = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
    return { line: JSON.stringify({ ...body, hash }) + "\n", hash };
  }

  async #append(event) {
    await this.#ensureLoaded();
    const { line, hash } = this.#buildLine(event);
    try {
      const st = await fs.stat(this.file);
      if (st.size + Buffer.byteLength(line) > MAX_BYTES) {
        // The chain continues across rotation: the new file's first `prev` is the rotated file's last
        // hash, so both generations remain a single verifiable chain.
        await fs.rename(this.file, `${this.file}.1`).catch(() => {});
      }
    } catch {
      /* no file yet — first append creates it */
    }
    await fs.appendFile(this.file, line, { encoding: "utf8", mode: 0o600 });
    this._prevHash = hash; // advance the chain tip only after a SUCCESSFUL write
  }

  /** Verify an audit file's hash-chain. Each line's `hash` must equal sha256 of its body (with `hash`
   *  removed), and each line's `prev` must equal the previous line's `hash`. Detects edited, reordered,
   *  inserted, or mid-stream-truncated lines. Returns { ok, lines, brokenAt?, reason? }. */
  static async verifyChain(file) {
    let raw;
    try {
      raw = await fs.readFile(file, "utf8");
    } catch {
      return { ok: true, lines: 0 }; // no log yet is a valid (empty) chain
    }
    const lines = raw.split("\n").filter(Boolean);
    let prev = null;
    for (let i = 0; i < lines.length; i++) {
      let obj;
      try {
        obj = JSON.parse(lines[i]);
      } catch {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "unparseable line" };
      }
      const { hash, ...body } = obj;
      if (body.prev !== prev) {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "prev-hash mismatch (reorder/insert/truncation)" };
      }
      const recomputed = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
      if (recomputed !== hash) {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "line hash mismatch (edited content)" };
      }
      prev = hash;
    }
    return { ok: true, lines: lines.length };
  }
}
