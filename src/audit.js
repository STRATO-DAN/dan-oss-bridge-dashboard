// Append-only audit log. Records what the SERVER established, never what the caller claimed — the
// `principal` field is always the authenticated subject (or null for a rejected unauthenticated
// attempt), never a caller-supplied `from`. That is the whole point: an audit trail that copies the
// client's own sender string is a record of claims, not of facts.
//
// Zero-dep, JSONL, one line per event. Light single-file rotation keeps it bounded (retention is part
// of the security model — an audit log that can grow without limit is its own denial-of-service).
import fs from "node:fs/promises";
import path from "node:path";

const MAX_BYTES = 8 * 1024 * 1024; // rotate audit.log -> audit.log.1 past this; one generation kept.

export class Audit {
  constructor(dataDir) {
    this.file = path.join(dataDir, "audit.log");
    this._chain = Promise.resolve(); // serialize appends so lines never interleave
  }

  /** Record one event. Server-established fields only:
   *  { op, result, principal?, channel?, msgId?, reason? }. `ts` is stamped here, server-side. */
  record(event) {
    const line = JSON.stringify({
      ts: Date.now(),
      op: event.op,
      result: event.result, // "ok" | "deny" | "error"
      principal: event.principal ?? null,
      channel: event.channel ?? null,
      msgId: event.msgId ?? null,
      reason: event.reason ?? null,
    }) + "\n";
    // Chain the writes; swallow errors so auditing can never take the request path down, but never
    // silently drop the security semantics of the request itself (the caller's result is unaffected).
    this._chain = this._chain.then(() => this.#append(line)).catch(() => {});
    return this._chain;
  }

  async #append(line) {
    try {
      const st = await fs.stat(this.file);
      if (st.size + Buffer.byteLength(line) > MAX_BYTES) {
        await fs.rename(this.file, `${this.file}.1`).catch(() => {});
      }
    } catch { /* no file yet — first append creates it */ }
    await fs.appendFile(this.file, line, { encoding: "utf8", mode: 0o600 });
  }
}
