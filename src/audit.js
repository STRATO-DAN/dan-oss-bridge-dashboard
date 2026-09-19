// Append-only audit log. Records what the SERVER established, never what the caller claimed — the
// `principal` field is always the authenticated subject (or null for a rejected unauthenticated
// attempt), never a caller-supplied `from`. That is the whole point: an audit trail that copies the
// client's own sender string is a record of claims, not of facts.
//
// Zero-dep, JSONL, one line per event. Light single-file rotation keeps it bounded (retention is part
// of the security model — an audit log that can grow without limit is its own denial-of-service).
//
// TAMPER-EVIDENCE: each line carries `prev` (the previous line's hash) and `hash` = sha256(body),
// forming a hash-chain. `verifyChain()`/`verifyDir()` recompute it, so any edited, reordered, inserted,
// or mid-stream-truncated line is DETECTABLE. The chain spans rotation: the new file's first `prev` is
// the rotated file's last hash, so a rotated log is ONE continuous chain across both generations, and
// `verifyDir()` verifies them together (a rotated log that read a single file would false-positive as
// tampered). A durable rotation ledger (`audit.anchor`) records the tip of every generation as it is
// rotated out, so a whole DROPPED generation (2-generation retention, or a deleted audit.log.1) is
// itself detectable rather than silent. Honest bound: this is tamper-EVIDENT, not tamper-PROOF — a
// process with write access can rewrite the whole chain (and the anchor) from a point; pair with
// append-only filesystem perms and/or shipping lines off-box for a stronger guarantee.
//
// FAILURES ARE SURFACED, not swallowed: a failed audit write increments `writeFailures`, records
// `lastError`, and logs to stderr — so "the thing documenting security events is quietly failing" cannot
// happen unnoticed — while still never taking the request path down (the caller's result is unaffected).
//
// DURABILITY: durable writes are fsync'd (the appended file and its parent directory), best-effort, so a
// crash right after the write does not lose an already-recorded line where the platform supports it.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const MAX_BYTES = 8 * 1024 * 1024; // rotate audit.log -> audit.log.1 past this; one generation kept on disk.

export class Audit {
  constructor(dataDir, opts = {}) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, "audit.log");
    this.anchorFile = path.join(dataDir, "audit.anchor"); // append-only rotation ledger (dropped-gen detection)
    // Overridable so tests can force rotation without writing 8 MiB of events.
    this.maxBytes = Number.isInteger(opts.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : MAX_BYTES;
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

  /** Wait for every audit write queued so far to settle (success or already-handled failure). A caller
   *  tearing down (test cleanup, graceful shutdown) should drain before removing/closing the data dir —
   *  record() is deliberately fire-and-forget so it never blocks the request path, so nothing else
   *  guarantees a pending write finishes before then. */
  drain() {
    return this._chain;
  }

  async #ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    // Continue the chain across a restart: seed _prevHash from the last line already on disk. If audit.log
    // is absent (a crash between the rotation rename and the first append would leave it so), fall back to
    // the rotated generation's tip — otherwise the next append would start prev=null and orphan a fresh
    // chain from audit.log.1, an orphan that verifies CLEAN as a single file.
    this._prevHash = (await Audit.#tailHash(this.file)) ?? (await Audit.#tailHash(`${this.file}.1`)) ?? null;
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
      if (st.size + Buffer.byteLength(line) > this.maxBytes) {
        // Record the rotated-out generation's tip in the durable append-only anchor BEFORE the rename, so
        // a later-dropped generation (retention eviction, or a deleted audit.log.1) stays DETECTABLE. The
        // chain also continues across rotation: the new file's first `prev` is the rotated file's tip, so
        // both generations remain a single verifiable chain.
        await this.#recordRotation(this._prevHash);
        await fs.rename(this.file, `${this.file}.1`).catch(() => {});
      }
    } catch {
      /* no file yet — first append creates it */
    }
    const fh = await fs.open(this.file, "a", 0o600);
    try {
      await fh.appendFile(line, { encoding: "utf8" });
      try { await fh.sync(); } catch { /* fsync unsupported here — best effort */ }
    } finally {
      await fh.close();
    }
    await Audit.#fsyncDir(this.dataDir); // make the appended line durable across a crash (best effort)
    this._prevHash = hash; // advance the chain tip only after a SUCCESSFUL write
  }

  // Append one rotation record: the generation number and the hash tip of the generation being rotated
  // out. Append-only + self-hashed, so removing a whole generation later is detectable — the anchor still
  // attests it existed and where its chain ended. Tamper-evidence, not proof (same honest bound as the log).
  async #recordRotation(tip) {
    let gen = 1;
    try {
      const raw = await fs.readFile(this.anchorFile, "utf8");
      gen = raw.split("\n").filter(Boolean).length + 1;
    } catch { /* first rotation — the ledger starts here */ }
    const rec = { gen, tip: tip ?? null, ts: Date.now() };
    const recHash = crypto.createHash("sha256").update(JSON.stringify(rec)).digest("hex");
    const fh = await fs.open(this.anchorFile, "a", 0o600);
    try {
      await fh.appendFile(JSON.stringify({ ...rec, hash: recHash }) + "\n", { encoding: "utf8" });
      try { await fh.sync(); } catch { /* best effort */ }
    } finally {
      await fh.close();
    }
    await Audit.#fsyncDir(this.dataDir);
  }

  static async #tailHash(file) {
    try {
      const raw = await fs.readFile(file, "utf8");
      const lines = raw.split("\n").filter(Boolean);
      const last = lines[lines.length - 1];
      if (last) {
        const parsed = JSON.parse(last);
        if (typeof parsed.hash === "string") return parsed.hash;
      }
    } catch { /* absent/unreadable — no tip to seed from */ }
    return null;
  }

  static async #exists(f) {
    try { await fs.access(f); return true; } catch { return false; }
  }

  static async #fsyncDir(dir) {
    let fh;
    try {
      fh = await fs.open(dir, "r");
      await fh.sync();
    } catch {
      /* opening/fsyncing a directory is not portable (e.g. Windows) — best effort */
    } finally {
      if (fh) await fh.close().catch(() => {});
    }
  }

  /** Verify one audit file's hash-chain. Each line's `hash` must equal sha256 of its body (with `hash`
   *  removed), and each line's `prev` must equal the previous line's `hash` (seeded from `seedPrev`, so a
   *  rotated continuation file verifies against the generation before it). Returns
   *  { ok, lines, prev, brokenAt?, reason? } — `prev` is the chain tip, for chaining across files. */
  static async verifyChain(file, { seedPrev = null } = {}) {
    let raw;
    try {
      raw = await fs.readFile(file, "utf8");
    } catch {
      return { ok: true, lines: 0, prev: seedPrev }; // no log yet is a valid (empty) chain
    }
    const lines = raw.split("\n").filter(Boolean);
    let prev = seedPrev;
    for (let i = 0; i < lines.length; i++) {
      let obj;
      try {
        obj = JSON.parse(lines[i]);
      } catch {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "unparseable line", prev };
      }
      const { hash, ...body } = obj;
      if (body.prev !== prev) {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "prev-hash mismatch (reorder/insert/truncation)", prev };
      }
      const recomputed = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
      if (recomputed !== hash) {
        return { ok: false, lines: lines.length, brokenAt: i, reason: "line hash mismatch (edited content)", prev };
      }
      prev = hash;
    }
    return { ok: true, lines: lines.length, prev };
  }

  /** Verify a data dir's audit chain as ONE continuous chain across the rotation boundary — audit.log.1
   *  (if present) then audit.log — instead of a single file (which false-positives on a clean rotated log,
   *  since audit.log's first `prev` is the rotated file's tip, not null). Also reports generation accounting
   *  from the rotation ledger so a DROPPED generation is detectable, not silent:
   *    { ok, lines, generations, generationsOnDisk, droppedGenerations, brokenAt?, reason? }.
   *  `generations` = every generation that has ever existed; `droppedGenerations` > 0 means older
   *  generations have aged out or been removed (the anchor still attests they existed). */
  static async verifyDir(dir) {
    const cur = path.join(dir, "audit.log");
    const prevGen = path.join(dir, "audit.log.1");
    const anchorFile = path.join(dir, "audit.anchor");

    let anchors = [];
    try {
      anchors = (await fs.readFile(anchorFile, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch { /* never rotated — no ledger */ }
    const rotations = anchors.length;

    const hasPrevGen = await Audit.#exists(prevGen);
    let lines = 0;
    let seed = null;
    if (hasPrevGen) {
      // audit.log.1 is the most-recently rotated generation; if a generation before IT was also rotated
      // out (and its file evicted), audit.log.1's own first `prev` is that earlier generation's tip — so
      // seed its verification from the anchor too, rather than expecting it to start at null.
      const seedPrev1 = rotations >= 2 ? (anchors[rotations - 2].tip ?? null) : null;
      const v1 = await Audit.verifyChain(prevGen, { seedPrev: seedPrev1 });
      if (!v1.ok) return { ...v1, generations: rotations + 1, generationsOnDisk: 2, droppedGenerations: rotations - 1, generation: "audit.log.1" };
      lines += v1.lines;
      seed = v1.prev; // audit.log continues from the previous generation's tip
    } else if (rotations > 0) {
      // A generation was rotated out but audit.log.1 is no longer on disk (2-generation retention, or a
      // deletion). The ledger still records the tip it ended on, so seed continuity from that recorded tip
      // rather than silently starting a fresh chain — and report the drop below.
      seed = anchors[anchors.length - 1].tip ?? null;
    }
    const vCur = await Audit.verifyChain(cur, { seedPrev: seed });
    if (!vCur.ok) return { ...vCur, generations: rotations + 1, generationsOnDisk: hasPrevGen ? 2 : 1, droppedGenerations: rotations - (hasPrevGen ? 1 : 0), generation: "audit.log" };
    lines += vCur.lines;

    return {
      ok: true,
      lines,
      generations: rotations + 1,                          // total generations that have ever existed
      generationsOnDisk: (hasPrevGen ? 1 : 0) + 1,
      droppedGenerations: rotations - (hasPrevGen ? 1 : 0), // > 0 ⇒ older generations gone — detectable, not silent
    };
  }
}
