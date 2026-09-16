// Per-principal token bucket. Resource limits are scoped to the authenticated principal, so one
// noisy or hostile agent throttles only itself — it can't exhaust the hub or drown out other agents
// (whose downstream LLM consumers would otherwise pay the amplification cost). Zero-dep, in-memory.
export class RateLimiter {
  constructor({ capacity = 60, refillPerSec = 1 } = {}) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.buckets = new Map(); // key -> { tokens, last }
  }

  /** Try to spend one token for `key`. Returns true if allowed, false if the principal is over its
   *  rate. Buckets refill continuously; idle buckets are swept lazily so the map stays bounded. */
  take(key) {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b) { b = { tokens: this.capacity, last: now }; this.buckets.set(key, b); }
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.last) / 1000) * this.refillPerSec);
    b.last = now;
    if (this.buckets.size > 4096) this.#sweep(now);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  #sweep(now) {
    for (const [k, b] of this.buckets) {
      if (b.tokens >= this.capacity && now - b.last > 60_000) this.buckets.delete(k);
    }
  }
}
