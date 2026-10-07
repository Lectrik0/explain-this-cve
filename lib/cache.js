// A small in-memory cache with per-entry expiry and a hard size limit.
//
// Why it exists: every lookup would otherwise hit NVD (shared quota of 5 or 50 requests per 30 s) and
// the LLM (free daily token budget). Why the size limit matters: the key is derived from user input
// (valid CVE IDs are unlimited in number), so an unbounded Map would be a memory-exhaustion hole.
//
// Honest limitation: on serverless, each running instance has its OWN cache and instances are recycled,
// so this is a best-effort optimisation, not a guarantee. Vercel's CDN caching (Cache-Control s-maxage)
// adds a second, shared layer in front.

export class TtlCache {
  constructor({ maxEntries = 200, now = Date.now } = {}) {
    this.maxEntries = maxEntries;
    this.now = now;
    this.map = new Map(); // Map keeps insertion order, so the first key is the oldest
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key, value, ttlMs) {
    this.map.delete(key); // re-inserting moves the key to the "newest" position
    this.map.set(key, { value, expiresAt: this.now() + ttlMs });
    if (this.map.size > this.maxEntries) this.#shrink();
  }

  #shrink() {
    const t = this.now();
    for (const [key, entry] of this.map) if (entry.expiresAt <= t) this.map.delete(key); // expired first
    while (this.map.size > this.maxEntries) this.map.delete(this.map.keys().next().value); // then oldest
  }

  get size() {
    return this.map.size;
  }
}
