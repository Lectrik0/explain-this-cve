// Rate limiting: a fixed-window counter per key (per client IP, plus one shared "NVD budget").
//
// Fixed window = "at most N requests per window; the counter resets when the window ends".
// Simple and cheap. Known weakness: a client can send N at the end of one window and N at the start of the
// next (2N in a short burst). Accepted here; the NVD budget and the Vercel firewall rule cover the rest.
//
// Honest limitation: counters live in this instance's memory. Several serverless instances each count
// separately, and a cold start resets the counters. That is why README tells you to ALSO add a Vercel
// Firewall rate-limit rule, which is enforced before the function runs.

import { isIP } from 'node:net';

export class RateLimiter {
  constructor({ limit, windowMs, maxKeys = 5000, now = Date.now }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys; // bound on memory: keys come from the network
    this.now = now;
    this.buckets = new Map();
  }

  /** Counts one request for `key`. Returns { allowed, remaining, retryAfterSec }. */
  check(key) {
    const t = this.now();
    let bucket = this.buckets.get(key);
    if (!bucket || t >= bucket.resetAt) {
      if (!bucket && this.buckets.size >= this.maxKeys) this.#makeRoom(t);
      bucket = { count: 0, resetAt: t + this.windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    return {
      allowed: bucket.count <= this.limit,
      remaining: Math.max(0, this.limit - bucket.count),
      retryAfterSec: Math.max(1, Math.ceil((bucket.resetAt - t) / 1000)),
    };
  }

  #makeRoom(t) {
    for (const [key, bucket] of this.buckets) if (t >= bucket.resetAt) this.buckets.delete(key); // expired first
    while (this.buckets.size >= this.maxKeys) this.buckets.delete(this.buckets.keys().next().value); // then oldest
  }
}

// ------------------------------------------------------------------ who is the client?

function expandIpv6(address) {
  let addr = address.split('%')[0].toLowerCase(); // drop a zone id like %eth0
  const lastColon = addr.lastIndexOf(':');
  const tail = addr.slice(lastColon + 1);
  if (tail.includes('.')) {
    // embedded IPv4 (e.g. ::ffff:1.2.3.4) -> two hex groups
    const o = tail.split('.').map(Number);
    addr = `${addr.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const [head, rest] = addr.split('::');
  const headGroups = head ? head.split(':') : [];
  if (rest === undefined) return headGroups.map((g) => g.padStart(4, '0'));
  const restGroups = rest ? rest.split(':') : [];
  const zeros = Array(8 - headGroups.length - restGroups.length).fill('0');
  return [...headGroups, ...zeros, ...restGroups].map((g) => g.padStart(4, '0'));
}

/**
 * The rate-limit key for a request.
 *  - IPv4: the address itself.
 *  - IPv6: the /64 prefix. One home or hosting customer usually controls a whole /64 (2^64 addresses),
 *    so limiting per single IPv6 address would be trivial to dodge.
 *  - Missing / malformed: one shared 'unknown' bucket (fails closed instead of skipping the limit).
 *
 * TRUST NOTE: on Vercel the platform sets x-real-ip / x-forwarded-for to the real client IP and
 * overwrites any value the client sent, so reading it is safe THERE. Running this behind a different
 * proxy, or directly on the internet, would let a client spoof the header.
 */
export function rateLimitKey(headers) {
  const raw = headers.get('x-real-ip') ?? headers.get('x-forwarded-for') ?? '';
  const first = raw.split(',')[0].trim();
  if (first.length === 0 || first.length > 64) return 'unknown';
  const family = isIP(first.split('%')[0]);
  if (family === 4) return first;
  if (family === 6) {
    const groups = expandIpv6(first);
    const isMappedIpv4 = groups.slice(0, 5).every((g) => g === '0000') && groups[5] === 'ffff';
    if (isMappedIpv4) {
      const [hi, lo] = [parseInt(groups[6], 16), parseInt(groups[7], 16)];
      return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    }
    return `v6:${groups.slice(0, 4).join(':')}`;
  }
  return 'unknown';
}
