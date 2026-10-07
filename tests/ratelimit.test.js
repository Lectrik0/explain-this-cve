import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter, rateLimitKey } from '../lib/ratelimit.js';

const headersOf = (obj) => new Headers(obj);

// ------------------------------------------------------------------ limiter

test('allows up to the limit, then blocks, then resets when the window ends', () => {
  let clock = 10_000;
  const rl = new RateLimiter({ limit: 3, windowMs: 60_000, now: () => clock });
  assert.deepEqual([1, 2, 3].map(() => rl.check('ip').allowed), [true, true, true]);
  const blocked = rl.check('ip');
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.remaining, 0);
  assert.equal(blocked.retryAfterSec, 60);

  clock += 59_000;
  assert.equal(rl.check('ip').retryAfterSec, 1, 'Retry-After counts down');
  clock += 1_000;
  assert.equal(rl.check('ip').allowed, true, 'new window');
});

test('keys are independent', () => {
  const rl = new RateLimiter({ limit: 1, windowMs: 1000 });
  assert.equal(rl.check('a').allowed, true);
  assert.equal(rl.check('a').allowed, false);
  assert.equal(rl.check('b').allowed, true);
});

test('remaining counts down', () => {
  const rl = new RateLimiter({ limit: 3, windowMs: 1000 });
  assert.deepEqual([rl.check('k').remaining, rl.check('k').remaining, rl.check('k').remaining], [2, 1, 0]);
});

test('memory is bounded when an attacker presents many different keys', () => {
  const rl = new RateLimiter({ limit: 5, windowMs: 60_000, maxKeys: 100 });
  for (let i = 0; i < 10_000; i++) rl.check(`10.0.${i >> 8}.${i & 255}`);
  assert.ok(rl.buckets.size <= 100);
});

test('expired buckets are cleaned out first when the table is full', () => {
  let clock = 0;
  const rl = new RateLimiter({ limit: 1, windowMs: 1000, maxKeys: 2, now: () => clock });
  rl.check('old1');
  rl.check('old2');
  clock = 5000;
  rl.check('fresh');
  assert.deepEqual([...rl.buckets.keys()], ['fresh']);
});

// ------------------------------------------------------------------ client key

test('IPv4 is used as is; x-real-ip wins over x-forwarded-for; only the first forwarded entry counts', () => {
  assert.equal(rateLimitKey(headersOf({ 'x-real-ip': '203.0.113.7' })), '203.0.113.7');
  assert.equal(rateLimitKey(headersOf({ 'x-forwarded-for': '203.0.113.7, 10.0.0.1' })), '203.0.113.7');
  assert.equal(rateLimitKey(headersOf({ 'x-real-ip': '203.0.113.7', 'x-forwarded-for': '198.51.100.1' })), '203.0.113.7');
});

test('IPv6 addresses in the same /64 share one bucket; different /64s do not', () => {
  const k = (ip) => rateLimitKey(headersOf({ 'x-real-ip': ip }));
  assert.equal(k('2001:db8::1'), k('2001:db8:0:0:ffff:ffff:ffff:ffff'));
  assert.equal(k('2001:db8::1'), 'v6:2001:0db8:0000:0000');
  assert.notEqual(k('2001:db8:0:1::1'), k('2001:db8::1'));
  assert.equal(k('::1'), 'v6:0000:0000:0000:0000');
  assert.equal(k('fe80::1%eth0'), 'v6:fe80:0000:0000:0000');
});

test('IPv4-mapped IPv6 is treated as the IPv4 address', () => {
  assert.equal(rateLimitKey(headersOf({ 'x-real-ip': '::ffff:203.0.113.7' })), '203.0.113.7');
});

test('missing, malformed or hostile values fall into one shared "unknown" bucket', () => {
  for (const value of ['', 'not-an-ip', '999.1.1.1', '1.2.3', '<script>', '1.2.3.4.5', 'a'.repeat(500), ' , ']) {
    assert.equal(rateLimitKey(headersOf({ 'x-real-ip': value })), 'unknown', JSON.stringify(value));
  }
  assert.equal(rateLimitKey(headersOf({})), 'unknown');
});
