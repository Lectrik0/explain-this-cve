import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TtlCache } from '../lib/cache.js';

test('returns stored values until they expire', () => {
  let clock = 1000;
  const cache = new TtlCache({ now: () => clock });
  cache.set('a', { v: 1 }, 500);
  assert.deepEqual(cache.get('a'), { v: 1 });
  clock = 1499;
  assert.deepEqual(cache.get('a'), { v: 1 });
  clock = 1500;
  assert.equal(cache.get('a'), undefined, 'expired at exactly ttl');
  assert.equal(cache.size, 0, 'expired entries are removed when read');
});

test('unknown keys return undefined', () => {
  assert.equal(new TtlCache().get('nope'), undefined);
});

test('size is bounded: oldest entries are evicted first', () => {
  const cache = new TtlCache({ maxEntries: 3 });
  for (const k of ['a', 'b', 'c', 'd', 'e']) cache.set(k, k, 10_000);
  assert.equal(cache.size, 3);
  assert.equal(cache.get('a'), undefined);
  assert.equal(cache.get('b'), undefined);
  assert.equal(cache.get('e'), 'e');
});

test('expired entries are dropped before live ones when the cache is full', () => {
  let clock = 0;
  const cache = new TtlCache({ maxEntries: 2, now: () => clock });
  cache.set('short', 1, 10);
  cache.set('long', 2, 10_000);
  clock = 100;
  cache.set('new', 3, 10_000);
  assert.equal(cache.get('long'), 2, 'the live entry survived');
  assert.equal(cache.get('new'), 3);
  assert.equal(cache.size, 2);
});

test('memory stays bounded under a flood of distinct keys', () => {
  const cache = new TtlCache({ maxEntries: 200 });
  for (let i = 0; i < 100_000; i++) cache.set(`CVE-2024-${i}`, { i }, 60_000);
  assert.equal(cache.size, 200);
});

test('overwriting a key refreshes its value and expiry', () => {
  let clock = 0;
  const cache = new TtlCache({ now: () => clock });
  cache.set('a', 1, 100);
  clock = 90;
  cache.set('a', 2, 100);
  clock = 150;
  assert.equal(cache.get('a'), 2);
});
