// Smoke test of the real entry point (api/cve.js): proves the wiring and the exported shape Vercel expects.
// Only requests that are rejected BEFORE any network call are used here.
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('api/cve.js exports a web-standard fetch handler and rejects bad requests without network access', async () => {
  const entry = (await import('../api/cve.js')).default;
  assert.equal(typeof entry.fetch, 'function');

  const bad = await entry.fetch(new Request('https://cve.example/api/cve?id=nope'));
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, 'invalid_id');

  const post = await entry.fetch(new Request('https://cve.example/api/cve?id=CVE-2021-44228', { method: 'POST' }));
  assert.equal(post.status, 405);
});
