import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchNvd, fetchEpss, createKevLoader } from '../lib/sources.js';
import { fetchJson, SourceError } from '../lib/http.js';
import { fixture, jsonResponse, routeFetch, HOSTS } from './helpers.js';

const SECRET = 'TEST-KEY-must-never-appear-in-errors-0123456789';

// ------------------------------------------------------------------ http.js

test('fetchJson maps failures to categories without leaking URLs or keys', async () => {
  const opts = { source: 'nvd', timeoutMs: 1000, maxBytes: 1000 };
  const cases = [
    [async () => { throw new TypeError('fetch failed: https://secret.example/?apiKey=' + SECRET); }, 'network'],
    [async () => { const e = new Error('x'); e.name = 'TimeoutError'; throw e; }, 'timeout'],
    [async () => new Response('nope', { status: 500 }), 'http'],
    [async () => new Response('slow down', { status: 429 }), 'rate_limited'],
    [async () => new Response('not json{'), 'bad_json'],
    [async () => new Response('x'.repeat(5000)), 'too_large'],
  ];
  for (const [impl, kind] of cases) {
    await assert.rejects(fetchJson('https://example.com/', { ...opts, fetchImpl: impl }), (err) => {
      assert.ok(err instanceof SourceError);
      assert.equal(err.kind, kind);
      assert.ok(!String(err.message).includes(SECRET) && !String(err.message).includes('example'), 'message must be generic');
      return true;
    });
  }
});

test('fetchJson refuses redirects and always sets a timeout signal', async () => {
  let seen;
  await fetchJson('https://example.com/', {
    source: 'epss', timeoutMs: 500, maxBytes: 1000,
    fetchImpl: async (_url, options) => { seen = options; return jsonResponse({ ok: true }); },
  });
  assert.equal(seen.redirect, 'error');
  assert.ok(seen.signal instanceof AbortSignal);
});

test('fetchJson enforces the size limit even when content-length is missing or lies', async () => {
  const big = new Response('{"a":"' + 'x'.repeat(10_000) + '"}', { headers: { 'content-length': '10' } });
  await assert.rejects(fetchJson('https://example.com/', { source: 'kev', timeoutMs: 500, maxBytes: 1000, fetchImpl: async () => big }), { kind: 'too_large' });
});

// ------------------------------------------------------------------ NVD

test('fetchNvd calls the NVD constant URL with only a cveId parameter', async () => {
  const fetchImpl = routeFetch({ [HOSTS.nvd]: () => jsonResponse(fixture('nvd-not-found.json')) });
  await fetchNvd('CVE-2021-44228', { fetchImpl });
  const call = fetchImpl.calls[0];
  assert.equal(call.host, HOSTS.nvd);
  assert.equal(new URL(call.url).pathname, '/rest/json/cves/2.0');
  assert.deepEqual([...new URL(call.url).searchParams.keys()], ['cveId']);
});

test('fetchNvd sends the API key in the apiKey header only when one is configured', async () => {
  const withKey = routeFetch({ [HOSTS.nvd]: () => jsonResponse({}) });
  await fetchNvd('CVE-2021-44228', { fetchImpl: withKey, apiKey: SECRET });
  assert.equal(withKey.calls[0].options.headers.apiKey, SECRET);
  assert.ok(!withKey.calls[0].url.includes(SECRET), 'the key must never be placed in the URL');

  const without = routeFetch({ [HOSTS.nvd]: () => jsonResponse({}) });
  await fetchNvd('CVE-2021-44228', { fetchImpl: without });
  assert.equal('apiKey' in without.calls[0].options.headers, false);
});

test('fetchNvd treats 403 and 429 as rate limiting', async () => {
  for (const status of [403, 429]) {
    const fetchImpl = routeFetch({ [HOSTS.nvd]: () => new Response('', { status }) });
    await assert.rejects(fetchNvd('CVE-2021-44228', { fetchImpl, apiKey: SECRET }), (err) => err.kind === 'rate_limited' && !String(err).includes(SECRET));
  }
});

// ------------------------------------------------------------------ EPSS

test('fetchEpss parses string numbers and validates ranges', async () => {
  const ok = routeFetch({ [HOSTS.epss]: () => jsonResponse(fixture('epss-log4shell.json')) });
  const r = await fetchEpss('CVE-2021-44228', { fetchImpl: ok });
  assert.equal(r.status, 'ok');
  assert.ok(r.score > 0.9 && r.score <= 1);
  assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual([...new URL(ok.calls[0].url).searchParams.entries()], [['cve', 'CVE-2021-44228']]);
});

test('fetchEpss: unknown CVE is "not_scored", garbage is an error', async () => {
  const none = routeFetch({ [HOSTS.epss]: () => jsonResponse(fixture('epss-none.json')) });
  assert.deepEqual(await fetchEpss('CVE-2030-12345', { fetchImpl: none }), { status: 'not_scored' });

  const bad = (row) => routeFetch({ [HOSTS.epss]: () => jsonResponse({ status: 'OK', data: [row] }) });
  for (const row of [{ cve: 'CVE-2021-44228', epss: '7', percentile: '0.5' }, { cve: 'CVE-2021-44228', epss: 'abc', percentile: '0.5' }, { cve: 'CVE-2021-44228', epss: null, percentile: '0.5' }]) {
    await assert.rejects(fetchEpss('CVE-2021-44228', { fetchImpl: bad(row) }), { kind: 'bad_json' });
  }
  const wrong = routeFetch({ [HOSTS.epss]: () => jsonResponse({ status: 'ERROR' }) });
  await assert.rejects(fetchEpss('CVE-2021-44228', { fetchImpl: wrong }), { kind: 'bad_json' });
});

// ------------------------------------------------------------------ KEV

test('KEV loader indexes the feed, caches it, and shares one download between concurrent callers', async () => {
  let clock = 1_000;
  const fetchImpl = routeFetch({ [HOSTS.kev]: () => jsonResponse(fixture('kev-sample.json')) });
  const load = createKevLoader({ fetchImpl, now: () => clock, minEntries: 1 });

  const [a, b] = await Promise.all([load(), load()]);
  assert.equal(a, b);
  assert.equal(fetchImpl.callsTo(HOSTS.kev).length, 1, 'concurrent callers share a single download');

  const entry = a.get('CVE-2021-44228');
  assert.equal(entry.ransomware, 'Known');
  assert.equal(entry.dateAdded, '2021-12-10');
  assert.match(entry.name, /Log4j/);

  clock += 60_000;
  await load();
  assert.equal(fetchImpl.callsTo(HOSTS.kev).length, 1, 'still fresh: served from memory');

  clock += 3_600_000;
  await load();
  assert.equal(fetchImpl.callsTo(HOSTS.kev).length, 2, 'expired: downloaded again');
});

test('KEV loader serves a stale copy when a refresh fails, but not forever', async () => {
  let clock = 0;
  let healthy = true;
  const fetchImpl = routeFetch({ [HOSTS.kev]: () => (healthy ? jsonResponse(fixture('kev-sample.json')) : new Response('', { status: 503 })) });
  const load = createKevLoader({ fetchImpl, now: () => clock, ttlMs: 1000, maxStaleMs: 10_000, minEntries: 1 });
  await load();
  healthy = false;
  clock = 5_000;
  assert.ok((await load()).has('CVE-2021-44228'), 'stale copy is used');
  clock = 20_000;
  await assert.rejects(load(), { kind: 'http' });
});

test('KEV loader backs off after a failure instead of re-downloading (and timing out) on every request', async () => {
  let clock = 0;
  let healthy = false;
  const fetchImpl = routeFetch({ [HOSTS.kev]: () => (healthy ? jsonResponse(fixture('kev-sample.json')) : new Response('', { status: 503 })) });
  const load = createKevLoader({ fetchImpl, now: () => clock, minEntries: 1, retryAfterFailureMs: 60_000 });
  await assert.rejects(load(), { kind: 'http' });
  await assert.rejects(load(), { kind: 'http' });
  await assert.rejects(load(), { kind: 'http' });
  assert.equal(fetchImpl.callsTo(HOSTS.kev).length, 1, 'only one attempt during the cool-down');
  healthy = true;
  clock = 30_000;
  await assert.rejects(load(), { kind: 'http' }, 'still cooling down');
  clock = 61_000;
  assert.ok((await load()).has('CVE-2021-44228'), 'tries again after the cool-down and recovers');
  assert.equal(fetchImpl.callsTo(HOSTS.kev).length, 2);
});

test('KEV loader treats an empty or tiny feed as BROKEN, never as "nothing is exploited"', async () => {
  const empty = routeFetch({ [HOSTS.kev]: () => jsonResponse({ vulnerabilities: [] }) });
  await assert.rejects(createKevLoader({ fetchImpl: empty })(), { kind: 'bad_json' });
  const tiny = routeFetch({ [HOSTS.kev]: () => jsonResponse(fixture('kev-sample.json')) });
  await assert.rejects(createKevLoader({ fetchImpl: tiny })(), { kind: 'bad_json' }, 'default minimum is 100 entries');
  const wrongShape = routeFetch({ [HOSTS.kev]: () => jsonResponse({ vulnerabilities: 'nope' }) });
  await assert.rejects(createKevLoader({ fetchImpl: wrongShape, minEntries: 1 })(), { kind: 'bad_json' });
});

test('KEV loader ignores rows with invalid IDs and caps text fields', async () => {
  const rows = [
    { cveID: 'CVE-2021-44228', vulnerabilityName: 'x'.repeat(5000), vendorProject: '<b>v</b>', product: 'p', dateAdded: '2021-12-10', dueDate: 'not a date', requiredAction: 'Apply updates', knownRansomwareCampaignUse: 'Known' },
    { cveID: '<script>alert(1)</script>', vulnerabilityName: 'evil' },
    { cveID: null },
    null,
  ];
  const fetchImpl = routeFetch({ [HOSTS.kev]: () => jsonResponse({ vulnerabilities: rows }) });
  const index = await createKevLoader({ fetchImpl, minEntries: 1 })();
  assert.equal(index.size, 1);
  const e = index.get('CVE-2021-44228');
  assert.ok(e.name.length <= 200);
  assert.equal(e.dueDate, null);
  assert.equal(e.vendor, '<b>v</b>', 'stored as inert text; the page renders it with textContent');
});
