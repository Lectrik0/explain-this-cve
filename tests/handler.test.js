import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../lib/handler.js';
import { TtlCache } from '../lib/cache.js';
import { RateLimiter } from '../lib/ratelimit.js';
import { createKevLoader } from '../lib/sources.js';
import { fixture, jsonResponse, routeFetch, HOSTS } from './helpers.js';

const KEY = 'TEST-NVD-KEY-do-not-leak-9f3a1c';
const okSummary = async () => ({ what: 'w', worry: 'x', action: 'y', source: 'template', model: null, llm: 'disabled' });

function setup({ nvd, kev, epss, summarize, limiter, nvdBudget, ...rest } = {}) {
  const logs = [];
  const fetchImpl = routeFetch({
    [HOSTS.nvd]: nvd ?? (() => jsonResponse(fixture('nvd-log4shell.json'))),
    [HOSTS.kev]: kev ?? (() => jsonResponse(fixture('kev-sample.json'))),
    [HOSTS.epss]: epss ?? (() => jsonResponse(fixture('epss-log4shell.json'))),
  });
  const app = createApp({
    fetchImpl,
    nvdApiKey: KEY,
    cache: new TtlCache(),
    limiter: limiter ?? new RateLimiter({ limit: 100, windowMs: 60_000 }),
    nvdBudget: nvdBudget ?? new RateLimiter({ limit: 100, windowMs: 30_000 }),
    getKevIndex: createKevLoader({ fetchImpl, minEntries: 1 }),
    summarize: summarize ?? okSummary,
    log: (event, fields) => logs.push({ event, ...fields }),
    ...rest,
  });
  const get = (qs, headers = {}, method = 'GET') => app(new Request(`https://cve.example/api/cve${qs}`, { method, headers }));
  return { get, fetchImpl, logs };
}

/** A copy of the Log4Shell record with a different ID and (optionally) without NVD's embedded KEV fields. */
function nvdRecordWith(id, { stripKev = false } = {}) {
  const raw = fixture('nvd-log4shell.json');
  raw.vulnerabilities[0].cve.id = id;
  if (stripKev) for (const k of ['cisaExploitAdd', 'cisaActionDue', 'cisaRequiredAction', 'cisaVulnerabilityName']) delete raw.vulnerabilities[0].cve[k];
  return raw;
}

// ------------------------------------------------------------------ happy path

test('200: full brief for a known exploited CVE, with the expected contract and headers', async () => {
  const { get, fetchImpl } = setup();
  const res = await get('?id=CVE-2021-44228');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('cache-control'), 'public, max-age=60, s-maxage=600');
  assert.equal(res.headers.get('access-control-allow-origin'), null, 'no CORS: other sites cannot read this API');

  const body = await res.json();
  assert.deepEqual(Object.keys(body).sort(), [
    'affected', 'cvss', 'description', 'exploitation', 'fix', 'generatedAt', 'id', 'lastModified', 'nvdUrl',
    'published', 'references', 'sources', 'status', 'summary', 'title', 'titleSource', 'weaknesses',
  ]);
  assert.equal(body.id, 'CVE-2021-44228');
  assert.equal(body.title, 'Apache Log4j2 Remote Code Execution Vulnerability');
  assert.equal(body.titleSource, 'cisa');
  assert.equal(body.nvdUrl, 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
  assert.equal(body.cvss.primary.score, 10);
  assert.equal(body.exploitation.kev.status, 'listed');
  assert.equal(body.exploitation.kev.source, 'cisa-feed');
  assert.equal(body.exploitation.kev.ransomware, 'Known');
  assert.equal(body.exploitation.epss.status, 'ok');
  assert.ok(body.exploitation.epss.score > 0.9);
  assert.ok(body.fix.advisories.length > 0);
  assert.ok(body.fix.requiredAction);
  assert.deepEqual(body.sources, { nvd: 'ok', kev: 'ok', epss: 'ok', summary: 'template' });
  assert.equal(body.summary.source, 'template');

  assert.equal(fetchImpl.callsTo(HOSTS.nvd)[0].options.headers.apiKey, KEY, 'the NVD key is sent (in a header)');
});

test('lower-case input is accepted and canonicalised', async () => {
  const { get } = setup();
  assert.equal((await (await get('?id=cve-2021-44228')).json()).id, 'CVE-2021-44228');
});

// ------------------------------------------------------------------ bad requests

test('400: invalid IDs are rejected before ANY upstream call, with a fixed message', async () => {
  const { get, fetchImpl } = setup();
  const queries = ['', '?id=', '?id=hello', '?id=CVE-2021-1', '?id=CVE-2021-44228&id=CVE-2021-1111', '?id=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    '?id=CVE-2021-44228%0d%0aX-Evil:1', '?id=' + 'A'.repeat(10_000), '?ID=CVE-2021-44228'];
  for (const qs of queries) {
    const res = await get(qs);
    assert.equal(res.status, 400, qs);
    const text = await res.text();
    assert.equal(JSON.parse(text).error.code, 'invalid_id');
    assert.ok(!/script|X-Evil|AAAA/.test(text), 'the input is never echoed back');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  }
  assert.equal(fetchImpl.calls.length, 0);
});

test('405: only GET is allowed', async () => {
  const { get, fetchImpl } = setup();
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']) {
    const res = await get('?id=CVE-2021-44228', {}, method);
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.get('allow'), 'GET');
  }
  assert.equal(fetchImpl.calls.length, 0);
});

// ------------------------------------------------------------------ not found, upstream failures

test('404: unknown CVE, and the "not found" answer is cached briefly', async () => {
  const { get, fetchImpl } = setup({ nvd: () => jsonResponse(fixture('nvd-not-found.json')) });
  const res = await get('?id=CVE-2030-12345');
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error.code, 'not_found');
  await get('?id=CVE-2030-12345');
  assert.equal(fetchImpl.callsTo(HOSTS.nvd).length, 1);
});

test('NVD failures map to clean 502/503 responses and are NOT cached', async () => {
  const timeout = () => { const e = new Error('x'); e.name = 'TimeoutError'; throw e; };
  const cases = [
    [() => new Response('boom', { status: 500 }), 502, 'upstream_unavailable'],
    [() => new Response('', { status: 403 }), 503, 'upstream_rate_limited'],
    [() => new Response('', { status: 429 }), 503, 'upstream_rate_limited'],
    [timeout, 502, 'upstream_unavailable'],
    [() => new Response('<html>not json</html>'), 502, 'upstream_unavailable'],
    [() => jsonResponse({ unexpected: 'shape' }), 502, 'upstream_unavailable'],
    [() => jsonResponse(nvdRecordWith('CVE-1999-0001')), 502, 'upstream_unavailable'], // data about a different CVE
  ];
  for (const [nvd, status, code] of cases) {
    const { get, fetchImpl } = setup({ nvd });
    const res = await get('?id=CVE-2021-44228');
    assert.equal(res.status, status, code);
    const body = await res.json();
    assert.equal(body.error.code, code);
    assert.ok(res.headers.get('retry-after'));
    assert.deepEqual(Object.keys(body), ['error'], 'no internals in the body');
    await get('?id=CVE-2021-44228');
    assert.equal(fetchImpl.callsTo(HOSTS.nvd).length, 2, 'errors are retried, not cached');
  }
});

// ------------------------------------------------------------------ degraded sources

test('KEV feed down: NVD\'s embedded CISA data is used and the page says the feed is unavailable', async () => {
  const { get } = setup({ kev: () => new Response('', { status: 503 }) });
  const res = await get('?id=CVE-2021-44228');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.exploitation.kev.status, 'listed');
  assert.equal(body.exploitation.kev.source, 'nvd');
  assert.equal(body.sources.kev, 'unavailable');
  assert.equal(res.headers.get('cache-control'), 'no-store', 'degraded answers are not cached by the CDN');
});

test('KEV feed down and no other evidence: the answer is "unknown", NEVER "not listed"', async () => {
  const { get } = setup({ kev: () => new Response('', { status: 500 }), nvd: () => jsonResponse(nvdRecordWith('CVE-2099-0003', { stripKev: true })) });
  const body = await (await get('?id=CVE-2099-0003')).json();
  assert.deepEqual(body.exploitation.kev, { status: 'unknown' });
});

test('KEV feed healthy and CVE absent from it: "not_listed"; EPSS has no score yet: "not_scored"', async () => {
  const { get } = setup({ nvd: () => jsonResponse(nvdRecordWith('CVE-2099-0003', { stripKev: true })), epss: () => jsonResponse(fixture('epss-none.json')) });
  const res = await get('?id=CVE-2099-0003');
  const body = await res.json();
  assert.deepEqual(body.exploitation.kev, { status: 'not_listed' });
  assert.deepEqual(body.exploitation.epss, { status: 'not_scored' });
  assert.equal(body.sources.epss, 'not_scored');
  assert.equal(res.headers.get('cache-control'), 'public, max-age=60, s-maxage=600', 'not being scored is a normal state, not a failure');
  assert.equal(body.titleSource, 'products', 'no CISA name: title is built from vendor + product');
});

test('EPSS down: the page still works and reports it', async () => {
  const { get } = setup({ epss: () => new Response('', { status: 503 }) });
  const res = await get('?id=CVE-2021-44228');
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.deepEqual(body.exploitation.epss, { status: 'unavailable' });
  assert.equal(body.sources.epss, 'unavailable');
});

test('summary failure never breaks the response', async () => {
  const { get, logs } = setup({ summarize: async () => { throw new Error('LLM exploded with secret ' + KEY); } });
  const res = await get('?id=CVE-2021-44228');
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.summary, null);
  assert.equal(body.sources.summary, 'none');
  assert.ok(!JSON.stringify(logs).includes(KEY), 'error messages are not logged');
});

test('an unavailable LLM marks the answer as degraded (short cache), a disabled one does not', async () => {
  const down = setup({ summarize: async () => ({ what: 'a', worry: 'b', action: 'c', source: 'template', model: null, llm: 'unavailable' }) });
  assert.equal((await down.get('?id=CVE-2021-44228')).headers.get('cache-control'), 'no-store');
  const off = setup();
  assert.equal((await off.get('?id=CVE-2021-44228')).headers.get('cache-control'), 'public, max-age=60, s-maxage=600');
});

// ------------------------------------------------------------------ limits, cache, single flight

test('429: per-IP rate limit, evaluated before any work, with Retry-After', async () => {
  const { get, fetchImpl } = setup({ limiter: new RateLimiter({ limit: 2, windowMs: 60_000 }) });
  const ip = { 'x-real-ip': '203.0.113.9' };
  assert.equal((await get('?id=CVE-2021-44228', ip)).status, 200);
  assert.equal((await get('?id=CVE-2021-44228', ip)).status, 200);
  const blocked = await get('?id=CVE-2021-44228', ip);
  assert.equal(blocked.status, 429);
  assert.equal((await blocked.json()).error.code, 'rate_limited');
  assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  assert.equal((await get('?id=CVE-2021-44228', { 'x-real-ip': '203.0.113.10' })).status, 200, 'other clients are unaffected');
  assert.equal(fetchImpl.callsTo(HOSTS.nvd).length, 1, 'the blocked request did no upstream work');

  const invalid = await get('?id=garbage', ip);
  assert.equal(invalid.status, 429, 'even invalid requests count against the limit');
});

test('429 "busy": when the shared NVD budget is used up we do not call NVD at all', async () => {
  const { get, fetchImpl } = setup({ nvdBudget: new RateLimiter({ limit: 0, windowMs: 30_000 }) });
  const res = await get('?id=CVE-2021-44228');
  assert.equal(res.status, 429);
  assert.equal((await res.json()).error.code, 'busy');
  assert.ok(res.headers.get('retry-after'));
  assert.equal(fetchImpl.calls.length, 0);
});

test('a second request for the same CVE is served from cache', async () => {
  const { get, fetchImpl } = setup();
  const a = await (await get('?id=CVE-2021-44228')).json();
  const b = await (await get('?id=cve-2021-44228')).json();
  assert.deepEqual(a, b);
  for (const host of Object.values(HOSTS)) assert.equal(fetchImpl.callsTo(host).length, 1, host);
});

test('concurrent requests for the same CVE share ONE upstream lookup', async () => {
  const { get, fetchImpl } = setup();
  const responses = await Promise.all(Array.from({ length: 8 }, () => get('?id=CVE-2021-44228')));
  assert.ok(responses.every((r) => r.status === 200));
  assert.equal(fetchImpl.callsTo(HOSTS.nvd).length, 1);
  assert.equal(fetchImpl.callsTo(HOSTS.epss).length, 1);
});

// ------------------------------------------------------------------ robustness and secrets

test('500: an unexpected internal error returns a generic message and logs only the error NAME', async () => {
  const boom = { check() { throw new TypeError('internal detail: secret ' + KEY); } };
  const { get, logs } = setup({ limiter: boom });
  const res = await get('?id=CVE-2021-44228');
  assert.equal(res.status, 500);
  const text = await res.text();
  assert.equal(JSON.parse(text).error.code, 'internal_error');
  assert.ok(!text.includes('internal detail') && !text.includes(KEY) && !text.includes('TypeError'));
  assert.deepEqual(logs, [{ event: 'internal_error', name: 'TypeError' }]);
});

test('the NVD API key never appears in any response, header or log line', async () => {
  const everything = [];
  const scenarios = [
    setup(),
    setup({ nvd: () => new Response('', { status: 403 }) }),
    setup({ nvd: () => new Response('', { status: 500 }) }),
    setup({ kev: () => new Response('', { status: 500 }), epss: () => new Response('', { status: 500 }) }),
  ];
  for (const s of scenarios) {
    for (const qs of ['?id=CVE-2021-44228', '?id=bad']) {
      const res = await s.get(qs);
      everything.push(await res.text(), JSON.stringify([...res.headers]));
    }
    everything.push(JSON.stringify(s.logs));
  }
  assert.ok(!everything.join('\n').includes(KEY));
});

test('logs contain no IP addresses', async () => {
  const { get, logs } = setup();
  await get('?id=CVE-2021-44228', { 'x-real-ip': '203.0.113.77' });
  assert.ok(!JSON.stringify(logs).includes('203.0.113.77'));
});
