// The request handler: the whole flow from "HTTP request in" to "JSON out".
//
//   method -> rate limit -> validate ID -> cache -> (NVD + KEV + EPSS in parallel) -> normalise
//          -> summary -> cache -> response
//
// Everything with state or side effects (cache, rate limiter, KEV loader, summarizer, fetch) is passed
// in, so tests can replace it and api/cve.js wires the real ones once per server instance.

import { readIdParam } from './validate.js';
import { fetchNvd, fetchEpss } from './sources.js';
import { SourceError } from './http.js';
import { normalizeNvd, buildKevStatus, buildEpssStatus, chooseTitle } from './normalize.js';
import { rateLimitKey } from './ratelimit.js';

// Error responses use FIXED messages. We never echo user input or upstream error text back,
// so an error body cannot be used to reflect content or to leak internals.
const ERRORS = {
  invalid_id: [400, 'That is not a valid CVE ID. Use the format CVE-YYYY-NNNN, for example CVE-2021-44228.'],
  method_not_allowed: [405, 'Only GET requests are supported.'],
  not_found: [404, 'No record was found for that CVE ID. It may not exist, or it may not be published yet.'],
  rate_limited: [429, 'Too many requests. Please wait a moment and try again.'],
  busy: [429, 'The service is busy right now. Please try again in a few seconds.'],
  upstream_rate_limited: [503, 'The vulnerability database is limiting requests right now. Please try again shortly.'],
  upstream_unavailable: [502, 'The vulnerability database is not responding right now. Please try again shortly.'],
  internal_error: [500, 'Something went wrong on our side. Please try again.'],
};

const TTL = { ok: 3_600_000, degraded: 120_000, notFound: 60_000 };

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  // No Access-Control-Allow-Origin on purpose: other websites cannot read this API from a browser.
  'Cross-Origin-Resource-Policy': 'same-origin',
};

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...BASE_HEADERS, 'Cache-Control': 'no-store', ...headers } });
}

function errorResponse(code, extraHeaders = {}) {
  const [status, message] = ERRORS[code];
  return json(status, { error: { code, message } }, extraHeaders);
}

function defaultLog(event, fields) {
  console.log(JSON.stringify({ event, ...fields }));
}

export function createApp({ fetchImpl = fetch, nvdApiKey = '', now = Date.now, cache, limiter, lookupLimiter, nvdBudget, getKevIndex, summarize, log = defaultLog }) {
  const inflight = new Map(); // id -> Promise: concurrent requests for the same CVE share one lookup

  /** Does the real work for one CVE. Returns a plain result object (never throws for expected failures). */
  async function lookup(id) {
    const started = performance.now();

    // Protect the shared NVD quota (5 or 50 requests per 30 s for ALL visitors together).
    const budget = nvdBudget.check('nvd');
    if (!budget.allowed) return { ok: false, code: 'busy', retryAfter: budget.retryAfterSec };

    const [nvdR, kevR, epssR] = await Promise.allSettled([
      fetchNvd(id, { fetchImpl, apiKey: nvdApiKey }),
      getKevIndex(),
      fetchEpss(id, { fetchImpl }),
    ]);

    if (nvdR.status === 'rejected') {
      const err = nvdR.reason;
      log('upstream_error', { source: 'nvd', kind: err instanceof SourceError ? err.kind : 'unexpected', status: err?.status ?? null });
      return { ok: false, code: err instanceof SourceError && err.kind === 'rate_limited' ? 'upstream_rate_limited' : 'upstream_unavailable', retryAfter: 30 };
    }

    let record;
    try {
      record = normalizeNvd(nvdR.value, id);
    } catch (err) {
      log('upstream_error', { source: 'nvd', kind: err instanceof SourceError ? err.kind : 'unexpected' });
      return { ok: false, code: 'upstream_unavailable', retryAfter: 30 };
    }
    if (!record) return { ok: false, code: 'not_found', cacheMs: TTL.notFound };

    const kevResult = kevR.status === 'fulfilled' ? { ok: true, entry: kevR.value.get(id) ?? null } : { ok: false };
    const epssResult = epssR.status === 'fulfilled' ? { ok: true, value: epssR.value } : { ok: false };
    if (!kevResult.ok) log('upstream_error', { source: 'kev', kind: kevR.reason?.kind ?? 'unexpected', status: kevR.reason?.status ?? null });
    if (!epssResult.ok) log('upstream_error', { source: 'epss', kind: epssR.reason?.kind ?? 'unexpected', status: epssR.reason?.status ?? null });

    const kev = buildKevStatus(record.nvdKev, kevResult);
    const epss = buildEpssStatus(epssResult);
    const { title, titleSource } = chooseTitle(kev, record.affected.products);

    let summary = null;
    try {
      summary = await summarize({ id, title, record, kev, epss });
    } catch {
      log('summary_error', { kind: 'unexpected' }); // the page still works without a summary
    }

    const degraded = !kevResult.ok || !epssResult.ok || summary === null || summary.llm === 'unavailable';
    const body = {
      id,
      title,
      titleSource,
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${id}`, // built from the validated ID only
      published: record.published,
      lastModified: record.lastModified,
      status: record.status,
      description: record.description,
      cvss: record.cvss,
      weaknesses: record.weaknesses,
      exploitation: { kev, epss, ssvc: record.ssvc ? { status: 'assessed', ...record.ssvc } : { status: 'not_assessed' } },
      affected: record.affected,
      fix: { requiredAction: kev.status === 'listed' ? kev.requiredAction : null, fixedIn: record.fixedIn, advisories: record.advisories },
      references: record.references,
      summary,
      sources: {
        nvd: 'ok',
        kev: kevResult.ok ? 'ok' : 'unavailable',
        epss: epssResult.ok ? (epssResult.value.status === 'ok' ? 'ok' : 'not_scored') : 'unavailable',
        summary: summary?.source ?? 'none',
      },
      generatedAt: new Date(now()).toISOString(),
    };
    log('lookup', { id, ms: Math.round(performance.now() - started), kev: body.sources.kev, epss: body.sources.epss, summary: body.sources.summary });
    return { ok: true, body: JSON.stringify(body), degraded, cacheMs: degraded ? TTL.degraded : TTL.ok };
  }

  function toResponse(result) {
    if (result.ok) {
      // Healthy answers may be cached by the CDN for 10 minutes; degraded ones must not be (so recovery is quick).
      const cacheControl = result.degraded ? 'no-store' : 'public, max-age=60, s-maxage=600';
      return new Response(result.body, { status: 200, headers: { ...BASE_HEADERS, 'Cache-Control': cacheControl } });
    }
    return errorResponse(result.code, result.retryAfter ? { 'Retry-After': String(result.retryAfter) } : {});
  }

  return async function handle(request) {
    try {
      if (request.method !== 'GET') return errorResponse('method_not_allowed', { Allow: 'GET' });

      // Rate limit BEFORE doing anything that costs money or quota.
      const client = rateLimitKey(request.headers);
      const verdict = limiter.check(client);
      if (!verdict.allowed) return errorResponse('rate_limited', { 'Retry-After': String(verdict.retryAfterSec) });

      const id = readIdParam(new URL(request.url));
      if (!id) return errorResponse('invalid_id');

      const cached = cache.get(id);
      if (cached) return toResponse(cached);

      let pending = inflight.get(id);
      if (!pending) {
        // A NEW lookup is the expensive kind: one NVD call from the shared quota and one LLM call from the
        // free daily budget. It gets its own, tighter per-client limit so a single client cannot use its
        // whole general allowance to drain those shared budgets for everybody else.
        const costly = lookupLimiter.check(client);
        if (!costly.allowed) return errorResponse('rate_limited', { 'Retry-After': String(costly.retryAfterSec) });
        pending = lookup(id).finally(() => inflight.delete(id));
        inflight.set(id, pending);
      }
      const result = await pending;
      if (result.cacheMs) cache.set(id, result, result.cacheMs);
      return toResponse(result);
    } catch (err) {
      // Anything unexpected: log the category only, return a generic message (no stack, no internals).
      log('internal_error', { name: err?.name ?? 'Error' });
      return errorResponse('internal_error');
    }
  };
}
