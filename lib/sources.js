// Clients for the three public data sources: NVD, CISA KEV and EPSS.
//
// SSRF note: the three base URLs below are constants. The only thing a visitor influences is the
// CVE ID, which has already passed the strict pattern in validate.js and is added with
// URL.searchParams (which percent-encodes), so it cannot change the host, path or other parameters.

import { fetchJson, SourceError } from './http.js';
import { parseCveId } from './validate.js';
import { cleanText, finiteNumberInRange } from './sanitize.js';

export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://api.first.org/data/v1/epss';

const USER_AGENT = 'explain-this-cve/1.0 (portfolio project)';
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const dateOnly = (value) => (typeof value === 'string' && DATE_ONLY.test(value) ? value : null);

/**
 * Fetches the raw NVD record. Returns the parsed JSON (shape validated later by normalizeNvd).
 * The API key, if configured, is sent only in the `apiKey` request header and is never logged.
 */
export async function fetchNvd(id, { fetchImpl = fetch, apiKey = '' } = {}) {
  const url = new URL(NVD_URL);
  url.searchParams.set('cveId', id);
  const headers = { Accept: 'application/json', 'User-Agent': USER_AGENT };
  if (apiKey) headers.apiKey = apiKey;
  try {
    return await fetchJson(url.href, { source: 'nvd', fetchImpl, headers, timeoutMs: 10_000, maxBytes: 5_000_000 });
  } catch (err) {
    // NVD signals "too many requests" with 403 as well as 429.
    if (err instanceof SourceError && err.kind === 'http' && err.status === 403) throw new SourceError('nvd', 'rate_limited', 403);
    throw err;
  }
}

/**
 * Creates a loader for the CISA KEV feed. The feed is ONE ~1.7 MB file listing every known
 * exploited CVE, so we download it once, keep only the fields we need in a Map, and reuse it.
 *  - fresh for `ttlMs`; if a refresh fails we keep serving the old copy for up to `maxStaleMs`
 *  - simultaneous requests share one download (no stampede)
 *  - a feed with fewer than `minEntries` rows is treated as BROKEN, never as "nothing is exploited"
 */
export function createKevLoader({ fetchImpl = fetch, now = Date.now, ttlMs = 3_600_000, maxStaleMs = 86_400_000, minEntries = 100, retryAfterFailureMs = 60_000 } = {}) {
  let state = null; // { index: Map<string, entry>, loadedAt: number }
  let inflight = null;
  let lastFailure = null; // { at: number, error: SourceError }

  async function refresh() {
    const data = await fetchJson(KEV_URL, {
      source: 'kev',
      fetchImpl,
      headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
      timeoutMs: 10_000,
      maxBytes: 8_000_000,
    });
    if (!Array.isArray(data?.vulnerabilities)) throw new SourceError('kev', 'bad_json');
    const index = new Map();
    for (const row of data.vulnerabilities) {
      const id = parseCveId(row?.cveID);
      if (!id) continue;
      index.set(id, {
        name: cleanText(row.vulnerabilityName, 200),
        vendor: cleanText(row.vendorProject, 80),
        product: cleanText(row.product, 80),
        dateAdded: dateOnly(row.dateAdded),
        dueDate: dateOnly(row.dueDate),
        requiredAction: cleanText(row.requiredAction, 600),
        ransomware: row.knownRansomwareCampaignUse === 'Known' ? 'Known' : 'Unknown',
      });
    }
    if (index.size < minEntries) throw new SourceError('kev', 'bad_json');
    state = { index, loadedAt: now() };
    return index;
  }

  return async function getKevIndex() {
    const t = now();
    if (state && t - state.loadedAt < ttlMs) return state.index;
    const stale = state && t - state.loadedAt < maxStaleMs ? state.index : null;
    // After a failed download, wait before trying again. Otherwise an outage at CISA would make EVERY
    // lookup sit through the full timeout, which also makes our own site easy to slow down.
    if (lastFailure && t - lastFailure.at < retryAfterFailureMs) {
      if (stale) return stale;
      throw lastFailure.error;
    }
    if (!inflight) {
      inflight = refresh()
        .then((index) => { lastFailure = null; return index; })
        .catch((err) => { lastFailure = { at: now(), error: err }; throw err; })
        .finally(() => { inflight = null; });
    }
    try {
      return await inflight;
    } catch (err) {
      if (stale) return stale; // stale copy beats no copy
      throw err;
    }
  };
}

/**
 * EPSS = the probability (0 to 1) that a CVE is exploited in the next 30 days.
 * Returns { status: 'ok', score, percentile, date } or { status: 'not_scored' } (brand-new CVEs).
 * The API returns numbers as strings, so they are parsed and range-checked.
 */
export async function fetchEpss(id, { fetchImpl = fetch } = {}) {
  const url = new URL(EPSS_URL);
  url.searchParams.set('cve', id);
  const data = await fetchJson(url.href, {
    source: 'epss',
    fetchImpl,
    headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
    timeoutMs: 6_000,
    maxBytes: 200_000,
  });
  if (data?.status !== 'OK' || !Array.isArray(data.data)) throw new SourceError('epss', 'bad_json');
  const row = data.data.find((r) => r && r.cve === id);
  if (!row) return { status: 'not_scored' };
  const score = finiteNumberInRange(row.epss, 0, 1);
  const percentile = finiteNumberInRange(row.percentile, 0, 1);
  if (score === null || percentile === null) throw new SourceError('epss', 'bad_json');
  return { status: 'ok', score, percentile, date: dateOnly(row.date) };
}
