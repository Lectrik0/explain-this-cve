// Turns raw, UNTRUSTED upstream JSON into the small, fixed response shape the page uses.
//
// Rules applied everywhere in this file:
//   * every value is type-checked before use (upstream data can be missing, null or the wrong type)
//   * text is cleaned and length-capped (cleanText), URLs must be http(s) (safeHttpUrl)
//   * tags / severities / statuses come from allow-lists or from OUR label tables
//   * loops over upstream arrays are bounded, so a giant record cannot burn CPU
// The browser then renders the result with textContent only, a second independent defence.

import { SourceError } from './http.js';
import { cleanText, safeHttpUrl, finiteNumberInRange } from './sanitize.js';
import { describeVector, isValidVector, severityFor } from './cvss.js';
import { CWE_NAMES } from './labels.js';

const asArray = (value) => (Array.isArray(value) ? value : []);
const NVD_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z?$/;
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const nvdDate = (v) => (typeof v === 'string' && NVD_DATETIME.test(v) ? v : null);
const dateOnly = (v) => (typeof v === 'string' && DATE_ONLY.test(v) ? v : null);

export const LIMITS = {
  maxMatchesScanned: 3000, // CPE entries examined
  maxProducts: 30, // products returned
  maxVersionsPerProduct: 12,
  maxFixedPerProduct: 6,
  maxReferencesScanned: 500,
  maxReferences: 60, // references returned
  maxAdvisories: 8,
  maxOtherScores: 5,
  maxWeaknesses: 10,
};

// ---------------------------------------------------------------- CVSS scores

const METRIC_KEYS = [
  ['cvssMetricV40', '4.0'],
  ['cvssMetricV31', '3.1'],
  ['cvssMetricV30', '3.0'],
  ['cvssMetricV2', '2.0'],
];

/**
 * Which score do we show as THE score? A CVE can carry several (NVD's and the vendor's, v3.1 and v4.0).
 * Rule: prefer a "Primary" metric (NVD's own analysis, or the CNA's when NVD has not scored yet),
 * and among those prefer the newest CVSS version. Everything else is listed as "other scores".
 */
function collectScores(metrics) {
  const found = [];
  if (!metrics || typeof metrics !== 'object') return { primary: null, others: [] };
  METRIC_KEYS.forEach(([key, version], versionRank) => {
    for (const metric of asArray(metrics[key]).slice(0, 10)) {
      const score = finiteNumberInRange(metric?.cvssData?.baseScore, 0, 10);
      if (score === null) continue;
      const vector = isValidVector(metric.cvssData.vectorString) ? metric.cvssData.vectorString : null;
      found.push({
        version,
        score,
        severity: severityFor(version, score),
        vector,
        provider: metric.source === 'nvd@nist.gov' ? 'NVD' : 'Other',
        isPrimary: metric.type === 'Primary',
        versionRank,
      });
    }
  });
  found.sort((a, b) => Number(!a.isPrimary) - Number(!b.isPrimary) || a.versionRank - b.versionRank);
  const [first, ...rest] = found;
  const strip = ({ version, score, severity, vector, provider }) => ({ version, score, severity, vector, provider });
  const seen = new Set();
  const others = [];
  for (const item of rest) {
    const signature = `${item.version}|${item.score}|${item.vector}`;
    if (seen.has(signature) || (first && signature === `${first.version}|${first.score}|${first.vector}`)) continue;
    seen.add(signature);
    others.push(strip(item));
  }
  return {
    primary: first ? { ...strip(first), breakdown: first.vector ? describeVector(first.vector) : [] } : null,
    others: others.slice(0, LIMITS.maxOtherScores),
  };
}

// ---------------------------------------------------------------- weaknesses

const CWE_PATTERN = /^(?:CWE-\d{1,5}|NVD-CWE-(?:Other|noinfo))$/;

function collectWeaknesses(weaknesses) {
  const ids = new Set();
  for (const w of asArray(weaknesses)) {
    for (const d of asArray(w?.description)) {
      if (typeof d?.value === 'string' && CWE_PATTERN.test(d.value)) ids.add(d.value);
    }
  }
  return [...ids].slice(0, LIMITS.maxWeaknesses).map((id) => ({ id, name: Object.hasOwn(CWE_NAMES, id) ? CWE_NAMES[id] : null }));
}

// ---------------------------------------------------------------- affected products

const prettyName = (s) => cleanText(String(s).replace(/_/g, ' '), 80);

/** cpe:2.3:a:apache:log4j:2.14.1:*:*:... -> { vendor, product, version, update } */
function parseCpe(criteria) {
  if (typeof criteria !== 'string' || criteria.length > 300 || !criteria.startsWith('cpe:2.3:')) return null;
  const parts = criteria.split(/(?<!\\):/); // split on colons that are not escaped with a backslash
  if (parts.length < 6) return null;
  const unescape = (s) => s.replace(/\\(.)/g, '$1');
  const vendor = prettyName(unescape(parts[3]));
  const product = prettyName(unescape(parts[4]));
  if (!vendor || !product) return null;
  return { vendor, product, version: unescape(parts[5]), update: unescape(parts[6] ?? '*') };
}

// NVD escapes punctuation in version strings ("11.5\(1\)"); show the plain text.
const plainVersion = (v) => cleanText(typeof v === 'string' ? v.replace(/\\(.)/g, '$1') : '', 60);

function cpeVersionText(match, cpe) {
  const lim = plainVersion;
  const start = match.versionStartIncluding ? `>= ${lim(match.versionStartIncluding)}` : match.versionStartExcluding ? `> ${lim(match.versionStartExcluding)}` : null;
  const end = match.versionEndIncluding ? `<= ${lim(match.versionEndIncluding)}` : match.versionEndExcluding ? `< ${lim(match.versionEndExcluding)}` : null;
  if (start || end) return [start, end].filter(Boolean).join(' and ');
  if (cpe.version === '*') return 'All versions';
  if (cpe.version === '-') return 'Version not specified';
  const update = cpe.update && cpe.update !== '*' && cpe.update !== '-' ? ` ${cpe.update}` : '';
  return lim(`${cpe.version}${update}`);
}

function addToGroup(groups, vendor, product, versionText, fixedVersion) {
  const key = `${vendor}\u0000${product}`;
  let group = groups.get(key);
  if (!group) {
    group = { vendor, product, versions: [], seen: new Set(), count: 0, fixed: new Set() };
    groups.set(key, group);
  }
  group.count += 1;
  if (versionText && !group.seen.has(versionText) && group.versions.length < 200) {
    group.seen.add(versionText);
    group.versions.push(versionText);
  }
  if (fixedVersion) group.fixed.add(fixedVersion);
}

function fromCpe(configurations) {
  const groups = new Map();
  let scanned = 0;
  for (const config of asArray(configurations)) {
    for (const node of asArray(config?.nodes)) {
      for (const match of asArray(node?.cpeMatch)) {
        if (++scanned > LIMITS.maxMatchesScanned) return groups;
        if (match?.vulnerable !== true) continue; // skip "runs on / combined with" platform entries
        const cpe = parseCpe(match.criteria);
        if (!cpe) continue;
        const fixed = match.versionEndExcluding ? plainVersion(match.versionEndExcluding) : null;
        addToGroup(groups, cpe.vendor, cpe.product, cpeVersionText(match, cpe), fixed);
      }
    }
  }
  return groups;
}

/** Fallback when NVD has no CPE data yet: the vendor's own ("CNA") affected-version list. */
function fromCna(affected) {
  const groups = new Map();
  let scanned = 0;
  for (const source of asArray(affected)) {
    for (const item of asArray(source?.affectedData)) {
      const vendor = prettyName(typeof item?.vendor === 'string' ? item.vendor : '');
      const product = prettyName(typeof item?.product === 'string' ? item.product : '');
      if (!vendor || !product) continue;
      for (const v of asArray(item.versions)) {
        if (++scanned > LIMITS.maxMatchesScanned) return groups;
        if (v?.status !== 'affected') continue;
        const text = (x) => (typeof x === 'string' ? cleanText(x, 60) : '');
        const base = text(v.version);
        let versionText = base;
        let fixed = null;
        if (text(v.lessThan)) {
          fixed = text(v.lessThan);
          versionText = base && base !== '0' ? `>= ${base} and < ${fixed}` : `< ${fixed}`;
        } else if (text(v.lessThanOrEqual)) {
          versionText = base && base !== '0' ? `>= ${base} and <= ${text(v.lessThanOrEqual)}` : `<= ${text(v.lessThanOrEqual)}`;
        }
        addToGroup(groups, vendor, product, versionText || 'Not specified', fixed);
        for (const change of asArray(v.changes)) {
          if (change?.status === 'unaffected' && text(change.at)) addToGroup(groups, vendor, product, null, text(change.at));
        }
      }
    }
  }
  return groups;
}

const flatten = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

/** The (vendor, product) pairs the CVE's own CNA (usually the vendor) says are affected, flattened for matching. */
function cnaPairs(affected) {
  const pairs = [];
  for (const source of asArray(affected)) {
    for (const item of asArray(source?.affectedData).slice(0, 50)) {
      if (typeof item?.vendor === 'string' && typeof item?.product === 'string') pairs.push([flatten(item.vendor.slice(0, 200)), flatten(item.product.slice(0, 200))]);
    }
  }
  return pairs;
}

function collectAffected(cve) {
  let groups = fromCpe(cve.configurations);
  let source = 'nvd-cpe';
  if (groups.size === 0) {
    groups = fromCna(cve.affected);
    source = groups.size ? 'cna' : 'none';
  }
  // Order: (1) products the CVE's own CNA names ("apache" + "log4j" inside "Apache Software Foundation" +
  // "Apache Log4j2"), because a widely embedded library drags in many third-party products;
  // (2) then by number of matching entries; (3) then alphabetically so the order is stable.
  const pairs = cnaPairs(cve.affected);
  const isCnaProduct = (g) => {
    const vendor = flatten(g.vendor);
    const product = flatten(g.product);
    if (!vendor || !product) return false; // "".includes("") is true: never let an empty name match everything
    return pairs.some(([v, p]) => v.includes(vendor) && p.includes(product));
  };
  for (const g of groups.values()) g.cnaMatch = isCnaProduct(g);
  const sorted = [...groups.values()].sort((a, b) => Number(b.cnaMatch) - Number(a.cnaMatch) || b.count - a.count || `${a.vendor} ${a.product}`.localeCompare(`${b.vendor} ${b.product}`));
  const products = sorted.slice(0, LIMITS.maxProducts).map((g) => ({
    vendor: g.vendor,
    product: g.product,
    versions: g.versions.slice(0, LIMITS.maxVersionsPerProduct),
    moreVersions: Math.max(0, g.versions.length - LIMITS.maxVersionsPerProduct),
  }));
  const fixedIn = sorted
    .filter((g) => g.fixed.size > 0)
    .slice(0, LIMITS.maxProducts)
    .map((g) => ({ vendor: g.vendor, product: g.product, versions: [...g.fixed].slice(0, LIMITS.maxFixedPerProduct) }));
  return { affected: { source, total: sorted.length, moreProducts: Math.max(0, sorted.length - products.length), products }, fixedIn };
}

// ---------------------------------------------------------------- references

// NVD's documented reference tags. Anything else is dropped.
const KNOWN_TAGS = new Set([
  'Broken Link', 'Exploit', 'Issue Tracking', 'Mailing List', 'Mitigation', 'Not Applicable', 'Patch',
  'Permissions Required', 'Press/Media Coverage', 'Product', 'Release Notes', 'Technical Description',
  'Third Party Advisory', 'US Government Resource', 'VDB Entry', 'Vendor Advisory',
]);
const FIX_TAGS = new Set(['Patch', 'Mitigation', 'Vendor Advisory', 'Release Notes']);
const TAG_WEIGHT = { Patch: 0, Mitigation: 1, 'Vendor Advisory': 2, 'Release Notes': 3, 'US Government Resource': 4, 'Third Party Advisory': 5, 'Technical Description': 6, 'Broken Link': 9 };
const weightOf = (tags) => Math.min(7, ...tags.map((t) => TAG_WEIGHT[t] ?? 7));

function collectReferences(references) {
  const byUrl = new Map();
  for (const ref of asArray(references).slice(0, LIMITS.maxReferencesScanned)) {
    const url = safeHttpUrl(ref?.url);
    if (!url) continue; // drops javascript:, data:, relative URLs, credentials in URLs ...
    const tags = [...new Set(asArray(ref.tags).filter((t) => typeof t === 'string' && KNOWN_TAGS.has(t)))];
    const existing = byUrl.get(url);
    if (existing) {
      existing.tags = [...new Set([...existing.tags, ...tags])];
    } else {
      byUrl.set(url, { url, host: new URL(url).hostname, tags });
    }
  }
  const all = [...byUrl.values()].sort((a, b) => weightOf(a.tags) - weightOf(b.tags)); // stable sort keeps NVD order within a weight
  const advisories = all.filter((r) => r.tags.some((t) => FIX_TAGS.has(t)) && !r.tags.includes('Broken Link')).slice(0, LIMITS.maxAdvisories);
  return {
    references: { total: all.length, more: Math.max(0, all.length - LIMITS.maxReferences), items: all.slice(0, LIMITS.maxReferences) },
    advisories,
  };
}

// ---------------------------------------------------------------- the NVD record

/**
 * @returns {null | object} null when NVD says the CVE does not exist
 * @throws {SourceError} when the response does not look like an NVD response at all
 */
export function normalizeNvd(raw, id) {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.vulnerabilities)) throw new SourceError('nvd', 'bad_json');
  if (raw.vulnerabilities.length === 0) return null;
  const cve = raw.vulnerabilities.find((v) => v?.cve?.id === id)?.cve;
  if (!cve || typeof cve !== 'object') throw new SourceError('nvd', 'bad_json'); // data about a different CVE: do not show it

  const descriptions = asArray(cve.descriptions);
  const en = descriptions.find((d) => d?.lang === 'en') ?? descriptions[0];
  const { affected, fixedIn } = collectAffected(cve);
  const { references, advisories } = collectReferences(cve.references);
  const { primary, others } = collectScores(cve.metrics);

  const kevDate = dateOnly(cve.cisaExploitAdd);
  return {
    id,
    published: nvdDate(cve.published),
    lastModified: nvdDate(cve.lastModified),
    status: cleanText(cve.vulnStatus, 40) || null,
    description: cleanText(en?.value, 4000),
    cvss: { primary, others },
    weaknesses: collectWeaknesses(cve.weaknesses),
    affected,
    fixedIn,
    advisories,
    references,
    // NVD copies CISA KEV data into the record; we use it as a fallback if the KEV feed is down.
    nvdKev: kevDate
      ? {
          name: cleanText(cve.cisaVulnerabilityName, 200),
          dateAdded: kevDate,
          dueDate: dateOnly(cve.cisaActionDue),
          requiredAction: cleanText(cve.cisaRequiredAction, 600),
        }
      : null,
  };
}

// ---------------------------------------------------------------- exploitation + title

/**
 * kevResult: { ok: true, entry: object|null } when the feed was read, { ok: false } when it was not.
 * "unknown" is a distinct state: a failed lookup must never be shown as "not exploited".
 */
export function buildKevStatus(nvdKev, kevResult) {
  const fromFeed = kevResult.ok ? kevResult.entry : null;
  if (fromFeed) return { status: 'listed', source: 'cisa-feed', ...pickKevFields(fromFeed), ransomware: fromFeed.ransomware };
  if (nvdKev) return { status: 'listed', source: 'nvd', ...pickKevFields(nvdKev), ransomware: null };
  return { status: kevResult.ok ? 'not_listed' : 'unknown' };
}
const pickKevFields = ({ name, dateAdded, dueDate, requiredAction }) => ({ name: name || null, dateAdded, dueDate, requiredAction: requiredAction || null });

export function buildEpssStatus(epssResult) {
  if (!epssResult.ok) return { status: 'unavailable' };
  if (epssResult.value.status === 'not_scored') return { status: 'not_scored' };
  const { score, percentile, date } = epssResult.value;
  return { status: 'ok', score, percentile, date };
}

export function chooseTitle(kev, products) {
  if (kev.status === 'listed' && kev.name) return { title: kev.name, titleSource: 'cisa' };
  const p = products[0];
  if (p) {
    const same = p.vendor.toLowerCase() === p.product.toLowerCase();
    return { title: cleanText(`${same ? p.product : `${p.vendor} ${p.product}`} vulnerability`, 160), titleSource: 'products' };
  }
  return { title: 'Vulnerability (no title available)', titleSource: 'none' };
}
