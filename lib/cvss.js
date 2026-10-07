// CVSS helpers: severity bands, vector parsing and plain-language breakdown.
//
// We derive the severity label ourselves from the numeric score instead of trusting the
// upstream "baseSeverity" string. That way the value that picks the badge colour is always
// one of a fixed set of words that WE produced.

import { VECTOR_TABLES } from './labels.js';

// Optional "CVSS:3.1/" prefix, then KEY:VALUE pairs separated by "/". Letters and digits only.
const VECTOR_PATTERN = /^(?:CVSS:(?:3\.[01]|4\.0)\/)?[A-Za-z0-9]{1,3}:[A-Za-z0-9]{1,3}(?:\/[A-Za-z0-9]{1,3}:[A-Za-z0-9]{1,3})*$/;
const MAX_VECTOR_LENGTH = 400;

export function isValidVector(vector) {
  return typeof vector === 'string' && vector.length <= MAX_VECTOR_LENGTH && VECTOR_PATTERN.test(vector);
}

/** 'critical' | 'high' | 'medium' | 'low' | 'none' */
export function severityFor(version, score) {
  if (version.startsWith('2')) {
    // CVSS v2 has no "critical" band.
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  if (score === 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

function familyOf(vector) {
  const match = /^CVSS:(\d)\./.exec(vector);
  return match ? match[1] : '2'; // v2 vectors have no prefix
}

/** Returns { family: '2'|'3'|'4', metrics: { AV: 'N', ... } } or null. */
export function parseVector(vector) {
  if (!isValidVector(vector)) return null;
  const family = familyOf(vector);
  const metrics = Object.create(null); // no prototype: keys like "__proto__" are just keys
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key === 'CVSS') continue;
    metrics[key] = value;
  }
  return { family, metrics };
}

/** [{ metric: 'Attack vector', value: 'Network' }, ...] using only our own label tables. */
export function describeVector(vector) {
  const parsed = parseVector(vector);
  if (!parsed) return [];
  const table = VECTOR_TABLES[parsed.family];
  const rows = [];
  for (const [key, [label, values]] of Object.entries(table)) {
    const code = parsed.metrics[key];
    if (code !== undefined && Object.hasOwn(values, code)) rows.push({ metric: label, value: values[code] });
  }
  return rows;
}

// Own-property lookup: a data-derived key can never resolve to something inherited
// from Object.prototype (e.g. "constructor").
const pick = (map, key) => (typeof key === 'string' && Object.hasOwn(map, key) ? map[key] : null);

/**
 * Version-independent facts used by the plain-language summary.
 * Every field is one of a few fixed words, or null when the vector does not say.
 */
export function impactFlags(vector) {
  const parsed = parseVector(vector);
  if (!parsed) return null;
  const { family, metrics: m } = parsed;
  const attackPath = pick({ N: 'network', A: 'adjacent', L: 'local', P: 'physical' }, m.AV);
  let privileges = null;
  let userInteraction = null;
  let impacts;
  if (family === '2') {
    privileges = pick({ N: 'none', S: 'low', M: 'high' }, m.Au);
    impacts = [m.C, m.I, m.A].map((v) => pick({ N: 'none', P: 'low', C: 'high' }, v));
  } else {
    privileges = pick({ N: 'none', L: 'low', H: 'high' }, m.PR);
    userInteraction = pick(family === '4' ? { N: 'none', P: 'required', A: 'required' } : { N: 'none', R: 'required' }, m.UI);
    const keys = family === '4' ? [m.VC, m.VI, m.VA] : [m.C, m.I, m.A];
    impacts = keys.map((v) => pick({ N: 'none', L: 'low', H: 'high' }, v));
  }
  const [confidentiality, integrity, availability] = impacts;
  return { attackPath, privileges, userInteraction, confidentiality, integrity, availability };
}
