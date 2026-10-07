// Cleaning helpers for UNTRUSTED data (everything that comes from NVD, CISA, EPSS or an LLM).
//
// Important distinction for interviews:
//   * These helpers CLEAN and LIMIT data (strip invisible characters, cap length,
//     allow only http/https links).
//   * They do NOT try to "escape HTML". The real XSS defence is on the page:
//     public/app.js only ever uses textContent, never innerHTML, plus a strict CSP.
//   Two independent layers, so one mistake does not become a vulnerability.

// C0/C1 control characters except tab (\u0009), line feed (\u000A) and carriage return.
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Invisible / direction-changing characters used to make text look different from what it is
// (zero-width characters, bidi overrides such as U+202E, BOM).
const INVISIBLE_CHARS = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
const LONE_HIGH_SURROGATE_AT_END = /[\uD800-\uDBFF]$/;

/**
 * Returns a plain string of at most `max` characters, or '' if `value` is not a string.
 * Over-long values end with an ellipsis so truncation is visible.
 */
export function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  // Bound the work first: never run the regexes over megabytes of text.
  let text = value.length > max * 4 ? value.slice(0, max * 4) : value;
  text = text
    .replace(/\r\n?/g, '\n')
    .replace(CONTROL_CHARS, '')
    .replace(INVISIBLE_CHARS, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (text.length <= max) return text;
  const cut = text.slice(0, Math.max(0, max - 1)).replace(LONE_HIGH_SURROGATE_AT_END, '');
  return `${cut.trimEnd()}…`;
}

/**
 * Returns a normalised absolute http(s) URL string, or null.
 * Rejects javascript:, data:, vbscript:, file:, relative and protocol-relative URLs,
 * URLs with embedded credentials (https://user:pass@host), and absurdly long URLs.
 */
export function safeHttpUrl(value, maxLength = 2000) {
  if (typeof value !== 'string' || value.length > maxLength) return null;
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  if (!url.hostname) return null;
  return url.href;
}

/** Clamps a number into [min, max]; returns null for anything that is not a finite number. */
export function finiteNumberInRange(value, min, max) {
  const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) return null;
  if (n < min || n > max) return null;
  return n;
}
