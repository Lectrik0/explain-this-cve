// Input validation for the one thing a visitor controls: the CVE ID.
//
// Security idea: the ID is the ONLY user input that ever reaches another server
// (it is appended to the NVD / EPSS URLs). If it passes this strict check it can
// contain nothing but "CVE-", digits and dashes, so it cannot change which host,
// path or query parameters we call (no SSRF, no injection into upstream URLs).

// Written with explicit [Cc][Vv][Ee] instead of a case-insensitive flag so no
// Unicode case-folding rules can ever make a non-ASCII character match.
// \d in JavaScript is ASCII 0-9 only (fullwidth or Arabic-Indic digits do not match).
const CVE_ID_PATTERN = /^[Cc][Vv][Ee]-\d{4}-\d{4,10}$/;

// A real ID is at most 3 + 1 + 4 + 1 + 10 = 19 characters. Anything much longer is
// rejected BEFORE the regex runs, so huge inputs cost us nothing.
const MAX_INPUT_LENGTH = 40;

/**
 * Returns the canonical upper-case CVE ID, or null if the input is not a valid one.
 * Never throws, whatever it is given.
 */
export function parseCveId(input) {
  if (typeof input !== 'string') return null;
  if (input.length > MAX_INPUT_LENGTH) return null;
  const candidate = input.trim();
  if (!CVE_ID_PATTERN.test(candidate)) return null;
  // Safe: the pattern guarantees pure ASCII, so toUpperCase() has no surprises.
  return candidate.toUpperCase();
}

/**
 * Reads the `id` query parameter from a URL object.
 * Exactly one `id` is accepted: ?id=A&id=B is rejected (HTTP parameter pollution).
 */
export function readIdParam(url) {
  const values = url.searchParams.getAll('id');
  if (values.length !== 1) return null;
  return parseCveId(values[0]);
}
