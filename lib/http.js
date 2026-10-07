// One safe way to call an external API. Every outbound request in this project goes through here.
//
// What it enforces (each line is a defence against a different failure):
//   * timeout            -> a slow or hanging server cannot hold our function open
//   * redirect: 'error'  -> an upstream cannot bounce us to a different host (SSRF hygiene)
//   * body size limit    -> a huge or malicious response cannot exhaust memory
//   * errors carry only a source name and a category, never URLs, headers or response bodies,
//     so API keys cannot leak into logs or into responses to the visitor.

export class SourceError extends Error {
  /**
   * @param {string} source  'nvd' | 'kev' | 'epss' | 'llm'
   * @param {'timeout'|'network'|'rate_limited'|'http'|'too_large'|'bad_json'} kind
   * @param {number} [status] HTTP status for kind 'http'
   */
  constructor(source, kind, status) {
    super(`${source}:${kind}${status ? `:${status}` : ''}`);
    this.name = 'SourceError';
    this.source = source;
    this.kind = kind;
    this.status = status ?? null;
  }
}

async function readTextLimited(response, maxBytes, source) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new SourceError(source, 'too_large');
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new SourceError(source, 'too_large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Fetches a URL and parses the JSON body.
 * @returns {Promise<unknown>} the parsed JSON (shape NOT trusted: callers must validate it)
 * @throws {SourceError}
 */
export async function fetchJson(url, { source, fetchImpl = fetch, method = 'GET', headers = {}, body, timeoutMs, maxBytes }) {
  let response;
  try {
    response = await fetchImpl(url, {
      method,
      headers,
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    throw new SourceError(source, timedOut ? 'timeout' : 'network');
  }

  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new SourceError(source, response.status === 429 ? 'rate_limited' : 'http', response.status);
  }

  let text;
  try {
    text = await readTextLimited(response, maxBytes, source);
  } catch (err) {
    if (err instanceof SourceError) throw err;
    throw new SourceError(source, err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new SourceError(source, 'bad_json');
  }
}
