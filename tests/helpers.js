// Shared test helpers (not a test file itself: the runner only picks up *.test.js).
import { readFileSync } from 'node:fs';

export function fixture(name) {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

export function jsonResponse(body, init = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

/**
 * A fake `fetch`. `routes` maps a hostname to a function (url, options) => Response | Promise<Response>.
 * Records every call in `.calls`; an unrouted hostname fails loudly so tests never hit the real network.
 */
export function routeFetch(routes) {
  const fake = async (url, options = {}) => {
    const parsed = new URL(String(url));
    fake.calls.push({ url: parsed.href, host: parsed.hostname, options });
    const route = routes[parsed.hostname];
    if (!route) throw new Error(`unrouted host in test: ${parsed.hostname}`);
    return route(parsed, options);
  };
  fake.calls = [];
  fake.callsTo = (host) => fake.calls.filter((c) => c.host === host);
  return fake;
}

export const HOSTS = {
  nvd: 'services.nvd.nist.gov',
  kev: 'www.cisa.gov',
  epss: 'api.first.org',
};
