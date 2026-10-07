// Manual end-to-end check against the REAL services (NVD, CISA, EPSS and, if configured, the LLM).
//   npm run live-check                  -> looks up CVE-2021-44228
//   npm run live-check -- CVE-2024-3094 -> looks up another CVE
//
// It loads .env.local the same way the app would, but never prints any variable's value:
// the startup line the app logs only says whether each setting is present.

import { existsSync } from 'node:fs';

const envFile = new URL('../.env.local', import.meta.url);
if (existsSync(envFile)) {
  try {
    process.loadEnvFile(envFile);
  } catch {
    console.error('Could not parse .env.local (check the KEY=value format). Continuing without it.');
  }
} else {
  console.log('No .env.local found: running without keys (template summary, lower NVD rate limit).');
}

const id = process.argv[2] ?? 'CVE-2021-44228';
const entry = (await import('../api/cve.js')).default;
const response = await entry.fetch(new Request(`https://local.test/api/cve?id=${encodeURIComponent(id)}`, { headers: { 'x-real-ip': '127.0.0.1' } }));
const body = await response.json();

console.log(`\nHTTP ${response.status}  cache-control: ${response.headers.get('cache-control')}`);
if (body.error) {
  console.log(`error: ${body.error.code}: ${body.error.message}`);
  process.exit(1);
}
const p = body.cvss.primary;
console.log(`${body.id}: ${body.title}  (title from: ${body.titleSource})`);
console.log(`severity: ${p ? `${p.severity.toUpperCase()} ${p.score} (CVSS ${p.version}, ${p.provider})` : 'no score'}`);
console.log(`KEV: ${body.exploitation.kev.status}${body.exploitation.kev.source ? ` via ${body.exploitation.kev.source}` : ''}   EPSS: ${body.exploitation.epss.status}${body.exploitation.epss.score !== undefined ? ` ${(body.exploitation.epss.score * 100).toFixed(2)}%` : ''}`);
console.log(`affected products: ${body.affected.total} (first: ${body.affected.products[0]?.vendor}/${body.affected.products[0]?.product})   references: ${body.references.total}   advisories: ${body.fix.advisories.length}`);
console.log(`sources: ${JSON.stringify(body.sources)}`);
if (body.summary) {
  console.log(`\nsummary (${body.summary.source}${body.summary.model ? `, ${body.summary.model}` : ''}, llm: ${body.summary.llm}):`);
  console.log(`  what:   ${body.summary.what}\n  worry:  ${body.summary.worry}\n  action: ${body.summary.action}`);
}
