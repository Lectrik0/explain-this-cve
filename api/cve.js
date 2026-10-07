// Vercel serverless function: GET /api/cve?id=CVE-YYYY-NNNN
//
// This file only WIRES things together. It is the one place that reads process.env (secrets).
// Objects created at module level live as long as this server instance stays warm, which is what
// makes the cache and rate limiter work between requests (see README: limitations).

import { createApp } from '../lib/handler.js';
import { TtlCache } from '../lib/cache.js';
import { RateLimiter } from '../lib/ratelimit.js';
import { createKevLoader } from '../lib/sources.js';
import { createSummarizer } from '../lib/summary.js';
import { readConfig } from '../lib/config.js';

const config = readConfig(process.env);
const log = (event, fields) => console.log(JSON.stringify({ event, ...fields }));

// Booleans only: confirms the environment was loaded without ever printing a secret value.
log('startup', { nvdKeyConfigured: Boolean(config.nvdApiKey), aiSummaryConfigured: Boolean(config.llm) });

const app = createApp({
  nvdApiKey: config.nvdApiKey,
  cache: new TtlCache({ maxEntries: 200 }),
  limiter: new RateLimiter({ limit: 20, windowMs: 60_000 }), // per client IP: every request
  lookupLimiter: new RateLimiter({ limit: 6, windowMs: 60_000 }), // per client IP: lookups that are not cached yet
  // NVD allows 5 requests / 30 s without a key and 50 with one. Stay just under, for ALL visitors together.
  nvdBudget: new RateLimiter({ limit: config.nvdApiKey ? 45 : 4, windowMs: 30_000 }),
  getKevIndex: createKevLoader(),
  summarize: createSummarizer({ llm: config.llm, log }),
  log,
});

export default {
  fetch: (request) => app(request),
};
