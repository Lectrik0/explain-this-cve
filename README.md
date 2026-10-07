# Explain This CVE

Type a CVE ID and get a one-page brief. There is a Manager view (what is this, should I worry, what do I do) and an Analyst view (CVSS vector, affected versions, references). The brief says how severe the flaw is, whether CISA lists it as exploited, how likely exploitation is according to EPSS, which products are affected and where the fix is.

It is a portfolio project. The page is plain HTML, CSS and JavaScript. One serverless function on Vercel does all the work.

## The problem

A CVE record is written for specialists. A manager who has to decide "do we drop everything today?" gets a score, a vector string and 100 reference links. An analyst gets the same data but has to open three sites to answer the question that matters: is anyone actually exploiting this?

This project answers that in one page by combining three free public sources, and it tells a manager and an analyst different amounts of the same story.

## What the page shows

Seven chapters, always in this order:

1. CVE ID, title and published date
2. Severity: the CVSS score with a colour badge and the severity written as a word
3. Exploitation status: is it in CISA's Known Exploited Vulnerabilities list, plus the EPSS probability
4. Plain-language summary, written by an AI model when a key is configured and by fixed rules otherwise
5. Affected products and versions
6. Fix and mitigation: CISA's required action, the first unaffected versions, patches and vendor advisories
7. References

Every brief carries the line "Always verify with the official vendor advisory."

## How it works

```
 Browser (public/)                Vercel function (api/cve.js)             Public data
 +-----------------+   GET        +--------------------------------+
 | index.html      | -----------> | 1  method check                |
 | app.js          |  /api/cve    | 2  rate limit, per client IP   |
 | styles.css      |  ?id=CVE-..  | 3  validate the CVE ID         | ---> NVD API 2.0
 +-----------------+              | 4  cache lookup                | ---> CISA KEV feed (cached)
        ^                         | 5  fetch the sources in        | ---> FIRST EPSS API
        |                         |    parallel, with timeouts     |
        |  small fixed JSON       | 6  normalise untrusted data    | ---> LLM provider
        +------------------------ | 7  summary: AI or template     |      (key read from env)
                                  +--------------------------------+
```

The steps for one lookup:

1. The browser checks the ID shape for convenience, then calls `/api/cve?id=...`.
2. The function accepts only GET and counts the request against a per-IP limit.
3. The ID must match `CVE-YYYY-NNNN` exactly, or the function answers 400 and calls nothing.
4. A finished answer for the same ID may already be in memory, in which case it is returned.
5. NVD, the CISA KEV feed and EPSS are called in parallel. NVD is required. KEV and EPSS can fail without breaking the page.
6. The raw JSON is turned into a small fixed shape. Every field is type-checked, cleaned and length-capped.
7. The summary comes from the LLM if a key is set and the answer passes validation. Otherwise a template builds it from the same facts.
8. The browser draws the result with `textContent` only.

If a source is down, the page says so. "Could not check CISA's list" is shown as unknown, never as "not exploited".

## Project layout

```
api/cve.js          the serverless function: wires the pieces together, the only place that reads process.env
lib/validate.js     CVE ID validation
lib/sanitize.js     text cleaning, http(s)-only URLs
lib/http.js         the one way to call an outside API (timeout, no redirects, size cap)
lib/sources.js      NVD, CISA KEV and EPSS clients
lib/normalize.js    untrusted JSON to the small fixed shape
lib/cvss.js         severity bands, vector parsing
lib/summary.js      template summary, LLM summary, output validation
lib/cache.js        small in-memory cache with a size limit
lib/ratelimit.js    per-IP limiter, client IP key
lib/handler.js      the request flow and error mapping
lib/config.js       reads environment variables
public/             the only folder the web server serves
tests/              unit tests, a security test suite and an XSS drill
docs/HOW-IT-WORKS.md  a walkthrough for explaining this project in an interview
```

## Run it locally

You need Node.js 24 and the Vercel CLI (`npm install -g vercel`). There are no other dependencies.

```
copy .env.example .env.local
npm run dev
```

Fill in `.env.local` first if you want the AI summary or the higher NVD limit. `npm run dev` loads that file and starts `vercel dev` in local mode, so no Vercel project is created. Open http://localhost:3000.

Other commands:

```
npm test            run all tests
npm run live-check  look up a CVE against the real services (npm run live-check -- CVE-2024-3094)
```

Neither command prints the value of any environment variable.

## Configuration

All settings are environment variables, read on the server only.

```
LLM_BASE_URL   any OpenAI-compatible chat API, for example https://api.groq.com/openai/v1
LLM_API_KEY    the provider key; leave empty to use the template summary
LLM_MODEL      for example openai/gpt-oss-120b
NVD_API_KEY    optional; raises NVD's limit from 5 to 50 requests per 30 seconds
```

The AI summary needs all three LLM variables. Changing provider means changing three values, not code. I chose Groq's free tier because it has a usable free quota and the model is fast. Gemini's free tier was ruled out because Google's terms only allow paid services for apps offered in the EEA, the UK and Switzerland.

## Deploy on Vercel

1. Push the repository to GitHub and import it in Vercel. Leave the framework as "Other" and the build command empty. Vercel serves `public/` and runs `api/cve.js`.
2. Add the four variables above under Project Settings, Environment Variables.
3. Add one firewall rate limit rule (Firewall, Configure, New Rule, then Rate Limit) for the path `/api/cve`. The Hobby plan allows one such rule. It runs before the function and is the limit that holds up when instances change.
4. Open the site and check the response headers in the browser developer tools.

## Design decisions

### The API key lives on the server only

The LLM key and the NVD key are read from `process.env` in `api/cve.js` and nowhere else. A test fails if any other file in `lib/` or `api/` touches `process.env`, or if the browser files mention a key. `.env*` is in `.gitignore` except `.env.example`, which holds names with empty values. A test scans every committed text file for key-shaped strings and checks that git does not track `.env.local`.

Errors that leave the server are built from a source name and a category such as `timeout` or `rate_limited`. They never contain a URL, a header or an upstream response body, so a key cannot leak into a log or into a response. Tests feed in errors that contain a fake key and check that it never comes out.

### Untrusted data and XSS

Everything from NVD, CISA, EPSS and the LLM is treated as hostile. Four layers, each of which would stop a mistake in the others:

1. The server cleans text (control and direction-changing characters removed), caps every length, allow-lists tags and statuses, and keeps only http and https links.
2. The page never builds HTML from data. It uses `textContent` and text nodes. A test fails if `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or inline styles appear in the browser code.
3. CSS class names come from fixed tables, not from data. Links are re-checked in the browser and always get `rel="noopener noreferrer nofollow"`.
4. The Content Security Policy is `default-src 'none'` with scripts, styles, fonts and connections limited to this site, no inline anything, and Trusted Types required with no policy allowed (`trusted-types 'none'`). In a browser that enforces Trusted Types, a stray `innerHTML` write throws an error, and so does creating a policy to get around it. I checked both in Chromium.

The XSS drill runs the real `app.js` against an API response that has an `<img onerror>` or `<script>` payload in every field, inside a small DOM stand-in that throws on any HTML write. It then checks that no unexpected element, attribute, link or class exists. I confirmed the drill works by running it against two deliberately broken copies of `app.js`: both fail.

### Input validation and SSRF

The CVE ID is the only visitor input that reaches another server. It must match `^CVE-\d{4}-\d{4,10}$` after trimming, with ASCII digits only and a length check before the pattern. The request must carry exactly one query parameter, `id`. Extra parameters are rejected, otherwise `?id=X&a=1`, `?id=X&a=2` and so on would be endless different URLs for one CVE, each stored separately in the CDN cache. The three API hosts are constants and the ID is added with `URL.searchParams`, so a visitor cannot change the host or path of an outgoing request. Redirects are refused and responses are size-capped.

### Prompt injection

A CVE description is text written by other people, and it goes into an LLM prompt. A malicious description could try to steer the model. The controls limit what a successful injection can do:

- the model gets public facts about one CVE and nothing else: no tools, no secrets, no visitor data
- the facts go in as JSON inside `<facts>` tags, with `<` escaped so the text cannot close the tag
- the answer must be a small JSON object with three short strings
- the text is normalised (NFKC) before it is checked, so look-alike characters such as fullwidth "ｈｔｔｐ://" cannot hide a link
- each string is rejected if it contains a link, an HTML-like tag, a backtick or a markdown link
- any version number in the answer must appear in the facts as a whole token, and so must any domain-like or file-like name such as `evil-patch.com` or `setup.exe`; otherwise the whole answer is dropped

A rejected answer becomes the template summary. While testing the real model I saw it turn the range ">= 2.0.1 and < 2.3.1" into "2.0.1 to 2.3.0" and invent "2.14.9". The version check caught that. The page labels AI text as AI-generated and tells the reader to verify it.

### Rate limiting and caching

Each client IP gets 20 requests per minute, and a tighter 6 per minute for lookups that are not cached yet, because those are the ones that spend NVD quota and free LLM tokens. All visitors together share a budget just under NVD's own limit. If the CISA download fails, the server waits a minute before trying again, so an outage at CISA does not make every lookup wait for a timeout. Finished answers are cached for an hour, and answers where a source failed for two minutes, so recovery is quick. The CISA feed is downloaded once and reused. Concurrent requests for the same CVE share one lookup. IPv6 clients are limited per /64, because one customer usually controls a whole /64.

### Choosing which score to show

A CVE can carry several scores: NVD's CVSS 3.1 and the vendor's CVSS 4.0, for example. The page shows one main score and lists the rest in the Analyst view. The rule: prefer a Primary score, then the newest CVSS version. The severity word is computed from the number, never taken from the upstream text.

### Look and feel

The visual design follows the design language of my portfolio site: comic-style panels with cut corners, a day and a night theme, self-hosted fonts and a small flat illustration. Severity needs red, orange and amber, which that palette does not have, so those three colours are a deliberate addition. Every severity is also written as a word.

## Tests

`npm test` runs more than 140 tests with Node's built-in test runner, with no test dependencies. They use saved real API responses, so they run offline. They cover validation, the normaliser against a hostile record, each failure of each source, the rate limiter and cache, the handler's status codes, the summary and prompt injection cases, the headers and CSP, the secret scan and the XSS drill.

## Limitations

- The cache and the rate limiter live in the memory of one function instance. Instances are created and recycled by Vercel, each has its own copy, and `vercel dev` reloads the function on every request, so locally neither persists. They are best-effort. The firewall rule is the limit to rely on.
- The per-IP limit trusts the `x-real-ip` header that Vercel sets. Behind any other proxy a client could fake it.
- NVD's quota is shared by every visitor, and Vercel functions share outgoing IPs with other projects. When the quota runs out the page shows a busy message.
- Groq's free tier allowed about 8,000 tokens per minute for this model in October 2026. A burst of new lookups gets HTTP 429 and those briefs fall back to the template summary.
- AI summaries can still be wrong in a sentence. The checks stop links, markup and invented versions, not a misleading opinion. Severity, KEV and EPSS are shown separately from structured data for that reason.
- NVD data is sometimes late or incomplete. New CVEs may have no score or no product list. The product list is grouped from CPE data and ordered by a heuristic, so it can include third-party products that embed the affected library.
- KEV lists confirmed exploitation only. A CVE missing from it is not proof of safety. EPSS is a probability, not a verdict.
- The CSP's Trusted Types rule is enforced by Chromium browsers. Other browsers still get every other control.
- I tested the page in one Chromium-based browser, at desktop and phone widths, in both themes. I did not test Safari or Firefox.
- The API is public. The CORS policy only stops other websites from reading it in a browser. Anyone can call it directly, which is what the rate limits are for.
- Several clients working together can still use up the shared NVD budget, because the per-IP limits do not add up across IPs. The result is a "busy" message, not a breach.
- A persuaded AI model can still write a misleading sentence that has no link, version or domain in it. The checks cannot catch an opinion.

## Version 2 ideas

- Nessus plugin IDs: show which Tenable Nessus plugins detect a CVE, so an analyst can go from a scanner finding to this brief and back. That needs a source for the CVE to plugin mapping, a new source module with its own failure handling, and a chapter on the page.
- A durable rate limit and cache in a shared store such as Vercel KV or Upstash, which removes the per-instance limitation above.
- More sources, such as GitHub security advisories and OSV for package ecosystems.
- Paste a list of CVE IDs from a scan export and get one combined brief.
- A CVSS 4.0 breakdown in the Analyst view, including the threat and environmental metrics.

## Credits

Data from the [NVD API](https://nvd.nist.gov/) (this product uses data from the NVD API but is not endorsed or certified by the NVD), the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/). Fonts: Chakra Petch and Instrument Sans, both under the SIL Open Font License (copies in `public/fonts`).

## About how this was built

Built with AI assistance; I designed the features and security requirements and reviewed and tested all code.
