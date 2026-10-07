// Static security checks on the files we ship: headers, CSP, frontend code patterns, and secret hygiene.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (p) => readFileSync(join(ROOT, p), 'utf8');

// ------------------------------------------------------------------ headers and CSP

const vercel = JSON.parse(read('vercel.json'));
const globalHeaders = Object.fromEntries(vercel.headers.find((h) => h.source === '/(.*)').headers.map((h) => [h.key, h.value]));
const csp = Object.fromEntries(globalHeaders['Content-Security-Policy'].split(';').map((d) => d.trim()).filter(Boolean).map((d) => {
  const [name, ...values] = d.split(/\s+/);
  return [name, values];
}));

test('security headers are configured for every path', () => {
  assert.match(globalHeaders['Strict-Transport-Security'], /max-age=\d{7,}/);
  assert.equal(globalHeaders['X-Content-Type-Options'], 'nosniff');
  assert.equal(globalHeaders['Referrer-Policy'], 'no-referrer');
  assert.equal(globalHeaders['X-Frame-Options'], 'DENY');
  assert.equal(globalHeaders['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.equal(globalHeaders['Cross-Origin-Resource-Policy'], 'same-origin');
  for (const feature of ['camera', 'microphone', 'geolocation', 'payment']) assert.match(globalHeaders['Permissions-Policy'], new RegExp(`${feature}=\\(\\)`));
});

test('CSP: deny by default, scripts and styles only from this site, no unsafe-* keywords', () => {
  assert.deepEqual(csp['default-src'], ["'none'"]);
  assert.deepEqual(csp['script-src'], ["'self'"]);
  assert.deepEqual(csp['style-src'], ["'self'"]);
  assert.deepEqual(csp['connect-src'], ["'self'"]);
  assert.deepEqual(csp['object-src'], ["'none'"]);
  assert.deepEqual(csp['base-uri'], ["'none'"]);
  assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
  assert.deepEqual(csp['frame-src'], ["'none'"]);
  assert.deepEqual(csp['require-trusted-types-for'], ["'script'"]);
  const everything = globalHeaders['Content-Security-Policy'];
  assert.ok(!/unsafe-inline|unsafe-eval|unsafe-hashes|\*|https?:|data:|blob:/.test(everything), 'no wildcard, remote, data: or unsafe sources');
});

test('the serverless function has a maximum duration', () => {
  assert.ok(vercel.functions['api/cve.js'].maxDuration <= 60);
});

// ------------------------------------------------------------------ frontend files

test('index.html has no inline scripts, inline styles or event-handler attributes', () => {
  const html = read('public/index.html');
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    assert.match(m[1], /\bsrc="\/[a-z.-]+\.js"/, 'every script is a same-site file');
    assert.equal(m[2].trim(), '', 'no inline script body');
  }
  assert.ok(!/\sstyle\s*=/.test(html), 'no style="" attributes');
  assert.ok(!/<style\b/i.test(html), 'no <style> blocks');
  assert.ok(!/\son[a-z]+\s*=/i.test(html), 'no onclick= style attributes');
  assert.ok(!/javascript:/i.test(html));
  assert.ok(!/<(iframe|object|embed|form[^>]+action)/i.test(html));
});

test('index.html loads nothing from other sites (only plain links to documentation)', () => {
  const html = read('public/index.html');
  for (const m of html.matchAll(/<(script|link|img|source|video|audio)\b[^>]*?(?:src|href)="([^"]+)"/gi)) {
    assert.ok(m[2].startsWith('/'), `${m[1]} loads ${m[2]}`);
  }
});

test('app.js and theme.js never use dangerous DOM sinks', () => {
  for (const file of ['public/app.js', 'public/theme.js']) {
    const code = read(file).replace(/\/\/.*$/gm, ''); // ignore comments
    for (const [name, pattern] of Object.entries({
      innerHTML: /\binnerHTML\b/, outerHTML: /\bouterHTML\b/, insertAdjacentHTML: /insertAdjacentHTML/, 'document.write': /document\.write/,
      eval: /\beval\s*\(/, 'new Function': /new\s+Function\b/, 'string timers': /set(?:Timeout|Interval)\s*\(\s*['"`]/,
      'inline style via script': /\.style\b|setAttribute\(\s*['"]style['"]/, 'javascript: URL': /javascript:/i,
      'inline handler attributes': /setAttribute\(\s*['"]on/i, 'DOMParser/createContextualFragment': /DOMParser|createContextualFragment/,
      'postMessage/window.open': /postMessage|window\.open/, 'document.cookie': /document\.cookie/,
    })) {
      assert.ok(!pattern.test(code), `${file} must not use ${name}`);
    }
  }
});

test('app.js only ever sets text through textContent / text nodes, and only creates links through the checked helper', () => {
  const code = read('public/app.js');
  assert.ok(/node\.textContent = String\(options\.text\)/.test(code));
  const hrefAssignments = [...code.matchAll(/href/g)].length;
  assert.ok(hrefAssignments > 0);
  assert.ok(/function safeHttpUrl/.test(code));
  assert.ok(code.includes("rel: 'noopener noreferrer nofollow'"));
});

test('styles.css loads only same-site fonts and has no @import or remote URLs', () => {
  const css = read('public/styles.css');
  assert.ok(!/@import/i.test(css));
  assert.ok(!/expression\s*\(|(?<![-\w])behavior\s*:|-moz-binding/i.test(css), 'no legacy script-in-CSS features');
  for (const m of css.matchAll(/url\(([^)]*)\)/g)) {
    const target = m[1].replace(/["']/g, '');
    assert.ok(target.startsWith('/fonts/') || target.startsWith('#'), `unexpected url(${target})`);
  }
  for (const file of readdirSync(join(ROOT, 'public/fonts')).filter((f) => f.endsWith('.woff2'))) assert.ok(css.includes(file), `${file} is used`);
  assert.ok(existsSync(join(ROOT, 'public/fonts/OFL-ChakraPetch.txt')) && existsSync(join(ROOT, 'public/fonts/OFL-InstrumentSans.txt')), 'font licences are shipped with the fonts');
});

test('text colours that carry meaning are never the only signal: severity is always also written as a word', () => {
  const code = read('public/app.js');
  assert.ok(/badge-label', text: info\.label/.test(code));
});

// ------------------------------------------------------------------ secrets

function listFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (['node_modules', '.git', '.vercel'].includes(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) listFiles(full, out);
    else out.push(full);
  }
  return out;
}

test('.gitignore keeps real secrets out of git and .env.example holds names only', () => {
  const ignore = read('.gitignore').split(/\r?\n/);
  assert.ok(ignore.includes('.env') && ignore.includes('.env.*') && ignore.includes('!.env.example'));
  const example = Object.fromEntries(read('.env.example').split(/\r?\n/).filter((l) => /^[A-Z_]+=/.test(l)).map((l) => l.split(/=(.*)/s).slice(0, 2)));
  assert.deepEqual(Object.keys(example).sort(), ['LLM_API_KEY', 'LLM_BASE_URL', 'LLM_MODEL', 'NVD_API_KEY']);
  assert.equal(example.LLM_API_KEY, '');
  assert.equal(example.NVD_API_KEY, '');
});

test('no committed file contains something that looks like a real key', () => {
  const textExt = new Set(['.js', '.json', '.md', '.html', '.css', '.txt', '.svg', '.example', '']);
  const suspicious = [
    /\bgsk_[A-Za-z0-9]{20,}/, // Groq
    /\bsk-[A-Za-z0-9_-]{20,}/, // OpenAI-style
    /\bBearer\s+[A-Za-z0-9._-]{24,}/,
    /(?:API_KEY|apiKey)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]/, // a long literal assigned to a key variable
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b.*apikey/i,
  ];
  for (const file of listFiles(ROOT)) {
    const rel = relative(ROOT, file).replace(/\\/g, '/');
    if (rel === '.env.local' || rel.startsWith('tests/fixtures/') || rel.startsWith('public/fonts/') || !textExt.has(extname(file))) continue;
    const text = readFileSync(file, 'utf8');
    for (const pattern of suspicious) assert.ok(!pattern.test(text), `${rel} matches ${pattern}`);
  }
});

test('git does not track .env.local (skipped when git is unavailable)', (t) => {
  let tracked;
  try {
    tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split(/\r?\n/);
  } catch {
    t.skip('git not available');
    return;
  }
  assert.ok(!tracked.some((f) => /^\.env(\.|$)/.test(f) && f !== '.env.example'));
});

test('the API key reaches the code only through process.env, in one place', () => {
  const withoutComments = (f) => readFileSync(f, 'utf8').replace(/\/\/.*$/gm, '');
  const offenders = listFiles(join(ROOT, 'lib')).concat(listFiles(join(ROOT, 'api'))).filter((f) => /process\.env/.test(withoutComments(f)));
  assert.deepEqual(offenders.map((f) => relative(ROOT, f).replace(/\\/g, '/')), ['api/cve.js']);
  assert.ok(!/process\.env|API_KEY/.test(read('public/app.js') + read('public/theme.js') + read('public/index.html')), 'the browser code never mentions keys');
});
