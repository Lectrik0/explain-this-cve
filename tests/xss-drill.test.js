// XSS drill: run the REAL public/app.js against a hostile API response and inspect what it builds.
//
// There is no browser here, so app.js runs inside Node's vm with a tiny stand-in for the DOM. The stand-in
// records every element and attribute app.js creates, and THROWS if app.js ever tries to write HTML
// (innerHTML and friends). If hostile data can become an element, an attribute, a dangerous link or a
// CSS class, these assertions fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const APP_JS = readFileSync(fileURLToPath(new URL('../public/app.js', import.meta.url)), 'utf8');

// ------------------------------------------------------------------ minimal DOM stand-in

class TextNode {
  constructor(data) { this.nodeType = 3; this.data = data; }
}

class Element {
  constructor(tag) {
    this.nodeType = 1; this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {};
    this.className = ''; this.hidden = false; this.disabled = false; this.value = ''; this.checked = false;
    this.listeners = {}; this._classes = new Set();
    this.classList = { toggle: (name, force) => { if (force) this._classes.add(name); else this._classes.delete(name); } };
  }
  append(...items) { for (const item of items) this.children.push(typeof item === 'string' ? new TextNode(item) : item); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  focus() {} scrollIntoView() {}
  get textContent() { return this.children.map((c) => (c.nodeType === 3 ? c.data : c.textContent)).join(''); }
  set textContent(value) { this.children = [new TextNode(String(value))]; }
  set innerHTML(_) { throw new Error('app.js wrote innerHTML'); }
  set outerHTML(_) { throw new Error('app.js wrote outerHTML'); }
  insertAdjacentHTML() { throw new Error('app.js used insertAdjacentHTML'); }
}

function* walk(node) {
  yield node;
  for (const child of node.children ?? []) yield* walk(child);
}

function boot(search) {
  const byId = {};
  const get = (id) => (byId[id] ??= new Element('div'));
  const radios = ['manager', 'analyst'].map((v) => { const r = new Element('input'); r.value = v; r.checked = v === 'manager'; return r; });
  const root = new Element('html');
  const sandbox = {
    document: {
      createElement: (tag) => new Element(tag),
      getElementById: get,
      documentElement: root,
      querySelector: (sel) => radios.find((r) => sel.includes(`[value="${r.value}"]`)) ?? null,
      querySelectorAll: (sel) => (sel.includes('name="view"') ? radios : []),
    },
    window: { matchMedia: () => ({ matches: false, addEventListener() {} }), print() {} },
    localStorage: { getItem: () => null, setItem() {} },
    history: { replaceState() {} },
    location: { search },
    fetch: null, URL, URLSearchParams, AbortController, setTimeout, clearTimeout, encodeURIComponent,
  };
  return { sandbox, byId, radios, get, run: () => vm.runInNewContext(APP_JS, sandbox) };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 15));

// ------------------------------------------------------------------ the hostile response

const IMG = '<img src=x onerror=alert(1)>';
const SCRIPT = '<script>alert(document.cookie)</script>';
const QUOTE_BREAK = '"><svg onload=alert(1)>';

function hostileBody() {
  return {
    id: 'CVE-2099-0001',
    title: IMG,
    titleSource: 'products',
    nvdUrl: 'javascript:alert(1)',
    published: `2099-01-01T00:00:00${SCRIPT}`,
    lastModified: IMG,
    status: SCRIPT,
    description: `${SCRIPT}\n${IMG}`,
    cvss: {
      primary: {
        severity: 'critical" onclick="alert(1)', score: 10, version: '3.1', provider: IMG, vector: SCRIPT,
        breakdown: [{ metric: IMG, value: SCRIPT }],
      },
      others: [{ severity: `high ${IMG}`, score: 9, version: IMG, provider: 'NVD' }, { severity: 'high', score: '9', version: '3.1' }],
    },
    weaknesses: [{ id: IMG, name: SCRIPT }],
    exploitation: {
      kev: { status: 'listed', source: IMG, name: IMG, dateAdded: SCRIPT, dueDate: IMG, requiredAction: SCRIPT, ransomware: IMG },
      epss: { status: 'ok', score: 'not a number', percentile: IMG, date: SCRIPT },
      ssvc: { status: 'assessed', exploitation: IMG, automatable: 'label', technicalImpact: { toString: () => SCRIPT }, assessed: SCRIPT },
    },
    affected: {
      source: IMG, total: 'many', moreProducts: SCRIPT,
      products: [{ vendor: IMG, product: SCRIPT, versions: [QUOTE_BREAK, IMG, 5, null, { toString: () => IMG }], moreVersions: IMG }, null, 'string', 42],
    },
    fix: {
      requiredAction: `${IMG} ${SCRIPT}`,
      fixedIn: [{ vendor: IMG, product: SCRIPT, versions: [IMG, QUOTE_BREAK] }, null],
      advisories: [
        { url: 'javascript:alert(1)', tags: [IMG] },
        { url: 'data:text/html,<script>alert(1)</script>', tags: ['Patch'] },
        { url: 'vbscript:msgbox(1)', tags: [] },
        { url: '//evil.example/x', tags: [] },
        { url: 'https://user:pass@evil.example/', tags: [] },
        { url: 'https://vendor.example/advisory?q="><script>alert(1)</script>', tags: [IMG, 'Patch', SCRIPT] },
      ],
    },
    references: {
      total: SCRIPT,
      items: [
        { url: 'JaVaScRiPt:alert(1)', tags: [] }, { url: 'java\nscript:alert(1)', tags: [] }, { url: 5, tags: [] }, null,
        { url: 'https://ok.example/path', tags: IMG },
      ],
    },
    summary: { source: IMG, model: IMG, llm: IMG, what: IMG, worry: SCRIPT, action: QUOTE_BREAK },
    sources: { nvd: IMG, kev: SCRIPT, epss: IMG, summary: SCRIPT },
    generatedAt: SCRIPT,
  };
}

async function renderHostile(view) {
  const app = boot('?id=CVE-2099-0001');
  app.sandbox.fetch = async () => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => hostileBody() });
  app.run();
  await tick();
  if (view === 'analyst') {
    const analyst = app.radios[1];
    analyst.checked = true;
    for (const fn of analyst.listeners.change ?? []) fn();
  }
  return app;
}

// ------------------------------------------------------------------ assertions

const ALLOWED_TAGS = new Set(['SECTION', 'DIV', 'SPAN', 'P', 'H2', 'H3', 'DL', 'DT', 'DD', 'UL', 'LI', 'A', 'CODE', 'STRONG', 'HR', 'PROGRESS', 'I']);
const ALLOWED_ATTRIBUTES = new Set(['href', 'rel', 'target', 'id', 'aria-labelledby', 'aria-hidden', 'aria-label', 'aria-busy', 'max', 'value', 'aria-invalid']);

for (const view of ['manager', 'analyst']) {
  test(`XSS drill (${view} view): hostile data never becomes elements, attributes, links or classes`, async () => {
    const app = await renderHostile(view);
    const body = app.byId['result-body'];
    assert.ok(body && body.children.length >= 7, 'the brief was rendered');
    assert.equal(app.get('result').hidden, false);

    const everything = [...walk(body)];
    const elements = everything.filter((n) => n.nodeType === 1);

    // 1. Only harmless tags exist: no img, script, svg, iframe, b, a-with-event...
    for (const node of elements) assert.ok(ALLOWED_TAGS.has(node.tagName), `unexpected <${node.tagName.toLowerCase()}>`);

    // 2. No event handlers, no style, no srcdoc, nothing outside the attribute allow-list.
    for (const node of elements) {
      for (const name of Object.keys(node.attributes)) {
        assert.ok(ALLOWED_ATTRIBUTES.has(name), `unexpected attribute ${name}`);
        assert.ok(!name.startsWith('on'), `event handler attribute ${name}`);
      }
    }

    // 3. Every link is plain http(s), points to a real host, and is hardened.
    const links = elements.filter((n) => n.tagName === 'A');
    assert.ok(links.length > 0, 'the one legitimate link is still rendered');
    for (const link of links) {
      const href = link.attributes.href;
      assert.match(href, /^https?:\/\/[^/]+/);
      assert.ok(!/javascript|data:|vbscript/i.test(href));
      assert.ok(!new URL(href).username && !new URL(href).password);
      assert.equal(link.attributes.rel, 'noopener noreferrer nofollow');
    }
    assert.ok(!elements.some((n) => n.tagName === 'A' && /evil\.example/.test(n.attributes.href)), 'schemeless or credentialed links were dropped');

    // 4. CSS classes come only from our own fixed names: no quote, no space-injected handler, no payload text.
    for (const node of elements) {
      for (const token of node.className.split(/\s+/).filter(Boolean)) assert.match(token, /^[a-z0-9-]+$/, `odd class token ${token}`);
      assert.ok(!/onclick|alert|<|>|"/.test(node.className));
    }
    const badge = elements.find((n) => n.className.startsWith('badge '));
    assert.ok(!badge, 'a severity word that is not on the allow-list produces no badge at all');

    // 5. The payloads that were shown are shown as TEXT (this is the proof they are inert).
    const texts = everything.filter((n) => n.nodeType === 3).map((n) => n.data).join('\n');
    assert.ok(texts.includes(IMG), 'the <img onerror> payload is visible as literal characters');
    assert.ok(texts.includes(SCRIPT.slice(0, 30)) || view === 'manager', 'script payload visible as text where shown');

    // 6. Nothing was written through an HTML sink (the stand-in throws if that happens, so reaching here proves it).
  });
}

test('XSS drill: the CVE id from the URL is validated before it is used, and bad ids never reach fetch', async () => {
  for (const search of ['?id=<script>alert(1)</script>', '?id=CVE-2021-1', '?id=javascript:alert(1)', '?id=' + 'A'.repeat(5000)]) {
    const app = boot(search);
    let fetched = false;
    app.sandbox.fetch = async () => { fetched = true; return { ok: false, status: 400, headers: { get: () => null }, json: async () => ({}) }; };
    app.run();
    await tick();
    assert.equal(fetched, false, search.slice(0, 40));
  }
});

test('XSS drill: a response for a different or malformed id is refused and nothing is rendered', async () => {
  for (const evil of [{ id: IMG }, { id: 5 }, null, 'string', { id: 'CVE-2021-1' }]) {
    const app = boot('?id=CVE-2099-0001');
    app.sandbox.fetch = async () => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => evil });
    app.run();
    await tick();
    assert.equal(app.get('result').hidden, true);
    assert.equal(app.get('message').hidden, false);
    assert.equal(app.get('message').textContent, 'The server sent an unexpected response. Please try again.');
  }
});

test('XSS drill: error messages come from a fixed table, never from the server text', async () => {
  const app = boot('?id=CVE-2099-0001');
  app.sandbox.fetch = async () => ({ ok: false, status: 400, headers: { get: () => '30' }, json: async () => ({ error: { code: IMG, message: SCRIPT } }) });
  app.run();
  await tick();
  assert.equal(app.get('message').textContent, 'Something went wrong. Please try again.');
  assert.ok(!app.get('message').textContent.includes('<'));
});

test('XSS drill: the server-provided rate-limit wait is only shown as a bounded number', async () => {
  const app = boot('?id=CVE-2099-0001');
  app.sandbox.fetch = async () => ({ ok: false, status: 429, headers: { get: () => '<b>30</b>' }, json: async () => ({ error: { code: 'rate_limited' } }) });
  app.run();
  await tick();
  assert.equal(app.get('message').textContent, 'Too many requests. Please wait a moment and try again.');
});
