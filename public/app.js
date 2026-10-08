'use strict';

// Explain This CVE: browser code.
//
// SECURITY RULES FOR THIS FILE (a test checks the first one):
//   1. Nothing from the server is ever turned into HTML. Text goes in with textContent / text nodes only
//      (never innerHTML, outerHTML, insertAdjacentHTML, document.write, eval). Even if the server were
//      compromised or sent "<img onerror=...>", it would be displayed as harmless characters.
//      The Content Security Policy also enables Trusted Types, which makes the browser refuse those
//      dangerous sinks outright.
//   2. Anything used as a CSS class comes from a fixed lookup table or a literal, never from the data itself.
//   3. Links are only created from http(s) URLs (checked again here, on top of the server's check) and
//      always carry rel="noopener noreferrer nofollow".
//   4. This client-side check of the CVE ID is only for convenience. The real validation is on the server.

(() => {
  const API_URL = '/api/cve';
  const CVE_PATTERN = /^CVE-\d{4}-\d{4,10}$/;
  const REQUEST_TIMEOUT_MS = 40000;

  const $ = (id) => document.getElementById(id);
  const form = $('lookup-form');
  const input = $('cve-input');
  const button = $('lookup-button');
  const fieldError = $('input-error');
  const statusEl = $('status');
  const messageEl = $('message');
  const announceEl = $('announce');
  const resultEl = $('result');
  const bodyEl = $('result-body');

  const state = { view: 'manager', data: null, requestId: 0, controller: null };

  // ------------------------------------------------------------------ safe DOM helpers

  /** Creates an element. Text is always set as text; attribute NAMES below are literals in this file. */
  function el(tag, options = {}, ...children) {
    const node = document.createElement(tag);
    if (options.class) node.className = options.class;
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.attrs) for (const [name, value] of Object.entries(options.attrs)) node.setAttribute(name, String(value));
    for (const child of children) if (child) node.append(child); // strings become text nodes, never markup
    return node;
  }

  const str = (value, max = 600) => (typeof value === 'string' ? value.slice(0, max) : '');
  const num = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
  const arr = (value) => (Array.isArray(value) ? value : []);

  function safeHttpUrl(value) {
    if (typeof value !== 'string' || value.length > 2000) return null;
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
      if (url.username || url.password) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  function externalLink(url, label) {
    const href = safeHttpUrl(url);
    if (!href) return el('span', { text: label });
    return el('a', { text: label, attrs: { href, rel: 'noopener noreferrer nofollow', target: '_blank' } });
  }

  // Fixed lookup tables: data selects a ROW, it never supplies the class name or the sentence.
  const SEVERITY = {
    critical: { cls: 'sev-critical', label: 'Critical', meaning: 'Treat this as an emergency if you run the affected software. Attackers can typically cause severe damage with little effort.' },
    high: { cls: 'sev-high', label: 'High', meaning: 'A serious weakness that should be fixed soon.' },
    medium: { cls: 'sev-medium', label: 'Medium', meaning: 'Worth fixing in your normal patch cycle, and sooner if the system is important or reachable from the internet.' },
    low: { cls: 'sev-low', label: 'Low', meaning: 'Limited impact. Fix it during routine maintenance.' },
    none: { cls: 'sev-none', label: 'None', meaning: 'The score says this has no direct security impact.' },
  };
  const severityInfo = (key) => (typeof key === 'string' && Object.hasOwn(SEVERITY, key) ? SEVERITY[key] : null);

  const ERROR_TEXT = {
    invalid_id: 'That does not look like a CVE ID. Use the format CVE-2021-44228.',
    not_found: 'No record was found for that CVE ID. It may not exist, or it may not be published yet.',
    rate_limited: 'Too many requests. Please wait a moment and try again.',
    busy: 'The service is busy right now. Please try again in a few seconds.',
    upstream_rate_limited: 'The vulnerability database is limiting requests right now. Please try again shortly.',
    upstream_unavailable: 'The vulnerability database is not responding right now. Please try again shortly.',
  };

  // ------------------------------------------------------------------ formatting

  function formatDate(value) {
    const match = typeof value === 'string' ? /^(\d{4})-(\d{2})-(\d{2})/.exec(value) : null;
    if (!match) return null;
    const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
    if (Number.isNaN(date.getTime())) return null;
    return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  }

  function formatPercent(p) {
    if (p < 0.001) return '<0.1%';
    if (p >= 0.995) return '>99%';
    return `${(p * 100).toFixed(p < 0.1 ? 1 : 0)}%`;
  }

  function epssLevel(p) {
    if (p >= 0.5) return 'Very high';
    if (p >= 0.1) return 'High';
    if (p >= 0.01) return 'Moderate';
    return 'Low';
  }

  const isAnalyst = () => state.view === 'analyst';

  // ------------------------------------------------------------------ building blocks: comic panels

  // Panels rotate through three cut-corner shapes so the page feels hand-laid (classes are literals).
  const CUTS = ['cut-a', 'cut-b', 'cut-c'];
  let panelCount = 0;

  /** A framed panel: outer .frame (the outline) around an inner .in (the paper). */
  function panel(span, labelledBy, ...children) {
    const cut = CUTS[panelCount % CUTS.length];
    panelCount += 1;
    const attrs = labelledBy ? { 'aria-labelledby': labelledBy } : {};
    return el('section', { class: `frame ${cut} span-${span}`, attrs }, el('div', { class: 'in' }, ...children));
  }

  /** A numbered chapter panel with a boxed caption and a title. */
  function chapter(number, title, id, span, ...children) {
    const head = el('div', { class: 'panel-head' }, el('span', { class: 'chap', text: `Chapter ${number}` }), el('h2', { text: title, attrs: { id: `h-${id}` } }));
    return panel(span, `h-${id}`, head, ...children);
  }

  const chip = (label, extra = '') => el('li', { class: `chip ${extra}`.trim(), text: label });
  const note = (label) => el('p', { class: 'note', text: label });

  function definitionList(rows) {
    const dl = el('dl', { class: 'facts' });
    for (const [label, value] of rows) {
      if (value === null || value === undefined || value === '') continue;
      dl.append(el('dt', { text: label }), el('dd', {}, value));
    }
    return dl;
  }

  // ------------------------------------------------------------------ chapter 1: header

  function renderHeader(d) {
    const published = formatDate(d.published);
    const modified = formatDate(d.lastModified);
    const status = str(d.status, 40);
    const meta = el('p', { class: 'meta' });
    if (published) meta.append(el('span', { text: `Published ${published}` }));
    if (isAnalyst() && modified) meta.append(el('span', { text: `Last modified ${modified}` }));
    if (isAnalyst() && status) meta.append(el('span', { text: `NVD status: ${status}` }));
    const nvdLink = safeHttpUrl(d.nvdUrl);
    if (nvdLink && new URL(nvdLink).hostname === 'nvd.nist.gov') meta.append(externalLink(nvdLink, 'View on NVD'));
    const top = el('div', { class: 'panel-head head' }, el('span', { class: 'chap', text: 'Chapter 1' }), el('span', { class: 'cve-id', text: str(d.id, 30) }));
    return panel(6, 'h-title',
      top,
      el('h2', { class: 'brief-title', text: str(d.title, 200), attrs: { id: 'h-title' } }),
      d.titleSource === 'products' ? note('This CVE has no official title; the title above is built from the affected product.') : null,
      meta);
  }

  // ------------------------------------------------------------------ chapter 2: severity

  function renderSeverity(d) {
    const primary = d.cvss && d.cvss.primary;
    const info = primary && severityInfo(primary.severity);
    const score = primary && num(primary.score);
    if (!info || score === null) {
      return chapter(2, 'Severity', 'severity', 3, note('No severity score is published yet. NVD may not have analysed this CVE so far.'));
    }
    const version = /^\d\.\d$/.test(str(primary.version, 5)) ? primary.version : '?';
    const provider = primary.provider === 'NVD' ? 'scored by NVD (NIST)' : 'scored by the vendor or another source';
    const badge = el('div', { class: `badge ${info.cls}` },
      el('span', { class: 'badge-label', text: info.label }),
      el('span', { class: 'badge-score', text: score.toFixed(1) }));
    const head = el('div', { class: 'severity-head' }, badge, el('p', { class: 'muted', text: `CVSS v${version} · ${provider}` }));
    const parts = [head, el('p', { text: info.meaning })];

    if (isAnalyst()) {
      const vector = str(primary.vector, 400);
      if (vector) parts.push(el('p', { class: 'label', text: 'Vector' }), el('code', { class: 'vector', text: vector }));
      const rows = arr(primary.breakdown).map((r) => [str(r && r.metric, 80), str(r && r.value, 80)]);
      if (rows.length) parts.push(definitionList(rows));
      const others = arr(d.cvss.others);
      if (others.length) {
        const list = el('ul', { class: 'chips' });
        for (const o of others) {
          const oi = severityInfo(o && o.severity);
          const os = num(o && o.score);
          if (oi && os !== null) list.append(chip(`CVSS ${str(o.version, 5)}: ${os.toFixed(1)} ${oi.label}${o.provider === 'NVD' ? ' (NVD)' : ' (other source)'}`, 'c-teal'));
        }
        parts.push(el('p', { class: 'label', text: 'Other scores' }), list);
      }
      const weaknesses = arr(d.weaknesses);
      if (weaknesses.length) {
        const list = el('ul', { class: 'chips' });
        for (const w of weaknesses) list.append(chip(`${str(w && w.id, 30)}${w && w.name ? ` · ${str(w.name, 80)}` : ''}`, 'c-purple'));
        parts.push(el('p', { class: 'label', text: 'Weakness type (CWE)' }), list);
      }
    }
    return chapter(2, 'Severity', 'severity', 3, ...parts);
  }

  // ------------------------------------------------------------------ chapter 3: exploitation

  function renderKev(kev) {
    const status = kev && kev.status;
    if (status === 'listed') {
      const rows = [el('p', {}, el('span', { class: 'tag-status danger', text: 'Known exploited' }), ' CISA confirms this vulnerability is being used in real attacks.')];
      const facts = [];
      const added = formatDate(kev.dateAdded);
      const due = formatDate(kev.dueDate);
      if (added) facts.push(['Added to the KEV list', added]);
      if (isAnalyst() && due) facts.push(['US federal fix deadline', due]);
      if (kev.ransomware === 'Known') facts.push(['Used by ransomware groups', 'Yes (known)']);
      if (isAnalyst()) facts.push(['Source', kev.source === 'nvd' ? 'NVD copy of CISA data (the CISA feed was unavailable)' : 'CISA KEV feed']);
      if (facts.length) rows.push(definitionList(facts));
      return rows;
    }
    if (status === 'not_listed') {
      return [el('p', {}, el('span', { class: 'tag-status ok', text: 'Not in CISA KEV' }), ' Not on CISA\'s list of known exploited vulnerabilities. That list only holds confirmed cases, so this is not proof of safety.')];
    }
    return [el('p', {}, el('span', { class: 'tag-status warn', text: 'Unknown' }), ' The CISA list could not be checked right now. This is NOT a sign the vulnerability is safe. Try again shortly.')];
  }

  function renderEpss(epss) {
    const label = el('p', { class: 'label', text: 'EPSS: estimated chance of exploitation in the next 30 days' });
    const status = epss && epss.status;
    if (status === 'ok' && num(epss.score) !== null && epss.score >= 0 && epss.score <= 1) {
      const p = epss.score;
      const bar = el('progress', { class: 'epss-bar', attrs: { max: 100, value: (p * 100).toFixed(2), 'aria-label': `EPSS ${formatPercent(p)}` } });
      const parts = [label, el('p', { class: 'epss-line' }, el('span', { class: 'epss-value', text: formatPercent(p) }), el('span', { class: 'muted', text: ` ${epssLevel(p)} likelihood` })), bar];
      if (isAnalyst()) {
        const pct = num(epss.percentile);
        const date = formatDate(epss.date);
        const facts = [];
        if (pct !== null) facts.push(['Percentile', `${(pct * 100).toFixed(1)} (compared with all scored CVEs; 100 is the highest)`]);
        if (date) facts.push(['Score date', date]);
        if (facts.length) parts.push(definitionList(facts));
      } else {
        parts.push(note('Most vulnerabilities have a very low score, so a high value is a strong warning sign.'));
      }
      return parts;
    }
    if (status === 'not_scored') return [label, note('No EPSS score yet. This is common for very new CVEs.')];
    return [label, note('EPSS data is unavailable right now.')];
  }

  // CISA's triage (SSVC). The server only sends one of a few exact words; the sentences below are ours.
  const SSVC_TEXT = {
    exploitation: {
      label: 'Exploitation',
      none: 'No sign of exploitation or a public exploit.',
      poc: 'A public proof-of-concept exploit exists.',
      active: 'It is being exploited in real attacks.',
    },
    automatable: {
      label: 'Can attacks be automated?',
      yes: 'Yes. An attacker can run it at scale with a script, with no manual work per target.',
      no: 'No. Each target needs manual effort.',
    },
    technicalImpact: {
      label: 'Technical impact',
      partial: 'Partial. The attacker gets limited control or access.',
      total: 'Total. The attacker gets full control of the affected software.',
    },
  };

  function renderSsvc(ssvc) {
    const label = el('p', { class: 'label', text: "CISA's triage (SSVC)" });
    if (!ssvc || ssvc.status !== 'assessed') return [label, note('CISA has not published a triage assessment for this CVE.')];
    const rows = [];
    for (const [field, table] of Object.entries(SSVC_TEXT)) {
      const answer = ssvc[field];
      rows.push([table.label, typeof answer === 'string' && Object.hasOwn(table, answer) && answer !== 'label' ? table[answer] : 'Not available']);
    }
    const parts = [label, definitionList(rows)];
    const assessed = formatDate(ssvc.assessed);
    if (isAnalyst() && assessed) parts.push(note(`Assessed by CISA on ${assessed}.`));
    return parts;
  }

  function renderExploitation(d) {
    const e = d.exploitation || {};
    return chapter(3, 'Exploitation status', 'exploitation', 3, ...renderKev(e.kev), el('hr'), ...renderEpss(e.epss), el('hr'), ...renderSsvc(e.ssvc));
  }

  // ------------------------------------------------------------------ chapter 4: summary

  function renderSummary(d) {
    const s = d.summary;
    const parts = [];
    if (!s) {
      parts.push(note('A summary is unavailable right now. The details below are still accurate.'));
    } else {
      const isAi = s.source === 'ai';
      parts.push(el('p', { class: 'summary-tag' },
        el('span', { class: `tag-status ${isAi ? 'ai' : 'neutral'}`, text: isAi ? 'AI-generated' : 'Automatic summary' }),
        el('span', { class: 'muted', text: isAi ? ` by ${str(s.model, 100)}. AI can make mistakes: verify before acting.` : s.llm === 'unavailable' ? ' The AI summary is unavailable right now, so a template summary is shown.' : ' Built from the data below by fixed rules (no AI configured).' })));
      const blocks = [['What is it?', s.what], ['Should I worry?', s.worry], ['What should I do?', s.action]];
      for (const [question, answer] of blocks) {
        parts.push(el('div', { class: 'qa' }, el('h3', { text: question }), el('p', { text: str(answer, 600) })));
      }
    }
    if (isAnalyst() && d.description) {
      parts.push(el('h3', { class: 'desc-title', text: 'Official description (NVD)' }), el('p', { class: 'description', text: str(d.description, 4000) }));
    }
    return chapter(4, 'Plain-language summary', 'summary', 6, ...parts);
  }

  // ------------------------------------------------------------------ chapter 5: affected products

  function renderAffected(d) {
    const a = d.affected || {};
    const products = arr(a.products);
    if (!products.length) {
      return chapter(5, 'Affected products and versions', 'affected', 3, note('No affected-product data is published yet. Check the vendor advisory in the references.'));
    }
    const maxProducts = isAnalyst() ? products.length : 5;
    const maxVersions = isAnalyst() ? 12 : 3;
    const list = el('ul', { class: 'products' });
    for (const p of products.slice(0, maxProducts)) {
      const versions = arr(p && p.versions);
      const chips = el('ul', { class: 'chips' });
      for (const v of versions.slice(0, maxVersions)) chips.append(chip(str(v, 80), 'mono c-blue'));
      const hidden = Math.max(0, versions.length - maxVersions) + (num(p && p.moreVersions) || 0);
      if (hidden > 0) chips.append(chip(`+${hidden} more`, 'c-muted'));
      list.append(el('li', {}, el('strong', { text: `${str(p && p.vendor, 80)} ${str(p && p.product, 80)}`.trim() }), chips));
    }
    const total = num(a.total) || products.length;
    const shown = Math.min(maxProducts, products.length);
    const parts = [list];
    if (total > shown) parts.push(note(`+${total - shown} more affected products${isAnalyst() ? ' are not shown here. See the full record on NVD.' : '. Switch to the Analyst view for more detail.'}`));
    const sources = { 'nvd-cpe': 'Source: NVD product data (CPE).', cna: 'Source: the vendor\'s own report (no NVD product data yet).' };
    if (Object.hasOwn(sources, a.source)) parts.push(note(sources[a.source]));
    return chapter(5, 'Affected products and versions', 'affected', 3, ...parts);
  }

  // ------------------------------------------------------------------ chapter 6: fix / mitigation

  function referenceLink(item) {
    const href = safeHttpUrl(item && item.url);
    if (!href) return null;
    const url = new URL(href);
    const rest = `${url.pathname}${url.search}`.replace(/\/$/, '');
    const short = rest.length > 70 ? `${rest.slice(0, 69)}…` : rest;
    const link = externalLink(href, url.hostname);
    const tags = el('span', { class: 'tags' });
    for (const t of arr(item.tags).slice(0, 4)) tags.append(el('span', { class: 'tag', text: str(t, 40) }));
    return el('li', {}, link, el('span', { class: 'path', text: short === '/' ? '' : short }), tags);
  }

  function renderFix(d) {
    const fix = d.fix || {};
    const parts = [];
    if (fix.requiredAction) {
      parts.push(el('p', { class: 'label', text: 'What CISA requires' }), el('p', { class: 'quote', text: str(fix.requiredAction, 600) }));
    }
    const fixedIn = arr(fix.fixedIn);
    if (fixedIn.length) {
      const rows = fixedIn.slice(0, isAnalyst() ? 30 : 3).map((f) => [`${str(f && f.vendor, 80)} ${str(f && f.product, 80)}`.trim(), el('span', { class: 'mono', text: arr(f && f.versions).map((v) => str(v, 60)).join(', ') })]);
      parts.push(el('p', { class: 'label', text: 'First unaffected versions, according to NVD data' }), definitionList(rows));
    }
    const advisories = arr(fix.advisories).slice(0, isAnalyst() ? 8 : 3);
    const items = advisories.map(referenceLink).filter(Boolean);
    if (items.length) parts.push(el('p', { class: 'label', text: 'Patches and vendor advisories' }), el('ul', { class: 'links' }, ...items));
    if (!parts.length) parts.push(note('No patch or advisory is listed in NVD yet. Check the vendor\'s website, and consider the mitigations in the references.'));
    parts.push(el('p', { class: 'verify', text: 'Always verify with the official vendor advisory before changing production systems.' }));
    return chapter(6, 'Fix and mitigation', 'fix', 3, ...parts);
  }

  // ------------------------------------------------------------------ chapter 7: references

  function renderReferences(d) {
    const refs = d.references || {};
    const all = arr(refs.items);
    const shown = all.slice(0, isAnalyst() ? all.length : 5).map(referenceLink).filter(Boolean);
    const parts = [];
    if (shown.length) parts.push(el('ul', { class: 'links' }, ...shown));
    else parts.push(note('No references are listed.'));
    const total = num(refs.total) || all.length;
    if (total > shown.length) parts.push(note(`${total - shown.length} more references${isAnalyst() ? ' are on the full NVD record.' : '. Switch to the Analyst view to see more.'}`));
    return chapter(7, 'References', 'references', 6, ...parts);
  }

  // ------------------------------------------------------------------ what data was available

  function renderDataNote(d) {
    const s = d.sources || {};
    const ok = (v) => v === 'ok';
    const generated = typeof d.generatedAt === 'string' ? d.generatedAt.slice(0, 16).replace('T', ' ') : '';
    const mark = (name, status, good) => el('li', { class: good ? 'good' : 'bad', text: `${good ? '✓' : '!'} ${name}: ${status}` });
    const list = el('ul', { class: 'source-status' },
      mark('NVD', ok(s.nvd) ? 'ok' : 'problem', ok(s.nvd)),
      mark('CISA KEV', ok(s.kev) ? 'ok' : 'unavailable', ok(s.kev)),
      mark('EPSS', ok(s.epss) ? 'ok' : s.epss === 'not_scored' ? 'not scored yet' : 'unavailable', ok(s.epss) || s.epss === 'not_scored'),
      mark('Summary', s.summary === 'ai' ? 'AI' : s.summary === 'template' ? 'template' : 'none', s.summary === 'ai' || s.summary === 'template'));
    return el('div', { class: 'data-note' }, list, generated ? el('p', { text: `Generated ${generated} UTC. Results can be cached for up to an hour.` }) : null);
  }

  // ------------------------------------------------------------------ page-level rendering

  /** `animate` is true only for a fresh lookup: panels settle in once. Switching views never re-animates. */
  function render(animate) {
    const d = state.data;
    if (!d) return;
    panelCount = 0;
    bodyEl.classList.toggle('animate-in', Boolean(animate));
    bodyEl.replaceChildren(renderHeader(d), renderSeverity(d), renderExploitation(d), renderSummary(d), renderAffected(d), renderFix(d), renderReferences(d), renderDataNote(d));
    resultEl.hidden = false;
  }

  function setBusy(busy, id) {
    button.disabled = busy;
    input.setAttribute('aria-busy', String(busy));
    statusEl.hidden = !busy;
    if (busy) statusEl.replaceChildren(el('span', { class: 'loader', attrs: { 'aria-hidden': 'true' } }, el('i'), el('i'), el('i')), `Looking up ${id}…`);
    else statusEl.replaceChildren();
  }

  function showMessage(text) {
    messageEl.textContent = text;
    messageEl.hidden = false;
  }

  function clearMessages() {
    messageEl.hidden = true;
    messageEl.textContent = '';
    fieldError.hidden = true;
    fieldError.textContent = '';
    input.removeAttribute('aria-invalid');
  }

  function showFieldError(text) {
    fieldError.textContent = text;
    fieldError.hidden = false;
    input.setAttribute('aria-invalid', 'true');
    input.focus();
  }

  async function lookup(rawValue) {
    clearMessages();
    const id = rawValue.trim().toUpperCase();
    if (!CVE_PATTERN.test(id)) {
      showFieldError('Enter a CVE ID like CVE-2021-44228 (CVE, a 4-digit year, then 4 or more digits).');
      return;
    }
    input.value = id;

    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    const requestId = ++state.requestId;
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    setBusy(true, id);
    resultEl.hidden = true;

    try {
      const response = await fetch(`${API_URL}?id=${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' }, signal: controller.signal, credentials: 'omit' });
      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      if (requestId !== state.requestId) return; // a newer lookup replaced this one

      if (!response.ok) {
        const code = body && body.error && typeof body.error.code === 'string' ? body.error.code : '';
        let text = Object.hasOwn(ERROR_TEXT, code) ? ERROR_TEXT[code] : 'Something went wrong. Please try again.';
        const wait = Number.parseInt(response.headers.get('Retry-After') || '', 10);
        if ((code === 'rate_limited' || code === 'busy') && wait > 0 && wait < 3600) text += ` (Try again in about ${wait} seconds.)`;
        showMessage(text);
        return;
      }
      if (!body || typeof body !== 'object' || typeof body.id !== 'string' || !CVE_PATTERN.test(body.id)) {
        showMessage('The server sent an unexpected response. Please try again.');
        return;
      }
      state.data = body;
      render(true);
      announceEl.textContent = `Brief ready for ${body.id}.`;
      resultEl.focus({ preventScroll: true });
      resultEl.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
      try {
        history.replaceState(null, '', `?id=${encodeURIComponent(body.id)}`);
      } catch { /* not important */ }
    } catch (err) {
      if (requestId !== state.requestId) return;
      showMessage(err && err.name === 'AbortError' ? 'The lookup took too long. Please try again.' : 'Could not reach the server. Check your connection and try again.');
    } finally {
      clearTimeout(timer);
      if (requestId === state.requestId) setBusy(false);
    }
  }

  // ------------------------------------------------------------------ day / night toggle

  const themeButton = $('theme-toggle');
  const themeLabel = $('theme-label');
  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function effectiveTheme() {
    const chosen = document.documentElement.getAttribute('data-theme');
    if (chosen === 'light' || chosen === 'dark') return chosen;
    return darkQuery.matches ? 'dark' : 'light';
  }

  // Same icons and wording as the portfolio site: a moon (label "Night") by day, a sun (label "Day") by night.
  const MOON = 'M6 .3a7.7 7.7 0 109.7 9.7A6.2 6.2 0 016 .3z';
  const SUN = 'M8 4a4 4 0 100 8 4 4 0 000-8zM7 0h2v2.5H7zM7 13.5h2V16H7zM0 7h2.5v2H0zM13.5 7H16v2h-2.5zM2.1 3.5l1.4-1.4 1.8 1.8-1.4 1.4zM10.7 12.1l1.4-1.4 1.8 1.8-1.4 1.4zM2.1 12.5l1.8-1.8 1.4 1.4-1.8 1.8zM10.7 3.9l1.8-1.8 1.4 1.4-1.8 1.8z';
  const themeIcon = $('theme-icon');

  function paintThemeButton() {
    const dark = effectiveTheme() === 'dark';
    themeLabel.textContent = dark ? 'Day' : 'Night';
    themeIcon.setAttribute('d', dark ? SUN : MOON);
    themeButton.setAttribute('aria-label', dark ? 'Switch to day mode' : 'Switch to night mode');
  }

  themeButton.addEventListener('click', () => {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try {
      localStorage.setItem('theme', next);
    } catch { /* ignore */ }
    paintThemeButton();
  });
  darkQuery.addEventListener('change', paintThemeButton);

  // ------------------------------------------------------------------ wiring

  function loadViewPreference() {
    try {
      const saved = localStorage.getItem('view');
      if (saved === 'manager' || saved === 'analyst') state.view = saved;
    } catch { /* storage can be blocked: the default is fine */ }
    const radio = document.querySelector(`input[name="view"][value="${state.view}"]`);
    if (radio) radio.checked = true;
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    lookup(input.value);
  });

  for (const example of document.querySelectorAll('[data-example]')) {
    example.addEventListener('click', () => {
      input.value = example.getAttribute('data-example') || '';
      lookup(input.value);
    });
  }

  for (const radio of document.querySelectorAll('input[name="view"]')) {
    radio.addEventListener('change', () => {
      if (!radio.checked || (radio.value !== 'manager' && radio.value !== 'analyst')) return;
      state.view = radio.value;
      try {
        localStorage.setItem('view', state.view);
      } catch { /* ignore */ }
      render(false);
    });
  }

  $('print-button').addEventListener('click', () => window.print());

  paintThemeButton();
  loadViewPreference();
  const initial = new URLSearchParams(location.search).get('id');
  if (initial && CVE_PATTERN.test(initial.trim().toUpperCase())) lookup(initial);
})();
