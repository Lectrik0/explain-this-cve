import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanText, safeHttpUrl, finiteNumberInRange } from '../lib/sanitize.js';

test('cleanText returns "" for non-strings', () => {
  for (const v of [null, undefined, 5, {}, [], ['a']]) assert.equal(cleanText(v, 100), '');
});

test('cleanText strips control and invisible characters but keeps normal text and newlines', () => {
  assert.equal(cleanText('a\u0000b\u0007c\u001Bd', 100), 'abcd');
  assert.equal(cleanText('safe‮evil​text﻿', 100), 'safeeviltext');
  assert.equal(cleanText('line1\r\nline2\n\n\n\n\nline3', 100), 'line1\nline2\n\nline3');
  assert.equal(cleanText('tab\there', 100), 'tab\there');
});

test('cleanText does NOT html-escape (escaping is the page\'s job: textContent + CSP)', () => {
  const payload = '<img src=x onerror=alert(1)> & "quotes"';
  assert.equal(cleanText(payload, 200), payload);
});

test('cleanText caps length and marks truncation', () => {
  const out = cleanText('x'.repeat(1000), 50);
  assert.equal(out.length, 50);
  assert.ok(out.endsWith('…'));
  assert.equal(cleanText('short', 50), 'short');
});

test('cleanText never leaves half of an emoji at the cut point', () => {
  const out = cleanText('a'.repeat(9) + '😀😀😀', 11);
  assert.ok(!/[\uD800-\uDBFF]…?$/.test(out.replace('…', '')), 'no lone high surrogate before the ellipsis');
});

test('cleanText handles huge input without scanning all of it', () => {
  const started = performance.now();
  const out = cleanText('A'.repeat(50_000_000), 100);
  assert.equal(out.length, 100);
  assert.ok(performance.now() - started < 500);
});

test('safeHttpUrl accepts normal http(s) URLs and returns the normalised form', () => {
  assert.equal(safeHttpUrl('https://logging.apache.org/log4j/2.x/security.html'), 'https://logging.apache.org/log4j/2.x/security.html');
  assert.equal(safeHttpUrl('http://example.com'), 'http://example.com/');
  assert.equal(safeHttpUrl('  https://example.com/a b  '), 'https://example.com/a%20b');
});

test('safeHttpUrl rejects dangerous schemes, even when disguised', () => {
  const bad = [
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '  javascript:alert(1)',
    'jav\tascript:alert(1)',
    'jav\nascript:alert(1)',
    '\u0001javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'ftp://example.com/file',
    'blob:https://example.com/uuid',
    'about:blank',
  ];
  for (const u of bad) assert.equal(safeHttpUrl(u), null, JSON.stringify(u));
});

test('safeHttpUrl rejects relative, protocol-relative, credential and malformed URLs', () => {
  for (const u of ['//evil.example/x', '/relative/path', 'example.com', 'https://', 'http://user:pass@example.com/', 'https://user@example.com/', '', ' ']) {
    assert.equal(safeHttpUrl(u), null, JSON.stringify(u));
  }
});

test('safeHttpUrl returns the parser-normalised form, so what we render is what the browser will open', () => {
  // The URL parser collapses the extra slash; we output ITS result, never the raw input.
  assert.equal(safeHttpUrl('https:///nohost'), 'https://nohost/');
  assert.equal(safeHttpUrl('HTTPS://EXAMPLE.com:443/x'), 'https://example.com/x');
});

test('safeHttpUrl rejects non-strings and over-long URLs', () => {
  for (const v of [null, undefined, 1, {}, [], ['https://example.com']]) assert.equal(safeHttpUrl(v), null);
  assert.equal(safeHttpUrl('https://example.com/' + 'a'.repeat(3000)), null);
});

test('finiteNumberInRange', () => {
  assert.equal(finiteNumberInRange(7.5, 0, 10), 7.5);
  assert.equal(finiteNumberInRange('0.97', 0, 1), 0.97);
  for (const v of [-1, 11, NaN, Infinity, null, undefined, '', ' ', 'abc', {}, [], true]) {
    assert.equal(finiteNumberInRange(v, 0, 10), null, String(v));
  }
});
