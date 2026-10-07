import { test } from 'node:test';
import assert from 'node:assert/strict';
import { severityFor, isValidVector, parseVector, describeVector, impactFlags } from '../lib/cvss.js';

test('severity bands follow the CVSS v3/v4 specification', () => {
  const cases = [[0, 'none'], [0.1, 'low'], [3.9, 'low'], [4, 'medium'], [6.9, 'medium'], [7, 'high'], [8.9, 'high'], [9, 'critical'], [10, 'critical']];
  for (const [score, expected] of cases) assert.equal(severityFor('3.1', score), expected, `v3.1 ${score}`);
  assert.equal(severityFor('4.0', 8.7), 'high');
});

test('CVSS v2 has no critical band', () => {
  assert.equal(severityFor('2.0', 10), 'high');
  assert.equal(severityFor('2.0', 9.3), 'high');
  assert.equal(severityFor('2.0', 5), 'medium');
  assert.equal(severityFor('2.0', 2), 'low');
});

test('isValidVector accepts real vectors and rejects everything else', () => {
  assert.ok(isValidVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'));
  assert.ok(isValidVector('AV:N/AC:M/Au:N/C:C/I:C/A:C'));
  assert.ok(isValidVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X'));
  for (const bad of ['', 'CVSS:3.1/', '<script>', 'AV:N/<img src=x>', 'CVSS:9.9/AV:N', 'AV:N/AC:L/' + 'A:B/'.repeat(200), null, undefined, 5, {}, 'AV:N AC:L']) {
    assert.equal(isValidVector(bad), false, String(bad));
  }
});

test('describeVector explains a v3.1 vector using only our own label tables', () => {
  const rows = describeVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.deepEqual(rows[0], { metric: 'Attack vector', value: 'Network' });
  assert.deepEqual(rows[3], { metric: 'User interaction', value: 'None' });
  assert.deepEqual(rows[4], { metric: 'Scope', value: 'Changed' });
  assert.equal(rows.length, 8);
});

test('describeVector skips unknown codes instead of echoing them', () => {
  const rows = describeVector('CVSS:3.1/AV:Z/AC:L/XX:9/PR:N/UI:N/S:U/C:N/I:N/A:N');
  assert.ok(!rows.some((r) => r.metric === 'Attack vector'), 'unknown value Z is dropped');
  assert.ok(!JSON.stringify(rows).includes('XX'));
});

test('describeVector handles v2 and v4 (base metrics only)', () => {
  assert.deepEqual(describeVector('AV:N/AC:M/Au:N/C:C/I:C/A:C')[2], { metric: 'Authentication', value: 'None' });
  const v4 = describeVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X');
  assert.ok(v4.some((r) => r.metric === 'Vulnerable system: availability' && r.value === 'High'));
  assert.ok(!v4.some((r) => r.metric === 'E'), 'threat/environmental metrics are not described');
});

test('parseVector uses a prototype-free object, so odd keys cannot reach Object.prototype', () => {
  const parsed = parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
  assert.equal(Object.getPrototypeOf(parsed.metrics), null);
  assert.equal(parseVector('not a vector'), null);
});

test('impactFlags summarises the Log4Shell vector', () => {
  assert.deepEqual(impactFlags('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), {
    attackPath: 'network', privileges: 'none', userInteraction: 'none', confidentiality: 'high', integrity: 'high', availability: 'high',
  });
});

test('impactFlags understands v4 and v2 and returns null for garbage', () => {
  const v4 = impactFlags('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N');
  assert.equal(v4.availability, 'high');
  assert.equal(v4.confidentiality, 'none');
  const v2 = impactFlags('AV:L/AC:L/Au:S/C:P/I:P/A:N');
  assert.deepEqual([v2.attackPath, v2.privileges, v2.userInteraction, v2.confidentiality, v2.availability], ['local', 'low', null, 'low', 'none']);
  assert.equal(impactFlags('<script>'), null);
});
