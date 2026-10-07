// Fixed lookup tables: human-readable names for CVSS vector codes and common CWE IDs.
// Because the display text comes from OUR tables (not from the upstream data),
// the only upstream influence on it is "which allow-listed row is selected".

// Common weakness types (https://cwe.mitre.org/). Unknown CWE IDs are shown without a name.
export const CWE_NAMES = {
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-77': 'Command Injection',
  'CWE-78': 'OS Command Injection',
  'CWE-79': 'Cross-site Scripting (XSS)',
  'CWE-89': 'SQL Injection',
  'CWE-94': 'Code Injection',
  'CWE-119': 'Memory Buffer Bounds Violation',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-190': 'Integer Overflow or Wraparound',
  'CWE-200': 'Exposure of Sensitive Information',
  'CWE-287': 'Improper Authentication',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-416': 'Use After Free',
  'CWE-434': 'Unrestricted Upload of Dangerous File Type',
  'CWE-476': 'NULL Pointer Dereference',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-611': 'XML External Entity (XXE) Reference',
  'CWE-787': 'Out-of-bounds Write',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-917': 'Expression Language Injection',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
};

const LEVEL_3 = { N: 'None', L: 'Low', H: 'High' };

// Base metrics only (the part that produces the score). Each entry: code -> [label, { value code -> label }].
export const VECTOR_TABLES = {
  // CVSS v3.0 and v3.1
  3: {
    AV: ['Attack vector', { N: 'Network', A: 'Adjacent network', L: 'Local', P: 'Physical' }],
    AC: ['Attack complexity', { L: 'Low', H: 'High' }],
    PR: ['Privileges required', LEVEL_3],
    UI: ['User interaction', { N: 'None', R: 'Required' }],
    S: ['Scope', { U: 'Unchanged', C: 'Changed' }],
    C: ['Confidentiality impact', LEVEL_3],
    I: ['Integrity impact', LEVEL_3],
    A: ['Availability impact', LEVEL_3],
  },
  // CVSS v4.0
  4: {
    AV: ['Attack vector', { N: 'Network', A: 'Adjacent network', L: 'Local', P: 'Physical' }],
    AC: ['Attack complexity', { L: 'Low', H: 'High' }],
    AT: ['Attack requirements', { N: 'None', P: 'Present' }],
    PR: ['Privileges required', LEVEL_3],
    UI: ['User interaction', { N: 'None', P: 'Passive', A: 'Active' }],
    VC: ['Vulnerable system: confidentiality', LEVEL_3],
    VI: ['Vulnerable system: integrity', LEVEL_3],
    VA: ['Vulnerable system: availability', LEVEL_3],
    SC: ['Subsequent systems: confidentiality', LEVEL_3],
    SI: ['Subsequent systems: integrity', LEVEL_3],
    SA: ['Subsequent systems: availability', LEVEL_3],
  },
  // CVSS v2
  2: {
    AV: ['Access vector', { L: 'Local', A: 'Adjacent network', N: 'Network' }],
    AC: ['Access complexity', { H: 'High', M: 'Medium', L: 'Low' }],
    Au: ['Authentication', { M: 'Multiple', S: 'Single', N: 'None' }],
    C: ['Confidentiality impact', { N: 'None', P: 'Partial', C: 'Complete' }],
    I: ['Integrity impact', { N: 'None', P: 'Partial', C: 'Complete' }],
    A: ['Availability impact', { N: 'None', P: 'Partial', C: 'Complete' }],
  },
};
