import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readConfig } from '../lib/config.js';

const full = { LLM_BASE_URL: 'https://api.groq.com/openai/v1', LLM_API_KEY: 'k', LLM_MODEL: 'openai/gpt-oss-120b', NVD_API_KEY: 'n' };

test('full configuration', () => {
  assert.deepEqual(readConfig(full), { nvdApiKey: 'n', llm: { apiKey: 'k', baseUrl: 'https://api.groq.com/openai/v1', model: 'openai/gpt-oss-120b' } });
});

test('empty environment: no NVD key, no AI (template summary will be used)', () => {
  assert.deepEqual(readConfig({}), { nvdApiKey: '', llm: null });
  assert.deepEqual(readConfig({ LLM_BASE_URL: '', LLM_API_KEY: '', LLM_MODEL: '', NVD_API_KEY: '' }), { nvdApiKey: '', llm: null });
});

test('the AI is enabled only when ALL THREE LLM variables are usable', () => {
  for (const missing of ['LLM_BASE_URL', 'LLM_API_KEY', 'LLM_MODEL']) {
    assert.equal(readConfig({ ...full, [missing]: '' }).llm, null, missing);
  }
});

test('values are trimmed and a trailing slash on the base URL is removed', () => {
  const c = readConfig({ ...full, LLM_BASE_URL: '  https://api.groq.com/openai/v1//  ', LLM_API_KEY: ' k \n', NVD_API_KEY: ' n ' });
  assert.equal(c.llm.baseUrl, 'https://api.groq.com/openai/v1');
  assert.equal(c.llm.apiKey, 'k');
  assert.equal(c.nvdApiKey, 'n');
});

test('plain http is refused for remote hosts (the key would travel in clear text) but allowed for localhost', () => {
  assert.equal(readConfig({ ...full, LLM_BASE_URL: 'http://api.example.com/v1' }).llm, null);
  assert.ok(readConfig({ ...full, LLM_BASE_URL: 'http://localhost:11434/v1' }).llm);
  assert.ok(readConfig({ ...full, LLM_BASE_URL: 'http://127.0.0.1:8080/v1' }).llm);
});

test('malformed or dangerous base URLs and model names disable the AI instead of being used', () => {
  for (const url of ['not a url', 'javascript:alert(1)', 'file:///etc/passwd', 'https://user:pass@api.example.com/v1', 'ftp://example.com']) {
    assert.equal(readConfig({ ...full, LLM_BASE_URL: url }).llm, null, url);
  }
  for (const model of ['has space', 'a'.repeat(200), 'model\nname', '<script>', '../../x']) {
    assert.equal(readConfig({ ...full, LLM_MODEL: model }).llm, null, JSON.stringify(model));
  }
});

test('non-string values are ignored', () => {
  assert.deepEqual(readConfig({ LLM_BASE_URL: 5, LLM_API_KEY: {}, LLM_MODEL: [], NVD_API_KEY: null }), { nvdApiKey: '', llm: null });
});
