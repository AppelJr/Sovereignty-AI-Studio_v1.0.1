'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOfficialProviderAdapter } = require('../backend/inference/official_provider_adapters');

const key = 'lane-specific-test-credential-123';

test('only explicitly supported provider contracts can be constructed', () => {
  assert.throws(() => createOfficialProviderAdapter('copilot', { credential: key, model: 'x' }), /PROVIDER_CONTRACT_UNAVAILABLE/);
  assert.throws(() => createOfficialProviderAdapter('xai', { model: 'x' }), /LANE_CREDENTIAL_REQUIRED/);
});

test('xAI adapter uses a fixed HTTPS destination and lane credential', async () => {
  let observed;
  const adapter = createOfficialProviderAdapter('xai', {
    credential: key, model: 'grok-test',
    fetch: async (url, init) => {
      observed = { url: String(url), init };
      return { status: 200, ok: true, text: async () => JSON.stringify({ model: 'grok-test', choices: [{ message: { content: 'answer' } }] }) };
    }
  });
  const result = await adapter.call({ prompt: 'hello' });
  assert.equal(result.ok, true);
  assert.equal(result.output, 'answer');
  assert.equal(observed.url, 'https://api.x.ai/v1/chat/completions');
  assert.equal(observed.init.headers.authorization, 'Bearer ' + key);
  assert.equal(observed.init.redirect, 'error');
  assert.equal(adapter.network, 'EXTERNAL');
});

test('Anthropic adapter uses Messages API authentication and request shape', async () => {
  let observed;
  const adapter = createOfficialProviderAdapter('anthropic', {
    credential: key, model: 'claude-test',
    fetch: async (url, init) => {
      observed = { url: String(url), init, body: JSON.parse(init.body) };
      return { status: 200, ok: true, text: async () => JSON.stringify({ content: [{ type: 'text', text: 'hello' }] }) };
    }
  });
  const result = await adapter.call({ prompt: 'test' });
  assert.equal(result.output, 'hello');
  assert.equal(observed.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(observed.init.headers['x-api-key'], key);
  assert.equal(observed.init.headers['anthropic-version'], '2023-06-01');
  assert.equal(observed.body.max_tokens, 1024);
});

test('provider HTTP and malformed response failures never become success', async () => {
  const httpFailure = createOfficialProviderAdapter('openai', {
    credential: key, model: 'gpt-test',
    fetch: async () => ({ status: 401, ok: false, text: async () => '{"error":"denied"}' })
  });
  assert.deepEqual(await httpFailure.call({ prompt: 'test' }), { ok: false, reason: 'PROVIDER_HTTP_401' });
  const malformed = createOfficialProviderAdapter('openai', {
    credential: key, model: 'gpt-test',
    fetch: async () => ({ status: 200, ok: true, text: async () => '{"choices":[]}' })
  });
  assert.equal((await malformed.call({ prompt: 'test' })).ok, false);
});

test('invalid input is rejected without network activity', async () => {
  let called = false;
  const adapter = createOfficialProviderAdapter('openai', {
    credential: key, model: 'gpt-test',
    fetch: async () => { called = true; throw new Error('unexpected'); }
  });
  assert.equal((await adapter.call({ prompt: '' })).reason, 'INVALID_INPUT');
  assert.equal(called, false);
});
