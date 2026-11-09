'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCompanyPipeRegistry } = require('../backend/inference/isolated_company_pipes');

function fixture(overrides = {}) {
  const lanes = Array.from({ length: 10 }, (_, i) => ({
    lane_id: 'pipe-' + String(i + 1).padStart(2, '0'),
    company_id: 'company-' + String(i + 1).padStart(2, '0'),
    provider_id: i === 0 ? 'xai' : 'local'
  }));
  const adapterBindings = {};
  const memoryStores = {};
  const transportPolicies = {};
  const scarLoggers = {};
  for (const lane of lanes) {
    adapterBindings[lane.lane_id] = { call: async () => ({ ok: true, output: 'ok' }) };
    memoryStores[lane.lane_id] = {
      read: key => lane.lane_id + ':' + key,
      write: (key, value) => ({ key, value })
    };
    transportPolicies[lane.lane_id] = { mode: 'LOCAL', allow_external: false, allowed_hosts: [] };
    scarLoggers[lane.lane_id] = { append: () => ({ ok: true }) };
  }
  return {
    lanes, adapterBindings, memoryStores, transportPolicies, scarLoggers,
    ...overrides
  };
}

test('requires exactly ten isolated lane declarations', () => {
  assert.throws(() => createCompanyPipeRegistry({ ...fixture(), lanes: [] }), /EXACTLY_TEN_LANES_REQUIRED/);
});

test('unbound provider adapter remains visible but cannot execute', async () => {
  const f = fixture();
  delete f.adapterBindings['pipe-01'];
  const registry = createCompanyPipeRegistry(f);
  assert.equal(registry.get('pipe-01').state, 'UNBOUND');
});

test('lane calls do not expose another lane memory namespace', async () => {
  const f = fixture();
  let captured;
  f.adapterBindings['pipe-01'] = { call: async request => {
    captured = request;
    assert.equal(request.memory.namespace, 'pipe-01');
    assert.equal(request.memory.read('allowed'), 'pipe-01:allowed');
    assert.throws(() => request.memory.read('other'), /MEMORY_SCOPE_DENIED/);
    return { ok: true };
  }};
  const registry = createCompanyPipeRegistry(f);
  const result = await registry.get('pipe-01').call({
    requestId: 'req-1', actorId: 'owner', prompt: 'test', memoryKeys: ['allowed']
  });
  assert.equal(result.ok, true);
  assert.equal(captured.transport.mode, 'LOCAL');
});

test('denies remote mode without explicit egress allow', async () => {
  const f = fixture();
  f.transportPolicies['pipe-01'] = { mode: 'HYBRID', allow_external: false, allowed_hosts: ['api.example.test'] };
  const registry = createCompanyPipeRegistry(f);
  const result = await registry.get('pipe-01').call({
    requestId: 'req-2', actorId: 'owner', prompt: 'test'
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /EXPLICIT_EGRESS_POLICY_REQUIRED/);
});

test('SCAR failure invalidates successful provider response', async () => {
  const f = fixture();
  f.scarLoggers['pipe-01'] = { append: () => ({ ok: false }) };
  const registry = createCompanyPipeRegistry(f);
  await assert.rejects(() => registry.get('pipe-01').call({
    requestId: 'req-3', actorId: 'owner', prompt: 'test'
  }), /SCAR_APPEND_FAILED/);
});

test('duplicate lane identity is rejected', () => {
  const f = fixture();
  f.lanes[1].company_id = f.lanes[0].company_id;
  assert.throws(() => createCompanyPipeRegistry(f), /LANE_IDENTITY_COLLISION/);
});
