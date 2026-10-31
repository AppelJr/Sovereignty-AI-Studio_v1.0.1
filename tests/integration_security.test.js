'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyOwnerSession } = require('../backend/integration/session_proof');
const { loadPolicy, decideProvider, writePolicy } = require('../backend/integration/provider_policy');

const SECRET = '0123456789abcdef0123456789abcdef';

function proof(claims = {}) {
  const payload = {
    session_id: 'session-live-test',
    identity_id: 'owner-test',
    capabilities: ['ai.inference', 'provider.policy.write'],
    mode: 'offline',
    expires_at: 2_000_000_000,
    ...claims
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET).update(encoded, 'ascii').digest('base64url');
  return encoded + '.' + signature;
}

test('signed owner session accepts exact owner and required capability', () => {
  const session = verifyOwnerSession(proof(), 'owner-test', 'ai.inference', {
    secret: SECRET, nowSeconds: 1_000_000_000
  });
  assert.equal(session.identity_id, 'owner-test');
  assert.equal(session.session_id, 'session-live-test');
});

test('owner session rejects forged identity, missing capability, expiry and signature tampering', () => {
  assert.throws(() => verifyOwnerSession(proof(), 'other-owner', 'ai.inference', {
    secret: SECRET, nowSeconds: 1_000_000_000
  }), /OWNER_IDENTITY_MISMATCH/);
  assert.throws(() => verifyOwnerSession(proof({ capabilities: [] }), 'owner-test', 'ai.inference', {
    secret: SECRET, nowSeconds: 1_000_000_000
  }), /OWNER_CAPABILITY_MISSING/);
  assert.throws(() => verifyOwnerSession(proof({ expires_at: 1 }), 'owner-test', 'ai.inference', {
    secret: SECRET, nowSeconds: 2
  }), /SESSION_PROOF_EXPIRED/);
  const parts = proof().split('.');
  assert.throws(() => verifyOwnerSession(parts[0] + '.' + Buffer.alloc(32).toString('base64url'), 'owner-test', 'ai.inference', {
    secret: SECRET, nowSeconds: 1_000_000_000
  }), /SESSION_PROOF_SIGNATURE_INVALID/);
});

test('provider policy v1.1.0 allows owner defaults and denies blocked/unknown providers', () => {
  const policy = loadPolicy();
  assert.equal(policy.policy_version, '1.1.0');
  assert.equal(decideProvider('xai').decision, 'ALLOW');
  assert.equal(decideProvider('openai').decision, 'ALLOW');
  assert.equal(decideProvider('anthropic').decision, 'ALLOW');
  assert.equal(decideProvider('google').decision, 'DENY');
  assert.equal(decideProvider('mistral').decision, 'DENY');
  assert.equal(decideProvider('unlisted-provider').reason, 'UNKNOWN_PROVIDER');
});

test('provider policy rejects non-HTTPS custom endpoints and persists atomically', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-policy-'));
  const target = path.join(dir, 'policy.json');
  try {
    const policy = loadPolicy();
    assert.throws(() => writePolicy({
      ...policy, custom_endpoint_allowlist: ['http://example.invalid']
    }, target), /PROVIDER_POLICY_ENDPOINT_MUST_BE_HTTPS/);
    const saved = writePolicy(policy, target);
    assert.equal(saved.policy_version, '1.1.0');
    assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
