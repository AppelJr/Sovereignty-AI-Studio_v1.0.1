'use strict';

/**
 * Step 2 Identity + Authority — negative tests first, then positive.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');

const {
  loadCanonicalState,
  buildCanonicalState,
  writeCanonicalState
} = require('../backend/state/canonical_state');

const {
  IDENTITY_KIND,
  IDENTITY_REASON,
  createOwnerIdentity,
  createParticipantIdentity,
  generateParticipantId,
  createIdentityRegistry
} = require('../backend/identity/identity_adapter');

const {
  AUTHORITY_REASON,
  checkAuthority,
  assertNotRootEscalation
} = require('../backend/authority/authority_gate');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-auth-'));
let failures = 0;

function check(name, fn) {
  try {
    fn();
    console.log('PASS  ' + name);
  } catch (err) {
    failures += 1;
    console.error('FAIL  ' + name);
    console.error('      ' + (err && err.message ? err.message : err));
  }
}

// Setup valid canonical state on disk
const stateFile = path.join(tmpRoot, 'state.json');
const validState = buildCanonicalState({ owner_id: 'Appel420' });
writeCanonicalState(stateFile, validState);
const canonicalOk = loadCanonicalState(stateFile);
assert.strictEqual(canonicalOk.allowed, true);

const registry = createIdentityRegistry();
const owner = createOwnerIdentity('Appel420');
registry.register(owner);

const participant = createParticipantIdentity({
  participant_id: generateParticipantId('grok-council'),
  name: 'Grok',
  provider: 'xAI',
  role: 'advisor',
  permission_set: ['advise', 'read_public']
});
registry.register(participant);

// ---------------------------------------------------------------------------
// NEGATIVE: no canonical state → DENY
// ---------------------------------------------------------------------------
check('resolve without canonical state → DENY / threat', () => {
  const r = registry.resolve({ allowed: false, state: null }, owner.identity_id);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, IDENTITY_REASON.NO_CANONICAL_STATE);
  assert.strictEqual(r.threat, true);
});

check('authority without canonical state → DENY / threat', () => {
  const idRes = registry.resolve(canonicalOk, owner.identity_id);
  const r = checkAuthority({ allowed: false, state: null }, idRes, 'any');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.NO_CANONICAL_STATE);
  assert.strictEqual(r.threat, true);
});

// ---------------------------------------------------------------------------
// NEGATIVE: missing / unknown identity → DENY
// ---------------------------------------------------------------------------
check('missing identity id → DENY', () => {
  const r = registry.resolve(canonicalOk, '');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, IDENTITY_REASON.MISSING_IDENTITY);
  assert.strictEqual(r.threat, true);
});

check('unknown identity → DENY', () => {
  const r = registry.resolve(canonicalOk, 'nobody');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, IDENTITY_REASON.UNKNOWN_IDENTITY);
  assert.strictEqual(r.threat, true);
});

check('authority without identity → DENY', () => {
  const r = checkAuthority(canonicalOk, { allowed: false, identity: null }, 'read');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.NO_IDENTITY);
  assert.strictEqual(r.threat, true);
});

// ---------------------------------------------------------------------------
// NEGATIVE: AI root / escalation → DENY
// ---------------------------------------------------------------------------
check('AI marked is_root → AI_ROOT_FORBIDDEN', () => {
  const evil = Object.freeze({
    kind: IDENTITY_KIND.PARTICIPANT,
    identity_id: 'evil',
    is_root: true,
    permission_set: []
  });
  const r = assertNotRootEscalation(evil);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.AI_ROOT_FORBIDDEN);
  assert.strictEqual(r.threat, true);
});

check('participant root action → ESCALATION_DENIED', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  assert.strictEqual(idRes.allowed, true);
  const r = checkAuthority(canonicalOk, idRes, 'grant_root');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.ESCALATION_DENIED);
  assert.strictEqual(r.threat, true);
});

check('participant bypass_policy → ESCALATION_DENIED', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  const r = checkAuthority(canonicalOk, idRes, 'bypass_policy');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.ESCALATION_DENIED);
  assert.strictEqual(r.threat, true);
});

check('participant missing permission → PERMISSION_DENIED', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  const r = checkAuthority(canonicalOk, idRes, 'write_vault', {
    required_permission: 'write_vault'
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.PERMISSION_DENIED);
  assert.strictEqual(r.threat, false);
});

check('participant action without required_permission → DENY', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  const r = checkAuthority(canonicalOk, idRes, 'advise');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.PERMISSION_DENIED);
});

check('participant mismatched capability cannot authorize action → DENY', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  const r = checkAuthority(canonicalOk, idRes, 'write_vault', {
    required_permission: 'advise'
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.PERMISSION_DENIED);
});

check('participant wildcard permission cannot authorize action → DENY', () => {
  const wildcard = Object.freeze({
    ...participant,
    identity_id: 'part_wildcard',
    permission_set: Object.freeze(['*'])
  });
  const r = checkAuthority(canonicalOk, { allowed: true, identity: wildcard }, 'delete_vault', {
    required_permission: 'delete_vault'
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, AUTHORITY_REASON.PERMISSION_DENIED);
});

// ---------------------------------------------------------------------------
// NEGATIVE: owner mismatch with canonical state → DENY
// ---------------------------------------------------------------------------
check('owner id mismatch vs canonical state → DENY', () => {
  const other = createOwnerIdentity('NotOwner');
  const reg2 = createIdentityRegistry();
  reg2.register(other);
  const r = reg2.resolve(canonicalOk, 'NotOwner');
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, IDENTITY_REASON.MALFORMED_IDENTITY);
  assert.strictEqual(r.threat, true);
});

// ---------------------------------------------------------------------------
// POSITIVE
// ---------------------------------------------------------------------------
check('valid owner resolve → ALLOW', () => {
  const r = registry.resolve(canonicalOk, 'Appel420');
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, IDENTITY_REASON.VALID);
  assert.strictEqual(r.identity.kind, IDENTITY_KIND.OWNER);
  assert.strictEqual(r.threat, false);
});

check('owner root action → ALLOW', () => {
  const idRes = registry.resolve(canonicalOk, 'Appel420');
  const r = checkAuthority(canonicalOk, idRes, 'grant_root');
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, AUTHORITY_REASON.ALLOWED);
  assert.strictEqual(r.threat, false);
});

check('participant allowed permission → ALLOW', () => {
  const idRes = registry.resolve(canonicalOk, participant.identity_id);
  const r = checkAuthority(canonicalOk, idRes, 'advise', {
    required_permission: 'advise'
  });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.reason, AUTHORITY_REASON.ALLOWED);
  assert.strictEqual(r.kind, IDENTITY_KIND.PARTICIPANT);
});

check('participant is never root via assertNotRootEscalation', () => {
  const r = assertNotRootEscalation(participant);
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(participant.is_root, false);
});

// cleanup
try {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
} catch {
  // ignore
}

if (failures > 0) {
  console.error('\n' + failures + ' failure(s)');
  process.exit(1);
}
console.log('\nAll identity + authority gate tests passed.');
process.exit(0);
