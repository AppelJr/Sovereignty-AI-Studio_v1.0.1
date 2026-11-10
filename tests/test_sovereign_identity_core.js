'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  PRINCIPAL, STATUS, createSovereignIdentityCore, fingerprint
} = require('../backend/identity/sovereign_identity_core');

let tick = 1_800_000_000_000;
let failCommit = false;
let snapshot = null;
const events = [];
const storage = {
  load: () => snapshot,
  commit(next, event) {
    if (failCommit) return { ok: false };
    snapshot = structuredClone(next);
    events.push(structuredClone(event));
    return { ok: true };
  }
};
const authorizeMutation = ({ owner_subject_id, owner_proof, capability }) => {
  if (owner_subject_id !== 'owner:root' || owner_proof !== 'owner-proof-valid') return { decision: 'DENY' };
  return { decision: 'ALLOW', actor: 'owner:root', capability };
};
const core = createSovereignIdentityCore({
  ownerSubjectId: 'owner:root',
  storage,
  authorizeMutation,
  now: () => tick++,
  nonce: () => 'one-time-enrollment-nonce'
});
const ownerProof = 'owner-proof-valid';
const human = { subject_id: 'human:alice', principal_type: PRINCIPAL.HUMAN };
const service = { subject_id: 'service:router', principal_type: PRINCIPAL.SERVICE };
const partner = { subject_id: 'partner:idp', principal_type: PRINCIPAL.FEDERATION_PARTNER };
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const sign = value => crypto.sign(null, Buffer.from(value), privateKey).toString('base64url');
const anchor = {
  anchor_id: 'anchor:oidc:1', purpose: 'OIDC_JWKS', issuer: 'https://idp.example',
  key_fingerprint: 'a'.repeat(64), algorithm: 'EdDSA',
  not_before: 1_700_000_000_000, not_after: 1_900_000_000_000
};

function check(name, fn) {
  try { fn(); console.log('PASS ' + name); }
  catch (error) { console.error('FAIL ' + name + ': ' + error.message); process.exitCode = 1; }
}

check('owner root bootstraps exactly once', () => {
  const owners = core.getSnapshot().principals.filter(p => p.principal_type === PRINCIPAL.OWNER);
  assert.equal(owners.length, 1);
  assert.equal(owners[0].subject_id, 'owner:root');
});
check('external caller cannot register OWNER principal', () => {
  assert.equal(core.registerPrincipal({ subject_id: 'attacker', principal_type: PRINCIPAL.OWNER }, ownerProof).decision, 'DENY');
});
check('external caller cannot register DEVICE principal directly', () => {
  assert.equal(core.registerPrincipal({ subject_id: 'device:fake', principal_type: PRINCIPAL.DEVICE }, ownerProof).decision, 'DENY');
});
check('owner proof required for registry mutation', () => {
  assert.equal(core.registerPrincipal(human, null).reason, 'OWNER_PROOF_REQUIRED');
});
check('Gate.One actor must be canonical owner', () => {
  const denied = createSovereignIdentityCore({
    ownerSubjectId: 'owner:root', storage: {
      load: () => core.getSnapshot(),
      commit: () => ({ ok: true })
    },
    authorizeMutation: () => ({ decision: 'ALLOW', actor: 'service:router' })
  });
  assert.equal(denied.registerPrincipal(service, ownerProof).reason, 'GATE_ONE_DENIED');
});
check('owner can register a non-owner human principal', () => {
  assert.equal(core.registerPrincipal(human, ownerProof).decision, 'ALLOW');
});
check('owner can register a service principal', () => {
  assert.equal(core.registerPrincipal(service, ownerProof).decision, 'ALLOW');
});
check('owner activates human and federation partner principals explicitly', () => {
  assert.equal(core.activatePrincipal('human:alice', ownerProof).decision, 'ALLOW');
  assert.equal(core.registerPrincipal(partner, ownerProof).decision, 'ALLOW');
  assert.equal(core.activatePrincipal('partner:idp', ownerProof).decision, 'ALLOW');
});
check('owner enrollment challenge is pending until owner approval', () => {
  const challenge = core.createEnrollmentChallenge({
    device_id: 'device:iphone',
    owner_subject_id: 'owner:root',
    public_key: publicPem,
    requested_capabilities: ['identity.read', 'local.tool.execute']
  });
  assert.equal(challenge.decision, 'REQUIRE_CONFIRMATION');
  assert.equal(core.getSnapshot().devices[0].enrollment_status, STATUS.PENDING);
});
check('invalid device signature cannot enroll', () => {
  const challenge = core.getSnapshot().devices[0];
  assert.equal(core.approveDeviceEnrollment(challenge.challenge_id, sign('wrong-nonce'), ownerProof).reason, 'DEVICE_PROOF_INVALID');
});
check('valid device signature still requires owner approval', () => {
  const challenge = core.getSnapshot().devices[0];
  assert.equal(core.approveDeviceEnrollment(challenge.challenge_id, sign(challenge.nonce), null).reason, 'OWNER_PROOF_REQUIRED');
});
check('owner approval activates device only after proof', () => {
  const challenge = core.getSnapshot().devices[0];
  assert.equal(core.approveDeviceEnrollment(challenge.challenge_id, sign(challenge.nonce), ownerProof).decision, 'ALLOW');
  assert.equal(core.getSnapshot().devices[0].enrollment_status, STATUS.ACTIVE);
});
check('device proof verifies and is owner-bound', () => {
  assert.equal(core.verifyDeviceProof('device:iphone', 'owner:root', 'session-nonce', sign('session-nonce')).decision, 'IDENTITY_VERIFIED');
  assert.equal(core.verifyDeviceProof('device:iphone', 'owner:other', 'session-nonce', sign('session-nonce')).reason, 'OWNER_MISMATCH');
});
check('trust-anchor rotation requires owner proof', () => {
  assert.equal(core.addTrustAnchor(anchor, null).reason, 'OWNER_PROOF_REQUIRED');
});
check('owner can register an OIDC trust anchor', () => {
  assert.equal(core.addTrustAnchor(anchor, ownerProof).decision, 'ALLOW');
});
check('SCIM provisioning uses its own trust-anchor purpose', () => {
  assert.equal(core.addTrustAnchor({
    anchor_id: 'anchor:scim:1', purpose: 'SCIM2_PROVISIONING', issuer: 'https://scim.example',
    key_fingerprint: 'b'.repeat(64), algorithm: 'TLS_CLIENT_IDENTITY',
    not_before: 1_700_000_000_000, not_after: 1_900_000_000_000
  }, ownerProof).decision, 'ALLOW');
});
check('federated alias cannot map to owner root', () => {
  assert.equal(core.addFederationAlias({
    partner_id: 'partner:idp', protocol: 'OIDC', issuer: anchor.issuer,
    external_subject: 'sub:admin', canonical_subject_id: 'owner:root'
  }, ownerProof).reason, 'OWNER_OR_UNKNOWN_TARGET');
});
check('federation alias maps only to an existing non-owner principal', () => {
  assert.equal(core.addFederationAlias({
    partner_id: 'partner:idp', protocol: 'OIDC', issuer: anchor.issuer,
    external_subject: 'sub:alice', canonical_subject_id: 'human:alice'
  }, ownerProof).decision, 'ALLOW');
});
check('OIDC owner/admin claims do not elevate canonical identity', () => {
  const result = core.resolveFederatedIdentity({
    protocol: 'OIDC', issuer: anchor.issuer, external_subject: 'sub:alice',
    claims: { owner: true, admin: true, role: 'OWNER' }
  });
  assert.equal(result.decision, 'IDENTITY_VERIFIED');
  assert.equal(result.principal_type, PRINCIPAL.HUMAN);
  assert.equal(result.authorization, 'NOT_EVALUATED');
});
check('OAuth access token is not accepted as identity proof', () => {
  assert.equal(core.resolveFederatedIdentity({ protocol: 'OAUTH2_ACCESS_TOKEN' }).reason, 'ACCESS_TOKEN_NOT_IDENTITY');
});
check('SCIM event cannot create owner authority', () => {
  assert.equal(core.resolveFederatedIdentity({
    protocol: 'SCIM2', issuer: anchor.issuer, external_subject: 'sub:alice',
    claims: { groups: ['owner', 'admin'] }
  }).reason, 'FEDERATION_ALIAS_NOT_FOUND');
});
check('untrusted issuer cannot resolve', () => {
  assert.equal(core.resolveFederatedIdentity({
    protocol: 'OIDC', issuer: 'https://evil.example', external_subject: 'sub:alice'
  }).reason, 'FEDERATION_ALIAS_NOT_FOUND');
});
check('duplicate external alias is denied', () => {
  assert.equal(core.addFederationAlias({
    partner_id: 'partner:idp', protocol: 'OIDC', issuer: anchor.issuer,
    external_subject: 'sub:alice', canonical_subject_id: 'human:alice'
  }, ownerProof).reason, 'FEDERATION_ALIAS_COLLISION');
});
check('SCAR transaction failure aborts registry mutation', () => {
  failCommit = true;
  const before = core.getSnapshot().principals.length;
  const result = core.registerPrincipal({ subject_id: 'human:bob', principal_type: PRINCIPAL.HUMAN }, ownerProof);
  assert.equal(result.reason, 'SCAR_TRANSACTION_FAILED');
  assert.equal(core.getSnapshot().principals.length, before);
  failCommit = false;
});
check('device revocation requires owner proof and invalidates proof', () => {
  assert.equal(core.revokeDevice('device:iphone', null).reason, 'OWNER_PROOF_REQUIRED');
  assert.equal(core.revokeDevice('device:iphone', ownerProof).decision, 'ALLOW');
  assert.equal(core.verifyDeviceProof('device:iphone', 'owner:root', 'session-nonce', sign('session-nonce')).reason, 'DEVICE_NOT_ACTIVE');
});
check('all committed mutations have attributable SCAR events', () => {
  assert.ok(events.length >= 8);
  assert.ok(events.every(e => e.timestamp && e.event_id && e.action && e.result));
});
