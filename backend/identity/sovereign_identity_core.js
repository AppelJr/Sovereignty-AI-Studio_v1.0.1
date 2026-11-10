'use strict';

/**
 * Sovereignty Identity Core — Stage 1.
 *
 * No protocol parsing, token issuance, action execution, or Gate.One decision
 * implementation lives here. External protocol adapters supply validated
 * federation metadata; Gate.One remains the independent authorization point.
 *
 * Persistence contract:
 *   storage.load() -> snapshot
 *   storage.commit(snapshot, scarEvent) -> { ok: true } only when BOTH the
 *   state transition and its SCAR event are durably committed as one logical
 *   transaction. A non-transactional adapter is not production-safe.
 */
const crypto = require('node:crypto');

const PRINCIPAL = Object.freeze({
  OWNER: 'OWNER',
  HUMAN: 'HUMAN',
  DEVICE: 'DEVICE',
  SERVICE: 'SERVICE',
  FEDERATION_PARTNER: 'FEDERATION_PARTNER'
});
const STATUS = Object.freeze({
  PENDING: 'PENDING',
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  REVOKED: 'REVOKED'
});
const PROTOCOLS = new Set(['SAML2', 'OIDC', 'SCIM2']);
const ANCHOR_PURPOSE = Object.freeze({ SAML2: 'SAML2_SIGNING', OIDC: 'OIDC_JWKS', SCIM2: 'SCIM2_PROVISIONING' });
const ZERO_HASH = '0'.repeat(64);

function fail(reason, extra = {}) {
  return { decision: 'DENY', reason, ...extra };
}
function clone(value) {
  return structuredClone(value);
}
function fingerprint(publicKey) {
  const key = crypto.createPublicKey(publicKey);
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}
function verifySignature(publicKey, message, signature) {
  const key = crypto.createPublicKey(publicKey);
  const type = key.asymmetricKeyType;
  const algorithm = type === 'ed25519' || type === 'ed448' ? null : 'sha256';
  return crypto.verify(algorithm, Buffer.from(message), key, Buffer.from(signature, 'base64url'));
}
function emptyState(ownerSubjectId) {
  return {
    version: 1,
    owner_subject_id: ownerSubjectId,
    principals: [{
      subject_id: ownerSubjectId,
      principal_type: PRINCIPAL.OWNER,
      status: STATUS.ACTIVE,
      created_at: Date.now(),
      updated_at: Date.now(),
      owner_root_ref: ownerSubjectId,
      assurance_level: 'OWNER_ROOT',
      attributes_hash: ZERO_HASH,
      registry_version: 1
    }],
    devices: [],
    trust_anchors: [],
    federation_aliases: [],
    used_nonces: []
  };
}

function createSovereignIdentityCore(options = {}) {
  const { ownerSubjectId, storage, authorizeMutation, now = () => Date.now(), nonce = () => crypto.randomBytes(32).toString('base64url') } = options;
  if (typeof ownerSubjectId !== 'string' || !ownerSubjectId.trim()) throw new TypeError('ownerSubjectId required');
  if (!storage || typeof storage.load !== 'function' || typeof storage.commit !== 'function') {
    throw new TypeError('transactional storage.load/commit adapter required');
  }
  if (typeof authorizeMutation !== 'function') throw new TypeError('Gate.One authorizeMutation adapter required');

  let state = storage.load();
  if (!state) {
    state = emptyState(ownerSubjectId);
    const seeded = storage.commit(clone(state), {
      event_type: 'IDENTITY_OWNER_ROOT_BOOTSTRAPPED',
      actor: 'LOCAL_BOOTSTRAP',
      subject_id: ownerSubjectId,
      result: 'INITIALIZED',
      timestamp: now()
    });
    if (!seeded || seeded.ok !== true) throw new Error('owner root bootstrap evidence transaction failed');
  }
  if (state.owner_subject_id !== ownerSubjectId ||
      !Array.isArray(state.principals) ||
      state.principals.filter(p => p.principal_type === PRINCIPAL.OWNER).length !== 1 ||
      !state.principals.some(p => p.subject_id === ownerSubjectId && p.principal_type === PRINCIPAL.OWNER && p.status === STATUS.ACTIVE)) {
    throw new Error('canonical owner-root state invalid; refusing startup');
  }

  function principal(subjectId) {
    return state.principals.find(p => p.subject_id === subjectId) || null;
  }
  function gate(ownerProof, capability, action) {
    if (!ownerProof) return fail('OWNER_PROOF_REQUIRED');
    let result;
    try {
      result = authorizeMutation({
        owner_subject_id: ownerSubjectId,
        owner_proof: ownerProof,
        capability,
        action
      });
    } catch {
      return fail('GATE_ONE_UNAVAILABLE');
    }
    if (!result || result.decision !== 'ALLOW' || result.actor !== ownerSubjectId) {
      return fail('GATE_ONE_DENIED');
    }
    return { decision: 'ALLOW', authorization_id: result.authorization_id || null };
  }
  function commit(next, event) {
    try {
      const result = storage.commit(clone(next), {
        event_id: crypto.randomUUID(),
        timestamp: now(),
        actor: event.actor || ownerSubjectId,
        ...event
      });
      if (!result || result.ok !== true) return fail('SCAR_TRANSACTION_FAILED');
      state = next;
      return { decision: 'ALLOW', result: 'COMMITTED' };
    } catch {
      return fail('SCAR_TRANSACTION_FAILED');
    }
  }
  function recordFailure(action, reason, details = {}) {
    try {
      const result = storage.commit(clone(state), {
        event_id: crypto.randomUUID(),
        timestamp: now(),
        actor: 'IDENTITY_CORE',
        action,
        result: 'DENY',
        reason,
        details
      });
      return result && result.ok === true;
    } catch {
      return false;
    }
  }

  function registerPrincipal(fields, ownerProof) {
    if (!fields || typeof fields.subject_id !== 'string' || !fields.subject_id.trim() ||
        !Object.values(PRINCIPAL).includes(fields.principal_type) ||
        fields.principal_type === PRINCIPAL.OWNER ||
        fields.principal_type === PRINCIPAL.DEVICE) {
      recordFailure('PRINCIPAL_REGISTER', 'INVALID_OR_FORBIDDEN_PRINCIPAL');
      return fail('INVALID_OR_FORBIDDEN_PRINCIPAL');
    }
    const auth = gate(ownerProof, 'identity.principal.register', 'PRINCIPAL_REGISTER');
    if (auth.decision !== 'ALLOW') return auth;
    if (principal(fields.subject_id)) return fail('SUBJECT_ALREADY_EXISTS');
    const next = clone(state);
    next.principals.push({
      subject_id: fields.subject_id,
      principal_type: fields.principal_type,
      status: STATUS.PENDING,
      created_at: now(),
      updated_at: now(),
      owner_root_ref: null,
      assurance_level: fields.assurance_level || 'UNVERIFIED',
      attributes_hash: fields.attributes_hash || ZERO_HASH,
      registry_version: state.version + 1
    });
    next.version += 1;
    return commit(next, {
      action: 'PRINCIPAL_REGISTER',
      subject_id: fields.subject_id,
      principal_type: fields.principal_type,
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      authorization_id: auth.authorization_id,
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['identity_registry']
    });
  }

  function activatePrincipal(subjectId, ownerProof) {
    const existing = principal(subjectId);
    if (!existing || existing.status !== STATUS.PENDING) return fail('PRINCIPAL_NOT_PENDING');
    const auth = gate(ownerProof, 'identity.principal.activate', 'PRINCIPAL_ACTIVATE');
    if (auth.decision !== 'ALLOW') return auth;
    const next = clone(state);
    const target = next.principals.find(p => p.subject_id === subjectId);
    target.status = STATUS.ACTIVE;
    target.updated_at = now();
    target.registry_version = state.version + 1;
    next.version += 1;
    return commit(next, {
      action: 'PRINCIPAL_ACTIVATED',
      subject_id: subjectId,
      principal_type: target.principal_type,
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      authorization_id: auth.authorization_id,
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['identity_registry']
    });
  }

  function createEnrollmentChallenge(input) {
    if (!input || typeof input.device_id !== 'string' || !input.device_id ||
        typeof input.public_key !== 'string' || !input.public_key ||
        input.owner_subject_id !== ownerSubjectId ||
        !Array.isArray(input.requested_capabilities) ||
        input.requested_capabilities.some(x => typeof x !== 'string' || !x)) {
      recordFailure('DEVICE_ENROLLMENT_CHALLENGE', 'INVALID_ENROLLMENT_REQUEST');
      return fail('INVALID_ENROLLMENT_REQUEST');
    }
    let keyFingerprint;
    try { keyFingerprint = fingerprint(input.public_key); } catch { return fail('INVALID_DEVICE_PUBLIC_KEY'); }
    if (state.devices.some(d => d.device_id === input.device_id) ||
        state.devices.some(d => d.public_key_fingerprint === keyFingerprint)) return fail('DEVICE_ALREADY_REGISTERED');
    const challenge = {
      challenge_id: crypto.randomUUID(),
      device_id: input.device_id,
      owner_subject_id: ownerSubjectId,
      public_key: input.public_key,
      public_key_fingerprint: keyFingerprint,
      key_algorithm: crypto.createPublicKey(input.public_key).asymmetricKeyType,
      requested_capabilities: [...new Set(input.requested_capabilities)].sort(),
      nonce: nonce(),
      expires_at: now() + Math.min(Math.max(input.ttl_ms || 300000, 1000), 300000),
      status: STATUS.PENDING
    };
    const next = clone(state);
    next.devices.push({
      ...challenge,
      public_key: input.public_key,
      attestation_ref: null,
      enrollment_status: STATUS.PENDING,
      enrolled_at: null,
      revoked_at: null,
      assurance_level: input.hardware_backed === true ? 'HARDWARE_ASSERTED_UNVERIFIED' : 'SOFTWARE_KEY'
    });
    next.version += 1;
    const result = commit(next, {
      action: 'DEVICE_ENROLLMENT_CHALLENGE',
      subject_id: input.device_id,
      device_id: input.device_id,
      result: 'PENDING',
      reason: 'OWNER_APPROVAL_REQUIRED',
      authorization: 'CHALLENGE_ONLY',
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['device_registry']
    });
    if (result.decision !== 'ALLOW') return result;
    return {
      decision: 'REQUIRE_CONFIRMATION',
      challenge_id: challenge.challenge_id,
      nonce: challenge.nonce,
      expires_at: challenge.expires_at,
      public_key_fingerprint: keyFingerprint
    };
  }

  function approveDeviceEnrollment(challengeId, deviceSignature, ownerProof) {
    const device = state.devices.find(d => d.challenge_id === challengeId);
    if (!device || device.enrollment_status !== STATUS.PENDING) return fail('CHALLENGE_UNKNOWN_OR_CONSUMED');
    if (device.expires_at <= now()) {
      recordFailure('DEVICE_ENROLLMENT_APPROVAL', 'CHALLENGE_EXPIRED', { device_id: device.device_id });
      return fail('CHALLENGE_EXPIRED');
    }
    if (device.owner_subject_id !== ownerSubjectId) return fail('OWNER_MISMATCH');
    let valid = false;
    try { valid = verifySignature(device.public_key, device.nonce, deviceSignature); } catch {}
    if (!valid) {
      recordFailure('DEVICE_ENROLLMENT_APPROVAL', 'DEVICE_PROOF_INVALID', { device_id: device.device_id });
      return fail('DEVICE_PROOF_INVALID');
    }
    const auth = gate(ownerProof, 'identity.device.enroll', 'DEVICE_ENROLLMENT_APPROVAL');
    if (auth.decision !== 'ALLOW') return auth;
    const next = clone(state);
    const target = next.devices.find(d => d.challenge_id === challengeId);
    target.enrollment_status = STATUS.ACTIVE;
    target.status = STATUS.ACTIVE;
    next.principals.push({
      subject_id: target.device_id,
      principal_type: PRINCIPAL.DEVICE,
      status: STATUS.ACTIVE,
      created_at: now(),
      updated_at: now(),
      owner_root_ref: ownerSubjectId,
      assurance_level: target.assurance_level,
      attributes_hash: target.public_key_fingerprint,
      registry_version: state.version + 1
    });
    target.enrolled_at = now();
    target.nonce = null;
    target.challenge_id = null;
    next.version += 1;
    return commit(next, {
      action: 'DEVICE_ENROLLMENT_APPROVED',
      subject_id: device.device_id,
      device_id: device.device_id,
      public_key_fingerprint: device.public_key_fingerprint,
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['device_registry']
    });
  }

  function verifyDeviceProof(deviceId, ownerSubject, message, signature) {
    const device = state.devices.find(d => d.device_id === deviceId);
    if (!device || device.enrollment_status !== STATUS.ACTIVE || device.status !== STATUS.ACTIVE) {
      recordFailure('DEVICE_PROOF_VERIFY', 'DEVICE_NOT_ACTIVE', { device_id: deviceId });
      return fail('DEVICE_NOT_ACTIVE');
    }
    if (ownerSubject !== device.owner_subject_id || ownerSubject !== ownerSubjectId) {
      recordFailure('DEVICE_PROOF_VERIFY', 'OWNER_MISMATCH', { device_id: deviceId });
      return fail('OWNER_MISMATCH');
    }
    try {
      if (!verifySignature(device.public_key, message, signature)) {
        recordFailure('DEVICE_PROOF_VERIFY', 'DEVICE_SIGNATURE_INVALID', { device_id: deviceId });
        return fail('DEVICE_SIGNATURE_INVALID');
      }
    } catch {
      recordFailure('DEVICE_PROOF_VERIFY', 'DEVICE_SIGNATURE_INVALID', { device_id: deviceId });
      return fail('DEVICE_SIGNATURE_INVALID');
    }
    return {
      decision: 'IDENTITY_VERIFIED',
      subject_id: ownerSubject,
      device_id: deviceId,
      public_key_fingerprint: device.public_key_fingerprint,
      assurance_level: device.assurance_level
    };
  }

  function revokeDevice(deviceId, ownerProof) {
    const device = state.devices.find(d => d.device_id === deviceId);
    if (!device || device.enrollment_status === STATUS.REVOKED) return fail('DEVICE_UNKNOWN_OR_REVOKED');
    const auth = gate(ownerProof, 'identity.device.revoke', 'DEVICE_REVOKE');
    if (auth.decision !== 'ALLOW') return auth;
    const next = clone(state);
    const target = next.devices.find(d => d.device_id === deviceId);
    target.status = STATUS.REVOKED;
    target.enrollment_status = STATUS.REVOKED;
    target.revoked_at = now();
    target.nonce = null;
    next.version += 1;
    return commit(next, {
      action: 'DEVICE_REVOKED',
      subject_id: deviceId,
      device_id: deviceId,
      public_key_fingerprint: device.public_key_fingerprint,
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['device_registry']
    });
  }

  function addTrustAnchor(anchor, ownerProof) {
    if (!anchor || typeof anchor.anchor_id !== 'string' || !anchor.anchor_id ||
        typeof anchor.issuer !== 'string' || !anchor.issuer ||
        typeof anchor.key_fingerprint !== 'string' || !/^[a-f0-9]{64}$/i.test(anchor.key_fingerprint) ||
        !['SAML2_SIGNING', 'OIDC_JWKS'].includes(anchor.purpose) ||
        !Number.isFinite(anchor.not_before) || !Number.isFinite(anchor.not_after) ||
        anchor.not_after <= anchor.not_before) {
      recordFailure('TRUST_ANCHOR_ADD', 'INVALID_TRUST_ANCHOR');
      return fail('INVALID_TRUST_ANCHOR');
    }
    const auth = gate(ownerProof, 'identity.trust_anchor.manage', 'TRUST_ANCHOR_ADD');
    if (auth.decision !== 'ALLOW') return auth;
    if (state.trust_anchors.some(a => a.anchor_id === anchor.anchor_id)) return fail('ANCHOR_ID_EXISTS');
    if (anchor.predecessor_anchor_id &&
        !state.trust_anchors.some(a => a.anchor_id === anchor.predecessor_anchor_id && a.status === STATUS.ACTIVE)) {
      return fail('ROTATION_PREDECESSOR_INVALID');
    }
    const next = clone(state);
    next.trust_anchors.push({
      anchor_id: anchor.anchor_id,
      purpose: anchor.purpose,
      issuer: anchor.issuer,
      key_fingerprint: anchor.key_fingerprint.toLowerCase(),
      algorithm: anchor.algorithm || 'UNSPECIFIED',
      not_before: anchor.not_before,
      not_after: anchor.not_after,
      status: STATUS.ACTIVE,
      version: next.trust_anchors.length + 1,
      predecessor_anchor_id: anchor.predecessor_anchor_id || null,
      approved_by_owner_proof_id: auth.authorization_id
    });
    next.version += 1;
    return commit(next, {
      action: 'TRUST_ANCHOR_ADDED',
      trust_anchor_id: anchor.anchor_id,
      issuer: anchor.issuer,
      key_fingerprint: anchor.key_fingerprint.toLowerCase(),
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['trust_anchor_registry']
    });
  }

  function addFederationAlias(alias, ownerProof) {
    if (!alias || !PROTOCOLS.has(alias.protocol) ||
        typeof alias.partner_id !== 'string' || !alias.partner_id ||
        typeof alias.issuer !== 'string' || !alias.issuer ||
        typeof alias.external_subject !== 'string' || !alias.external_subject ||
        typeof alias.canonical_subject_id !== 'string' || !alias.canonical_subject_id) {
      recordFailure('FEDERATION_ALIAS_ADD', 'INVALID_FEDERATION_ALIAS');
      return fail('INVALID_FEDERATION_ALIAS');
    }
    const auth = gate(ownerProof, 'identity.federation_alias.manage', 'FEDERATION_ALIAS_ADD');
    if (auth.decision !== 'ALLOW') return auth;
    const anchor = state.trust_anchors.find(a =>
      a.issuer === alias.issuer && a.status === STATUS.ACTIVE &&
      a.purpose === ANCHOR_PURPOSE[alias.protocol] &&
      a.not_before <= now() && a.not_after > now()
    );
    if (!anchor) {
      recordFailure('FEDERATION_ALIAS_ADD', 'UNTRUSTED_ISSUER', { issuer: alias.issuer });
      return fail('UNTRUSTED_ISSUER');
    }
    const partner = principal(alias.partner_id);
    if (!partner || partner.status !== STATUS.ACTIVE || partner.principal_type !== PRINCIPAL.FEDERATION_PARTNER) {
      recordFailure('FEDERATION_ALIAS_ADD', 'FEDERATION_PARTNER_NOT_ACTIVE', { partner_id: alias.partner_id });
      return fail('FEDERATION_PARTNER_NOT_ACTIVE');
    }
    const target = principal(alias.canonical_subject_id);
    if (!target || target.status !== STATUS.ACTIVE || target.principal_type === PRINCIPAL.OWNER) {
      recordFailure('FEDERATION_ALIAS_ADD', 'OWNER_OR_UNKNOWN_TARGET', { canonical_subject_id: alias.canonical_subject_id });
      return fail('OWNER_OR_UNKNOWN_TARGET');
    }
    if (state.federation_aliases.some(a =>
      a.protocol === alias.protocol && a.issuer === alias.issuer && a.external_subject === alias.external_subject
    )) return fail('FEDERATION_ALIAS_COLLISION');
    const next = clone(state);
    next.federation_aliases.push({
      partner_id: alias.partner_id,
      protocol: alias.protocol,
      issuer: alias.issuer,
      external_subject: alias.external_subject,
      canonical_subject_id: alias.canonical_subject_id,
      mapping_status: STATUS.ACTIVE,
      created_at: now(),
      last_verified_at: null
    });
    next.version += 1;
    return commit(next, {
      action: 'FEDERATION_ALIAS_ADDED',
      subject_id: alias.canonical_subject_id,
      trust_anchor_id: anchor.anchor_id,
      protocol: alias.protocol,
      issuer: alias.issuer,
      result: 'ALLOW',
      authorization: 'GATE_ONE_ALLOW',
      authorization_id: auth.authorization_id,
      memory_loaded: false,
      network_accessed: false,
      files_changed: ['federation_alias_registry']
    });
  }

  function resolveFederatedIdentity(assertion) {
    if (!assertion || assertion.protocol === 'OAUTH2_ACCESS_TOKEN') {
      recordFailure('FEDERATION_RESOLVE', 'ACCESS_TOKEN_NOT_IDENTITY');
      return fail('ACCESS_TOKEN_NOT_IDENTITY');
    }
    if (!PROTOCOLS.has(assertion.protocol)) return fail('UNSUPPORTED_OR_UNTRUSTED_PROTOCOL');
    const alias = state.federation_aliases.find(a =>
      a.protocol === assertion.protocol &&
      a.issuer === assertion.issuer &&
      a.external_subject === assertion.external_subject &&
      a.mapping_status === STATUS.ACTIVE
    );
    if (!alias) {
      recordFailure('FEDERATION_RESOLVE', 'FEDERATION_ALIAS_NOT_FOUND');
      return fail('FEDERATION_ALIAS_NOT_FOUND');
    }
    const target = principal(alias.canonical_subject_id);
    if (!target || target.status !== STATUS.ACTIVE || target.principal_type === PRINCIPAL.OWNER) {
      recordFailure('FEDERATION_RESOLVE', 'FEDERATED_TARGET_INVALID');
      return fail('FEDERATED_TARGET_INVALID');
    }
    // Ignore owner/admin/root/group/role claims. Identity resolution never authorizes.
    return {
      decision: 'IDENTITY_VERIFIED',
      subject_id: target.subject_id,
      principal_type: target.principal_type,
      federation: {
        partner_id: alias.partner_id,
        protocol: alias.protocol,
        issuer: alias.issuer
      },
      authorization: 'NOT_EVALUATED',
      gate_one_required: true
    };
  }

  function getSnapshot() {
    return clone(state);
  }

  return Object.freeze({
    PRINCIPAL,
    STATUS,
    registerPrincipal,
    activatePrincipal,
    createEnrollmentChallenge,
    approveDeviceEnrollment,
    verifyDeviceProof,
    revokeDevice,
    addTrustAnchor,
    addFederationAlias,
    resolveFederatedIdentity,
    getSnapshot
  });
}

module.exports = {
  PRINCIPAL,
  STATUS,
  ANCHOR_PURPOSE,
  createSovereignIdentityCore,
  fingerprint
};
