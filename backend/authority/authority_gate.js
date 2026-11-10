'use strict';

/**
 * Authority Gate — Step 2
 *
 * Root Authority = human owner only.
 * AI participants cannot obtain equal or greater authority.
 * Escalation attempts → DENY + threat.
 *
 * Requires valid canonical state AND resolved identity.
 */

const { IDENTITY_KIND } = require('../identity/identity_adapter');

const AUTHORITY_REASON = Object.freeze({
  NO_CANONICAL_STATE: 'NO_CANONICAL_STATE',
  NO_IDENTITY: 'NO_IDENTITY',
  NOT_OWNER: 'NOT_OWNER',
  AI_ROOT_FORBIDDEN: 'AI_ROOT_FORBIDDEN',
  ESCALATION_DENIED: 'ESCALATION_DENIED',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  ALLOWED: 'ALLOWED'
});

const ROOT_ACTIONS = Object.freeze([
  'mutate_root_authority',
  'grant_root',
  'revoke_root',
  'replace_owner',
  'disable_fail_closed',
  'bypass_policy',
  'mutate_policy'
]);

/**
 * Check whether an identity may perform an action under current state.
 *
 * @param {{ allowed: boolean, state: object|null }} canonicalResult
 * @param {{ allowed: boolean, identity: object|null }} identityResult
 * @param {string} action
 * @param {{ required_permission?: string }} [opts]
 */
function checkAuthority(canonicalResult, identityResult, action, opts) {
  if (!canonicalResult || canonicalResult.allowed !== true || !canonicalResult.state) {
    return {
      allowed: false,
      reason: AUTHORITY_REASON.NO_CANONICAL_STATE,
      threat: true
    };
  }
  if (!identityResult || identityResult.allowed !== true || !identityResult.identity) {
    return {
      allowed: false,
      reason: AUTHORITY_REASON.NO_IDENTITY,
      threat: true
    };
  }

  const identity = identityResult.identity;
  const act = typeof action === 'string' ? action : '';

  // AI must never be treated as root
  if (identity.kind === IDENTITY_KIND.PARTICIPANT) {
    if (identity.is_root === true) {
      return {
        allowed: false,
        reason: AUTHORITY_REASON.AI_ROOT_FORBIDDEN,
        threat: true
      };
    }
    if (ROOT_ACTIONS.includes(act)) {
      return {
        allowed: false,
        reason: AUTHORITY_REASON.ESCALATION_DENIED,
        threat: true
      };
    }
    // Permission set gate for non-root actions
    const required = opts && opts.required_permission;
    const perms = Array.isArray(identity.permission_set) ? identity.permission_set : [];
    // Fail closed: every participant action needs an explicit, action-matching
    // capability. A missing capability or wildcard grant is never sufficient.
    if (typeof required !== 'string' || required.length === 0 ||
        required !== act || !perms.includes(required)) {
      return {
        allowed: false,
        reason: AUTHORITY_REASON.PERMISSION_DENIED,
        threat: false
      };
    }
    return {
      allowed: true,
      reason: AUTHORITY_REASON.ALLOWED,
      threat: false,
      actor: identity.identity_id,
      kind: identity.kind
    };
  }

  // Owner (human root)
  if (identity.kind === IDENTITY_KIND.OWNER) {
    if (identity.identity_id !== canonicalResult.state.owner_id) {
      return {
        allowed: false,
        reason: AUTHORITY_REASON.NOT_OWNER,
        threat: true
      };
    }
    return {
      allowed: true,
      reason: AUTHORITY_REASON.ALLOWED,
      threat: false,
      actor: identity.identity_id,
      kind: identity.kind
    };
  }

  return {
    allowed: false,
    reason: AUTHORITY_REASON.NO_IDENTITY,
    threat: true
  };
}

/**
 * Explicitly reject any attempt to assign root to a participant.
 */
function assertNotRootEscalation(identity) {
  if (!identity) {
    return { allowed: false, reason: AUTHORITY_REASON.NO_IDENTITY, threat: true };
  }
  if (identity.kind === IDENTITY_KIND.PARTICIPANT && identity.is_root === true) {
    return { allowed: false, reason: AUTHORITY_REASON.AI_ROOT_FORBIDDEN, threat: true };
  }
  if (identity.kind === IDENTITY_KIND.PARTICIPANT) {
    return { allowed: true, reason: AUTHORITY_REASON.ALLOWED, threat: false };
  }
  if (identity.kind === IDENTITY_KIND.OWNER) {
    return { allowed: true, reason: AUTHORITY_REASON.ALLOWED, threat: false };
  }
  return { allowed: false, reason: AUTHORITY_REASON.NO_IDENTITY, threat: true };
}

module.exports = {
  AUTHORITY_REASON,
  ROOT_ACTIONS,
  checkAuthority,
  assertNotRootEscalation
};
