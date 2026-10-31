'use strict';

// Node-side verifier for the existing backend/coordination/session_authorization.py
// proof contract. This verifies the same HMAC-signed local owner session; it
// does not mint sessions or treat caller-supplied identity labels as authority.
const crypto = require('node:crypto');

function decodeBase64Url(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('SESSION_PROOF_INVALID_' + label);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) {
    throw new Error('SESSION_PROOF_INVALID_' + label);
  }
  return decoded;
}

function verifyOwnerSession(proof, canonicalOwnerId, requiredCapability, options = {}) {
  if (typeof proof !== 'string' || proof.length > 8192) {
    throw new Error('OWNER_SESSION_REQUIRED');
  }
  const secret = options.secret || process.env.SOVEREIGN_SESSION_SIGNING_KEY;
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('OWNER_SESSION_VERIFICATION_KEY_UNAVAILABLE');
  }
  const parts = proof.split('.');
  if (parts.length !== 2) throw new Error('SESSION_PROOF_MALFORMED');

  const payloadBytes = decodeBase64Url(parts[0], 'PAYLOAD');
  const signature = decodeBase64Url(parts[1], 'SIGNATURE');
  const expected = crypto.createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(parts[0], 'ascii').digest();
  if (signature.length !== expected.length || !crypto.timingSafeEqual(signature, expected)) {
    throw new Error('SESSION_PROOF_SIGNATURE_INVALID');
  }

  let payload;
  try { payload = JSON.parse(payloadBytes.toString('utf8')); }
  catch { throw new Error('SESSION_PROOF_PAYLOAD_INVALID'); }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('SESSION_PROOF_PAYLOAD_INVALID');
  }
  if (typeof payload.session_id !== 'string' || !payload.session_id ||
      typeof payload.identity_id !== 'string' || !payload.identity_id ||
      !Array.isArray(payload.capabilities) ||
      !['offline', 'hybrid', 'online'].includes(payload.mode) ||
      !Number.isSafeInteger(payload.expires_at)) {
    throw new Error('SESSION_PROOF_CLAIMS_INVALID');
  }
  const now = options.nowSeconds === undefined ? Math.floor(Date.now() / 1000) : options.nowSeconds;
  if (payload.expires_at <= now) throw new Error('SESSION_PROOF_EXPIRED');
  if (payload.identity_id !== canonicalOwnerId) throw new Error('OWNER_IDENTITY_MISMATCH');
  if (requiredCapability && !payload.capabilities.includes(requiredCapability)) {
    throw new Error('OWNER_CAPABILITY_MISSING');
  }

  return Object.freeze({
    session_id: payload.session_id,
    identity_id: payload.identity_id,
    capabilities: Object.freeze(payload.capabilities.map(String)),
    branch: typeof payload.branch === 'string' ? payload.branch : null,
    mode: payload.mode,
    expires_at: payload.expires_at
  });
}

module.exports = { verifyOwnerSession };
