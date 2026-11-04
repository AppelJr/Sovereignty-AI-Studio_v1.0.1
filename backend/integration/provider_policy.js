'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_PATH = path.resolve(process.env.SOVEREIGN_PROVIDER_POLICY_PATH ||
  path.join(__dirname, '..', '..', 'config', 'provider-policy.v1.1.json'));
const KNOWN = new Set(['xai', 'local', 'openai', 'anthropic', 'custom', 'google', 'meta', 'mistral']);

function validatePolicy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.policy_version !== '1.1.0' ||
      value.unknown_provider !== 'DENY' ||
      !Array.isArray(value.default_allow) ||
      !Array.isArray(value.default_block) ||
      !value.providers || typeof value.providers !== 'object' ||
      !Array.isArray(value.custom_endpoint_allowlist) ||
      !Array.isArray(value.blocked_providers)) {
    throw new Error('PROVIDER_POLICY_INVALID');
  }
  for (const id of [...value.default_allow, ...value.default_block, ...value.blocked_providers]) {
    if (typeof id !== 'string' || !KNOWN.has(id)) throw new Error('PROVIDER_POLICY_UNKNOWN_ID');
  }
  for (const [id, entry] of Object.entries(value.providers)) {
    if (!KNOWN.has(id) || !entry || !['ALLOW', 'BLOCK'].includes(entry.decision)) {
      throw new Error('PROVIDER_POLICY_ENTRY_INVALID');
    }
  }
  for (const endpoint of value.custom_endpoint_allowlist) {
    let url;
    try { url = new URL(endpoint); } catch { throw new Error('PROVIDER_POLICY_ENDPOINT_INVALID'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
      throw new Error('PROVIDER_POLICY_ENDPOINT_MUST_BE_HTTPS');
    }
  }
  return value;
}

function loadPolicy(policyPath = DEFAULT_PATH) {
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(policyPath, 'utf8')); }
  catch { throw new Error('PROVIDER_POLICY_MISSING_OR_UNREADABLE'); }
  return validatePolicy(parsed);
}

function decideProvider(provider, policyPath = DEFAULT_PATH) {
  const id = typeof provider === 'string' ? provider.trim().toLowerCase() : '';
  if (!KNOWN.has(id)) return Object.freeze({ decision: 'DENY', reason: 'UNKNOWN_PROVIDER' });
  const policy = loadPolicy(policyPath);
  if (policy.default_block.includes(id) || policy.blocked_providers.includes(id)) {
    return Object.freeze({ decision: 'DENY', reason: 'OWNER_BLOCKED_PROVIDER', policy_version: policy.policy_version });
  }
  const entry = policy.providers[id];
  if (!entry) return Object.freeze({ decision: 'DENY', reason: 'PROVIDER_NOT_CONFIGURED', policy_version: policy.policy_version });
  if (entry.decision !== 'ALLOW' || !policy.default_allow.includes(id)) {
    return Object.freeze({ decision: 'DENY', reason: 'PROVIDER_NOT_ALLOWED', policy_version: policy.policy_version });
  }
  return Object.freeze({ decision: 'ALLOW', reason: 'POLICY_ALLOWED', policy_version: policy.policy_version });
}

function writePolicy(next, policyPath = DEFAULT_PATH) {
  validatePolicy(next);
  const dir = path.dirname(policyPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = policyPath + '.tmp.' + process.pid;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(next, null, 2) + '\n', 'utf8');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, policyPath);
  try {
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch { /* directory fsync is platform-dependent */ }
  return loadPolicy(policyPath);
}

module.exports = { DEFAULT_PATH, validatePolicy, loadPolicy, decideProvider, writePolicy };
