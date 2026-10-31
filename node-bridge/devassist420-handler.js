'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { createSovereigntyPipeline } = require('../backend/integration/sovereignty_pipeline');
const { loadCanonicalState } = require('../backend/state/canonical_state');
const { verifyOwnerSession } = require('../backend/integration/session_proof');
const { loadPolicy, decideProvider, writePolicy } = require('../backend/integration/provider_policy');

const STATE_PATH = process.env.SOVEREIGN_STATE_PATH || path.resolve('state/canonical.json');
const SCAR_PATH = process.env.SCAR_PATH || path.resolve('AUDIT/devassist-device.jsonl');
const PYTHON_WS_URL = process.env.SOVEREIGN_PYTHON_WS_URL || 'ws://127.0.0.1:9897';
const AUTH_TTL_MS = 60 * 1000;
const MAX_TEXT = 10000;
const authorizations = new Map();

const AGREEMENT = Object.freeze({
  protocol: 'devassist420-live-v1',
  authority: 'human-owner',
  orchestrator: 'DevAssist420',
  orchestrator_is_root: false,
  memory: 'permission-only',
  network: 'loopback-only',
  default_decision: 'DENY',
  inference_transport: 'python-websocket-9897',
  provider_policy: 'server-authoritative-v1.1.0'
});

function json(res, status, value) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(value));
}

function normalize(body, ownerId, sessionId) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('REQUEST_OBJECT_REQUIRED');
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  if (!text) throw new Error('TEXT_REQUIRED');
  if (text.length > MAX_TEXT) throw new Error('TEXT_TOO_LONG');
  const provider = typeof body.provider === 'string' ? body.provider.trim().toLowerCase() : 'local';
  return {
    requester_id: ownerId,
    action: typeof body.action === 'string' && body.action.trim() ? body.action.trim() : 'chat',
    prefer: body.prefer === 'external' ? 'external' : 'local',
    provider,
    required_permission: typeof body.required_permission === 'string' ? body.required_permission.trim() || undefined : 'ai.inference',
    text,
    request_id: typeof body.request_id === 'string' && body.request_id ? body.request_id : crypto.randomUUID(),
    session_id: sessionId
  };
}

function pipeline(ownerId) {
  return createSovereigntyPipeline({
    statePath: STATE_PATH, scarPath: SCAR_PATH,
    ownerId, orchestratorId: 'DevAssist420', participants: []
  });
}

function authenticate(proof, canonical, capability = 'ai.inference') {
  if (!canonical.allowed || !canonical.state) throw new Error(canonical.reason || 'CANONICAL_STATE_BLOCKED');
  return verifyOwnerSession(proof, canonical.state.owner_id, capability);
}

function verifiedPipeline(ownerId) {
  const p = pipeline(ownerId);
  const chain = p.scar.verifyChain();
  if (!chain.ok) throw new Error('SCAR_CHAIN_INVALID');
  return p;
}

function recordVerified(p, event) {
  const chain = p.scar.verifyChain();
  if (!chain.ok) throw new Error('SCAR_CHAIN_INVALID');
  return p.record(event);
}

function probePythonWebSocket(timeoutMs = 2000) {
  return new Promise((resolve) => {
    let settled = false;
    const ws = new WebSocket(PYTHON_WS_URL);
    const finish = (online, detail) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws.close(); } catch {}
      resolve({ online, detail });
    };
    const timer = setTimeout(() => finish(false, 'PYTHON_WS_TIMEOUT'), timeoutMs);
    ws.once('open', () => finish(true, 'websocket_connected'));
    ws.once('error', error => finish(false, error && error.message ? error.message : 'PYTHON_WS_ERROR'));
  });
}

function authorize(body, proof) {
  const canonical = loadCanonicalState(STATE_PATH);
  const session = authenticate(proof, canonical, 'ai.inference');
  const request = normalize(body, session.identity_id, session.session_id);
  const providerDecision = decideProvider(request.provider);
  if (providerDecision.decision !== 'ALLOW') {
      const p = verifiedPipeline(session.identity_id);
      const evidence = recordVerified(p, { participant: session.identity_id, action: request.action, result: 'DENY', details: { reason: providerDecision.reason, provider: request.provider, policy_version: providerDecision.policy_version || null } });
      return { state: 'DENY', reason: providerDecision.reason, request, evidence, agreement: AGREEMENT };
  }
  if (request.prefer === 'external' || request.provider !== 'local') {
    return { state: 'DENY', reason: 'PROVIDER_ADAPTER_NOT_CONNECTED_TO_CANONICAL_EXECUTION_PATH', request, provider_policy: providerDecision, agreement: AGREEMENT };
  }
  const p = verifiedPipeline(session.identity_id);
  const route = p.devassist.route(canonical, request);
  const evidence = recordVerified(p, { participant: session.identity_id, action: request.action, result: route.route === 'deny' ? 'DENY' : 'ALLOW', details: { route: route.route, reason: route.reason, policy_reason: route.policy_reason, session_id: session.session_id } });
  if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', request, agreement: AGREEMENT };
  if (route.route !== 'local') return { state: route.route === 'resource_wait' ? 'REQUIRE_APPROVAL' : 'DENY', reason: route.reason, request, evidence, agreement: AGREEMENT };
  const authorization = {
    state: 'AUTHORIZED', capability_id: crypto.randomUUID(), epoch: Date.now(),
    session_id: session.session_id, identity_id: session.identity_id,
    request_id: request.request_id, expires_at: Math.min(Date.now() + AUTH_TTL_MS, session.expires_at * 1000),
    route: 'local', evidence, agreement: AGREEMENT
  };
  authorizations.set(authorization.capability_id, authorization);
  return authorization;
}

function infer(request) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(PYTHON_WS_URL);
    let done = false;
    const finish = (fn, value) => { if (!done) { done = true; clearTimeout(timer); try { ws.close(); } catch {} fn(value); } };
    const timer = setTimeout(() => finish(reject, new Error('PYTHON_BRIDGE_TIMEOUT')), 45000);
    ws.once('open', () => ws.send(JSON.stringify({
      type: 'ai_chat', agent: 'devassist420', message: request.text,
      context: 'Sovereignty AI Studio / DevAssist420', session: request.session_id,
      system: 'You are the authorized local Sovereignty AI assistant. Be accurate. Never fabricate access, actions, files, model identity, or evidence.'
    })));
    ws.on('message', raw => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === 'ai_response') finish(resolve, msg);
        else if (msg.type === 'ai_error') finish(reject, new Error(msg.error || 'LOCAL_INFERENCE_FAILED'));
      } catch (error) { finish(reject, error); }
    });
    ws.once('error', error => finish(reject, error));
  });
}

async function execute(body, proof) {
  const canonical = loadCanonicalState(STATE_PATH);
  const session = authenticate(proof, canonical, 'ai.inference');
  const request = normalize(body.request || body, session.identity_id, session.session_id);
  const auth = authorizations.get(body.capability_id);
  if (!auth || auth.expires_at <= Date.now()) return { state: 'DENY', reason: 'AUTHORIZATION_EXPIRED_OR_UNKNOWN', agreement: AGREEMENT };
  if (auth.session_id !== session.session_id || auth.identity_id !== session.identity_id ||
      auth.session_id !== body.session_id || auth.epoch !== body.epoch ||
      auth.request_id !== request.request_id) {
    return { state: 'DENY', reason: 'AUTHORIZATION_BINDING_MISMATCH', agreement: AGREEMENT };
  }
  authorizations.delete(body.capability_id);
  const p = verifiedPipeline(session.identity_id);
  try {
    const response = await infer(request);
    const evidence = recordVerified(p, { participant: session.identity_id, action: request.action, result: 'ALLOW', details: { route: 'local', transport: PYTHON_WS_URL, response_hash: response.hash || null, request_id: request.request_id, session_id: session.session_id } });
    if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', agreement: AGREEMENT };
    return { state: 'EXECUTED', response: response.text || '', agent: response.agent || 'devassist420', hash: response.hash || null, ts: response.ts || Date.now(), evidence, agreement: AGREEMENT };
  } catch (error) {
    const evidence = recordVerified(p, { participant: session.identity_id, action: request.action, result: 'FAIL', details: { route: 'local', error: error.message, request_id: request.request_id, session_id: session.session_id } });
    return { state: 'FAIL', reason: 'LOCAL_INFERENCE_UNAVAILABLE', detail: error.message, evidence, agreement: AGREEMENT };
  }
}

async function handle(body, proof) {
  const authorization = authorize(body, proof);
  if (authorization.state !== 'AUTHORIZED') return authorization;
  return execute({ request: authorization.request, capability_id: authorization.capability_id, session_id: authorization.session_id, epoch: authorization.epoch }, proof);
}

function updateProviderPolicy(body, proof) {
  const canonical = loadCanonicalState(STATE_PATH);
  const session = authenticate(proof, canonical, 'provider.policy.write');
  const p = verifiedPipeline(session.identity_id);
  const policy = writePolicy(body.policy);
  const evidence = p.record({ participant: session.identity_id, action: 'provider_policy_update', result: 'ALLOW', details: { policy_version: policy.policy_version, storage: 'server-authoritative' } });
  if (!evidence || evidence.ok !== true) throw new Error('SCAR_PERSISTENCE_FAILED');
  return { state: 'UPDATED', policy, evidence };
}

async function status() {
  const python = await probePythonWebSocket();
  const canonical = loadCanonicalState(STATE_PATH);
  let scar;
  let policy;
  try { scar = pipeline(canonical.state && canonical.state.owner_id || 'system').scar.verifyChain(); } catch { scar = { ok: false, reason: 'SCAR_UNAVAILABLE' }; }
  try { policy = loadPolicy(); } catch (error) { policy = null; }
  const ready = python.online && canonical.allowed && !!scar && scar.ok && !!policy;
  return {
    status: ready ? 'ready' : 'degraded',
    service: 'DevAssist420',
    state_path: STATE_PATH,
    canonical_state: { state: canonical.allowed ? 'VALID' : 'BLOCKED', allowed: canonical.allowed === true, reason: canonical.reason, threat: canonical.threat === true },
    python: { state: python.online ? 'ONLINE' : 'OFFLINE', transport: 'websocket', detail: python.detail },
    provider_policy: { state: policy ? 'VALID' : 'BLOCKED', version: policy && policy.policy_version || null, authority: 'server' },
    scar: { state: scar && scar.ok ? 'VALID' : 'BROKEN', reason: scar && scar.reason },
    readiness: { ready, blockers: [
      ...(!canonical.allowed ? [canonical.reason || 'CANONICAL_STATE_BLOCKED'] : []),
      ...(!python.online ? [python.detail || 'PYTHON_WEBSOCKET_OFFLINE'] : []),
      ...(!scar || !scar.ok ? ['SCAR_CHAIN_INVALID'] : []),
      ...(!policy ? ['PROVIDER_POLICY_INVALID'] : [])
    ] },
    agreement: AGREEMENT
  };
}

function route(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method === 'GET' && (url.pathname === '/api/devassist/status' || url.pathname === '/api/devassist420/status')) {
    status().then(value => json(res, 200, value)).catch(error => json(res, 503, { status: 'error', service: 'DevAssist420', reason: error.message, agreement: AGREEMENT }));
    return true;
  }
  if (req.method === 'GET' && url.pathname === '/api/devassist420/provider-policy') {
    try { return json(res, 200, { state: 'READ_ONLY_POLICY', policy: loadPolicy() }); }
    catch (error) { return json(res, 503, { state: 'DENY', reason: error.message }); }
  }
  if (req.method === 'GET' && url.pathname === '/api/devassist/agreement') return json(res, 200, AGREEMENT);
  const allowedPaths = [
    '/api/devassist420/authorize','/api/devassist/authorize',
    '/api/devassist420/execute','/api/devassist/execute',
    '/api/devassist/message','/api/devassist420/provider-policy'
  ];
  if (req.method !== 'POST' || !allowedPaths.includes(url.pathname)) return false;
  let raw = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { raw += chunk; if (raw.length > 65536) req.destroy(); });
  req.on('end', async () => {
    try {
      const body = JSON.parse(raw || '{}');
      const proof = req.headers['x-sovereignty-owner-session'];
      let result;
      if (url.pathname === '/api/devassist420/provider-policy') result = updateProviderPolicy(body, proof);
      else if (url.pathname.endsWith('/authorize')) result = authorize(body, proof);
      else if (url.pathname.endsWith('/execute')) result = await execute(body, proof);
      else result = await handle(body, proof);
      json(res, result.state === 'EXECUTED' ? 200 : 200, result);
    } catch (error) {
      json(res, 403, { state: 'DENY', reason: error.message, agreement: AGREEMENT });
    }
  });
  return true;
}

module.exports = { route, authorize, execute, handle, status, AGREEMENT };
