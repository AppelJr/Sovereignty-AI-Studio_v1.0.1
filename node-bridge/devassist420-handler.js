'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { createSovereigntyPipeline } = require('../backend/integration/sovereignty_pipeline');
const { loadCanonicalState } = require('../backend/state/canonical_state');

const STATE_PATH = process.env.SOVEREIGN_STATE_PATH || path.resolve('state/canonical.json');
const SCAR_PATH = process.env.SCAR_PATH || path.resolve('AUDIT/devassist-device.jsonl');
const PYTHON_WS_URL = process.env.SOVEREIGN_PYTHON_WS_URL || 'ws://127.0.0.1:9897';
const AUTH_TTL_MS = 60 * 1000;
const MAX_TEXT = 10000;
const authorizations = new Map();

const AGREEMENT = Object.freeze({
  protocol: 'devassist420-live-v1', authority: 'human-owner', orchestrator: 'DevAssist420',
  orchestrator_is_root: false, memory: 'permission-only', network: 'loopback-only',
  default_decision: 'DENY', inference_transport: 'python-websocket-9897'
});

function json(res, status, value) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(value));
}

function normalize(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('REQUEST_OBJECT_REQUIRED');
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  if (!text) throw new Error('TEXT_REQUIRED');
  if (text.length > MAX_TEXT) throw new Error('TEXT_TOO_LONG');
  return {
    requester_id: typeof body.requester_id === 'string' && body.requester_id.trim() ? body.requester_id.trim() : (process.env.SOVEREIGN_OWNER_ID || 'Appel420'),
    action: typeof body.action === 'string' && body.action.trim() ? body.action.trim() : 'chat',
    prefer: body.prefer === 'external' ? 'external' : 'local',
    required_permission: typeof body.required_permission === 'string' ? body.required_permission.trim() || undefined : undefined,
    text,
    request_id: typeof body.request_id === 'string' && body.request_id ? body.request_id : crypto.randomUUID(),
    session_id: typeof body.session_id === 'string' && body.session_id ? body.session_id : crypto.randomUUID()
  };
}

function pipeline() {
  return createSovereigntyPipeline({
    statePath: STATE_PATH, scarPath: SCAR_PATH,
    ownerId: process.env.SOVEREIGN_OWNER_ID || 'Appel420',
    orchestratorId: 'DevAssist420', participants: []
  });
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
    ws.once('error', (error) => finish(false, error && error.message ? error.message : 'PYTHON_WS_ERROR'));
  });
}

function authorize(body) {
  const request = normalize(body);
  if (body.owner_authenticated !== true) return { state: 'REQUIRE_APPROVAL', reason: 'OWNER_AUTHENTICATION_REQUIRED', request, agreement: AGREEMENT };
  const p = pipeline();
  const canonical = loadCanonicalState(STATE_PATH);
  if (!canonical.allowed) {
    const evidence = p.record({ participant: request.requester_id, action: request.action, result: 'DENY', details: { reason: canonical.reason } });
    return { state: 'DENY', reason: canonical.reason, request, evidence, agreement: AGREEMENT };
  }
  const route = p.devassist.route(canonical, request);
  const evidence = p.record({ participant: request.requester_id, action: request.action, result: route.route === 'deny' ? 'DENY' : 'ALLOW', details: { route: route.route, reason: route.reason, policy_reason: route.policy_reason } });
  if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', request, agreement: AGREEMENT };
  if (route.route !== 'local') return { state: route.route === 'resource_wait' ? 'REQUIRE_APPROVAL' : 'DENY', reason: route.reason, request, evidence, agreement: AGREEMENT };
  const authorization = {
    state: 'AUTHORIZED', capability_id: crypto.randomUUID(), epoch: Date.now(),
    session_id: request.session_id, request_id: request.request_id, expires_at: Date.now() + AUTH_TTL_MS,
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
      system: 'You are the authorized local Sovereignty AI Studio assistant. Be accurate. Never fabricate access, actions, files, model identity, or evidence.'
    })));
    ws.on('message', raw => {
      try { const msg = JSON.parse(String(raw)); if (msg.type === 'ai_response') finish(resolve, msg); }
      catch (e) { finish(reject, e); }
    });
    ws.once('error', e => finish(reject, e));
  });
}

async function execute(body) {
  const request = normalize(body.request || body);
  const auth = authorizations.get(body.capability_id);
  if (!auth || auth.expires_at <= Date.now()) return { state: 'DENY', reason: 'AUTHORIZATION_EXPIRED_OR_UNKNOWN', agreement: AGREEMENT };
  if (auth.session_id !== body.session_id || auth.epoch !== body.epoch || auth.request_id !== request.request_id) return { state: 'DENY', reason: 'AUTHORIZATION_BINDING_MISMATCH', agreement: AGREEMENT };
  const reauth = authorize({ ...request, owner_authenticated: true });
  if (reauth.state !== 'AUTHORIZED') return { state: 'DENY', reason: reauth.reason || 'REAUTHORIZATION_FAILED', evidence: reauth.evidence, agreement: AGREEMENT };
  try {
    const response = await infer(request);
    const evidence = pipeline().record({ participant: request.requester_id, action: request.action, result: 'ALLOW', details: { route: 'local', transport: PYTHON_WS_URL, response_hash: response.hash || null } });
    if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', agreement: AGREEMENT };
    authorizations.delete(body.capability_id);
    return { state: 'EXECUTED', response: response.text || '', agent: response.agent || 'devassist420', hash: response.hash || null, ts: response.ts || Date.now(), evidence, agreement: AGREEMENT };
  } catch (error) {
    const evidence = pipeline().record({ participant: request.requester_id, action: request.action, result: 'FAIL', details: { route: 'local', error: error.message } });
    return { state: 'FAIL', reason: 'LOCAL_INFERENCE_UNAVAILABLE', detail: error.message, evidence, agreement: AGREEMENT };
  }
}

async function handle(body) {
  const authorization = authorize(body);
  if (authorization.state !== 'AUTHORIZED') return authorization;
  return execute({ request: authorization.request, capability_id: authorization.capability_id, session_id: authorization.session_id, epoch: authorization.epoch });
}

async function status() {
  const python = await probePythonWebSocket();
  return {
    status: 'ok',
    service: 'DevAssist420',
    state_path: STATE_PATH,
    python_ws: PYTHON_WS_URL,
    python: { state: python.online ? 'ONLINE' : 'OFFLINE', transport: 'websocket', detail: python.detail },
    agreement: AGREEMENT
  };
}

function route(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method === 'GET' && (url.pathname === '/api/devassist/status' || url.pathname === '/api/devassist420/status')) {
    status().then(value => json(res, 200, value)).catch(error => json(res, 503, { status: 'error', service: 'DevAssist420', reason: error.message, agreement: AGREEMENT }));
    return true;
  }
  if (req.method === 'GET' && url.pathname === '/api/devassist/agreement') return json(res, 200, AGREEMENT);
  if (req.method !== 'POST' || !['/api/devassist420/authorize','/api/devassist/authorize','/api/devassist420/execute','/api/devassist/execute','/api/devassist/message'].includes(url.pathname)) return false;
  let raw = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { raw += chunk; if (raw.length > 65536) req.destroy(); });
  req.on('end', async () => {
    try {
      const body = JSON.parse(raw || '{}');
      const result = url.pathname.endsWith('/authorize') ? authorize(body) : url.pathname.endsWith('/execute') ? await execute(body) : await handle(body);
      json(res, result.state === 'EXECUTED' ? 200 : 200, result);
    } catch (e) { json(res, 400, { state: 'DENY', reason: e.message, agreement: AGREEMENT }); }
  });
  return true;
}

module.exports = { route, authorize, execute, handle, AGREEMENT };