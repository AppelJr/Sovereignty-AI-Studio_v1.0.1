'use strict';

const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { createSovereigntyPipeline } = require('../integration/sovereignty_pipeline');
const { loadCanonicalState } = require('../state/canonical_state');

const HOST = process.env.DEVASSIST_BRIDGE_HOST || '127.0.0.1';
const PORT = Number(process.env.DEVASSIST_BRIDGE_PORT || 9899);
const STATE_PATH = process.env.SOVEREIGN_STATE_PATH || path.resolve('state/canonical.json');
const SCAR_PATH = process.env.SCAR_PATH || path.resolve('AUDIT/devassist-device.jsonl');
const PYTHON_WS_URL = process.env.SOVEREIGN_PYTHON_WS_URL || 'ws://127.0.0.1:9897';
const MAX_BODY = 64 * 1024;
const AUTH_TTL_MS = 60 * 1000;
const authorizations = new Map();

const AGREEMENT = Object.freeze({
  protocol: 'devassist420-device-v1',
  authority: 'human-owner',
  device: 'custodian',
  orchestrator: 'DevAssist420',
  orchestrator_is_root: false,
  model: 'advisor',
  memory: 'permission-only',
  network: 'loopback-only',
  default_decision: 'DENY',
  peer_coordination: true,
  owner_remains_authority: true,
  inference_transport: 'python-websocket-9897'
});

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': process.env.CORS_ORIGIN || 'http://127.0.0.1:9898',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Sovereignty-Protocol'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY) {
        reject(new Error('REQUEST_TOO_LARGE'));
        req.destroy();
        return;
      }
      raw += chunk;
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

function createPipeline() {
  return createSovereigntyPipeline({
    statePath: STATE_PATH,
    scarPath: SCAR_PATH,
    ownerId: process.env.SOVEREIGN_OWNER_ID || 'Appel420',
    orchestratorId: 'DevAssist420',
    participants: []
  });
}

function normalizeRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('REQUEST_OBJECT_REQUIRED');
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  if (!text) throw new Error('TEXT_REQUIRED');
  if (text.length > 10000) throw new Error('TEXT_TOO_LONG');
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

function authorize(body) {
  const request = normalizeRequest(body);
  if (body.owner_authenticated !== true) return { state: 'REQUIRE_APPROVAL', reason: 'OWNER_AUTHENTICATION_REQUIRED', request };

  const pipeline = createPipeline();
  const canonical = loadCanonicalState(STATE_PATH);
  if (!canonical.allowed) {
    const evidence = pipeline.record({ participant: request.requester_id, action: request.action, result: 'DENY', details: { reason: canonical.reason } });
    return { state: 'DENY', reason: canonical.reason, request, evidence };
  }

  const route = pipeline.devassist.route(canonical, request);
  const evidence = pipeline.record({
    participant: request.requester_id,
    action: request.action,
    result: route.route === 'deny' ? 'DENY' : 'ALLOW',
    details: { route: route.route, reason: route.reason, policy_reason: route.policy_reason }
  });
  if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', request, evidence };
  if (route.route !== 'local') return { state: route.route === 'resource_wait' ? 'REQUIRE_APPROVAL' : 'DENY', reason: route.reason, request, evidence };

  const capability_id = crypto.randomUUID();
  const epoch = Date.now();
  const authorization = {
    state: 'AUTHORIZED', capability_id, epoch, session_id: request.session_id,
    request_id: request.request_id, expires_at: epoch + AUTH_TTL_MS,
    route: route.route, evidence, agreement: AGREEMENT
  };
  authorizations.set(capability_id, authorization);
  return authorization;
}

function invokePython(request) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(PYTHON_WS_URL);
    let settled = false;
    const finish = (fn, value) => { if (!settled) { settled = true; try { ws.close(); } catch {} fn(value); } };
    const timer = setTimeout(() => finish(reject, new Error('PYTHON_BRIDGE_TIMEOUT')), 45000);
    ws.once('open', () => ws.send(JSON.stringify({
      type: 'ai_chat', agent: 'devassist420', message: request.text,
      context: 'DevAssist420 live dashboard', session: request.session_id,
      system: 'You are the authorized local Sovereignty AI Studio assistant. Answer accurately. Do not fabricate access, actions, or evidence.'
    })));
    ws.on('message', (raw) => {
      try {
        const message = JSON.parse(String(raw));
        if (message.type === 'ai_response') { clearTimeout(timer); finish(resolve, message); }
      } catch (error) { clearTimeout(timer); finish(reject, error); }
    });
    ws.once('error', (error) => { clearTimeout(timer); finish(reject, error); });
  });
}

async function execute(body) {
  const request = normalizeRequest(body.request || body);
  const auth = authorizations.get(body.capability_id);
  if (!auth || auth.state !== 'AUTHORIZED' || auth.expires_at <= Date.now()) return { state: 'DENY', reason: 'AUTHORIZATION_EXPIRED_OR_UNKNOWN', agreement: AGREEMENT };
  if (auth.session_id !== body.session_id || auth.epoch !== body.epoch || auth.request_id !== request.request_id) return { state: 'DENY', reason: 'AUTHORIZATION_BINDING_MISMATCH', agreement: AGREEMENT };

  const gate = authorize({ ...request, owner_authenticated: true });
  if (gate.state !== 'AUTHORIZED') return { state: 'DENY', reason: gate.reason || 'REAUTHORIZATION_FAILED', evidence: gate.evidence, agreement: AGREEMENT };

  try {
    const result = await invokePython(request);
    const pipeline = createPipeline();
    const evidence = pipeline.record({ participant: request.requester_id, action: request.action, result: 'ALLOW', details: { route: 'local', provider: 'python-sovereign-bridge', response_hash: result.hash || null } });
    if (!evidence || evidence.ok !== true) return { state: 'DENY', reason: 'SCAR_PERSISTENCE_FAILED', agreement: AGREEMENT };
    authorizations.delete(body.capability_id);
    return { state: 'EXECUTED', response: result.text || '', agent: result.agent || 'devassist420', hash: result.hash || null, ts: result.ts || Date.now(), evidence, agreement: AGREEMENT };
  } catch (error) {
    const pipeline = createPipeline();
    const evidence = pipeline.record({ participant: request.requester_id, action: request.action, result: 'FAIL', details: { route: 'local', error: error.message } });
    return { state: 'FAIL', reason: 'LOCAL_INFERENCE_UNAVAILABLE', detail: error.message, evidence, agreement: AGREEMENT };
  }
}

async function handleMessage(body) {
  const authorization = authorize(body);
  if (authorization.state !== 'AUTHORIZED') return authorization;
  return execute({ request: authorization.request, capability_id: authorization.capability_id, session_id: authorization.session_id, epoch: authorization.epoch });
}

function createServer() {
  return http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') return json(res, 204, {});
    try {
      if (req.method === 'GET' && (req.url === '/health' || req.url === '/api/devassist/status')) return json(res, 200, { status: 'ok', service: 'DevAssist420-device-bridge', host: HOST, port: PORT, state_path: STATE_PATH, python_ws: PYTHON_WS_URL, agreement: AGREEMENT, network_accessed: false });
      if (req.method === 'GET' && req.url === '/api/devassist/agreement') return json(res, 200, AGREEMENT);
      if (req.method === 'POST' && (req.url === '/api/devassist420/authorize' || req.url === '/api/devassist/authorize')) return json(res, 200, authorize(JSON.parse(await readBody(req))));
      if (req.method === 'POST' && (req.url === '/api/devassist420/execute' || req.url === '/api/devassist/execute')) return json(res, 200, await execute(JSON.parse(await readBody(req))));
      if (req.method === 'POST' && (req.url === '/api/v1/shortcut/route' || req.url === '/api/devassist/message')) {
        const result = await handleMessage(JSON.parse(await readBody(req)));
        return json(res, result.state === 'EXECUTED' || result.status === 'ALLOW' ? 200 : 403, result);
      }
      return json(res, 404, { status: 'DENY', reason: 'NOT_FOUND', agreement: AGREEMENT, network_accessed: false });
    } catch (error) {
      return json(res, 400, { status: 'DENY', reason: error.message || 'INVALID_REQUEST', agreement: AGREEMENT, network_accessed: false });
    }
  });
}

if (require.main === module) {
  if (!['127.0.0.1', 'localhost', '::1'].includes(HOST)) throw new Error('DEVASSIST_BRIDGE_HOST must be loopback');
  createServer().listen(PORT, HOST, () => process.stdout.write(`DevAssist420 device bridge listening on http://${HOST}:${PORT}\n`));
}

module.exports = { AGREEMENT, createServer, handleMessage, normalizeRequest, authorize, execute };
