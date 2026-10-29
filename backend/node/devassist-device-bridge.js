'use strict';

/**
 * DevAssist420 device bridge.
 *
 * Single loopback entry point for iPhone/Shortcut -> DevAssist420.
 * The bridge is a transport boundary, not an authority boundary:
 *   device -> canonical state -> identity -> policy -> DevAssist420 -> inference -> SCAR
 *
 * It deliberately fails closed when canonical state is absent, malformed, invalid,
 * or stale. It does not expose a LAN bind by default and never treats network
 * reachability as authorization.
 */

const http = require('node:http');
const path = require('node:path');
const { createSovereigntyPipeline } = require('../integration/sovereignty_pipeline');

const HOST = process.env.DEVASSIST_BRIDGE_HOST || '127.0.0.1';
const PORT = Number(process.env.DEVASSIST_BRIDGE_PORT || 9899);
const STATE_PATH = process.env.SOVEREIGN_STATE_PATH || path.resolve('state/canonical.json');
const SCAR_PATH = process.env.SCAR_PATH || path.resolve('AUDIT/devassist-device.jsonl');
const MAX_BODY = 64 * 1024;

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
  owner_remains_authority: true
});

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body)
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
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('REQUEST_OBJECT_REQUIRED');
  }
  if (typeof body.text !== 'string' || body.text.trim() === '') {
    throw new Error('TEXT_REQUIRED');
  }
  if (body.text.length > 10000) {
    throw new Error('TEXT_TOO_LONG');
  }

  return {
    requester_id: typeof body.requester_id === 'string' && body.requester_id.trim()
      ? body.requester_id.trim()
      : (process.env.SOVEREIGN_OWNER_ID || 'Appel420'),
    action: typeof body.action === 'string' && body.action.trim() ? body.action.trim() : 'chat',
    prefer: body.prefer === 'external' ? 'external' : 'local',
    required_permission: typeof body.required_permission === 'string'
      ? body.required_permission.trim() || undefined
      : undefined,
    text: body.text.trim(),
    request_id: typeof body.request_id === 'string' ? body.request_id : undefined
  };
}

function handleMessage(body) {
  const request = normalizeRequest(body);
  const pipeline = createPipeline();
  const result = pipeline.execute(request, { prompt: request.text });

  return {
    protocol: AGREEMENT.protocol,
    request_id: request.request_id || null,
    status: result.ok ? 'ALLOW' : 'DENY',
    route: result.route || 'deny',
    stage: result.stage,
    response: result.execution && result.execution.result
      ? result.execution.result.output
      : null,
    reason: result.reason || (result.execution && result.execution.reason) || null,
    evidence: result.evidence || null,
    agreement: AGREEMENT,
    network_accessed: false
  };
}

function createServer() {
  return http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && (req.url === '/health' || req.url === '/api/devassist/status')) {
        return json(res, 200, {
          status: 'ok',
          service: 'DevAssist420-device-bridge',
          host: HOST,
          port: PORT,
          state_path: STATE_PATH,
          agreement: AGREEMENT,
          network_accessed: false
        });
      }

      if (req.method === 'GET' && req.url === '/api/devassist/agreement') {
        return json(res, 200, AGREEMENT);
      }

      if (req.method === 'POST' && (req.url === '/api/v1/shortcut/route' || req.url === '/api/devassist/message')) {
        let body;
        try {
          body = JSON.parse(await readBody(req));
        } catch (error) {
          return json(res, 400, { status: 'DENY', reason: error.message === 'REQUEST_TOO_LARGE' ? 'REQUEST_TOO_LARGE' : 'INVALID_JSON', agreement: AGREEMENT, network_accessed: false });
        }

        try {
          const result = handleMessage(body);
          return json(res, result.status === 'ALLOW' ? 200 : 403, result);
        } catch (error) {
          return json(res, 400, { status: 'DENY', reason: error.message, agreement: AGREEMENT, network_accessed: false });
        }
      }

      return json(res, 404, { status: 'DENY', reason: 'NOT_FOUND', agreement: AGREEMENT, network_accessed: false });
    } catch (error) {
      return json(res, 500, { status: 'DENY', reason: 'INTERNAL_ERROR', agreement: AGREEMENT, network_accessed: false });
    }
  });
}

if (require.main === module) {
  if (!['127.0.0.1', 'localhost', '::1'].includes(HOST)) {
    throw new Error('DEVASSIST_BRIDGE_HOST must be loopback');
  }
  createServer().listen(PORT, HOST, () => {
    process.stdout.write(`DevAssist420 device bridge listening on http://${HOST}:${PORT}\n`);
  });
}

module.exports = { AGREEMENT, createServer, handleMessage, normalizeRequest };
