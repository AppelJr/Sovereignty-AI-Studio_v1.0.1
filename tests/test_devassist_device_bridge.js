'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const { createServer, normalizeRequest, AGREEMENT } = require('../backend/node/devassist-device-bridge');

function request(server, method, path, body) {
  return new Promise((resolve, reject) => {
    const address = server.address();
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1',
      port: address.port,
      path,
      method,
      headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw) }));
    });
    req.on('error', reject);
    if (payload) req.end(payload); else req.end();
  });
}

test('agreement makes owner/device/orchestrator roles explicit', () => {
  assert.equal(AGREEMENT.authority, 'human-owner');
  assert.equal(AGREEMENT.device, 'custodian');
  assert.equal(AGREEMENT.orchestrator, 'DevAssist420');
  assert.equal(AGREEMENT.orchestrator_is_root, false);
  assert.equal(AGREEMENT.owner_remains_authority, true);
});

test('normalizes a device message without granting authority', () => {
  const value = normalizeRequest({ text: 'hello', action: 'chat' });
  assert.equal(value.requester_id, 'Appel420');
  assert.equal(value.action, 'chat');
  assert.equal(value.prefer, 'local');
});

test('health exposes the shared agreement', async () => {
  const server = createServer().listen(0, '127.0.0.1');
  try {
    const result = await request(server, 'GET', '/api/devassist/status');
    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'ok');
    assert.equal(result.body.network_accessed, false);
    assert.equal(result.body.agreement.protocol, 'devassist420-device-v1');
  } finally {
    server.close();
  }
});

test('message fails closed when canonical state is unavailable', async () => {
  const server = createServer().listen(0, '127.0.0.1');
  try {
    const result = await request(server, 'POST', '/api/devassist/message', { text: 'hello' });
    assert.equal(result.status, 403);
    assert.equal(result.body.status, 'DENY');
    assert.equal(result.body.network_accessed, false);
    assert.ok(result.body.reason);
  } finally {
    server.close();
  }
});
