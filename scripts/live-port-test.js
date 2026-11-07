#!/usr/bin/env node
'use strict';

/*
 * Interactive, loopback-only smoke test for the canonical Sovereignty ports.
 * This script is read-only. It never mutates provider policy, memory, keys,
 * audit records, Git refs, or service configuration.
 */
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const WebSocket = require('ws');

const HOST = '127.0.0.1';
const TIMEOUT_MS = 2200;
const results = [];

function record(name, state, detail = '') {
  const item = { name, state, detail, at: new Date().toISOString() };
  results.push(item);
  process.stdout.write('[' + state + '] ' + name + (detail ? ' — ' + detail : '') + '\n');
}

function get(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: HOST, port, path: pathname, method: 'GET', timeout: TIMEOUT_MS }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('timeout', () => req.destroy(new Error('TIMEOUT')));
    req.on('error', reject);
    req.end();
  });
}

function tcp(port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: HOST, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, TIMEOUT_MS);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

function wsCheck(port, pathname, expectedFirst, pingMessage, expectedPong, rejectExecution = false) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket('ws://' + HOST + ':' + port + pathname, {
      handshakeTimeout: TIMEOUT_MS,
      perMessageDeflate: false
    });
    let stage = 'first';
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error('WEBSOCKET_TIMEOUT_' + stage));
    }, TIMEOUT_MS * 2);
    socket.once('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on('message', raw => {
      let message;
      try { message = JSON.parse(String(raw)); } catch {
        clearTimeout(timer); socket.close(); reject(new Error('INVALID_JSON_FRAME')); return;
      }
      if (stage === 'first') {
        if (message.type !== expectedFirst) {
          clearTimeout(timer); socket.close(); reject(new Error('EXPECTED_' + expectedFirst + '_GOT_' + message.type)); return;
        }
        stage = 'pong';
        socket.send(JSON.stringify(pingMessage));
        return;
      }
      if (stage === 'pong' && message.type === expectedPong) {
        if (rejectExecution) {
          stage = 'deny';
          socket.send(JSON.stringify({ type: 'execute', command: 'must-not-run' }));
          return;
        }
        clearTimeout(timer); socket.close(); resolve(message); return;
      }
      if (stage === 'deny' && message.type === 'ui.error' && message.reason === 'READ_ONLY_UI_CHANNEL') {
        clearTimeout(timer); socket.close(); resolve(message); return;
      }
    });
  });
}

async function runHttp(name, port, pathname, check) {
  try {
    const response = await get(port, pathname);
    if (response.status < 200 || response.status >= 300) {
      record(name, 'FAIL', 'HTTP ' + response.status);
      return null;
    }
    let body = {};
    try { body = JSON.parse(response.body); } catch {}
    const detail = check ? check(body, response) : 'HTTP ' + response.status;
    if (detail === false) record(name, 'FAIL', 'response contract mismatch');
    else record(name, 'PASS', typeof detail === 'string' ? detail : 'HTTP ' + response.status);
    return body;
  } catch (error) {
    record(name, 'FAIL', error.message);
    return null;
  }
}

async function runWs(name, port, pathname, first, ping, pong, deny = false) {
  try {
    const result = await wsCheck(port, pathname, first, ping, pong, deny);
    record(name, 'PASS', result.type);
  } catch (error) {
    record(name, 'FAIL', error.message);
  }
}

async function main() {
  const auto = process.argv.includes('--yes') || process.argv.includes('-y');
  const skipPrompt = process.argv.includes('--no-prompt');
  if (!auto && !skipPrompt) {
    const rl = readline.createInterface({ input: stdin, output: stdout });
    const answer = await rl.question('Run read-only checks against 127.0.0.1 ports 9897, 9898, 9899 and optional Keycloak 8080/8443? [y/N] ');
    rl.close();
    if (!/^y(es)?$/i.test(answer.trim())) {
      record('live test', 'SKIPPED', 'user declined');
      return 2;
    }
  }

  process.stdout.write('\nSovereignty AI — canonical port smoke test\n');
  process.stdout.write('Target: 127.0.0.1 only; no external network calls; no mutations.\n\n');

  await runHttp('9897 Python bridge HTTP health', 9897, '/api/health', body =>
    body.service === 'sovereignty-python-bridge' && body.port === 9897 ? body.transport : false);
  await runWs('9897 Python bridge WebSocket', 9897, '/', 'handshake_ack', { type: 'ping' }, 'pong');

  await runHttp('9898 dashboard health', 9898, '/health', body =>
    body.service === 'sovereignty-dashboard' ? 'UI WS /ws/ui' : false);
  await runHttp('9898 same-origin API proxy → 9899', 9898, '/api/devassist420/provider-policy', body =>
    body.state === 'READ_ONLY_POLICY' && body.policy ? 'read-only provider policy received' : false);
  await runWs('9898 read-only UI WebSocket', 9898, '/ws/ui', 'ui.connected', { type: 'ping' }, 'ui.pong', true);

  await runHttp('9899 Unified Node health', 9899, '/health', body =>
    body.status === 'ok' || body.status === 'healthy' ? 'Node bridge responds' : 'HTTP health endpoint responds');
  await runWs('9899 Unified Node WebSocket', 9899, '/', 'welcome', { type: 'ping' }, 'pong');

  for (const port of [8080, 8443]) {
    const connected = await tcp(port);
    record('Keycloak TCP ' + port, connected ? 'PASS' : 'NOT_CONNECTED',
      connected ? 'listener detected' : 'identity provider not listening on loopback');
  }
  record('Redis 6379 / PostgreSQL 5432', 'EXPECTED_INTERNAL',
    'not probed on host; these must remain internal Docker-network services');

  const required = results.filter(item => ['9897 Python bridge HTTP health','9897 Python bridge WebSocket',
    '9898 dashboard health','9898 same-origin API proxy → 9899','9898 read-only UI WebSocket',
    '9899 Unified Node health','9899 Unified Node WebSocket'].includes(item.name));
  const failed = required.filter(item => item.state !== 'PASS');
  const identityMissing = results.some(item => item.name.startsWith('Keycloak') && item.state === 'NOT_CONNECTED');
  const status = failed.length ? 'FAIL' : identityMissing ? 'PASS_WITH_IDENTITY_GAP' : 'PASS';
  const report = {
    schema_version: '1.0',
    status,
    target: HOST,
    started_at: results[0]?.at || new Date().toISOString(),
    completed_at: new Date().toISOString(),
    results
  };
  try {
    const dir = path.join(os.homedir(), '.sovereignty-ai', 'reports');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = path.join(dir, 'live-port-test-' + Date.now() + '.json');
    fs.writeFileSync(file, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    process.stdout.write('\nEvidence report: ' + file + '\n');
  } catch (error) {
    process.stdout.write('\nEvidence report not persisted: ' + error.message + '\n');
  }
  process.stdout.write('\nFINAL: ' + status + '\n');
  return failed.length ? 1 : 0;
}

main().then(code => { process.exitCode = code; }).catch(error => {
  process.stderr.write('LIVE_TEST_ERROR: ' + error.message + '\n');
  process.exitCode = 1;
});
