'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const WebSocket = require('ws');
const { createDashboardServer } = require('../server_9898');

function request(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path: pathname }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body, headers: response.headers }));
    }).on('error', reject);
  });
}

test('dashboard serves health and canonical HTML over loopback', async t => {
  const app = createDashboardServer({ root: process.cwd(), upstreamPort: 1 });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const port = app.server.address().port;
  const health = await request(port, '/health');
  assert.equal(health.status, 200);
  assert.equal(JSON.parse(health.body).service, 'sovereignty-dashboard');
  const page = await request(port, '/');
  assert.equal(page.status, 200);
  assert.match(page.headers['content-type'], /text\/html/);
  assert.match(page.body, /DevAssist420|Sovereignty/i);
  assert.equal((await request(port, '/.env')).status, 404);
  assert.equal((await request(port, '/state/canonical.json')).status, 404);
});

test('dashboard UI websocket is read-only and supports ping', async t => {
  const app = createDashboardServer({ root: process.cwd(), upstreamPort: 1 });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const port = app.server.address().port;
  const ws = new WebSocket('ws://127.0.0.1:' + port + '/ws/ui', { perMessageDeflate: false });
  t.after(() => ws.close());
  const first = await new Promise((resolve, reject) => {
    ws.once('message', raw => resolve(JSON.parse(String(raw))));
    ws.once('error', reject);
  });
  assert.equal(first.type, 'ui.connected');
  const pong = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('UI websocket ping timeout')), 2000);
    ws.on('message', raw => {
      const value = JSON.parse(String(raw));
      if (value.type === 'ui.pong') { clearTimeout(timer); resolve(value); }
    });
    ws.once('error', reject);
  });
  ws.send(JSON.stringify({ type: 'ping' }));
  assert.equal((await pong).type, 'ui.pong');
  const rejected = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('UI websocket rejection timeout')), 2000);
    ws.on('message', raw => {
      const value = JSON.parse(String(raw));
      if (value.type === 'ui.error') { clearTimeout(timer); resolve(value); }
    });
    ws.once('error', reject);
  });
  ws.send(JSON.stringify({ type: 'execute', command: 'must-not-run' }));
  assert.equal((await rejected).reason, 'READ_ONLY_UI_CHANNEL');
});
