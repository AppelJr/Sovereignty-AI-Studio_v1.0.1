#!/usr/bin/env node
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { WebSocketServer } = require('ws');

const MIME = Object.freeze({
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf'
});
const EVENT_TYPES = new Set(['status', 'audit', 'memory', 'voice', 'checkpoint', 'provider', 'system']);
const BLOCKED_ROOTS = new Set([
  '.git', '.github', '.venv', 'AUDIT', 'backend', 'config', 'data', 'docs',
  'external', 'models', 'node_modules', 'scripts', 'secrets', 'state', 'tests',
  'piper-tts', 'gitsovereign'
]);
const SENSITIVE_KEY = /secret|token|api[_-]?key|password|private[_-]?key|credential|transcript|raw[_-]?audio/i;

function json(res, status, body) {
  if (res.headersSent) return;
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(body));
}

function hasSensitiveKey(value, depth = 0) {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key) || hasSensitiveKey(child, depth + 1)) return true;
  }
  return false;
}

function safeStaticFile(root, pathname) {
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return null; }
  if (decoded.includes('\0') || decoded.includes('\\')) return null;
  const segments = decoded.split('/').filter(Boolean);
  if (segments.some(segment => segment.startsWith('.') || BLOCKED_ROOTS.has(segment))) return null;
  const relative = segments.length ? segments.join(path.sep) : 'DevAssist420SGHv119.html';
  const candidate = path.resolve(root, relative);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) return null;
  if (!MIME[path.extname(candidate).toLowerCase()]) return null;
  return candidate;
}

function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', chunk => {
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > limit) {
        reject(new Error('REQUEST_TOO_LARGE'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); }
      catch { reject(new Error('INVALID_JSON')); }
    });
    req.on('error', reject);
  });
}

function timingSafeToken(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' ||
      Buffer.byteLength(actual) !== Buffer.byteLength(expected)) return false;
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function createDashboardServer(options = {}) {
  const root = path.resolve(options.root || __dirname);
  const upstreamPort = Number(options.upstreamPort || process.env.PORT_UNIFIED || process.env.NODE_BRIDGE_PORT || 9899);
  const maxProxyBytes = Number(options.maxProxyBytes || 20 * 1024 * 1024);
  const subscriptions = new Map();
  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024, perMessageDeflate: false });

  function publish(event) {
    const packet = JSON.stringify({ ...event, delivered_at: new Date().toISOString() });
    let delivered = 0;
    for (const [client, types] of subscriptions.entries()) {
      if (client.readyState === 1 && (types.has('*') || types.has(event.type))) {
        try { client.send(packet); delivered += 1; } catch { subscriptions.delete(client); }
      }
    }
    return delivered;
  }

  function proxyApi(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (!url.pathname.startsWith('/api/')) return false;
    const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
    if (!methods.has(req.method)) {
      json(res, 405, { state: 'DENY', reason: 'METHOD_NOT_ALLOWED' });
      return true;
    }
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > maxProxyBytes) {
      json(res, 413, { state: 'DENY', reason: 'REQUEST_TOO_LARGE' });
      return true;
    }
    const headers = { ...req.headers, host: '127.0.0.1:' + upstreamPort };
    for (const name of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
      delete headers[name];
    }
    const upstream = http.request({
      hostname: '127.0.0.1', port: upstreamPort, method: req.method,
      path: url.pathname + url.search, headers, timeout: 15000
    }, upstreamRes => {
      const responseHeaders = { ...upstreamRes.headers };
      for (const name of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
        delete responseHeaders[name];
      }
      responseHeaders['cache-control'] = 'no-store';
      res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
      upstreamRes.pipe(res);
    });
    let received = 0;
    req.on('data', chunk => {
      received += chunk.length;
      if (received > maxProxyBytes && !upstream.destroyed) {
        upstream.destroy();
        json(res, 413, { state: 'DENY', reason: 'REQUEST_TOO_LARGE' });
      }
    });
    req.on('aborted', () => upstream.destroy());
    upstream.on('timeout', () => upstream.destroy(new Error('UPSTREAM_TIMEOUT')));
    upstream.on('error', error => {
      if (!res.headersSent) json(res, 502, { state: 'UNAVAILABLE', reason: 'UNIFIED_SERVER_UNAVAILABLE', detail: error.message });
      else res.destroy(error);
    });
    req.pipe(upstream);
    return true;
  }

  const server = http.createServer((req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') {
      json(res, 405, { state: 'DENY', reason: 'METHOD_NOT_ALLOWED' });
      return;
    }
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/health') {
      json(res, 200, {
        status: 'healthy', service: 'sovereignty-dashboard', port: Number(process.env.PORT || 9898),
        websocket: '/ws/ui', api_proxy: '127.0.0.1:' + upstreamPort
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/internal/events') {
      const expected = process.env.SG_DASHBOARD_EVENT_TOKEN;
      if (!expected || Buffer.byteLength(expected) < 32 ||
          !timingSafeToken(req.headers['x-sg-dashboard-token'], expected)) {
        json(res, 403, { state: 'DENY', reason: 'INTERNAL_EVENT_AUTH_REQUIRED' });
        return;
      }
      readJson(req, 64 * 1024).then(event => {
        if (!event || typeof event !== 'object' || Array.isArray(event) ||
            typeof event.event_id !== 'string' || !event.event_id ||
            !EVENT_TYPES.has(event.type) || !event.data || typeof event.data !== 'object' ||
            Array.isArray(event.data) || hasSensitiveKey(event.data)) {
          json(res, 400, { state: 'DENY', reason: 'INVALID_OR_SENSITIVE_UI_EVENT' });
          return;
        }
        json(res, 200, { state: 'PUBLISHED', delivered: publish({
          event_id: event.event_id, type: event.type,
          timestamp: typeof event.timestamp === 'string' ? event.timestamp : new Date().toISOString(),
          data: event.data
        }) });
      }).catch(error => json(res, 400, { state: 'DENY', reason: error.message }));
      return;
    }
    if (proxyApi(req, res)) return;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      json(res, 404, { state: 'NOT_FOUND' });
      return;
    }
    const file = safeStaticFile(root, url.pathname);
    if (!file) {
      json(res, 404, { state: 'NOT_FOUND' });
      return;
    }
    fs.stat(file, (statError, stat) => {
      if (statError || !stat.isFile()) {
        json(res, 404, { state: 'NOT_FOUND' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(file).toLowerCase()],
        'Content-Length': stat.size,
        'Cache-Control': 'no-store'
      });
      if (req.method === 'HEAD') res.end();
      else fs.createReadStream(file).pipe(res);
    });
  });

  server.on('upgrade', (req, socket, head) => {
    let pathname;
    try { pathname = new URL(req.url, 'http://127.0.0.1').pathname; } catch { socket.destroy(); return; }
    if (pathname !== '/ws/ui') { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
  });

  wss.on('connection', ws => {
    subscriptions.set(ws, new Set(['*']));
    ws.send(JSON.stringify({ type: 'ui.connected', timestamp: new Date().toISOString() }));
    ws.on('message', raw => {
      let message;
      try { message = JSON.parse(String(raw)); } catch {
        ws.send(JSON.stringify({ type: 'ui.error', reason: 'INVALID_JSON' }));
        return;
      }
      if (message.type === 'ping') {
        ws.send(JSON.stringify({ type: 'ui.pong', timestamp: new Date().toISOString() }));
      } else if (message.type === 'subscribe' && Array.isArray(message.events) &&
          message.events.length <= EVENT_TYPES.size &&
          message.events.every(type => EVENT_TYPES.has(type))) {
        subscriptions.set(ws, new Set(message.events));
        ws.send(JSON.stringify({ type: 'ui.subscribed', events: message.events }));
      } else {
        ws.send(JSON.stringify({ type: 'ui.error', reason: 'READ_ONLY_UI_CHANNEL' }));
      }
    });
    ws.on('close', () => subscriptions.delete(ws));
    ws.on('error', () => subscriptions.delete(ws));
  });

  return {
    server, wss, publish,
    close: () => new Promise(resolve => {
      for (const client of wss.clients) client.close();
      wss.close(() => server.close(() => resolve()));
    })
  };
}

function start() {
  const host = process.env.DASHBOARD_HOST || '127.0.0.1';
  const port = Number.parseInt(process.env.PORT || process.env.STATIC_PORT || '9898', 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('DASHBOARD_PORT_INVALID');
  const app = createDashboardServer();
  app.server.listen(port, host, () => {
    process.stdout.write('[dashboard] listening on http://' + host + ':' + port + '\n');
  });
  app.server.on('error', error => {
    process.stderr.write('[dashboard] server error: ' + error.message + '\n');
    process.exitCode = 1;
  });
  return app;
}

if (require.main === module) start();
module.exports = { createDashboardServer, start };
