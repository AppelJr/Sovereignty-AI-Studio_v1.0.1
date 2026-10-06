/**
 * Sovereignty AI Studio — Node.js Communication Bridge
 *
 * Connects the React frontend, Python backends (FastAPI + Quart), and
 * iSH / Code Pad developer environments through a single entry-point.
 *
 * Endpoints:
 *   GET  /health                  – bridge health check
 *   ALL  /api/v1/*                – proxy to FastAPI  (BACKEND_URL)
 *   ALL  /api/weather*            – proxy to Quart    (WEATHER_URL)
 *   ALL  /api/forecast*           – proxy to Quart    (WEATHER_URL)
 *   POST /ai/:agentId             – AI agent bridge   (GATEWAY_URL)
 *   POST /chat                    – chat HTTP fallback (GATEWAY_URL)
 *   ALL  /api/chat                – proxy to Gateway   (GATEWAY_URL)
 *   ALL  /api/voice               – proxy to Gateway   (GATEWAY_URL)
 *   ALL  /api/plugins/*           – proxy to Gateway   (GATEWAY_URL)
 *   ALL  /api/judge/*             – proxy to Gateway   (GATEWAY_URL)
 *   GET  /api/metrics             – real process/system metrics
 *   GET  /api/agents/status       – aggregated ecosystem health
 *   GET  /api/bridge/status       – aggregated backend service health
 *   POST /api/bridge/notify       – push real-time alert to WebSocket clients
 *   POST /validate/step           – validation pipeline step
 *   POST /validate/signatures     – signature chain validation
 *   POST /tpm/attest              – TPM attestation probe
 *   POST /threats/feed            – threat feed sync
 *   POST /scan/directory          – directory scan
 *   POST /test/poison             – adversarial test runner
 *   POST /proxy/fetch             – URL proxy (JSON response)
 *   POST /proxy/text              – URL proxy (text response)
 *   POST /proxy                   – general URL proxy
 *   POST /keycloak/token          – Keycloak token exchange
 *   POST /mtls/handshake          – mTLS TLS probe
 *   POST /spiffe/svid             – SPIFFE SVID status
 *   POST /exec/code               – sandboxed code execution (Node.js, Python, shell)
 *   GET  /satellite/imagery       – NASA EONET events + NOAA GOES satellite feeds
 *   GET  /satellite/goes          – NOAA GOES satellite image URL
 *   GET  /alerts/live             – live alerts feed
 *   POST /error_ping              – client error reporting
 *   WS   /ws/alerts               – WebSocket for live alerts + terminal exec + status
 */

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFile } = require('child_process');
const { WebSocket: WsClient, WebSocketServer } = require('ws');

// ---------------------------------------------------------------------------
// Config from environment (sensible defaults for local / iSH)
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.NODE_BRIDGE_PORT || '9899', 10);
const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:8002';
const WEATHER_URL = process.env.WEATHER_URL || 'http://127.0.0.1:8001';
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:9001';
const SG_BRIDGE_URL = (process.env.SG_BRIDGE_URL || '').trim();
// Derived HTTP base URL for health-check probes against the Python backend bridge
const SG_BRIDGE_HTTP_URL = (process.env.SG_BRIDGE_HTTP_URL || (SG_BRIDGE_URL ? SG_BRIDGE_URL.replace(/^ws(s?):\/\//, 'http$1://') : '')).trim();
const TLS_CERT = process.env.TLS_CERT || '';
const TLS_KEY = process.env.TLS_KEY || '';
const TLS_CA = process.env.TLS_CA || '';
const TLS_REQUEST_CERT = process.env.TLS_REQUEST_CERT === '1';
const TLS_REJECT_UNAUTHORIZED = process.env.TLS_REJECT_UNAUTHORIZED !== '0';
const UPSTREAM_DEFAULT_PORT = parseInt(process.env.UPSTREAM_DEFAULT_PORT || '9898', 10);
const NETWORK_MODE = ['offline', 'hybrid', 'online'].includes(process.env.SG_NETWORK_MODE)
  ? process.env.SG_NETWORK_MODE
  : (process.env.SG_OFFLINE_MODE === '0' ? 'hybrid' : 'offline');
const OFFLINE_MODE = NETWORK_MODE === 'offline';
const REMOTE_NETWORK_ENABLED = process.env.SG_ENABLE_REMOTE_NETWORK === '1';
const TLS_MODE = process.env.SG_TLS_MODE || 'local-ca';
const REMOTE_AUDIT_LOG = [];
const LOCAL_NETWORK_ALLOWLIST = new Set(
  (process.env.SG_LOCAL_NETWORK_ALLOWLIST || '').split(',').map((host) => host.trim()).filter(Boolean),
);

function isLoopbackHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
}

function networkAllowed(target) {
  try {
    const url = target instanceof URL ? target : new URL(target);
    if (isLoopbackHost(url.hostname)) return true;
    if (NETWORK_MODE === 'hybrid') return LOCAL_NETWORK_ALLOWLIST.has(url.hostname);
    return NETWORK_MODE === 'online' && REMOTE_NETWORK_ENABLED;
  } catch {
    return false;
  }
}

function recordRemoteAttempt(target, allowed, reason) {
  REMOTE_AUDIT_LOG.push({
    timestamp: new Date().toISOString(),
    target: String(target),
    allowed,
    reason,
  });
  if (REMOTE_AUDIT_LOG.length > 100) REMOTE_AUDIT_LOG.shift();
}

// Reconnect tuning for Python-backend proxy
const SG_BASE_RECONNECT_MS = 3000;
const SG_MAX_RECONNECT_MS = 30000;

const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------------------------------------------------------------------------
// CORS — default to bridge origin
// ---------------------------------------------------------------------------
app.use((_req, res, next) => {
  const origin = process.env.CORS_ORIGIN || 'null';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (_req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'node-bridge',
    uptime: process.uptime(),
    backends: { api: BACKEND_URL, weather: WEATHER_URL, gateway: GATEWAY_URL },
    network: {
      offline_mode: OFFLINE_MODE,
      network_mode: NETWORK_MODE,
      remote_network_enabled: REMOTE_NETWORK_ENABLED,
      tls_mode: TLS_MODE,
    },
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/network/status', (_req, res) => {
  res.json({
    offline_mode: OFFLINE_MODE,
    network_mode: NETWORK_MODE,
    remote_network_enabled: REMOTE_NETWORK_ENABLED,
    local_network_allowlist: [...LOCAL_NETWORK_ALLOWLIST],
    tls_mode: TLS_MODE,
    lets_encrypt: {
      enabled: TLS_MODE === 'letsencrypt' && NETWORK_MODE === 'online' && REMOTE_NETWORK_ENABLED,
      configured: Boolean(process.env.ACME_EMAIL && process.env.ACME_DOMAIN),
      note: 'ACME issuance requires an explicitly enabled Internet-connected public deployment.',
    },
    recent_remote_attempts: REMOTE_AUDIT_LOG.slice(-20),
  });
});

// ---------------------------------------------------------------------------
// Lightweight reverse proxy (no extra dependency)
// ---------------------------------------------------------------------------
function requestClientFor(url) {
  return url.protocol === 'https:' ? https : http;
}

function resolveUpstreamPort(url) {
  return url.port || UPSTREAM_DEFAULT_PORT;
}

function proxyRequest(targetBase, req, res) {
  let url;
  try {
    url = new URL(req.originalUrl, targetBase);
  } catch {
    return res.status(400).json({ error: 'Invalid upstream URL' });
  }
  if (!networkAllowed(url)) {
    recordRemoteAttempt(url, false, 'offline policy');
    return res.status(503).json({
      error: 'Outbound network disabled by offline policy',
      code: 'OFFLINE_NETWORK_BLOCKED',
    });
  }
  const client = requestClientFor(url);
  const options = {
    hostname: url.hostname,
    port: resolveUpstreamPort(url),
    path: url.pathname + url.search,
    method: req.method,
    headers: { ...req.headers, host: url.host },
  };

  const proxyReq = client.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', (err) => {
    console.error(`[proxy] ${targetBase} error:`, err.message);
    if (!res.headersSent) {
      res.status(502).json({ error: 'Backend unavailable', target: targetBase });
    }
  });

  req.pipe(proxyReq, { end: true });
}

// Proxy /api/v1/* → FastAPI
app.use('/api/v1', (req, res) => proxyRequest(BACKEND_URL, req, res));

// Proxy /api/weather* and /api/forecast* → Quart
app.use('/api/weather', (req, res) => proxyRequest(WEATHER_URL, req, res));
app.use('/api/forecast', (req, res) => proxyRequest(WEATHER_URL, req, res));

// ---------------------------------------------------------------------------
// Agent / Gateway proxy
// ---------------------------------------------------------------------------

app.post('/ai/:agentId', (req, res) => {
  const agentId = (req.params.agentId || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  if (!agentId) {
    return res.status(400).json({ error: 'Invalid agent ID' });
  }
  const body = req.body || {};
  const payload = JSON.stringify({
    prompt: (body.messages && body.messages.length)
      ? body.messages[body.messages.length - 1].content
      : '',
    system: (body.messages && body.messages.length > 1)
      ? body.messages[0].content
      : undefined,
    task_type: body.task_type || 'general',
    model: body.model,
    max_tokens: body.max_tokens || 1024,
  });

  const url = new URL('/api/chat', GATEWAY_URL);
  if (!networkAllowed(url)) {
    recordRemoteAttempt(url, false, 'offline policy');
    return res.status(503).json({
      error: 'Remote AI requires explicit network enablement',
      code: 'OFFLINE_NETWORK_BLOCKED',
    });
  }
  const options = {
    hostname: url.hostname,
    port: resolveUpstreamPort(url),
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-SG-Agent': agentId,
      'Content-Length': Buffer.byteLength(payload),
    },
  };

  const client = requestClientFor(url);
  const proxyReq = client.request(options, (proxyRes) => {
    let data = '';
    proxyRes.on('data', (chunk) => { data += chunk; });
    proxyRes.on('end', () => {
      try {
        const result = JSON.parse(data);
        res.json({
          choices: [{
            message: { content: result.result || result.error || data, role: 'assistant' },
          }],
          agent: agentId,
          timestamp: new Date().toISOString(),
        });
      } catch {
        res.json({
          choices: [{ message: { content: data || 'No response', role: 'assistant' } }],
          agent: agentId,
          timestamp: new Date().toISOString(),
        });
      }
    });
  });

  proxyReq.on('error', (err) => {
    console.error('[ai-proxy] gateway error for %s: %s', agentId, err.message);
    res.json({
      choices: [{ message: { content: '[' + agentId + ' offline] Gateway unreachable', role: 'assistant' } }],
      agent: agentId,
      error: true,
    });
  });

  proxyReq.write(payload);
  proxyReq.end();
});

app.use('/api/chat', (req, res) => proxyRequest(GATEWAY_URL, req, res));
app.use('/api/voice', (req, res) => proxyRequest(GATEWAY_URL, req, res));
app.use('/api/plugins', (req, res) => proxyRequest(GATEWAY_URL, req, res));
app.use('/api/judge', (req, res) => proxyRequest(GATEWAY_URL, req, res));

// GET /api/agents/status
app.get('/api/agents/status', async (_req, res) => {
  const agents = {
    gateway: { url: GATEWAY_URL, status: 'offline', port: 9001 },
    backend: { url: BACKEND_URL, status: 'offline', port: 8002 },
    weather: { url: WEATHER_URL, status: 'offline', port: 8001 },
    py_bridge: { url: SG_BRIDGE_HTTP_URL, status: 'offline', port: 9897, role: 'python-bridge' },
  };

  const checkAgent = (key) =>
    new Promise((resolve) => {
      const baseUrl = agents[key].url;
      if (!baseUrl) return resolve();

      let target;
      try {
        target = new URL('/health', baseUrl);
      } catch {
        return resolve();
      }
      if (!networkAllowed(target)) {
        recordRemoteAttempt(target, false, 'status probe blocked by offline policy');
        return resolve();
      }

      const client = requestClientFor(target);
      const req = client.request({
        hostname: target.hostname,
        port: resolveUpstreamPort(target),
        path: target.pathname + target.search,
        method: 'GET',
        timeout: 3000,
      }, (r) => {
        let data = '';
        r.on('data', (chunk) => { data += chunk; });
        r.on('end', () => {
          if (r.statusCode && r.statusCode < 500) {
            agents[key].status = 'online';
            try { agents[key].detail = JSON.parse(data); } catch { /* skip */ }
          }
          resolve();
        });
      });
      req.setTimeout(3000, () => { req.destroy(); resolve(); });
      req.on('error', () => resolve());
      req.end();
    });

  await Promise.all(Object.keys(agents).map(checkAgent));

  const onlineCount = Object.values(agents).filter((a) => a.status === 'online').length;
  res.json({
    ecosystem: onlineCount === Object.keys(agents).length ? 'healthy' : onlineCount > 0 ? 'degraded' : 'offline',
    agents,
    bridge: { status: 'online', uptime: process.uptime(), websocket_clients: clients.size + rootClients.size },
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Metrics / bridge status / notify
// ---------------------------------------------------------------------------
app.get('/api/metrics', (_req, res) => {
  const mem = process.memoryUsage();
  res.json({
    uptime_s: process.uptime(),
    memory: mem,
    pid: process.pid,
    node: process.version,
    websocket_clients: clients.size + rootClients.size,
    network_mode: NETWORK_MODE,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/bridge/status', (_req, res) => {
  res.json({
    service: 'node-bridge',
    status: 'online',
    port: PORT,
    uptime_s: process.uptime(),
    backends: { api: BACKEND_URL, weather: WEATHER_URL, gateway: GATEWAY_URL },
    websocket: { alerts: clients.size, root: rootClients.size },
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/bridge/notify', (req, res) => {
  const payload = JSON.stringify({ type: 'notify', ...(req.body || {}), ts: new Date().toISOString() });
  let sent = 0;
  for (const ws of clients) {
    if (ws.readyState === 1) {
      ws.send(payload);
      sent += 1;
    }
  }
  res.json({ ok: true, delivered: sent });
});

// Fail-closed stubs for optional capabilities (report UNAVAILABLE, never fake success)
function unavailable(res, capability) {
  return res.status(503).json({ status: 'UNAVAILABLE', capability, code: 'REQUIRE_APPROVAL' });
}

app.post('/validate/step', (_req, res) => unavailable(res, 'validate/step'));
app.post('/validate/signatures', (_req, res) => unavailable(res, 'validate/signatures'));
app.post('/tpm/attest', (_req, res) => unavailable(res, 'tpm/attest'));
app.post('/threats/feed', (_req, res) => unavailable(res, 'threats/feed'));
app.post('/scan/directory', (_req, res) => unavailable(res, 'scan/directory'));
app.post('/test/poison', (_req, res) => unavailable(res, 'test/poison'));
app.post('/keycloak/token', (_req, res) => unavailable(res, 'keycloak/token'));
app.post('/mtls/handshake', (_req, res) => unavailable(res, 'mtls/handshake'));
app.post('/spiffe/svid', (_req, res) => unavailable(res, 'spiffe/svid'));

app.post('/proxy/fetch', (req, res) => {
  const target = req.body && req.body.url;
  if (!target) return res.status(400).json({ error: 'url required' });
  if (!networkAllowed(target)) {
    recordRemoteAttempt(target, false, 'offline policy');
    return res.status(503).json({ error: 'Outbound network disabled by offline policy', code: 'OFFLINE_NETWORK_BLOCKED' });
  }
  return unavailable(res, 'proxy/fetch');
});
app.post('/proxy/text', (req, res) => unavailable(res, 'proxy/text'));
app.post('/proxy', (req, res) => unavailable(res, 'proxy'));

app.post('/exec/code', (req, res) => {
  const lang = ((req.body && req.body.lang) || 'node').toLowerCase();
  const code = (req.body && req.body.code) || '';
  if (!code) return res.status(400).json({ error: 'No code provided' });
  if (lang === 'node' || lang === 'javascript' || lang === 'js') {
    try {
      const logs = [];
      const sandbox = {
        console: {
          log: (...args) => logs.push(args.map(String).join(' ')),
          error: (...args) => logs.push('[ERR] ' + args.map(String).join(' ')),
          warn: (...args) => logs.push('[WARN] ' + args.map(String).join(' ')),
        },
        Math, Date, JSON, parseInt, parseFloat, String, Number, Boolean, Array, Object,
      };
      const ctx = vm.createContext(sandbox);
      const script = new vm.Script(code, { filename: 'exec-code.js', timeout: 10000 });
      const result = script.runInContext(ctx, { timeout: 10000 });
      if (result !== undefined && logs.length === 0) {
        logs.push(typeof result === 'object' ? JSON.stringify(result, null, 2) : String(result));
      }
      return res.json({ output: logs.join('\n') || '(no output)', lang });
    } catch (err) {
      return res.status(400).json({ output: '', error: err.message, lang });
    }
  }
  if (lang === 'python' || lang === 'py') {
    return execFile('python3', ['-c', code], { timeout: 15000, maxBuffer: 512 * 1024 }, (err, stdout, stderr) => {
      const output = (stdout || '') + (stderr ? '\n[stderr] ' + stderr : '');
      res.json({
        output: output || (err ? err.message : '(no output)'),
        error: err ? err.message : undefined,
        lang,
      });
    });
  }
  return res.status(400).json({ error: 'Unsupported lang: ' + lang });
});

app.get('/satellite/imagery', (_req, res) => unavailable(res, 'satellite/imagery'));
app.get('/satellite/goes', (_req, res) => unavailable(res, 'satellite/goes'));
app.get('/alerts/live', (_req, res) => {
  res.json({ alerts: [], source: 'node-bridge', timestamp: new Date().toISOString() });
});
app.post('/error_ping', (req, res) => {
  console.error('[error_ping]', JSON.stringify(req.body || {}).slice(0, 500));
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// WebSocket — /ws/alerts (broadcast) + root (Python-backend proxy)
// ---------------------------------------------------------------------------
const useTLS = TLS_CERT && TLS_KEY && fs.existsSync(TLS_CERT) && fs.existsSync(TLS_KEY);
const tlsOptions = useTLS
  ? {
      cert: fs.readFileSync(TLS_CERT),
      key: fs.readFileSync(TLS_KEY),
      requestCert: TLS_REQUEST_CERT || Boolean(TLS_CA),
      rejectUnauthorized: TLS_REJECT_UNAUTHORIZED,
      ca: TLS_CA && fs.existsSync(TLS_CA) ? fs.readFileSync(TLS_CA) : undefined,
    }
  : null;
const server = useTLS
  ? https.createServer(tlsOptions, app)
  : http.createServer(app);

const wss = new WebSocketServer({ noServer: true });
const wssRoot = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const pathname = (() => {
    try { return new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname; }
    catch { return '/'; }
  })();
  if (pathname === '/ws/alerts') {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  } else {
    wssRoot.handleUpgrade(req, socket, head, (ws) => wssRoot.emit('connection', ws, req));
  }
});

const clients = new Set();
const rootClients = new Set();

function handleWsExec(msg, ws) {
  const lang = (msg.lang || 'node').toLowerCase();
  const code = msg.code || '';
  const user = String(msg.user || 'anon').replace(/[^\x20-\x7E]/g, '').slice(0, 64) || 'anon';
  if (!code) {
    ws.send(JSON.stringify({ type: 'exec_result', output: '', error: 'No code provided' }));
    return;
  }
  if (lang === 'node' || lang === 'javascript' || lang === 'js') {
    try {
      const logs = [];
      const pendingTimers = [];
      const cryptoMod = require('crypto');
      const sandbox = {
        console: {
          log: (...args) => logs.push(args.map(String).join(' ')),
          error: (...args) => logs.push('[ERR] ' + args.map(String).join(' ')),
          warn: (...args) => logs.push('[WARN] ' + args.map(String).join(' ')),
          info: (...args) => logs.push(args.map(String).join(' ')),
        },
        Math, Date, JSON, parseInt, parseFloat, String, Number, Boolean, Array, Object,
        RegExp, Map, Set, Promise, Error, Buffer,
        setTimeout: (fn, ms) => { const t = setTimeout(fn, Math.min(ms || 0, 5000)); pendingTimers.push(t); return t; },
        clearTimeout: (t) => { clearTimeout(t); },
        crypto: {
          randomBytes: cryptoMod.randomBytes,
          randomUUID: cryptoMod.randomUUID,
          createHash: cryptoMod.createHash,
          createHmac: cryptoMod.createHmac,
          getRandomValues: (buf) => cryptoMod.randomFillSync(buf),
        },
        TextEncoder, TextDecoder,
      };
      const ctx = vm.createContext(sandbox);
      const script = new vm.Script(code, { filename: 'ws-exec.js', timeout: 10000 });
      const result = script.runInContext(ctx, { timeout: 10000 });
      pendingTimers.forEach((t) => clearTimeout(t));
      if (result !== undefined && logs.length === 0) {
        logs.push(typeof result === 'object' ? JSON.stringify(result, null, 2) : String(result));
      }
      ws.send(JSON.stringify({ type: 'exec_result', output: logs.join('\n') || '(no output)', lang, user }));
    } catch (err) {
      ws.send(JSON.stringify({ type: 'exec_result', output: '', error: err.message, lang, user }));
    }
  } else if (lang === 'python' || lang === 'py') {
    execFile('python3', ['-c', code], { timeout: 15000, maxBuffer: 512 * 1024 }, (err, stdout, stderr) => {
      const output = (stdout || '') + (stderr ? '\n[stderr] ' + stderr : '');
      ws.send(JSON.stringify({
        type: 'exec_result',
        output: output || (err ? err.message : '(no output)'),
        error: err ? err.message : undefined,
        lang, user,
      }));
    });
  } else {
    ws.send(JSON.stringify({ type: 'exec_result', output: '', error: 'Unsupported lang: ' + lang }));
  }
}

// /ws/alerts — broadcast channel for dashboard alerts/notifications
wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`[ws/alerts] client connected (${clients.size} total)`);
  ws.send(JSON.stringify({ type: 'welcome', channel: 'alerts', clients: clients.size }));

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid JSON' }));
      return;
    }
    if (msg.type === 'exec') {
      handleWsExec(msg, ws);
      return;
    }
    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
      return;
    }
    // Broadcast other messages to all alert clients
    const out = JSON.stringify({ type: 'broadcast', ...(msg || {}), ts: new Date().toISOString() });
    for (const client of clients) {
      if (client !== ws && client.readyState === 1) client.send(out);
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[ws/alerts] client disconnected (${clients.size} total)`);
  });

  ws.on('error', (err) => {
    console.error('[ws/alerts] error:', err.message);
    clients.delete(ws);
  });
});

// Root WebSocket — terminal / Python-backend proxy path
wssRoot.on('connection', (ws) => {
  rootClients.add(ws);
  console.log(`[ws/root] client connected (${rootClients.size} total)`);
  ws.send(JSON.stringify({ type: 'welcome', channel: 'root', clients: rootClients.size }));

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid JSON' }));
      return;
    }
    if (msg.type === 'exec') {
      handleWsExec(msg, ws);
      return;
    }
    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
      return;
    }
    ws.send(JSON.stringify({ type: 'ack', received: msg.type || 'unknown' }));
  });

  ws.on('close', () => {
    rootClients.delete(ws);
    console.log(`[ws/root] client disconnected (${rootClients.size} total)`);
  });

  ws.on('error', (err) => {
    console.error('[ws/root] error:', err.message);
    rootClients.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[node-bridge] listening on 127.0.0.1:${PORT} (TLS=${Boolean(useTLS)}) mode=${NETWORK_MODE}`);
});

server.on('error', (err) => {
  console.error('[node-bridge] server error:', err.message);
  process.exit(1);
});

module.exports = { app, server, clients, rootClients };
