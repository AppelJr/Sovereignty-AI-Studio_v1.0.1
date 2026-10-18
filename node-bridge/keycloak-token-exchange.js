/**
 * Keycloak Token Exchange Endpoint — node-bridge (port 9899)
 *
 * Validates minted credentials against a JWKS and exchanges them for
 * Keycloak-issued tokens. This is the bridge between the local OAuth
 * credential generator and a live authorization server.
 *
 * Environment:
 *   KEYCLOAK_URL        – Keycloak base URL (default: http://127.0.0.1:8080)
 *   KEYCLOAK_REALM      – Realm name (default: master)
 *   KEYCLOAK_CLIENT_ID  – Client ID for token exchange
 *   KEYCLOAK_CLIENT_SECRET – Client secret
 *   KEYCLOAK_JWKS_URL   – JWKS endpoint (default: derived from KEYCLOAK_URL/REALM)
 *
 * Endpoints:
 *   POST /keycloak/token/exchange  – Exchange a minted credential for a Keycloak token
 *   GET  /keycloak/jwks            – Proxy the Keycloak JWKS
 *   POST /keycloak/consent         – Consent flow stub (returns consent URL)
 *
 * Rate limiting: 10 requests per minute per IP.
 *
 * Provenance: Grok (xAI) drafted this file. Owner: AppelJr.
 * Timestamp: 2026-10-08T16:00:00Z. Version: v0.4.1.
 */

'use strict';

const http = require('http');
const https = require('https);
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CFG = {
  keycloakUrl: (process.env.KEYCLOAK_URL || 'http://127.0.0.1:8080').replace(/\/$/, ''),
  realm: process.env.KEYCLOAK_REALM || 'master',
  clientId: process.env.KEYCLOAK_CLIENT_ID || '',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET || '',
  jwksUrl: process.env.KEYCLOAK_JWKS_URL || '',
  rateLimit: 10,
  rateWindowMs: 60000,
  tokenCache: new Map(),
  jwksCache: { keys: null, fetchedAt: 0, ttlMs: 300000 },
  rateBuckets: new Map(),
};

if (!CFG.jwksUrl) {
  CFG.jwksUrl = `${CFG.keycloakUrl}/realms/${CFG.realm}/protocol/openid-connect/certs`;
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = CFG.rateBuckets.get(ip);
  if (!bucket || now > bucket.reset) {
    bucket = { count: 0, reset: now + CFG.rateWindowMs };
  }
  bucket.count += 1;
  CFG.rateBuckets.set(ip, bucket);
  return bucket.count <= CFG.rateLimit;
}

// ---------------------------------------------------------------------------
// JWKS fetching and caching
// ---------------------------------------------------------------------------

function fetchJwks() {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    if (CFG.jwksCache.keys && now - CFG.jwksCache.fetchedAt < CFG.jwksCache.ttlMs) {
      return resolve(CFG.jwksCache.keys);
    }
    let url;
    try {
      url = new URL(CFG.jwksUrl);
    } catch (e) {
      return reject(new Error('Invalid JWKS URL'));
    }
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        timeout: 10000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => {
          data += c;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(data);
              CFG.jwksCache.keys = parsed.keys || [];
              CFG.jwksCache.fetchedAt = now;
              resolve(CFG.jwksCache.keys);
            } catch (e) {
              reject(new Error('Invalid JWKS JSON: ' + e.message));
            }
          } else {
            reject(new Error('JWKS fetch failed: HTTP ' + res.statusCode));
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('JWKS fetch timeout'));
    });
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Token validation against JWKS
// ---------------------------------------------------------------------------

function base64urlDecode(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function verifyEd25519(message, signature, publicKeyRaw) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKeyRaw,
      ]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  } catch (e) {
    return false;
  }
}

function validateMintedToken(token) {
  return new Promise(async (resolve, reject) => {
    if (!token || typeof token !== 'string') {
      return reject(new Error('Token required'));
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      return reject(new Error('Invalid token format'));
    }
    let header, payload;
    try {
      header = JSON.parse(base64urlDecode(parts[0]).toString('utf8'));
      payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
    } catch (e) {
      return reject(new Error('Invalid token encoding'));
    }
    if (header.alg !== 'EdDSA' || header.crv !== 'Ed25519') {
      return reject(new Error('Unsupported algorithm: ' + (header.alg || 'none') + ' ' + (header.crv || '')));
    }
    if (payload.iss !== 'local') {
      return reject(new Error('Issuer must be local'));
    }
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return reject(new Error('Token expired'));
    }
    let keys;
    try {
      keys = await fetchJwks();
    } catch (e) {
      return reject(new Error('JWKS unavailable: ' + e.message));
    }
    const kid = header.kid;
    const key = keys.find((k) => k.kid === kid && k.kty === 'OKP' && k.crv === 'Ed25519' && k.alg === 'EdDSA' && k.use === 'sig);
    if (!key) {
      return reject(new Error('Key not found in JWKS for kid: ' + kid));
    }
    let publicKeyRaw;
    try {
      publicKeyRaw = base64urlDecode(key.x);
    } catch (e) {
      return reject(new Error('Invalid public key encoding'));
    }
    const message = Buffer.from(parts[0] + '.' + parts[1], 'utf8);
    const signature = base64urlDecode(parts[2]);
    if (!verifyEd25519(message, signature, publicKeyRaw)) {
      return reject(new Error('Invalid token signature'));
    }
    resolve(payload);
  });
}

// ---------------------------------------------------------------------------
// Keycloak token exchange
// ---------------------------------------------------------------------------

function exchangeWithKeycloak(subjectToken) {
  return new Promise((resolve, reject) => {
    if (!CFG.clientId || !CFG.clientSecret) {
      return reject(new Error('Keycloak client credentials not configured'));
    }
    const url = new URL(
      `${CFG.keycloakUrl}/realms/${CFG.realm}/protocol/openid-connect/token`
    );
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subjectToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      client_id: CFG.clientId,
      client_secret: CFG.clientSecret,
    }).toString();
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 15000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => {
          data += c;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(new Error('Invalid Keycloak response: ' + e.message));
            }
          } else {
            reject(
              new Error(
                'Keycloak token exchange failed: HTTP ' +
                  res.statusCode +
                  ' ' +
                  data.slice(0, 200)
              )
            );
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Keycloak request timeout'));
    });
    req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Consent flow stub
// ---------------------------------------------------------------------------

function consentUrl(redirectUri, state) {
  const params = new URLSearchParams({
    client_id: CFG.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email agent:read admin',
    state: state || crypto.randomBytes(16).toString('hex'),
  });
  return `${CFG.keycloakUrl}/realms/${CFG.realm}/protocol/openid-connect/auth?${params}`;
}

// ---------------------------------------------------------------------------
// HTTP handlers (mounted by node-bridge/server.js)
// ---------------------------------------------------------------------------

function handleExchange(req, res) {
  const ip = (req.socket && req.socket.remoteAddress) || 'unknown';
  if (!checkRateLimit(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Rate limit exceeded', code: 'RATE_LIMIT' }));
    return;
  }
  let body = '';
  req.on('data', (c) => {
    body += c;
    if (body.length > 1024 * 1024) {
      req.connection.destroy();
    }
  });
  req.on('end', async () => {
    let parsed;
    try {
      parsed = JSON.parse(body || '{}');
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const token = parsed.token || parsed.subject_token;
    if (!token) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'token required' }));
      return;
    }
    try {
      const payload = await validateMintedToken(token);
      const kcToken = await exchangeWithKeycloak(token);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify(
          {
            status: 'ok',
            minted_payload: payload,
            keycloak_token: kcToken,
            timestamp: new Date().toISOString(),
          },
          null,
          2
        )
      );
    } catch (e) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message, code: 'TOKEN_INVALID' }));
    }
  });
}

function handleJwks(req, res) {
  fetchJwks()
    .then((keys) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys }, null, 2));
    })
    .catch((e) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message, code: 'JWKS_UNAVAILABLE' }));
    });
}

function handleConsent(req, res) {
  let body = '';
  req.on('data', (c) => {
    body += c;
  });
  req.on('end', () => {
    let parsed;
    try {
      parsed = JSON.parse(body || '{}');
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const redirectUri = parsed.redirect_uri;
    if (!redirectUri) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'redirect_uri required' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify(
        {
          consent_url: consentUrl(redirectUri, parsed.state),
          note: 'Consent flow stub — configure KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET to enable.',
        },
        null,
        2
      )
    );
  });
}

module.exports = {
  handleExchange,
  handleJwks,
  handleConsent,
  CFG,
  validateMintedToken,
  exchangeWithKeycloak,
  consentUrl,
  fetchJwks,
};