'use strict';

const PROVIDERS = Object.freeze({
  xai: Object.freeze({ origin: 'https://api.x.ai', path: '/v1/chat/completions', protocol: 'openai-compatible' }),
  openai: Object.freeze({ origin: 'https://api.openai.com', path: '/v1/chat/completions', protocol: 'openai-compatible' }),
  anthropic: Object.freeze({ origin: 'https://api.anthropic.com', path: '/v1/messages', protocol: 'anthropic-messages' })
});

function createOfficialProviderAdapter(providerId, options = {}) {
  const spec = PROVIDERS[providerId];
  if (!spec) throw new Error('PROVIDER_CONTRACT_UNAVAILABLE');
  const fetchImpl = options.fetch || globalThis.fetch;
  const credential = options.credential;
  const model = options.model;
  const timeoutMs = options.timeoutMs === undefined ? 30000 : options.timeoutMs;
  if (typeof fetchImpl !== 'function') throw new Error('FETCH_UNAVAILABLE');
  if (typeof credential !== 'string' || credential.length < 16) throw new Error('LANE_CREDENTIAL_REQUIRED');
  if (typeof model !== 'string' || !model.trim()) throw new Error('PROVIDER_MODEL_REQUIRED');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) throw new Error('PROVIDER_TIMEOUT_INVALID');

  async function call(request) {
    if (!request || typeof request.prompt !== 'string' || !request.prompt.trim()) return Object.freeze({ ok: false, reason: 'INVALID_INPUT' });
    const url = new URL(spec.path, spec.origin);
    if (url.origin !== spec.origin || url.protocol !== 'https:') throw new Error('PROVIDER_DESTINATION_REJECTED');
    const headers = { 'content-type': 'application/json' };
    let body;
    if (spec.protocol === 'anthropic-messages') {
      headers['x-api-key'] = credential;
      headers['anthropic-version'] = '2023-06-01';
      body = { model, max_tokens: 1024, messages: [{ role: 'user', content: request.prompt }] };
    } else {
      headers.authorization = 'Bearer ' + credential;
      body = { model, messages: [{ role: 'user', content: request.prompt }] };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(body), signal: controller.signal, redirect: 'error' });
      if (!response || typeof response.status !== 'number' || typeof response.text !== 'function') throw new Error('PROVIDER_RESPONSE_INVALID');
      const raw = await response.text();
      let parsed;
      try { parsed = JSON.parse(raw); } catch { throw new Error('PROVIDER_RESPONSE_NOT_JSON'); }
      if (!response.ok) return Object.freeze({ ok: false, reason: 'PROVIDER_HTTP_' + response.status });
      const output = spec.protocol === 'anthropic-messages'
        ? (Array.isArray(parsed.content) ? parsed.content.filter(p => p && p.type === 'text').map(p => p.text).join('') : '')
        : (parsed.choices && parsed.choices[0] && parsed.choices[0].message ? parsed.choices[0].message.content : '');
      if (typeof output !== 'string' || !output) throw new Error('PROVIDER_RESPONSE_SHAPE_INVALID');
      return Object.freeze({ ok: true, provider: providerId, model: typeof parsed.model === 'string' ? parsed.model : model, output });
    } catch (error) {
      return Object.freeze({ ok: false, reason: error && error.name === 'AbortError' ? 'PROVIDER_TIMEOUT' : String(error && error.message || 'PROVIDER_TRANSPORT_FAILURE').slice(0, 120) });
    } finally { clearTimeout(timer); }
  }
  return Object.freeze({ provider: providerId, origin: spec.origin, network: 'EXTERNAL', call });
}
module.exports = { PROVIDERS, createOfficialProviderAdapter };
