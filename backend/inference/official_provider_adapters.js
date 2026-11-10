'use strict';

/**
 * First-party HTTPS adapters for documented text APIs.
 * Fixed origins and paths prevent caller-controlled destinations.
 * Credentials are lane-specific and never logged or returned.
 */
const PROVIDERS = Object.freeze({
  xai: Object.freeze({ origin: 'https://api.x.ai', path: '/v1/chat/completions', keyEnv: 'XAI_API_KEY', protocol: 'openai-compatible' }),
  openai: Object.freeze({ origin: 'https://api.openai.com', path: '/v1/chat/completions', keyEnv: 'OPENAI_API_KEY', protocol: 'openai-compatible' }),
  anthropic: Object.freeze({ origin: 'https://api.anthropic.com', path: '/v1/messages', keyEnv: 'ANTHROPIC_API_KEY', protocol: 'anthropic-messages' })
});

function safeResponse(response) {
  if (!response || typeof response.status !== 'number' || typeof response.text !== 'function') {
    throw new Error('PROVIDER_RESPONSE_INVALID');
  }
  return response;
}

function createOfficialProviderAdapter(providerId, options = {}) {
  const spec = PROVIDERS[providerId];
  if (!spec) throw new Error('PROVIDER_CONTRACT_UNAVAILABLE');
  const env = options.env || process.env;
  const fetchImpl = options.fetch || globalThis.fetch;
  const credential = options.credential || env[spec.keyEnv] || '';
  const model = options.model;
  const timeoutMs = options.timeoutMs === undefined ? 30000 : options.timeoutMs;

  if (typeof fetchImpl !== 'function') throw new Error('FETCH_UNAVAILABLE');
  if (typeof model !== 'string' || !model.trim()) throw new Error('PROVIDER_MODEL_REQUIRED');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
    throw new Error('PROVIDER_TIMEOUT_INVALID');
  }

  async function call(request) {
    if (!request || typeof request.prompt !== 'string' || !request.prompt.trim()) {
      return Object.freeze({ ok: false, reason: 'INVALID_INPUT' });
    }
    if (typeof credential !== 'string' || credential.length < 16) {
      return Object.freeze({ ok: false, reason: 'PROVIDER_CREDENTIAL_MISSING' });
    }

    const url = new URL(spec.path, spec.origin);
    if (url.origin !== spec.origin || url.protocol !== 'https:' || url.hostname !== new URL(spec.origin).hostname) {
      throw new Error('PROVIDER_DESTINATION_REJECTED');
    }

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
      const response = safeResponse(await fetchImpl(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
        redirect: 'error'
      }));
      const raw = await response.text();
      let parsed;
      try { parsed = JSON.parse(raw); } catch { throw new Error('PROVIDER_RESPONSE_NOT_JSON'); }
      if (!response.ok) {
        return Object.freeze({
          ok: false,
          reason: 'PROVIDER_HTTP_' + response.status,
          request_id: response.headers && typeof response.headers.get === 'function'
            ? response.headers.get('x-request-id') : null
        });
      }
      let output;
      if (spec.protocol === 'anthropic-messages') {
        output = Array.isArray(parsed.content)
          ? parsed.content.filter(part => part && part.type === 'text').map(part => part.text).join('')
          : '';
      } else {
        output = parsed.choices && parsed.choices[0] && parsed.choices[0].message
          ? parsed.choices[0].message.content : '';
      }
      if (typeof output !== 'string' || !output) throw new Error('PROVIDER_RESPONSE_SHAPE_INVALID');
      return Object.freeze({
        ok: true,
        provider: providerId,
        model: typeof parsed.model === 'string' ? parsed.model : model,
        output,
        request_id: response.headers && typeof response.headers.get === 'function'
          ? response.headers.get('x-request-id') : null
      });
    } catch (error) {
      return Object.freeze({
        ok: false,
        reason: error && error.name === 'AbortError' ? 'PROVIDER_TIMEOUT' :
          String(error && error.message || 'PROVIDER_TRANSPORT_FAILURE').slice(0, 120)
      });
    } finally {
      clearTimeout(timer);
    }
  }

  return Object.freeze({ provider: providerId, call });
}

module.exports = { PROVIDERS, createOfficialProviderAdapter };
