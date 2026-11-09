'use strict';

/**
 * Isolated company-lane boundary.
 *
 * This module deliberately does not implement vendor HTTP APIs. It accepts
 * only an injected adapter implementing { call(request) }, and never reads
 * credentials from shared process environment. A lane owns its credential
 * reference, memory namespace, transport decision, and SCAR logger.
 *
 * A missing adapter or missing explicit policy is a hard denial.
 */
const crypto = require('node:crypto');
const { decideProvider } = require('../integration/provider_policy');

const MAX_LANES = 10;
const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function requireId(value, field) {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) {
    throw new TypeError(field + '_INVALID');
  }
  return value;
}

function createCompanyPipeRegistry({ lanes, adapterBindings, memoryStores, transportPolicies, scarLoggers, policyPath }) {
  if (!Array.isArray(lanes) || lanes.length !== MAX_LANES) {
    throw new TypeError('EXACTLY_TEN_LANES_REQUIRED');
  }
  for (const [name, value] of Object.entries({
    adapterBindings, memoryStores, transportPolicies, scarLoggers
  })) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError(name.toUpperCase() + '_REQUIRED');
    }
  }

  const seen = new Set();
  const pipes = new Map();

  for (const lane of lanes) {
    if (!lane || typeof lane !== 'object') throw new TypeError('LANE_INVALID');
    const laneId = requireId(lane.lane_id, 'LANE_ID');
    const companyId = requireId(lane.company_id, 'COMPANY_ID');
    const providerId = requireId(lane.provider_id, 'PROVIDER_ID');
    if (seen.has(laneId) || seen.has(companyId)) throw new Error('LANE_IDENTITY_COLLISION');
    seen.add(laneId);
    seen.add(companyId);

    const adapter = adapterBindings[laneId];
    const memory = memoryStores[laneId];
    const transport = transportPolicies[laneId];
    const scar = scarLoggers[laneId];

    if (!adapter || typeof adapter.call !== 'function') {
      pipes.set(laneId, Object.freeze({ laneId, companyId, providerId, state: 'UNBOUND' }));
      continue;
    }
    if (!memory || typeof memory.read !== 'function' || typeof memory.write !== 'function') {
      throw new TypeError('LANE_MEMORY_STORE_INVALID:' + laneId);
    }
    if (!transport || !['LOCAL', 'HYBRID', 'ONLINE'].includes(transport.mode) ||
        transport.allow_external !== true && transport.mode !== 'LOCAL' ||
        transport.mode !== 'LOCAL' && (!Array.isArray(transport.allowed_hosts) || transport.allowed_hosts.length === 0)) {
      throw new TypeError('LANE_TRANSPORT_POLICY_INVALID:' + laneId);
    }
    if (!scar || typeof scar.append !== 'function') throw new TypeError('LANE_SCAR_LOGGER_INVALID:' + laneId);

    const decision = decideProvider(providerId, policyPath);
    pipes.set(laneId, Object.freeze({
      laneId, companyId, providerId, state: decision.decision === 'ALLOW' ? 'BOUND' : 'POLICY_DENIED',
      async call({ requestId, actorId, prompt, memoryKeys = [] }) {
        const event = { participant: companyId, action: 'provider.call', policy: decision.policy_version || 'provider-policy-unknown', result: 'DENY' };
        try {
          if (decision.decision !== 'ALLOW') throw new Error(decision.reason);
          if (typeof requestId !== 'string' || !requestId || typeof actorId !== 'string' || !actorId ||
              typeof prompt !== 'string' || !prompt || !Array.isArray(memoryKeys)) {
            throw new TypeError('REQUEST_INVALID');
          }
          const transportDecision = transport.mode === 'LOCAL'
            ? { allow: true, reason: 'LOCAL_MODE' }
            : { allow: transport.allow_external === true, reason: 'EXPLICIT_EGRESS_POLICY_REQUIRED' };
          if (!transportDecision.allow) throw new Error(transportDecision.reason);

          const scopedMemory = Object.freeze({
            namespace: laneId,
            read: key => {
              if (typeof key !== 'string' || !memoryKeys.includes(key)) throw new Error('MEMORY_SCOPE_DENIED');
              return memory.read(key);
            },
            write: (key, value) => {
              if (typeof key !== 'string' || !memoryKeys.includes(key)) throw new Error('MEMORY_SCOPE_DENIED');
              return memory.write(key, value);
            }
          });

          // Credentials remain inside the injected lane adapter. They are never
          // copied into request data, logs, or another provider's context.
          const result = await adapter.call(Object.freeze({
            request_id: requestId,
            actor_id: actorId,
            prompt,
            memory: scopedMemory,
            transport: Object.freeze({
              mode: transport.mode,
              allowed_hosts: Object.freeze([...(transport.allowed_hosts || [])])
            })
          }));
          if (!result || result.ok !== true) throw new Error('PROVIDER_ADAPTER_DID_NOT_RETURN_SUCCESS');
          event.result = 'ALLOW';
          event.details = { lane_id: laneId, request_id: requestId, provider_id: providerId };
          return Object.freeze({ ok: true, lane_id: laneId, result });
        } catch (error) {
          event.details = {
            lane_id: laneId,
            reason: String(error && error.message || 'PROVIDER_FAILURE').slice(0, 160)
          };
          return Object.freeze({ ok: false, lane_id: laneId, reason: event.details.reason });
        } finally {
          // Never include prompt, memory contents, credentials, or raw response.
          const receipt = scar.append(event);
          if (!receipt || receipt.ok !== true) {
            // Evidence failure invalidates an otherwise successful call.
            throw new Error('SCAR_APPEND_FAILED:' + laneId);
          }
        }
      }
    }));
  }

  return Object.freeze({
    list: () => Object.freeze([...pipes.values()].map(({ laneId, companyId, providerId, state }) =>
      Object.freeze({ lane_id: laneId, company_id: companyId, provider_id: providerId, state }))),
    get: laneId => pipes.get(laneId) || null
  });
}

module.exports = { MAX_LANES, createCompanyPipeRegistry };
