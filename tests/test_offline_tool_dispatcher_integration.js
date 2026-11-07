'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-dispatch-'));
const statePath = path.join(root, 'state.json');
const scarPath = path.join(root, 'scar.jsonl');
const signingKey = 'test-only-session-signing-key-at-least-32-bytes';
process.env.SOVEREIGN_STATE_PATH = statePath;
process.env.SCAR_PATH = scarPath;
process.env.SOVEREIGN_SESSION_SIGNING_KEY = signingKey;
process.env.SOVEREIGN_PYTHON_EXECUTABLE = '/usr/bin/python3';

const {
  buildCanonicalState,
  writeCanonicalState
} = require('../backend/state/canonical_state');
const { executeLocalTool } = require('../node-bridge/devassist420-handler');

function ownerProof(capabilities) {
  const payload = Buffer.from(JSON.stringify({
    session_id: 'test-session-1',
    identity_id: 'Appel420',
    capabilities,
    mode: 'offline',
    expires_at: Math.floor(Date.now() / 1000) + 300
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', signingKey).update(payload, 'ascii').digest('base64url');
  return payload + '.' + signature;
}

async function main() {
  const now = Date.now();
  writeCanonicalState(statePath, buildCanonicalState({
    version: '1.0.0',
    owner_id: 'Appel420',
    created_at: now,
    updated_at: now,
    policy_version: '1.0.0',
    mode_default: 'offline'
  }));

  const denied = await executeLocalTool(
    { tool: 'echo', args: ['should-not-run'], request_id: 'denied-request' },
    ownerProof(['ai.inference'])
  );
  assert.equal(denied.state, 'DENY');
  assert.equal(denied.reason, 'OWNER_CAPABILITY_MISSING');
  assert.equal(denied.evidence.ok, true, 'denied request must have durable SCAR evidence');
  const deniedEvents = fs.readFileSync(scarPath, 'utf8').trim().split('\\n').map(JSON.parse);
  assert.equal(deniedEvents.length, 1);
  assert.equal(deniedEvents[0].result, 'DENY');
  assert.equal(deniedEvents[0].details.dispatcher_started, false);

  const result = await executeLocalTool(
    { tool: 'echo', args: ['Sovereignty', 'dispatcher'], request_id: 'approved-request' },
    ownerProof(['local.tool.execute'])
  );
  assert.equal(result.state, 'EXECUTED');
  assert.equal(result.result.status, 'success');
  assert.equal(result.result.stdout, 'Sovereignty dispatcher\n');
  assert.match(result.result.stdout_sha3_512, /^[a-f0-9]{128}$/);
  assert.equal(result.evidence.ok, true);

  const lines = fs.readFileSync(scarPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 2);
  assert.equal(lines[1].result, 'ALLOW');
  assert.equal(lines[1].details.capability, 'local.tool.execute');
  assert.equal(lines[1].details.request_id, 'approved-request');
  assert.match(lines[1].details.stdout_sha3_512, /^[a-f0-9]{128}$/);

  const deniedTool = await executeLocalTool(
    { tool: 'python', args: ['-c', 'print(1)'], request_id: 'blocked-tool' },
    ownerProof(['local.tool.execute'])
  );
  assert.equal(deniedTool.state, 'DENY');
  const all = fs.readFileSync(scarPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(all.length, 3);
  assert.equal(all[2].result, 'DENY');
  assert.equal(all[2].details.dispatcher_status, 'denied');

  console.log('PASS owner capability gates local dispatcher');
  console.log('PASS fixed allowlist executes echo only');
  console.log('PASS stdout SHA3-512 provenance bound to SCAR');
  console.log('PASS denied tool call is recorded in SCAR');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
});
