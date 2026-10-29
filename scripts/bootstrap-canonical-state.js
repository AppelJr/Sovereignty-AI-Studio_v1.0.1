'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  buildCanonicalState,
  loadCanonicalState,
  writeCanonicalState
} = require('../backend/state/canonical_state');
const { createScarLogger } = require('../backend/audit/scar_logger');

function fail(message) {
  process.stderr.write(`BOOTSTRAP=DENY reason=${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const out = { owner: '', confirmed: false, state: '', scar: '' };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--confirm-owner-bootstrap') out.confirmed = true;
    else if (arg === '--owner' && argv[i + 1]) out.owner = argv[++i];
    else if (arg === '--state' && argv[i + 1]) out.state = argv[++i];
    else if (arg === '--scar' && argv[i + 1]) out.scar = argv[++i];
    else fail(`UNKNOWN_OR_INCOMPLETE_ARGUMENT:${arg}`);
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.confirmed) fail('EXPLICIT_OWNER_CONFIRMATION_REQUIRED');
  if (!args.owner || !/^[A-Za-z0-9._@-]{1,128}$/.test(args.owner)) fail('VALID_OWNER_ID_REQUIRED');

  const statePath = path.resolve(args.state || process.env.SOVEREIGN_STATE_PATH || 'state/canonical.json');
  const scarPath = path.resolve(args.scar || process.env.SCAR_PATH || 'AUDIT/devassist-device.jsonl');
  if (fs.existsSync(statePath)) fail('CANONICAL_STATE_ALREADY_EXISTS_REFUSING_OVERWRITE');

  const state = buildCanonicalState({
    owner_id: args.owner,
    policy_version: '1.0.0',
    mode_default: 'offline',
    authority: { root: 'human', owner_id: args.owner, orchestrator: 'DevAssist420' }
  });
  writeCanonicalState(statePath, state);

  const receipt = createScarLogger(scarPath).append({
    participant: args.owner,
    action: 'bootstrap_canonical_state',
    policy: 'owner-state-sovereignty-v1',
    result: 'ALLOW',
    details: {
      state_path: statePath,
      state_hash: state.hash,
      state_version: state.version,
      network_accessed: false,
      external_data_sent: false,
      confirmation: '--confirm-owner-bootstrap'
    }
  });
  if (!receipt.ok) fail('SCAR_RECEIPT_FAILED_STATE_WRITTEN_REQUIRES_MANUAL_REVIEW');

  const verified = loadCanonicalState(statePath);
  if (!verified.allowed || verified.state.hash !== state.hash) fail('POST_WRITE_STATE_VERIFICATION_FAILED');
  process.stdout.write(`BOOTSTRAP=PASS\nOWNER=${args.owner}\nSTATE_PATH=${statePath}\nSTATE_HASH=${state.hash}\nSCAR_HASH=${receipt.hash}\nNETWORK_ACCESSED=false\n`);
}

try {
  main();
} catch (error) {
  fail(error && error.message ? error.message : 'UNEXPECTED_ERROR');
}
