'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadCanonicalState } = require('../backend/state/canonical_state');
const { createScarLogger } = require('../backend/audit/scar_logger');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canonical-bootstrap-'));
const state = path.join(root, 'state', 'canonical.json');
const scar = path.join(root, 'audit', 'scar.jsonl');
const script = path.resolve(__dirname, '../scripts/bootstrap-canonical-state.js');

function run(args) {
  return spawnSync(process.execPath, [script, '--state', state, '--scar', scar, ...args], {
    encoding: 'utf8',
    timeout: 5000
  });
}

try {
  const noConsent = run(['--owner', 'Appel420']);
  assert.notEqual(noConsent.status, 0, 'must deny bootstrap without explicit confirmation');
  assert.equal(fs.existsSync(state), false, 'must not create state without confirmation');

  const first = run(['--owner', 'Appel420', '--confirm-owner-bootstrap']);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /BOOTSTRAP=PASS/);
  const verified = loadCanonicalState(state);
  assert.equal(verified.allowed, true);
  assert.equal(verified.state.owner_id, 'Appel420');
  assert.equal(createScarLogger(scar).verifyChain().ok, true);

  const before = fs.readFileSync(state, 'utf8');
  const second = run(['--owner', 'attacker', '--confirm-owner-bootstrap']);
  assert.notEqual(second.status, 0, 'must refuse overwriting existing owner state');
  assert.match(second.stderr, /CANONICAL_STATE_ALREADY_EXISTS_REFUSING_OVERWRITE/);
  assert.equal(fs.readFileSync(state, 'utf8'), before, 'must preserve existing state byte-for-byte');
  process.stdout.write('PASS bootstrap requires explicit confirmation\nPASS canonical state verifies\nPASS SCAR receipt chain verifies\nPASS existing owner state cannot be overwritten\n');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
