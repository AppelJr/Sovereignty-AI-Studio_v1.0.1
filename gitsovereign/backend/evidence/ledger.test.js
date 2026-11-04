'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const { EvidenceLedger, canonicalHash, canonicalJSON } = require('./ledger');

test('canonical JSON sorts object keys recursively', () => {
  assert.strictEqual(canonicalJSON({ z: 1, a: { y: 2, x: 3 } }), '{"a":{"x":3,"y":2},"z":1}');
});

test('ledger appends and verifies a hash chain', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsovereign-ledger-'));
  const file = path.join(dir, 'evidence.log.jsonl');
  const ledger = new EvidenceLedger(file);

  const first = ledger.append({ action: 'authorize', decision: 'allowed', reason: 'owner-approved' });
  const second = ledger.append({ action: 'execute', decision: 'allowed', reason: 'capability-valid' });

  assert.strictEqual(first.sequence, 1);
  assert.strictEqual(first.previous_hash, null);
  assert.strictEqual(second.sequence, 2);
  assert.strictEqual(second.previous_hash, first.event_hash);
  assert.strictEqual(ledger.verifyChain(), true);
  assert.deepStrictEqual(ledger.recent(2).map((event) => event.sequence), [2, 1]);
});

test('ledger rejects caller-controlled chain fields', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsovereign-ledger-'));
  const ledger = new EvidenceLedger(path.join(dir, 'evidence.log.jsonl'));
  assert.throws(() => ledger.append({ sequence: 99, action: 'tamper' }), /ledger-controlled fields/);
});

test('tampering breaks verification', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsovereign-ledger-'));
  const file = path.join(dir, 'evidence.log.jsonl');
  const ledger = new EvidenceLedger(file);
  ledger.append({ action: 'one' });
  ledger.append({ action: 'two' });

  const lines = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
  lines[0].action = 'tampered';
  fs.writeFileSync(file, lines.map(JSON.stringify).join('\n') + '\n');

  assert.strictEqual(ledger.verifyChain(), false);
});

assert.match(canonicalHash({ value: true }), /^sha256:[0-9a-f]{64}$/);
