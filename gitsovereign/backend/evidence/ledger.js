// GitSovereign — evidence ledger.
// Append-only, hash-chained. Canonical JSON uses sorted object keys.
// Each event references the previous event hash and receives a monotonic sequence.
// No randomness is used for identity, ordering, or integrity.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortKeysDeep(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function canonicalJSON(value) {
  return JSON.stringify(sortKeysDeep(value));
}

function canonicalHash(value) {
  return 'sha256:' + crypto
    .createHash('sha256')
    .update(canonicalJSON(value), 'utf8')
    .digest('hex');
}

class EvidenceLedger {
  constructor(filePath) {
    this.filePath = path.resolve(
      filePath || path.join(__dirname, 'evidence.log.jsonl')
    );
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    if (!fs.existsSync(this.filePath)) {
      fs.writeFileSync(this.filePath, '', { encoding: 'utf8', flag: 'wx' });
    }
  }

  _readAll() {
    const raw = fs.readFileSync(this.filePath, 'utf8').trim();
    if (!raw) return [];
    return raw.split('\n').map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`Invalid ledger JSON at line ${index + 1}: ${error.message}`);
      }
    });
  }

  append(event) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('event must be a JSON object');
    }
    if (Object.prototype.hasOwnProperty.call(event, 'sequence') ||
        Object.prototype.hasOwnProperty.call(event, 'previous_hash') ||
        Object.prototype.hasOwnProperty.call(event, 'event_hash')) {
      throw new Error('sequence, previous_hash, and event_hash are ledger-controlled fields');
    }

    const all = this._readAll();
    const previous = all.length ? all[all.length - 1] : null;
    const candidate = {
      sequence: all.length + 1,
      previous_hash: previous ? previous.event_hash : null,
      timestamp: new Date().toISOString(),
      ...event,
    };

    candidate.event_hash = canonicalHash(candidate);
    fs.appendFileSync(
      this.filePath,
      JSON.stringify(candidate) + '\n',
      { encoding: 'utf8', flag: 'a' }
    );
    return Object.freeze(candidate);
  }

  recent(limit = 50) {
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new RangeError('limit must be a non-negative safe integer');
    }
    return this._readAll().slice(-limit).reverse();
  }

  verifyChain() {
    const all = this._readAll();
    let previousHash = null;
    let expectedSequence = 1;

    for (const event of all) {
      const { event_hash, ...rest } = event;
      if (event.sequence !== expectedSequence) return false;
      if (event.previous_hash !== previousHash) return false;
      if (typeof event_hash !== 'string') return false;
      if (canonicalHash(rest) !== event_hash) return false;
      previousHash = event_hash;
      expectedSequence += 1;
    }

    return true;
  }
}

module.exports = { EvidenceLedger, canonicalHash, canonicalJSON, sortKeysDeep };
