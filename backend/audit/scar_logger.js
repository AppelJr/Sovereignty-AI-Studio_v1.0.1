'use strict';

/**
 * SCAR Evidence Logger — fail-closed runtime JSONL ledger.
 * Hash linkage detects modification; it is not a signature or authorization.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCAR_REASON = Object.freeze({
  INVALID: 'INVALID',
  APPENDED: 'APPENDED',
  READ: 'READ',
  CHAIN_OK: 'CHAIN_OK',
  CHAIN_BROKEN: 'CHAIN_BROKEN'
});
const GENESIS_HASH = '0'.repeat(64);

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function canonicalEntryBody(entry) {
  const body = {
    action: entry.action,
    participant: entry.participant,
    policy: entry.policy,
    prev_hash: entry.prev_hash,
    result: entry.result,
    timestamp: entry.timestamp
  };
  if (entry.details !== undefined) body.details = entry.details;
  return JSON.stringify(body);
}

function createScarLogger(logPath) {
  if (typeof logPath !== 'string' || !logPath || !path.isAbsolute(logPath)) {
    throw new Error('logPath must be a non-empty absolute path');
  }

  function ensureDir() {
    fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
    try {
      if (fs.lstatSync(logPath).isSymbolicLink()) throw new Error('SCAR symlink path refused');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  function readAll() {
    let raw;
    try {
      const st = fs.lstatSync(logPath);
      if (st.isSymbolicLink() || !st.isFile()) {
        return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, entries: [], threat: true };
      }
      raw = fs.readFileSync(logPath, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') return { ok: true, reason: SCAR_REASON.READ, entries: [] };
      throw error;
    }
    if (raw.length === 0) return { ok: true, reason: SCAR_REASON.READ, entries: [] };
    if (!raw.endsWith('\n')) {
      return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, entries: [], threat: true };
    }
    const lines = raw.slice(0, -1).split('\n');
    if (lines.some(line => line.length === 0)) {
      return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, entries: [], threat: true };
    }
    const entries = [];
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('record must be object');
        entries.push(entry);
      } catch {
        return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, entries: [], threat: true };
      }
    }
    return { ok: true, reason: SCAR_REASON.READ, entries };
  }

  function verifyChain() {
    const snap = readAll();
    if (!snap.ok) return snap;
    let prev = GENESIS_HASH;
    for (const entry of snap.entries) {
      if (entry.prev_hash !== prev || typeof entry.hash !== 'string') {
        return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, threat: true };
      }
      const expected = sha256Hex(canonicalEntryBody(entry));
      if (entry.hash !== expected) {
        return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, threat: true };
      }
      prev = entry.hash;
    }
    return { ok: true, reason: SCAR_REASON.CHAIN_OK, count: snap.entries.length, threat: false };
  }

  function append(ev) {
    if (!ev || typeof ev !== 'object' || Array.isArray(ev) ||
        typeof ev.participant !== 'string' || !ev.participant ||
        typeof ev.action !== 'string' || !ev.action ||
        typeof ev.policy !== 'string' || !ev.policy ||
        typeof ev.result !== 'string' || !ev.result) {
      return { ok: false, reason: SCAR_REASON.INVALID, threat: true };
    }

    ensureDir();
    const verified = verifyChain();
    if (!verified.ok) {
      return { ok: false, reason: SCAR_REASON.CHAIN_BROKEN, threat: true };
    }
    const snap = readAll();
    const prev_hash = snap.entries.length
      ? snap.entries[snap.entries.length - 1].hash
      : GENESIS_HASH;
    const entry = {
      timestamp: Date.now(),
      participant: ev.participant,
      action: ev.action,
      policy: ev.policy,
      result: ev.result,
      prev_hash
    };
    if (ev.details !== undefined) entry.details = ev.details;
    entry.hash = sha256Hex(canonicalEntryBody(entry));

    const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND |
      fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0);
    const fd = fs.openSync(logPath, flags, 0o600);
    try {
      if (!fs.fstatSync(fd).isFile()) throw new Error('SCAR ledger is not a regular file');
      fs.writeFileSync(fd, JSON.stringify(entry) + '\n', { encoding: 'utf8' });
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return { ok: true, reason: SCAR_REASON.APPENDED, hash: entry.hash, prev_hash, threat: false };
  }

  return Object.freeze({ append, readAll, verifyChain, path: logPath, SCAR_REASON });
}

module.exports = { SCAR_REASON, createScarLogger };
