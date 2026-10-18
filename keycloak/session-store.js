/**
 * GATEONE Persistent Session Store for Keycloak
 *
 * Replaces the in-memory Map with a PostgreSQL-backed store so sessions
 * survive restarts and token revocation is durable.
 *
 * Environment:
 *   KC_DB_HOST      – PostgreSQL host (default: localhost)
 *   KC_DB_PORT      – PostgreSQL port (default: 5432)
 *   KC_DB_NAME      – database name (default: keycloak)
 *   KC_DB_USER      – database user
 *   KC_DB_PASSWORD  – database password
 *
 * Provenance: Grok (xAI) drafted. Owner: AppelJr.
 * Timestamp: 2026-10-08T20:30:00Z. Version: v1.0.
 */

'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.KC_DB_HOST || 'localhost',
  port: parseInt(process.env.KC_DB_PORT || '5432', 10),
  database: process.env.KC_DB_NAME || 'keycloak',
  user: process.env.KC_DB_USER || 'keycloak',
  password: process.env.KC_DB_PASSWORD || '',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gateone_sessions (
      session_id   TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      node_id      TEXT,
      algorithm    TEXT,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at   TIMESTAMPTZ NOT NULL,
      revoked      BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_gateone_sessions_user
    ON gateone_sessions (user_id)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_gateone_sessions_expires
    ON gateone_sessions (expires_at)
  `);
}

async function createSession(sessionId, userId, nodeId, algorithm, ttlSeconds) {
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  await pool.query(
    `INSERT INTO gateone_sessions (session_id, user_id, node_id, algorithm, expires_at)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (session_id) DO UPDATE SET
       user_id = EXCLUDED.user_id,
       node_id = EXCLUDED.node_id,
       algorithm = EXCLUDED.algorithm,
       expires_at = EXCLUDED.expires_at,
       revoked = FALSE`,
    [sessionId, userId, nodeId, algorithm, expiresAt]
  );
}

async function getSession(sessionId) {
  const res = await pool.query(
    `SELECT * FROM gateone_sessions
     WHERE session_id = $1 AND revoked = FALSE AND expires_at > NOW()`,
    [sessionId]
  );
  return res.rows[0] || null;
}

async function revokeSession(sessionId) {
  await pool.query(
    `UPDATE gateone_sessions SET revoked = TRUE WHERE session_id = $1`,
    [sessionId]
  );
}

async function revokeAllForUser(userId) {
  await pool.query(
    `UPDATE gateone_sessions SET revoked = TRUE WHERE user_id = $1`,
    [userId]
  );
}

async function cleanupExpired() {
  await pool.query(
    `DELETE FROM gateone_sessions WHERE expires_at < NOW()`
  );
}

module.exports = {
  init,
  createSession,
  getSession,
  revokeSession,
  revokeAllForUser,
  cleanupExpired,
  pool,
};