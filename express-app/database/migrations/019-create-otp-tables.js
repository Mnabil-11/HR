/**
 * Migration: Create OTP token tables
 *
 * The email-OTP login flow stores a hashed code (+ expiry + attempt count) per actor:
 *   - branch_otp_tokens  → branch_manager logins (codes emailed to the branch email)
 *   - user_otp_tokens    → branch_operations_manager logins (codes emailed to the user)
 *
 * These tables used to be created lazily by `CREATE TABLE IF NOT EXISTS` on EVERY
 * login/verify/resend request in routes/auth.js. That added 3 DDL round-trips to every
 * OTP request against a cold-start-sensitive database. This migration creates them once
 * so the per-request DDL can be dropped. (Note: these tables only hold a SHA-256 hash of
 * the emailed code — they have nothing to do with phone numbers or code delivery.)
 *
 * Run with: node database/migrations/019-create-otp-tables.js
 */

import sql from '../../config/database.js';

export async function up(db) {
  // Branch OTP tokens (branch_manager — stored in the branches table)
  await db`
    CREATE TABLE IF NOT EXISTS branch_otp_tokens (
      id SERIAL PRIMARY KEY,
      branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
      otp_hash VARCHAR(128) NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      attempts INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  await db`CREATE INDEX IF NOT EXISTS idx_branch_otp_branch_id ON branch_otp_tokens(branch_id)`;
  await db`CREATE INDEX IF NOT EXISTS idx_branch_otp_expires ON branch_otp_tokens(expires_at)`;
  // Speeds up the "latest token for this actor" lookup done on verify/resend.
  await db`CREATE INDEX IF NOT EXISTS idx_branch_otp_branch_created ON branch_otp_tokens(branch_id, created_at DESC)`;

  // User OTP tokens (branch_operations_manager — stored in the users table)
  await db`
    CREATE TABLE IF NOT EXISTS user_otp_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      otp_hash VARCHAR(128) NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      attempts INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  await db`CREATE INDEX IF NOT EXISTS idx_user_otp_user_id ON user_otp_tokens(user_id)`;
  await db`CREATE INDEX IF NOT EXISTS idx_user_otp_expires ON user_otp_tokens(expires_at)`;
  await db`CREATE INDEX IF NOT EXISTS idx_user_otp_user_created ON user_otp_tokens(user_id, created_at DESC)`;
}

// Standalone execution
const isMain = process.argv[1] && import.meta.url.includes(process.argv[1].split('\\').join('/').split('/').pop());
if (isMain) {
  console.log('Running migration 019 standalone...');
  up(sql)
    .then(() => console.log('Migration 019 completed.'))
    .catch(err => { console.error('Migration 019 failed:', err.message); process.exit(1); })
    .finally(() => sql.end());
}
