// ─── Database Migrations ──────────────────────────────────────────────────────

/**
 * Creates the `users` table if it doesn't already exist.
 * Also enables the pgcrypto extension for UUID generation (gen_random_uuid).
 *
 * Called once at startup after the app pool is ready.
 *
 * Table columns:
 *  - id           UUID, auto-generated primary key
 *  - name         User's display name
 *  - email        Unique email (login identifier)
 *  - password_hash Bcrypt hash (NULL for OAuth users)
 *  - role         'USER' or 'ADMIN' (default: 'USER')
 *  - user_image   Path or URL to profile image (nullable)
 *  - provider     Auth method: 'LOCAL', 'GOOGLE', 'GITHUB'
 *  - provider_id  OAuth provider's user ID (nullable, for OAuth users)
 *  - created_at   Timestamp of account creation
 *
 * @param {Pool} pool - Initialized PostgreSQL pool
 */
const createUsersTableIfNotExists = async (pool) => {
  await pool.query(`
    -- Enable pgcrypto for gen_random_uuid()
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    CREATE TABLE IF NOT EXISTS users (
      id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name          VARCHAR(100) NOT NULL,
      email         VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT         NULL,                          -- NULL for OAuth users
      role          VARCHAR(20)  DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
      user_image    TEXT         NULL,
      provider      VARCHAR(30)  DEFAULT 'LOCAL',               -- LOCAL | GOOGLE | GITHUB
      provider_id   VARCHAR(255) NULL,                          -- OAuth provider's user ID
      created_at    TIMESTAMP    DEFAULT NOW()
    );
  `);
};

module.exports = { createUsersTableIfNotExists };