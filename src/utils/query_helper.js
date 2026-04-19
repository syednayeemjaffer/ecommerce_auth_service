const createUsersTableIfNotExists = async (pool) => {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    CREATE TABLE IF NOT EXISTS users (
      id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name          VARCHAR(100) NOT NULL,
      email         VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT         NULL,
      role          VARCHAR(20)  DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
      user_image    TEXT         NULL,
      provider      VARCHAR(30)  DEFAULT 'LOCAL',
      provider_id   VARCHAR(255) NULL,
      created_at    TIMESTAMP    DEFAULT NOW()
    );
  `);
};

module.exports = { createUsersTableIfNotExists };