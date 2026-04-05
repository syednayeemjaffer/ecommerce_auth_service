const pool = require("../config/db");

const initTables = async () => {
  try {
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("✅ users table ready");
  } catch (error) {
    console.error("❌ table init error:", error.message);
  }
};

module.exports = initTables;