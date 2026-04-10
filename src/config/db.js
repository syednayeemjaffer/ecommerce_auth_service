require("dotenv").config();
const { Pool } = require("pg");
const { createUsersTableIfNotExists } = require("../utils/query_helper");

console.log("DATABASE_URL =", process.env.DATABASE_URL);

// ─── Parse DB Name from Connection String ────────────────────────────────────
// We extract the database name so we can first connect to "postgres" (admin DB)
// and create our target database if it doesn't exist yet.
const dbUrl = new URL(process.env.DATABASE_URL);
const dbName = dbUrl.pathname.substring(1); // Remove the leading "/"
// ─── Admin Pool (postgres default DB) ───────────────────────────────────────
// Used only during startup to check/create the target database.
// Connects to "postgres" base DB instead of the app DB.
const adminPool = new Pool({
  connectionString: process.env.DATABASE_URL.replace(`/${dbName}`, "/postgres"),
});
/**
 * Checks if the target database exists; creates it if not.
 * Runs once at startup using the admin pool, then closes it.
 */
const createDatabaseIfNotExists = async () => {
  try {
    // Check if the database already exists in pg_database catalog
    const result = await adminPool.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [dbName]
    );

    if (result.rows.length === 0) {
      console.log(`Database "${dbName}" does not exist. Creating...`);
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      console.log(`✅ Database "${dbName}" created successfully`);
    } else {
      console.log(`✅ Database "${dbName}" already exists`);
    }
  } catch (error) {
    console.error("❌ Error creating database:", error);
    throw error;
  } finally {
    // Always close the admin pool after this one-time check
    await adminPool.end();
  }
};

// ─── App Pool (singleton) ─────────────────────────────────────────────────
// This is the main connection pool used throughout the application.
// It's initialized once and reused via getPool().
let pool;

/**
 * Initializes the database:
 *  1. Creates the target DB if missing (via admin pool)
 *  2. Creates the app pool connected to the target DB
 *  3. Runs table migrations
 *
 * Should be called once at app startup (in app.js).
 * Returns the pool instance for convenience.
 */
const initializePool = async () => {
  // Guard: don't re-initialize if already done
  if (pool) return pool;

  // Step 1: Ensure the database exists
  await createDatabaseIfNotExists();

  // Step 2: Create the main app pool
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });

  // Log successful client connections
  pool.on("connect", () => {
    console.log("🔌 Connected to PostgreSQL");
  });

  // Fatal error on idle client — safest to crash and restart
  pool.on("error", (err) => {
    console.error("❌ Unexpected error on idle PostgreSQL client:", err);
    process.exit(-1);
  });

  // Step 3: Run table creation migrations
  await createUsersTableIfNotExists(pool);

  return pool;
};

/**
 * Returns the initialized pool.
 * Throws if called before initializePool() completes.
 * Use this in controllers/services after startup.
 */
const getPool = () => {
  if (!pool) {
    throw new Error("❌ Database pool has not been initialized yet. Call initializePool() first.");
  }
  return pool;
};

module.exports = { initializePool, getPool };