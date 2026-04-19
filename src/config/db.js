require("dotenv").config();
const { Pool } = require("pg");
const { createUsersTableIfNotExists } = require("../utils/query_helper");

const dbUrl = new URL(process.env.DATABASE_URL);
const dbName = dbUrl.pathname.substring(1);

const adminPool = new Pool({
  connectionString: process.env.DATABASE_URL.replace(`/${dbName}`, "/postgres"),
});

const createDatabaseIfNotExists = async () => {
  try {
    const result = await adminPool.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [dbName]
    );
    if (result.rows.length === 0) {
      console.log(`Database "${dbName}" does not exist. Creating...`);
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      console.log(`Database "${dbName}" created successfully`);
    } else {
      console.log(`Database "${dbName}" already exists`);
    }
  } catch (error) {
    console.error("Error creating database:", error);
    throw error;
  } finally {
    await adminPool.end();
  }
};

let pool;

const initializePool = async () => {
  if (pool) return pool;

  await createDatabaseIfNotExists();

  pool = new Pool({ connectionString: process.env.DATABASE_URL });

  let connectionLogged = false;
  pool.on("connect", () => {
    if (!connectionLogged) {
      console.log("Connected to PostgreSQL");
      connectionLogged = true;
    }
  });

  pool.on("error", (err) => {
    console.error("PostgreSQL pool error:", err);
  });

  await createUsersTableIfNotExists(pool);
  return pool;
};

const getPool = () => {
  if (!pool) {
    throw new Error("Database pool has not been initialized yet. Call initializePool() first.");
  }
  return pool;
};

module.exports = { initializePool, getPool };