require("dotenv").config();
const { Pool } = require("pg");
const { createUsersTableIfNotExists } = require("../utils/query_helper");

console.log("DATABASE_URL =", process.env.DATABASE_URL);

// Extract database name from connection string
const dbUrl = new URL(process.env.DATABASE_URL);
const dbName = dbUrl.pathname.substring(1); // Remove leading slash

// Create a pool for connecting to postgres database (for creating the target database)
const adminPool = new Pool({
  connectionString: process.env.DATABASE_URL.replace(`/${dbName}`, '/postgres'),
});

// Create the database if it doesn't exist
const createDatabaseIfNotExists = async () => {
  try {
    const result = await adminPool.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [dbName]
    );
    
    if (result.rows.length === 0) {
      console.log(`Database ${dbName} does not exist. Creating...`);
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      console.log(`✅ Database ${dbName} created successfully`);
    } else {
      console.log(`✅ Database ${dbName} already exists`);
    }
  } catch (error) {
    console.error("Error creating database:", error);
    throw error;
  } finally {
    await adminPool.end();
  }
};

// Main pool for the application database
let pool;

const initializePool = async () => {
  if (pool) {
    return pool;
  }

  await createDatabaseIfNotExists();
  
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });

  pool.on("connect", () => {
    console.log("Connected to PostgreSQL");
  });

  pool.on("error", (err) => {
    console.error("Unexpected error on idle client", err);
    process.exit(-1);
  });

  // Create tables after database is ready
  await createUsersTableIfNotExists(pool);

  return pool;
};

const getPool = () => {
  if (!pool) {
    throw new Error("Database pool has not been initialized yet");
  }

  return pool;
};

module.exports = { initializePool, getPool };
