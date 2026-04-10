const Redis = require("ioredis");

// ─── Redis Client ─────────────────────────────────────────────────────────────
// Single shared Redis client instance.
// Used for: OTP storage, refresh token storage, and session invalidation.
const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});

// Log successful connection
redis.on("connect", () => {
  console.log("✅ Redis connected");
});

// Log connection errors (non-fatal — ioredis auto-reconnects)
redis.on("error", (err) => {
  console.error("❌ Redis error:", err.message);
});

module.exports = redis;