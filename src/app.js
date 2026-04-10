require("dotenv").config();

// Initialize DB pool and Redis connection before anything else
const { initializePool } = require("./config/db");
require("./config/redis"); // Connects on import; logs success/error

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const cookieParser = require("cookie-parser");
const morgan     = require("morgan");
const rateLimit  = require("express-rate-limit");

/**
 * Bootstraps the Express application:
 *  1. Initializes the DB pool (creates DB + tables if needed)
 *  2. Registers all middleware
 *  3. Mounts routes
 *  4. Starts the HTTP server
 *
 * Wrapped in an async function so we can await DB initialization
 * before accepting any requests.
 */
async function init() {
  // ── Step 1: Initialize Database ───────────────────────────────────────────
  // Must complete before routes are mounted — controllers depend on getPool()
  await initializePool();

  // Lazy-require after DB is ready (passport uses getPool() at import time)
  const authRoutes = require("./routes/auth.routes");
  const passport   = require("./config/passport");

  // ── Step 2: Create Express App ────────────────────────────────────────────
  const app = express();

  // ── Security Headers ──────────────────────────────────────────────────────
  // Sets various HTTP headers to protect against common web vulnerabilities
  app.use(helmet());

  // ── CORS ──────────────────────────────────────────────────────────────────
  // Allow requests only from the configured frontend origin.
  // credentials: true is required for cookies (refresh token) to work cross-origin.
  app.use(
    cors({
      origin:      process.env.FRONTEND_URL,
      credentials: true,
    })
  );

  // ── Body Parsers ──────────────────────────────────────────────────────────
  app.use(express.json());   // Parse JSON request bodies
  app.use(cookieParser());   // Parse Cookie header (for refreshToken)

  // ── Request Logger ────────────────────────────────────────────────────────
  // "dev" format: METHOD /path STATUS response-time ms
  app.use(morgan("dev"));

  // ── Rate Limiting ─────────────────────────────────────────────────────────
  // Applies globally: max 100 requests per IP per 15 minutes.
  // Protects login, OTP, and other sensitive endpoints from brute-force.
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max:      100,
      message:  "Too many requests from this IP, please try again later",
    })
  );

  // ── Passport Initialization ───────────────────────────────────────────────
  // Required for OAuth strategies (Google, GitHub).
  // session: false — we use JWTs, not server-side sessions.
  app.use(passport.initialize());

  // ── Routes ────────────────────────────────────────────────────────────────
  app.use("/api/auth", authRoutes);

  // ── Start Server ──────────────────────────────────────────────────────────
  const PORT = process.env.PORT || 5001;
  app.listen(PORT, () => {
    console.log(`🚀 Auth service running on port ${PORT}`);
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
init().catch((error) => {
  console.error("❌ Failed to start auth service:", error);
  process.exit(1);
});