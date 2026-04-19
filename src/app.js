require("dotenv").config();

const { initializePool } = require("./config/db");
require("./config/redis");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

async function init() {
  await initializePool();

  const authRoutes = require("./routes/auth.routes");
  const passport = require("./config/passport");

  const app = express();

  app.use(helmet());

  app.use(
    cors({
      origin: process.env.FRONTEND_URL,
      credentials: true,
    })
  );

  app.use(express.json());
  app.use(cookieParser());

  // Use "combined" in production for full log output; "dev" is fine for local
  app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

  // Global rate limit — 100 req / 15 min per IP
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      message: "Too many requests from this IP, please try again later",
    })
  );

  // Stricter limit on auth endpoints — 20 req / 15 min per IP
  app.use(
    "/api/auth/login",
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 20,
      message: "Too many login attempts, please try again later",
    })
  );

  app.use(
    "/api/auth/send-register-otp",
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 10,
      message: "Too many OTP requests, please try again later",
    })
  );

  app.use(passport.initialize());
  app.use("/api/auth", authRoutes);

  const PORT = process.env.PORT || 5001;
  app.listen(PORT, () => {
    console.log(`Auth service running on port ${PORT} [${process.env.NODE_ENV || "development"}]`);
  });
}

init().catch((error) => {
  console.error("Failed to start auth service:", error);
  process.exit(1);
});