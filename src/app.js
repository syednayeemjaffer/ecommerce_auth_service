const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

// routes
const authRoutes = require("./routes/auth.routes");

const app = express();

// security
app.use(helmet());

// cors
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

// parser
app.use(express.json());
app.use(cookieParser());

// logger
app.use(morgan("dev"));

// rate limit
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many login attempts, try again later"
  })
);

// routes
app.use("/api/auth", authRoutes);

module.exports = app;