const jwt = require("jsonwebtoken");

/**
 * Access token — 1m for testing, use "15m" in production.
 * Contains id, email, role so middleware never needs a DB lookup.
 */
const generateAccessToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "1m" }
  );

/**
 * Refresh token — 2m for testing, use "7d" in production.
 * Minimal payload — only id. Real user data re-fetched from DB on rotation.
 */
const generateRefreshToken = (user) =>
  jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "2m" }
  );

module.exports = { generateAccessToken, generateRefreshToken };