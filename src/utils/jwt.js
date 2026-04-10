const jwt = require("jsonwebtoken");

// ─── Token Generators ─────────────────────────────────────────────────────────

/**
 * Generates a short-lived access token (15 minutes).
 * Payload includes id, email, and role for use in middleware/controllers.
 *
 * @param {Object} user - User row from the database
 * @returns {string} Signed JWT access token
 */
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id:    user.id,
      email: user.email,
      role:  user.role,
    },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" }
  );
};

/**
 * Generates a long-lived refresh token (7 days).
 * Payload contains only the user ID — minimal claims for security.
 * The actual user data is re-fetched from DB during token rotation.
 *
 * @param {Object} user - User row from the database
 * @returns {string} Signed JWT refresh token
 */
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );
};

module.exports = { generateAccessToken, generateRefreshToken };