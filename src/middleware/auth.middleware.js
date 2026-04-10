const jwt = require("jsonwebtoken");

// ─── authenticate ─────────────────────────────────────────────────────────────
/**
 * Middleware: Verifies the Bearer access token in the Authorization header.
 * On success, attaches the decoded payload to req.user and calls next().
 * On failure, responds with 401 Unauthorized.
 *
 * Expected header format: Authorization: Bearer <token>
 */
const authenticate = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // Reject requests missing the Authorization header or wrong format
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Access token missing",
      });
    }

    // Extract token from "Bearer <token>"
    const token   = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // Attach decoded payload (id, email, role) to request for downstream use
    req.user = decoded;
    next();
  } catch (error) {
    // Catches jwt.verify errors (expired, invalid signature, malformed)
    return res.status(401).json({
      success: false,
      message: "Invalid or expired access token",
    });
  }
};

// ─── authorize ────────────────────────────────────────────────────────────────
/**
 * Middleware factory: Restricts a route to users with specific role(s).
 * Must be used AFTER authenticate (requires req.user to be set).
 *
 * Usage: authorize("ADMIN")  or  authorize("ADMIN", "MANAGER")
 *
 * @param {...string} roles - Allowed role(s)
 * @returns Express middleware
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized",
      });
    }
    next();
  };
};

module.exports = { authenticate, authorize };