const jwt = require("jsonwebtoken");

/**
 * authenticate
 * Verifies the Bearer access token from the Authorization header.
 * Attaches decoded payload { id, email, role } to req.user on success.
 */
const authenticate = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Access token missing" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Invalid or expired access token" });
  }
};

/**
 * authorize(...roles)
 * Restricts a route to users with specific role(s).
 * Must be used AFTER authenticate.
 *
 * Usage: authorize("ADMIN")  or  authorize("ADMIN", "MANAGER")
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({ success: false, message: "You are not authorized" });
    }
    next();
  };
};

module.exports = { authenticate, authorize };