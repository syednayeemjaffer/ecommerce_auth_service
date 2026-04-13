const express = require("express");
const router  = express.Router();

const {
  register,
  login,
  refreshAccessToken,
  logout,
  getProfile,
  getAllOrUserById,
  sendRegisterOtp,
  forgotPasswordOtp,
  resetPassword,
  changePassword,
  oauthLoginHandler,
} = require("../controller/auth.controller");

const passport        = require("../config/passport");
const uploadUserImage = require("../utils/userimage");
const { authenticate, authorize } = require("../middleware/auth.middleware");

// ─── Registration ─────────────────────────────────────────────────────────────

// Step 1: Send OTP to email before registration
router.post("/send-register-otp", sendRegisterOtp);

// Step 2: Register with OTP + optional profile image
router.post(
  "/register",
  uploadUserImage.single("user_image"), // Parse multipart/form-data for image
  register
);

// ─── Authentication ───────────────────────────────────────────────────────────

// Email + password login → returns access token + sets refresh cookie
router.post("/login", login);

// Exchange refresh cookie for a new access token (token rotation)
router.post("/refresh", refreshAccessToken);

// Clear refresh cookie and invalidate token in Redis
router.post("/logout", logout);

// ─── Password Management ──────────────────────────────────────────────────────

// Send OTP to email for forgot-password flow
router.post("/forgot-password", forgotPasswordOtp);

// Reset password using forgot-password OTP
router.post("/reset-password", resetPassword);

// Change password while logged in (requires valid access token)
router.post("/change-password", authenticate, changePassword);

// ─── OAuth — Google ───────────────────────────────────────────────────────────

// Redirect user to Google consent screen
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google redirects back here after user grants access
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  oauthLoginHandler
);

// ─── OAuth — GitHub ───────────────────────────────────────────────────────────

// Redirect user to GitHub consent screen
router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

// GitHub redirects back here after user grants access
router.get(
  "/github/callback",
  passport.authenticate("github", { session: false }),
  oauthLoginHandler
);

// ─── User Profile ─────────────────────────────────────────────────────────────

// Get the authenticated user's own profile
router.get("/user", authenticate, getProfile);

// ─── Admin — User Management ──────────────────────────────────────────────────

// Get all users (admin only)
router.get("/users",     authenticate, authorize("ADMIN"), getAllOrUserById);

// Get a single user by ID (admin only)
router.get("/users/:id", authenticate, authorize("ADMIN"), getAllOrUserById);

module.exports = router;