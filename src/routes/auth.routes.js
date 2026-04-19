const express = require("express");
const router = express.Router();

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

const passport = require("../config/passport");
const uploadUserImage = require("../utils/userimage");
const { authenticate, authorize } = require("../middleware/auth.middleware");

// ─── Registration ─────────────────────────────────────────────────────────────
router.post("/send-register-otp", sendRegisterOtp);
router.post("/register", uploadUserImage.single("user_image"), register);

// ─── Authentication ───────────────────────────────────────────────────────────
router.post("/login", login);
router.post("/refresh", refreshAccessToken);
router.post("/logout", logout);

// ─── Password Management ──────────────────────────────────────────────────────
router.post("/forgot-password", forgotPasswordOtp);
router.post("/reset-password", resetPassword);
router.post("/change-password", authenticate, changePassword);

// ─── OAuth — Google ───────────────────────────────────────────────────────────
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  oauthLoginHandler
);

// ─── OAuth — GitHub ───────────────────────────────────────────────────────────
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get(
  "/github/callback",
  passport.authenticate("github", { session: false }),
  oauthLoginHandler
);

// ─── User Profile ─────────────────────────────────────────────────────────────
router.get("/user", authenticate, getProfile);

// ─── Admin — User Management ──────────────────────────────────────────────────
router.get("/users", authenticate, authorize("ADMIN"), getAllOrUserById);
router.get("/users/:id", authenticate, authorize("ADMIN"), getAllOrUserById);

module.exports = router;