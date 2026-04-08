const express = require("express");
const router = express.Router();

const {
  register,
  login,
  refreshAccessToken,
  logout,
  getProfile,
  getAllOrUserById,
  sendRegisterOtp
} = require("../controller/auth.controller");

const uploadUserImage = require("../utils/userimage");
const {
  authenticate,
  authorize,
} = require("../middleware/auth.middleware");

router.post("/send-register-otp", sendRegisterOtp);
router.post(
  "/register",
  uploadUserImage.single("user_image"),
  register
);

router.post("/login", login);
router.post("/refresh", refreshAccessToken);
router.post("/logout", logout);

router.get("/me", authenticate, getProfile);

router.get(
  "/users",
  authenticate,
  authorize("ADMIN"),
  getAllOrUserById
);

router.get(
  "/users/:id",
  authenticate,
  authorize("ADMIN"),
  getAllOrUserById
);

module.exports = router;