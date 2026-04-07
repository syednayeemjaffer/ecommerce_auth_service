const express = require("express");
const router = express.Router();

const {
  register,
  login,
  refreshAccessToken,
  logout,
  getProfile,
} = require("../controller/auth.controller");

const uploadUserImage = require("../utils/userimage");
const {
  authenticate,
  authorize,
} = require("../middleware/auth.middleware");

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
  "/admin-only",
  authenticate,
  authorize("ADMIN"),
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome Admin 🚀",
    });
  }
);

module.exports = router;