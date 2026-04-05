const express = require("express");
const router = express.Router();

const {
  register,
  login,
} = require("../controller/auth.controller");

const uploadUserImage = require("../utils/userimage");

router.post(
  "/register",
  uploadUserImage.single("user_image"),
  register
);

router.post("/login", login);

module.exports = router;