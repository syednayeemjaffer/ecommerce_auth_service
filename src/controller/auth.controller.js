const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const { getPool } = require("../config/db");
const redis = require("../config/redis");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const { sendOtpMail } = require("../utils/mail");

// ─── Constants ───────────────────────────────────────────────────────────────
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_REGEX = /^[A-Za-z\s]+$/;
const PASSWORD_SPECIAL_REGEX = /[!@#$%^&*(),.?":{}|<>]/;
const ALLOWED_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/jpg"]);
const UPLOAD_DIR = path.join(__dirname, "../../uploads");

// ─── Helpers ─────────────────────────────────────────────────────────────────
const badRequest = (res, field, message) =>
  res.status(400).json({ success: false, error: { field, message } });

const saveImageToDisk = (file) => {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }
  const fileName = `${Date.now()}-${file.originalname}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, fileName), file.buffer);
  return fileName;
};

// ─── Validation ──────────────────────────────────────────────────────────────
const validateRegisterInput = (body, file) => {
  let { name, email, password, role } = body;

  // Name
  if (!name?.trim())
    return { error: badRequest(null, "name", "Please provide name") };
  name = name.trim();
  if (name.length < 3 || name.length > 30)
    return {
      error: { field: "name", message: "Name must be 3–30 characters" },
    };
  if (!NAME_REGEX.test(name))
    return {
      error: {
        field: "name",
        message: "Name can only contain letters and spaces",
      },
    };

  // Email
  if (!email?.trim())
    return { error: { field: "email", message: "Please provide email" } };
  email = email.trim();
  if (!EMAIL_REGEX.test(email))
    return {
      error: { field: "email", message: "Please enter a valid email address" },
    };

  // Password
  if (!password)
    return { error: { field: "password", message: "Please provide password" } };
  if (password.length < 6 || password.length > 30)
    return {
      error: { field: "password", message: "Password must be 6–30 characters" },
    };
  if (
    !/[A-Z]/.test(password) ||
    !/[a-z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !PASSWORD_SPECIAL_REGEX.test(password)
  )
    return {
      error: {
        field: "password",
        message:
          "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
      },
    };

  // Role
  role = role ? role.toUpperCase() : "USER";
  if (!["USER", "ADMIN"].includes(role))
    return { error: { field: "role", message: "Role must be USER or ADMIN" } };

  // Image MIME type (existence check only — do NOT write to disk here)
  if (file && !ALLOWED_MIME_TYPES.has(file.mimetype))
    return {
      error: {
        field: "user_image",
        message: "Only png, jpg, jpeg images are allowed",
      },
    };

  return { data: { name, email, password, role } };
};

// ─── Controllers ─────────────────────────────────────────────────────────────
const register = async (req, res) => {
  try {
    const pool = getPool();

    // 1. Validate all inputs
    const { data, error } = validateRegisterInput(req.body, req.file);

    if (error) {
      return res.status(400).json({
        success: false,
        error,
      });
    }

    // ✅ USE VALIDATED DATA
    const { name, email, password, role } = data;
    const { otp } = req.body;

    // =========================
    // OTP VALIDATION
    // =========================
    if (!otp) {
      return badRequest(res, "otp", "Please provide OTP");
    }

    const storedOtp = await redis.get(`register_otp:${email}`);

    if (!storedOtp) {
      return badRequest(res, "otp", "OTP expired or not sent");
    }

    if (storedOtp !== otp) {
      return badRequest(res, "otp", "Invalid OTP");
    }

    // =========================
    // CHECK DUPLICATE EMAIL
    // =========================
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: {
          field: "email",
          message: "Email already exists",
        },
      });
    }

    // =========================
    // SAVE IMAGE
    // =========================
    let imagePath = null;

    if (req.file) {
      imagePath = saveImageToDisk(req.file);
    }

    // =========================
    // CREATE USER
    // =========================
    const passwordHash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, user_image)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role, user_image`,
      [name, email, passwordHash, role, imagePath]
    );

    // OTP delete after successful register
    await redis.del(`register_otp:${email}`);

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: rows[0],
    });
  } catch (error) {
    console.error("Register error:", error.message);

    return res.status(500).json({
      success: false,
      message: error.message, // temporary for debugging
    });
  }
};

const sendRegisterOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const pool = getPool();

    if (!email?.trim()) {
      return badRequest(res, "email", "Please provide email");
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!EMAIL_REGEX.test(normalizedEmail)) {
      return badRequest(res, "email", "Please enter a valid email address");
    }

    // check already registered
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [
      normalizedEmail,
    ]);

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: {
          field: "email",
          message: "Email already registered",
        },
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await redis.set(`register_otp:${normalizedEmail}`, otp, "EX", 300); // 5 mins

    await sendOtpMail(normalizedEmail, otp);

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
    });
  } catch (error) {
    console.error("Send OTP error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
    });
  }
};

const login = async (req, res) => {
  try {
    const pool = getPool();
    let { email, password } = req.body;

    // Validate email
    if (!email?.trim()) return badRequest(res, "email", "Please provide email");
    email = email.trim();
    if (!EMAIL_REGEX.test(email))
      return badRequest(res, "email", "Please enter a valid email address");

    // Validate password presence
    if (!password)
      return badRequest(res, "password", "Please provide password");

    // Fetch user
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: {
          field: "email",
          message: "User not found, please create an account",
        },
      });
    }

    const user = rows[0];

    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid)
      return res.status(401).json({
        success: false,
        error: { field: "password", message: "Incorrect password" },
      });

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await redis.set(`refresh:${user.id}`, refreshToken, "EX", 7 * 24 * 60 * 60);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // ← use true in prod
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        user_image: user.user_image,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const refreshAccessToken = async (req, res) => {
  try {
    const pool = getPool();
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Refresh token missing",
      });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const storedToken = await redis.get(`refresh:${decoded.id}`);

    if (!storedToken || storedToken !== refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      decoded.id,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const user = rows[0];

    // ROTATE TOKENS
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    await redis.set(
      `refresh:${user.id}`,
      newRefreshToken,
      "EX",
      7 * 24 * 60 * 60,
    );

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.error("Refresh error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired refresh token",
    });
  }
};

const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

      await redis.del(`refresh:${decoded.id}`);
    }

    res.clearCookie("refreshToken");

    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error.message);

    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  }
};

const getProfile = async (req, res) => {
  try {
    const pool = getPool();

    const { rows } = await pool.query(
      `SELECT id, name, email, role, user_image, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id],
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      user: rows[0],
    });
  } catch (error) {
    console.error("Profile error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

const getAllOrUserById = async (req, res) => {
  try {
    const pool = getPool();
    const { id } = req.params;

    // =========================
    // GET SINGLE USER BY ID
    // =========================
    if (id) {
      const { rows } = await pool.query(
        `SELECT id, name, email, role, user_image, created_at
         FROM users
         WHERE id = $1`,
        [id],
      );

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      return res.status(200).json({
        success: true,
        user: rows[0],
      });
    }

    // =========================
    // GET ALL USERS
    // =========================
    const { rows } = await pool.query(
      `SELECT id, name, email, role, user_image, created_at
       FROM users
       ORDER BY created_at DESC`,
    );

    return res.status(200).json({
      success: true,
      totalUsers: rows.length,
      users: rows,
    });
  } catch (error) {
    console.error("Get users error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

module.exports = {
  sendRegisterOtp,
  register,
  login,
  refreshAccessToken,
  logout,
  getProfile,
  getAllOrUserById,
};
