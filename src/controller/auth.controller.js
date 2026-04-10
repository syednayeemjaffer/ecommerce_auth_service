const bcrypt = require("bcrypt");
const fs    = require("fs");
const path  = require("path");
const jwt   = require("jsonwebtoken");

const { getPool }                               = require("../config/db");
const redis                                     = require("../config/redis");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const { sendOtpMail }                           = require("../utils/mail");

// ─── Constants ────────────────────────────────────────────────────────────────
const EMAIL_REGEX            = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_REGEX             = /^[A-Za-z\s]+$/;
const PASSWORD_SPECIAL_REGEX = /[!@#$%^&*(),.?":{}|<>]/;
const ALLOWED_MIME_TYPES     = new Set(["image/png", "image/jpeg", "image/jpg"]);
const UPLOAD_DIR             = path.join(__dirname, "../../uploads");

// Refresh token TTL: 7 days in seconds
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

// ─── Response Helpers ─────────────────────────────────────────────────────────

/**
 * Sends a 400 Bad Request response with a field-level error.
 * @param {Response} res
 * @param {string}   field   - The form field that caused the error
 * @param {string}   message - Human-readable error message
 */
const badRequest = (res, field, message) =>
  res.status(400).json({ success: false, error: { field, message } });

/**
 * Saves an uploaded file buffer to the UPLOAD_DIR on disk.
 * Creates the directory if it doesn't exist.
 * @param {Express.Multer.File} file
 * @returns {string} The saved filename (not full path)
 */
const saveImageToDisk = (file) => {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }
  const fileName = `${Date.now()}-${file.originalname}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, fileName), file.buffer);
  return fileName;
};

/**
 * Builds and sets the refresh token cookie on the response.
 * Uses httpOnly + secure + sameSite=strict for CSRF/XSS protection.
 * @param {Response} res
 * @param {string}   token
 */
const setRefreshTokenCookie = (res, token) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production", // HTTPS only in prod
    sameSite: "strict",
    maxAge:   REFRESH_TOKEN_TTL * 1000, // ms
  });
};

// ─── Input Validation ─────────────────────────────────────────────────────────

/**
 * Validates all fields for the /register endpoint.
 * Does NOT write anything to disk — pure validation only.
 *
 * @param {Object}              body - req.body
 * @param {Express.Multer.File} file - req.file (optional)
 * @returns {{ data, error }} - `data` contains sanitized fields; `error` is set on failure
 */
const validateRegisterInput = (body, file) => {
  let { name, email, password, role } = body;

  // ── Name ──────────────────────────────────────────────────────────────────
  if (!name?.trim())
    return { error: { field: "name", message: "Please provide name" } };
  name = name.trim();
  if (name.length < 3 || name.length > 30)
    return { error: { field: "name", message: "Name must be 3–30 characters" } };
  if (!NAME_REGEX.test(name))
    return { error: { field: "name", message: "Name can only contain letters and spaces" } };

  // ── Email ─────────────────────────────────────────────────────────────────
  if (!email?.trim())
    return { error: { field: "email", message: "Please provide email" } };
  email = email.trim();
  if (!EMAIL_REGEX.test(email))
    return { error: { field: "email", message: "Please enter a valid email address" } };

  // ── Password ──────────────────────────────────────────────────────────────
  if (!password)
    return { error: { field: "password", message: "Please provide password" } };
  if (password.length < 6 || password.length > 30)
    return { error: { field: "password", message: "Password must be 6–30 characters" } };
  if (
    !/[A-Z]/.test(password) ||
    !/[a-z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !PASSWORD_SPECIAL_REGEX.test(password)
  )
    return {
      error: {
        field: "password",
        message: "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
      },
    };

  // ── Role ──────────────────────────────────────────────────────────────────
  role = role ? role.toUpperCase() : "USER";
  if (!["USER", "ADMIN"].includes(role))
    return { error: { field: "role", message: "Role must be USER or ADMIN" } };

  // ── Profile Image (MIME type check only — no disk write here) ─────────────
  if (file && !ALLOWED_MIME_TYPES.has(file.mimetype))
    return { error: { field: "user_image", message: "Only png, jpg, jpeg images are allowed" } };

  return { data: { name, email, password, role } };
};

// ─── Controllers ──────────────────────────────────────────────────────────────

/**
 * POST /send-register-otp
 * Sends a 6-digit OTP to the user's email for registration verification.
 * Rejects if the email is already registered.
 */
const sendRegisterOtp = async (req, res) => {
  try {
    const pool = getPool();
    const { email } = req.body;

    // Validate email presence and format
    if (!email?.trim())
      return badRequest(res, "email", "Please provide email");

    const normalizedEmail = email.trim().toLowerCase();

    if (!EMAIL_REGEX.test(normalizedEmail))
      return badRequest(res, "email", "Please enter a valid email address");

    // Reject if email is already registered
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: { field: "email", message: "Email already registered" },
      });
    }

    // Generate a secure 6-digit OTP and store in Redis for 5 minutes
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redis.set(`register_otp:${normalizedEmail}`, otp, "EX", 300);

    // Send the OTP via email
    await sendOtpMail(normalizedEmail, otp);

    return res.status(200).json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("Send OTP error:", error.message);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

/**
 * POST /register
 * Registers a new user after validating all fields and verifying the OTP.
 * Saves profile image to disk only after all validations pass.
 */
const register = async (req, res) => {
  try {
    const pool = getPool();

    // 1. Validate all inputs (name, email, password, role, image MIME)
    const { data, error } = validateRegisterInput(req.body, req.file);
    if (error) {
      return res.status(400).json({ success: false, error });
    }

    const { name, email, password, role } = data;
    const { otp } = req.body;

    // 2. Verify OTP
    if (!otp)
      return badRequest(res, "otp", "Please provide OTP");

    const storedOtp = await redis.get(`register_otp:${email}`);
    if (!storedOtp)
      return badRequest(res, "otp", "OTP expired or not sent");
    if (storedOtp !== otp)
      return badRequest(res, "otp", "Invalid OTP");

    // 3. Check for duplicate email
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: { field: "email", message: "Email already exists" },
      });
    }

    // 4. Save profile image to disk (only after all validations pass)
    let imagePath = null;
    if (req.file) {
      imagePath = saveImageToDisk(req.file);
    }

    // 5. Hash password and insert user into DB
    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, user_image)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role, user_image`,
      [name, email, passwordHash, role, imagePath]
    );

    // 6. Invalidate OTP after successful registration
    await redis.del(`register_otp:${email}`);

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: rows[0],
    });
  } catch (error) {
    console.error("Register error:", error.message);
    return res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * POST /login
 * Authenticates a user with email + password.
 * Issues a short-lived access token and a long-lived refresh token (httpOnly cookie).
 */
const login = async (req, res) => {
  try {
    const pool = getPool();
    let { email, password } = req.body;

    // Validate email
    if (!email?.trim())
      return badRequest(res, "email", "Please provide email");
    email = email.trim();
    if (!EMAIL_REGEX.test(email))
      return badRequest(res, "email", "Please enter a valid email address");

    // Validate password presence
    if (!password)
      return badRequest(res, "password", "Please provide password");

    // Fetch user from DB
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { field: "email", message: "User not found, please create an account" },
      });
    }

    const user = rows[0];

    // Verify password against stored hash
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        error: { field: "password", message: "Incorrect password" },
      });
    }

    // Generate tokens
    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Store refresh token in Redis (keyed by user ID) for rotation/invalidation
    await redis.set(`refresh:${user.id}`, refreshToken, "EX", REFRESH_TOKEN_TTL);

    // Set refresh token as httpOnly cookie
    setRefreshTokenCookie(res, refreshToken);

    return res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      user: {
        id:         user.id,
        name:       user.name,
        email:      user.email,
        role:       user.role,
        user_image: user.user_image,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/**
 * POST /refresh
 * Rotates the refresh token and issues a new access token.
 * Validates the token against Redis to detect reuse/theft.
 */
const refreshAccessToken = async (req, res) => {
  try {
    const pool         = getPool();
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ success: false, message: "Refresh token missing" });
    }

    // Verify JWT signature and expiry
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Compare against stored token in Redis to detect reuse after logout/rotation
    const storedToken = await redis.get(`refresh:${decoded.id}`);
    if (!storedToken || storedToken !== refreshToken) {
      return res.status(401).json({ success: false, message: "Invalid refresh token" });
    }

    // Fetch latest user data from DB
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [decoded.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const user = rows[0];

    // Issue new token pair (rotation: old refresh token is replaced)
    const newAccessToken  = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // Overwrite old refresh token in Redis
    await redis.set(`refresh:${user.id}`, newRefreshToken, "EX", REFRESH_TOKEN_TTL);

    // Overwrite cookie with new refresh token
    setRefreshTokenCookie(res, newRefreshToken);

    return res.status(200).json({ success: true, accessToken: newAccessToken });
  } catch (error) {
    console.error("Refresh error:", error.message);
    return res.status(401).json({ success: false, message: "Invalid or expired refresh token" });
  }
};

/**
 * POST /logout
 * Invalidates the refresh token in Redis and clears the httpOnly cookie.
 * Always returns 200 even if token is missing/expired (idempotent logout).
 */
const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // Decode to get user ID (even if already expired, best effort)
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      // Remove refresh token from Redis to prevent future use
      await redis.del(`refresh:${decoded.id}`);
    }

    res.clearCookie("refreshToken");

    return res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    // Even if verification fails (expired token, etc.), still clear the cookie
    console.error("Logout error:", error.message);
    res.clearCookie("refreshToken");
    return res.status(200).json({ success: true, message: "Logged out successfully" });
  }
};

/**
 * POST /forgot-password
 * Sends a 6-digit OTP to the registered email for password reset.
 * Returns 404 if the email is not found.
 */
const forgotPasswordOtp = async (req, res) => {
  try {
    const pool  = getPool();
    const { email } = req.body;

    if (!email?.trim())
      return badRequest(res, "email", "Please provide email");

    const normalizedEmail = email.trim().toLowerCase();

    if (!EMAIL_REGEX.test(normalizedEmail))
      return badRequest(res, "email", "Please enter valid email");

    // Ensure the user exists before sending OTP
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (existing.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { field: "email", message: "User not found" },
      });
    }

    // Generate OTP and store in Redis for 5 minutes
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redis.set(`forgot_otp:${normalizedEmail}`, otp, "EX", 300);

    await sendOtpMail(normalizedEmail, otp);

    return res.status(200).json({
      success: true,
      message: "Forgot password OTP sent successfully",
    });
  } catch (error) {
    console.error("Forgot password error:", error.message);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

/**
 * POST /reset-password
 * Resets the user's password after verifying the forgot-password OTP.
 * Full password strength validation is applied to the new password.
 */
const resetPassword = async (req, res) => {
  try {
    const pool = getPool();
    let { email, otp, newPassword } = req.body;

    // Validate inputs
    if (!email?.trim())
      return badRequest(res, "email", "Please provide email");
    email = email.trim().toLowerCase();

    if (!otp)
      return badRequest(res, "otp", "Please provide OTP");
    if (!newPassword)
      return badRequest(res, "newPassword", "Please provide new password");

    // Verify OTP from Redis
    const storedOtp = await redis.get(`forgot_otp:${email}`);
    if (!storedOtp)
      return badRequest(res, "otp", "OTP expired or not sent");
    if (storedOtp !== otp)
      return badRequest(res, "otp", "Invalid OTP");

    // Validate new password strength
    if (
      newPassword.length < 6 ||
      newPassword.length > 30 ||
      !/[A-Z]/.test(newPassword) ||
      !/[a-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword) ||
      !PASSWORD_SPECIAL_REGEX.test(newPassword)
    ) {
      return badRequest(
        res,
        "newPassword",
        "Password must contain uppercase, lowercase, number and special char"
      );
    }

    // Hash and update password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE email = $2",
      [passwordHash, email]
    );

    // Invalidate OTP after successful reset
    await redis.del(`forgot_otp:${email}`);

    return res.status(200).json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/**
 * POST /change-password  (authenticated)
 * Allows a logged-in user to change their password by providing the old one.
 */
const changePassword = async (req, res) => {
  try {
    const pool   = getPool();
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword)
      return badRequest(res, "oldPassword", "Please provide old password");
    if (!newPassword)
      return badRequest(res, "newPassword", "Please provide new password");

    // Fetch current password hash
    const { rows } = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Verify old password
    const isValid = await bcrypt.compare(oldPassword, rows[0].password_hash);
    if (!isValid)
      return badRequest(res, "oldPassword", "Old password is incorrect");

    // Hash and update to new password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [passwordHash, userId]
    );

    return res.status(200).json({ success: true, message: "Password changed successfully" });
  } catch (error) {
    console.error("Change password error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/**
 * GET /google/callback, GET /github/callback
 * Shared OAuth callback handler (called after Passport validates the OAuth user).
 * Issues tokens, sets the refresh cookie, and redirects to the frontend.
 */
const oauthLoginHandler = async (req, res) => {
  try {
    const user = req.user; // Set by Passport strategy

    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Store refresh token in Redis
    await redis.set(`refresh:${user.id}`, refreshToken, "EX", REFRESH_TOKEN_TTL);

    // Set httpOnly refresh cookie
    setRefreshTokenCookie(res, refreshToken);

    // Redirect to frontend with access token in URL
    // Note: Frontend should immediately extract + store this token, then clean the URL
    return res.redirect(
      `${process.env.FRONTEND_URL}/oauth-success?token=${accessToken}`
    );
  } catch (error) {
    console.error("OAuth callback error:", error.message);
    return res.redirect(`${process.env.FRONTEND_URL}/login`);
  }
};

/**
 * GET /me  (authenticated)
 * Returns the authenticated user's profile data.
 */
const getProfile = async (req, res) => {
  try {
    const pool = getPool();

    const { rows } = await pool.query(
      `SELECT id, name, email, role, user_image, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({ success: true, user: rows[0] });
  } catch (error) {
    console.error("Profile error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/**
 * GET /users       (admin) → returns all users
 * GET /users/:id   (admin) → returns a single user by ID
 * Both handled by this single controller using the optional :id param.
 */
const getAllOrUserById = async (req, res) => {
  try {
    const pool     = getPool();
    const { id }   = req.params;

    // ── Single User ────────────────────────────────────────────────────────
    if (id) {
      const { rows } = await pool.query(
        `SELECT id, name, email, role, user_image, created_at
         FROM users
         WHERE id = $1`,
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: "User not found" });
      }
      return res.status(200).json({ success: true, user: rows[0] });
    }

    // ── All Users ──────────────────────────────────────────────────────────
    const { rows } = await pool.query(
      `SELECT id, name, email, role, user_image, created_at
       FROM users
       ORDER BY created_at DESC`
    );

    return res.status(200).json({
      success: true,
      totalUsers: rows.length,
      users: rows,
    });
  } catch (error) {
    console.error("Get users error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

// ─── Exports ──────────────────────────────────────────────────────────────────
module.exports = {
  sendRegisterOtp,
  register,
  login,
  refreshAccessToken,
  logout,
  getProfile,
  getAllOrUserById,
  forgotPasswordOtp,
  resetPassword,
  changePassword,
  oauthLoginHandler,
};