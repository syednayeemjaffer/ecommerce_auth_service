const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const { getPool } = require("../config/db");
const redis = require("../config/redis");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const { sendOtpMail } = require("../utils/mail");

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_REGEX = /^[A-Za-z\s]+$/;
const PASSWORD_SPECIAL_REGEX = /[!@#$%^&*(),.?":{}|<>]/;
const ALLOWED_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/jpg"]);
const UPLOAD_DIR = path.join(__dirname, "../../uploads");

// Must match generateRefreshToken expiry. Used for Redis TTL.
const REFRESH_TOKEN_TTL = 2 * 60; // 2 minutes for testing — use 7 * 24 * 60 * 60 in production

// ─── Helpers ──────────────────────────────────────────────────────────────────

const badRequest = (res, field, message) =>
  res.status(400).json({ success: false, error: { field, message } });

const saveImageToDisk = (file) => {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const fileName = `${Date.now()}-${file.originalname}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, fileName), file.buffer);
  return fileName;
};

/**
 * Sets the refresh token as an httpOnly cookie.
 * httpOnly   — JS cannot read it (XSS protection).
 * secure     — HTTPS only in production.
 * sameSite   — CSRF protection.
 */
const setRefreshTokenCookie = (res, token) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    maxAge: REFRESH_TOKEN_TTL * 1000,
  });
};

/**
 * Formats a user row for all API responses.
 * Never expose password_hash, provider_id, or other internal fields.
 */
const formatUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role: user.role,
  user_image: user.user_image,
});

// ─── Validation ───────────────────────────────────────────────────────────────

const validateRegisterInput = (body, file) => {
  let { name, email, password, role } = body;

  if (!name?.trim())
    return { error: { field: "name", message: "Please provide name" } };
  name = name.trim();
  if (name.length < 3 || name.length > 30)
    return { error: { field: "name", message: "Name must be 3–30 characters" } };
  if (!NAME_REGEX.test(name))
    return { error: { field: "name", message: "Name can only contain letters and spaces" } };

  if (!email?.trim())
    return { error: { field: "email", message: "Please provide email" } };
  email = email.trim().toLowerCase();
  if (!EMAIL_REGEX.test(email))
    return { error: { field: "email", message: "Please enter a valid email address" } };

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
        message:
          "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
      },
    };

  role = role ? role.toUpperCase() : "USER";
  if (!["USER", "ADMIN"].includes(role))
    return { error: { field: "role", message: "Role must be USER or ADMIN" } };

  if (file && !ALLOWED_MIME_TYPES.has(file.mimetype))
    return { error: { field: "user_image", message: "Only png, jpg, jpeg images are allowed" } };

  return { data: { name, email, password, role } };
};

// ─── Controllers ──────────────────────────────────────────────────────────────

const sendRegisterOtp = async (req, res) => {
  try {
    const pool = getPool();
    const { email } = req.body;

    if (!email?.trim()) return badRequest(res, "email", "Please provide email");
    const normalizedEmail = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(normalizedEmail))
      return badRequest(res, "email", "Please enter a valid email address");

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: { field: "email", message: "Email already registered" },
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redis.set(`register_otp:${normalizedEmail}`, otp, "EX", 300);
    await sendOtpMail(normalizedEmail, otp);

    return res.status(200).json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("Send OTP error:", error.message);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

const register = async (req, res) => {
  try {
    const pool = getPool();

    const { data, error } = validateRegisterInput(req.body, req.file);
    if (error) return res.status(400).json({ success: false, error });

    const { name, email, password, role } = data;
    const { otp } = req.body;

    if (!otp) return badRequest(res, "otp", "Please provide OTP");

    const storedOtp = await redis.get(`register_otp:${email}`);
    if (!storedOtp) return badRequest(res, "otp", "OTP expired or not sent");
    if (storedOtp !== otp) return badRequest(res, "otp", "Invalid OTP");

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: { field: "email", message: "Email already exists" },
      });
    }

    let imagePath = null;
    if (req.file) imagePath = saveImageToDisk(req.file);

    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, user_image)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role, user_image`,
      [name, email, passwordHash, role, imagePath]
    );

    await redis.del(`register_otp:${email}`);

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: rows[0],
    });
  } catch (error) {
    console.error("Register error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const login = async (req, res) => {
  try {
    const pool = getPool();
    let { email, password } = req.body;

    if (!email?.trim()) return badRequest(res, "email", "Please provide email");
    email = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(email))
      return badRequest(res, "email", "Please enter a valid email address");
    if (!password) return badRequest(res, "password", "Please provide password");

    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { field: "email", message: "User not found, please create an account" },
      });
    }

    const user = rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        error: { field: "password", message: "Incorrect password" },
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await redis.set(`refresh:${user.id}`, refreshToken, "EX", REFRESH_TOKEN_TTL);
    setRefreshTokenCookie(res, refreshToken);

    return res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      user: formatUser(user),
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/**
 * POST /refresh  - Access Token Refresh
 *
 * PATTERN: Static refresh token (simpler approach)
 * Every successful /refresh call:
 *   x Issues new access token
 *   - Keeps the same refresh token
 *   - Does not rotate refresh tokens
 *
 * SECURITY:
 *   - Refresh token is stored in Redis for validation
 *   - Same refresh token can be used multiple times
 *   - Refresh token expires according to TTL (7 days)
 *
 * Benefits of static refresh tokens:
 *   - Simpler implementation
 *   - No race conditions from token rotation
 *   - Consistent session management
 *   - Easier debugging and testing
 */
const refreshAccessToken = async (req, res) => {
  try {
  console.log("=== REFRESH TOKEN REQUEST RECEIVED ===");
  const pool = getPool();
  const incomingRefreshToken = req.cookies.refreshToken;
  console.log("Refresh token cookie present:", !!incomingRefreshToken);

  if (!incomingRefreshToken) {
    return res.status(401).json({ success: false, message: "Refresh token missing" });
  }

  // Step 1: Verify JWT signature + expiry
  // jwt.verify throws on expired/tampered tokens — no need for manual decode check
  let decoded;
  try {
    decoded = jwt.verify(incomingRefreshToken, process.env.JWT_REFRESH_SECRET);
  } catch {
    res.clearCookie("refreshToken");
    return res.status(401).json({ success: false, message: "Refresh token invalid or expired" });
  }

  // Step 2: Check Redis for the stored token
  let storedToken;
  try {
    storedToken = await redis.get(`refresh:${decoded.id}`);
  } catch (err) {
    console.error("Redis error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
  if (!storedToken) {
    // Token not in Redis — it was already rotated or never existed
    res.clearCookie("refreshToken");
    return res.status(401).json({ success: false, message: "Session expired, please log in again" });
  }

  if (storedToken !== incomingRefreshToken) {
    // ⚠️ REUSE DETECTED: A previously rotated token was submitted
    // This means either the old token was stolen, or there's a race condition
    // Safest action: invalidate ALL sessions for this user
    await redis.del(`refresh:${decoded.id}`);
    res.clearCookie("refreshToken");
    return res.status(401).json({
      success: false,
      message: "Token reuse detected. All sessions invalidated. Please log in again.",
    });
  }

  // Step 3: Fetch fresh user data from DB
  let user;
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [decoded.id]);
    if (rows.length === 0) {
      await redis.del(`refresh:${decoded.id}`);
      res.clearCookie("refreshToken");
      return res.status(404).json({ success: false, message: "User not found" });
    }
    user = rows[0];
  } catch (error) {
    console.error("Refresh DB error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }

  const newAccessToken = generateAccessToken(user);

  return res.status(200).json({
    success: true,
    accessToken: newAccessToken,
    // Return user so frontend never needs a separate GET /user after session restore
    user: formatUser(user),
  });
  } catch (error) {
    console.error("Refresh error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        await redis.del(`refresh:${decoded.id}`);
      } catch {
        // Token already expired — still clear cookie
      }
    }
    res.clearCookie("refreshToken");
    return res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error.message);
    res.clearCookie("refreshToken");
    return res.status(200).json({ success: true, message: "Logged out successfully" });
  }
};

const forgotPasswordOtp = async (req, res) => {
  try {
    const pool = getPool();
    const { email } = req.body;

    if (!email?.trim()) return badRequest(res, "email", "Please provide email");
    const normalizedEmail = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(normalizedEmail))
      return badRequest(res, "email", "Please enter valid email");

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normalizedEmail]);
    if (existing.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { field: "email", message: "User not found" },
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redis.set(`forgot_otp:${normalizedEmail}`, otp, "EX", 300);
    await sendOtpMail(normalizedEmail, otp);

    return res.status(200).json({ success: true, message: "Forgot password OTP sent successfully" });
  } catch (error) {
    console.error("Forgot password error:", error.message);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

const resetPassword = async (req, res) => {
  try {
    const pool = getPool();
    let { email, otp, newPassword } = req.body;

    if (!email?.trim()) return badRequest(res, "email", "Please provide email");
    email = email.trim().toLowerCase();
    if (!otp) return badRequest(res, "otp", "Please provide OTP");
    if (!newPassword) return badRequest(res, "newPassword", "Please provide new password");

    const storedOtp = await redis.get(`forgot_otp:${email}`);
    if (!storedOtp) return badRequest(res, "otp", "OTP expired or not sent");
    if (storedOtp !== otp) return badRequest(res, "otp", "Invalid OTP");

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
        "Password must contain uppercase, lowercase, number and special character"
      );
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE email = $2", [passwordHash, email]);

    // Invalidate all active sessions after password reset for security
    const userResult = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (userResult.rows.length > 0) {
      await redis.del(`refresh:${userResult.rows[0].id}`);
    }

    await redis.del(`forgot_otp:${email}`);

    return res.status(200).json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const changePassword = async (req, res) => {
  try {
    const pool = getPool();
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword) return badRequest(res, "oldPassword", "Please provide old password");
    if (!newPassword) return badRequest(res, "newPassword", "Please provide new password");

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
        "Password must contain uppercase, lowercase, number and special character"
      );
    }

    const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [userId]);
    if (rows.length === 0)
      return res.status(404).json({ success: false, message: "User not found" });

    const isValid = await bcrypt.compare(oldPassword, rows[0].password_hash);
    if (!isValid) return badRequest(res, "oldPassword", "Old password is incorrect");

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, userId]);

    // Invalidate all active sessions after password change for security
    await redis.del(`refresh:${userId}`);

    return res.status(200).json({ success: true, message: "Password changed successfully" });
  } catch (error) {
    console.error("Change password error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const oauthLoginHandler = async (req, res) => {
  try {
    const user = req.user;
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await redis.set(`refresh:${user.id}`, refreshToken, "EX", REFRESH_TOKEN_TTL);
    setRefreshTokenCookie(res, refreshToken);

    // Pass formatted user as base64 JSON in URL — avoids extra GET /user call
    const userParam = Buffer.from(JSON.stringify(formatUser(user))).toString("base64");
    return res.redirect(
      `${process.env.FRONTEND_URL}/oauth/callback?token=${accessToken}&user=${userParam}`
    );
  } catch (error) {
    console.error("OAuth callback error:", error.message);
    return res.redirect(`${process.env.FRONTEND_URL}/login`);
  }
};

const getProfile = async (req, res) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      "SELECT id, name, email, role, user_image, created_at FROM users WHERE id = $1",
      [req.user.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ success: false, message: "User not found" });
    return res.status(200).json({ success: true, user: rows[0] });
  } catch (error) {
    console.error("Profile error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

const getAllOrUserById = async (req, res) => {
  try {
    const pool = getPool();
    const { id } = req.params;

    if (id) {
      const { rows } = await pool.query(
        "SELECT id, name, email, role, user_image, created_at FROM users WHERE id = $1",
        [id]
      );
      if (rows.length === 0)
        return res.status(404).json({ success: false, message: "User not found" });
      return res.status(200).json({ success: true, user: rows[0] });
    }

    const { rows } = await pool.query(
      "SELECT id, name, email, role, user_image, created_at FROM users ORDER BY created_at DESC"
    );
    return res.status(200).json({ success: true, totalUsers: rows.length, users: rows });
  } catch (error) {
    console.error("Get users error:", error.message);
    return res.status(500).json({ success: false, message: "Server error" });
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
  forgotPasswordOtp,
  resetPassword,
  changePassword,
  oauthLoginHandler,
};