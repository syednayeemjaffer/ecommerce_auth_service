const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");

const { pool } = require("../config/db");
const redis = require("../config/redis");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/jwt");

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const nameRegex = /^[A-Za-z\s]+$/;
const passwordSpecialRegex = /[!@#$%^&*(),.?":{}|<>]/;

const ALLOWED_MIME_TYPES = [
  "image/png",
  "image/jpeg",
  "image/jpg",
];



const register = async (req, res) => {
  try {
    let { name, email, password, role } = req.body;

    // =========================
    // NAME VALIDATION
    // =========================
    if (!name || !name.trim()) {
      return res.status(400).json({
        success: false,
        error: {
          field: "name",
          message: "Please provide name",
        },
      });
    }

    name = name.trim();

    if (name.length < 3 || name.length > 30) {
      return res.status(400).json({
        success: false,
        error: {
          field: "name",
          message: "Name must be at least 3 characters & no more than 30 characters",
        },
      });
    }


    if (!nameRegex.test(name)) {
      return res.status(400).json({
        success: false,
        error: {
          field: "name",
          message: "Name can only contain letters and spaces",
        },
      });
    }

    // =========================
    // EMAIL VALIDATION
    // =========================
    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        error: {
          field: "email",
          message: "Please provide email",
        },
      });
    }

    email = email.trim()

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: {
          field: "email",
          message: "Please enter a valid email address",
        },
      });
    }

    // =========================
    // PASSWORD VALIDATION
    // =========================
    if (!password) {
      return res.status(400).json({
        success: false,
        error: {
          field: "password",
          message: "Please provide password",
        },
      });
    }

    if (password.length < 6 || password.length > 30) {
      return res.status(400).json({
        success: false,
        error: {
          field: "password",
          message: "Password must be at least 6 characters and at most 30 characters",
        },
      });
    }


    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !passwordSpecialRegex.test(password)) {
      return res.status(400).json({
        success: false,
        error: {
          field: "password",
          message: "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character",
        },
      });
    }

    // =========================
    // ROLE VALIDATION
    // =========================
    role = role ? role.toUpperCase() : "USER";

    if (!["USER", "ADMIN"].includes(role)) {
      return res.status(400).json({
        success: false,
        error: {
          field: "role",
          message: "Role must be USER or ADMIN",
        },
      });
    }

    // =========================
    // IMAGE VALIDATION
    // =========================
    let imagePath = null;

    if (req.file) {
      if (!ALLOWED_MIME_TYPES.includes(req.file.mimetype)) {
        return res.status(400).json({
          success: false,
          error: {
            field: "user_image",
            message: "Only png, jpg, jpeg images are allowed",
          },
        });
      }

      // save image only after all validations pass
      const uploadDir = path.join(__dirname, "../../uploads");

      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }

      const fileName = `${Date.now()}-${req.file.originalname}`;
      const filePath = path.join(uploadDir, fileName);

      fs.writeFileSync(filePath, req.file.buffer);

      imagePath = fileName;
    }

    // =========================
    // CHECK EXISTING USER
    // =========================
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: {
          field: "email",
          message: "Email already exists",
        },
      });
    }

    // =========================
    // CREATE USER
    // =========================
    const passwordHash = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, user_image)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role, user_image`,
      [name, email, passwordHash, role, imagePath]
    );

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: userResult.rows[0],
    });
  } catch (error) {
    console.error("Register error:", error.message);

    return res.status(500).json({
      success: false,
      message: error.message || "Server error",
    });
  }
};

const login = async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        error: {
          field: "email",
          message: "Please provide email",
        },
      });
    }

    email = email.trim();

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: {
          field: "email",
          message: "Please enter a valid email address",
        },
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        error: {  
          field: "password",
          message: "Please provide password",
        },
      });
    }

    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: {
          field: "email",
          message: "User not found, please create an account",
        },
      });
    }

    const user = userResult.rows[0];

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: {
          field: "password",
          message: "Incorrect password",
        },
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await redis.set(
      `refresh:${user.id}`,
      refreshToken,
      "EX",
      7 * 24 * 60 * 60
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
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

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

module.exports = {
  register,
  login,
};