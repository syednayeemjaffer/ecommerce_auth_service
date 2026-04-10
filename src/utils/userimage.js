const multer = require("multer");

// ─── Multer Upload Config — Profile Images ────────────────────────────────────
/**
 * Multer instance configured for user profile image uploads.
 *
 * - Storage: memory (buffer) — we write to disk manually in the controller
 *   after all validations pass, to avoid orphaned files on invalid requests.
 * - File size limit: 2MB
 *
 * MIME type validation is handled in the controller's validateRegisterInput().
 * Multer itself does not restrict file types here.
 */
const uploadUserImage = multer({
  storage: multer.memoryStorage(), // Keep file in memory until controller decides to save
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB max
  },
});

module.exports = uploadUserImage;