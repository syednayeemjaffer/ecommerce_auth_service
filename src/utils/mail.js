const nodemailer = require("nodemailer");

// ─── SMTP Transporter ─────────────────────────────────────────────────────────
// Uses Gmail SMTP. Credentials are loaded from environment variables.
// For production, consider using an app password or a transactional email service
// (e.g. SendGrid, Resend, Mailgun) instead of direct Gmail credentials.
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS, // Use a Gmail App Password, not your account password
  },
});

// ─── Mail Senders ─────────────────────────────────────────────────────────────

/**
 * Sends a 6-digit OTP to the given email address.
 * Used for both registration verification and forgot-password flows.
 *
 * @param {string} email - Recipient email address
 * @param {string} otp   - 6-digit OTP string
 */
const sendOtpMail = async (email, otp) => {
  await transporter.sendMail({
    from:    process.env.MAIL_USER,
    to:      email,
    subject: "Your OTP Code",
    html: `
      <h2>Email Verification OTP</h2>
      <p>Your OTP is:</p>
      <h1 style="letter-spacing: 4px;">${otp}</h1>
      <p>This OTP expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
    `,
  });
};

module.exports = { sendOtpMail };