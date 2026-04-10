const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const { getPool } = require("./db");

// ─── Shared OAuth Upsert Helper ───────────────────────────────────────────────
/**
 * Finds an existing user by email or creates a new one.
 * Used by both Google and GitHub OAuth strategies to avoid code duplication.
 *
 * @param {Pool}   pool       - PostgreSQL pool instance
 * @param {Object} userData   - { name, email, image, provider, providerId }
 * @returns {Object} The existing or newly created user row
 */
const findOrCreateOAuthUser = async (pool, { name, email, image, provider, providerId }) => {
  // Check if a user with this email already exists
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  // Return existing user if found
  if (rows.length > 0) return rows[0];

  // Otherwise, insert a new user with OAuth provider details
  const inserted = await pool.query(
    `INSERT INTO users
       (name, email, role, user_image, provider, provider_id)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [name, email, "USER", image, provider, providerId]
  );

  return inserted.rows[0];
};

// ─── Google OAuth Strategy ────────────────────────────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const pool = getPool();

        // Extract primary email and profile photo from Google profile
        const email = profile.emails?.[0]?.value;
        const image = profile.photos?.[0]?.value || null;

        const user = await findOrCreateOAuthUser(pool, {
          name:       profile.displayName,
          email,
          image,
          provider:   "GOOGLE",
          providerId: profile.id,
        });

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// ─── GitHub OAuth Strategy ────────────────────────────────────────────────────
passport.use(
  new GitHubStrategy(
    {
      clientID:     process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL:  process.env.GITHUB_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const pool = getPool();

        // GitHub may not expose email publicly — fall back to a synthetic local email
        const email =
          profile.emails?.[0]?.value ||
          `${profile.username}@github.local`;

        const image = profile.photos?.[0]?.value || null;

        const user = await findOrCreateOAuthUser(pool, {
          name:       profile.displayName || profile.username,
          email,
          image,
          provider:   "GITHUB",
          providerId: profile.id,
        });

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

module.exports = passport;