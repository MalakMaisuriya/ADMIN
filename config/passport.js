const bcrypt = require('bcryptjs');
const { Strategy: LocalStrategy } = require('passport-local');
const { getDb } = require('../db');

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function configurePassport(passport) {
  passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
  }, async (email, password, done) => {
    try {
      const normalizedEmail = normalizeEmail(email);
      const db = await getDb();
      const user = await db.get(
        'SELECT id, name, email, password_hash FROM users WHERE email = ?',
        normalizedEmail,
      );

      if (!user) {
        return done(null, false, { message: 'Invalid email or password.' });
      }

      const passwordMatches = await bcrypt.compare(String(password || ''), user.password_hash);
      if (!passwordMatches) {
        return done(null, false, { message: 'Invalid email or password.' });
      }

      return done(null, {
        id: user.id,
        name: user.name,
        email: user.email,
      });
    } catch (error) {
      return done(error);
    }
  }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const db = await getDb();
      const user = await db.get('SELECT id, name, email FROM users WHERE id = ?', id);

      if (!user) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  });
}

module.exports = {
  configurePassport,
  normalizeEmail,
};
