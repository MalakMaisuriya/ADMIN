const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { getDb } = require('../db');
const { redirectIfAuthenticated } = require('../middleware/auth');
const { normalizeEmail } = require('../config/passport');

const router = express.Router();
const SALT_ROUNDS = 12;

function renderLogin(res, options = {}) {
  return res.render('login', {
    error: null,
    message: null,
    ...options,
  });
}

function renderSignup(res, options = {}) {
  return res.render('signup', {
    error: null,
    message: null,
    ...options,
  });
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

router.get('/login', redirectIfAuthenticated, (req, res) => {
  renderLogin(res, { message: req.query.registered ? 'Account created. Please login.' : null });
});

router.post('/login', redirectIfAuthenticated, (req, res, next) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');

  if (!email || !password) {
    return renderLogin(res, { error: 'Email and password are required.' });
  }

  passport.authenticate('local', (error, user, info) => {
    if (error) {
      return next(error);
    }

    if (!user) {
      return renderLogin(res, { error: info?.message || 'Invalid email or password.' });
    }

    return req.login(user, (loginError) => {
      if (loginError) {
        return next(loginError);
      }

      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

router.get('/signup', redirectIfAuthenticated, (req, res) => {
  renderSignup(res);
});

router.post('/signup', redirectIfAuthenticated, asyncHandler(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!name || !email || !password || !confirmPassword) {
    return renderSignup(res, { error: 'All fields are required.' });
  }

  if (password.length < 6) {
    return renderSignup(res, { error: 'Password must be at least 6 characters.' });
  }

  if (password !== confirmPassword) {
    return renderSignup(res, { error: 'Passwords do not match.' });
  }

  const db = await getDb();
  const existingUser = await db.get('SELECT id FROM users WHERE email = ?', email);

  if (existingUser) {
    return renderSignup(res, { error: 'This email is already registered.' });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  await db.run(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
    name,
    email,
    passwordHash,
  );

  return res.redirect('/auth/login?registered=1');
}));

router.post('/logout', (req, res, next) => {
  req.logout((logoutError) => {
    if (logoutError) {
      return next(logoutError);
    }

    return req.session.destroy((error) => {
      if (error) {
        return next(error);
      }

      res.clearCookie('connect.sid');
      return res.redirect('/auth/login');
    });
  });
});

module.exports = router;
