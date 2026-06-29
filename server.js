const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const authRoutes = require('./routes/auth');
const { configurePassport } = require('./config/passport');
const { getDb } = require('./db');
const { requireAuth } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

configurePassport(passport);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
  },
}));
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.redirect(req.isAuthenticated() ? '/dashboard' : '/auth/login');
});

app.use('/auth', authRoutes);

app.get('/login', (req, res) => {
  res.redirect('/auth/login');
});

app.post('/login', (req, res) => {
  res.redirect(307, '/auth/login');
});

app.get('/signup', (req, res) => {
  res.redirect('/auth/signup');
});

app.post('/signup', (req, res) => {
  res.redirect(307, '/auth/signup');
});

app.get('/norzha-rti-dashboard-master', (req, res) => {
  res.redirect('/norzha-rti-dashboard-master/');
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.user });
});

app.get('/users', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const users = await db.all(
      'SELECT id, name, email, password_hash, created_at FROM users ORDER BY id DESC',
    );

    res.render('users', { users });
  } catch (error) {
    next(error);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong.');
});

getDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Nozha admin panel running at http://localhost:${PORT}`);
  });
}).catch((error) => {
  console.error('Failed to initialize database:', error);
  process.exit(1);
});
