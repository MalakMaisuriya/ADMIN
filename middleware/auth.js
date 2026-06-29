function requireAuth(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }

  return next();
}

function redirectIfAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }

  return next();
}

module.exports = {
  requireAuth,
  redirectIfAuthenticated,
};
