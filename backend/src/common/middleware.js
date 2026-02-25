const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const env = require('../config/env');
const { AppError } = require('./errors');
const jwt = require('jsonwebtoken');
const User = require('../modules/users/user.model');
const Certificate = require('../modules/pki/certificate.model');
const Revocation = require('../modules/pki/revocation.model');
const RateLimitEvent = require('../modules/admin/rateLimitEvent.model');

const baseLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  limit: env.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    try {
      await RateLimitEvent.create({ ip: req.ip, path: req.path, method: req.method });
    } catch {}
    res.status(429).json({ code: 'RATE_LIMITED', message: 'Too many requests', correlationId: req.correlationId });
  }
});

const authLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  limit: env.AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false
});

function commonMiddleware(app) {
  app.use(helmet());
  app.use(cors({ origin: env.CORS_ORIGIN, credentials: true }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    req.correlationId = uuidv4();
    res.setHeader('X-Correlation-Id', req.correlationId);
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(baseLimiter);
  app.use('/api/v1/auth', authLimiter);
}

function requireAuth(req, _res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return next(new AppError('UNAUTHORIZED', 'Missing bearer token', 401));
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET);
    req.user = payload;
    return next();
  } catch {
    return next(new AppError('UNAUTHORIZED', 'Invalid access token', 401));
  }
}

async function attachCurrentUser(req, _res, next) {
  if (!req.user?.sub) return next(new AppError('UNAUTHORIZED', 'Unauthorized', 401));
  const user = await User.findById(req.user.sub);
  if (!user) return next(new AppError('UNAUTHORIZED', 'User not found', 401));
  if (user.disabled) return next(new AppError('ACCOUNT_DISABLED', 'Account disabled', 403));
  req.currentUser = user;
  next();
}

function requireRole(requiredRoles) {
  const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  return (req, _res, next) => {
    const actual = req.user?.role;
    if (!actual) return next(new AppError('FORBIDDEN', 'Forbidden', 403));
    // hierarchy: superadmin can do everything admin can
    const expanded = new Set(roles);
    if (expanded.has('admin')) expanded.add('superadmin');
    if (!expanded.has(actual)) return next(new AppError('FORBIDDEN', 'Forbidden', 403));
    next();
  };
}

async function requireValidCert(req, _res, next) {
  const cert = await Certificate.findOne({ user: req.currentUser._id, status: 'issued' }).sort({ issuedAt: -1 });
  if (!cert) return next(new AppError('CERT_MISSING', 'Certificate missing', 403));
  if (new Date(cert.expiresAt) < new Date()) return next(new AppError('CERT_EXPIRED', 'Certificate expired', 403));
  const revoked = await Revocation.findOne({ serial: cert.serial });
  if (revoked) return next(new AppError('CERT_REVOKED', 'Certificate revoked', 403));
  req.currentCert = cert;
  next();
}

function errorHandler(err, req, res, _next) {
  const status = err.status || 500;
  res.status(status).json({
    code: err.code || 'INTERNAL_ERROR',
    message: err.message || 'Internal error',
    details: err.details || null,
    correlationId: req.correlationId
  });
}

module.exports = {
  commonMiddleware,
  requireAuth,
  requireRole,
  attachCurrentUser,
  requireValidCert,
  errorHandler
};
