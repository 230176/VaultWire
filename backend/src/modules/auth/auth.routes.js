const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const forge = require('node-forge');
const User = require('../users/user.model');
const Otp = require('../otp/otp.model');
const Session = require('./session.model');
const { AppError } = require('../../common/errors');
const { passwordMeetsPolicy, isStrongPassword, encryptText } = require('../../common/crypto');
const { signAccessToken, createSession, verifyRefreshToken, hashToken } = require('../../common/auth');
const env = require('../../config/env');
const { requireAuth, attachCurrentUser } = require('../../common/middleware');
const { audit } = require('../audit/audit.service');

const router = express.Router();

function generateOtp() {
  return `${Math.floor(100000 + Math.random() * 900000)}`;
}
function cookieOptions() {
  return {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/api/v1/auth'
  };
}
function generateUserKeyPairs() {
  const rsa = forge.pki.rsa.generateKeyPair(2048);
  const cryptoPublicKeyPem = forge.pki.publicKeyToPem(rsa.publicKey);
  const cryptoPrivateKeyPem = forge.pki.privateKeyToPem(rsa.privateKey);

  const ec = crypto.generateKeyPairSync('x25519');
  const chatPublicKeyPem = ec.publicKey.export({ type: 'spki', format: 'pem' });
  const chatPrivateKeyPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' });

  return { cryptoPublicKeyPem, cryptoPrivateKeyPem, chatPublicKeyPem, chatPrivateKeyPem };
}

router.post('/register', async (req, res, next) => {
  try {
    const { username, email, password, phone = '', bio = '' } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();
    if (!username || !normalizedEmail || !password) throw new AppError('VALIDATION_ERROR', 'username, email and password are required');
    const pwPolicy = passwordMeetsPolicy(password);
    if (!isStrongPassword(password)) {
      throw new AppError('WEAK_PASSWORD', 'Password does not meet policy', 400, pwPolicy);
    }
    const exists = await User.findOne({ $or: [{ email: normalizedEmail }, { username }] });
    if (exists) throw new AppError('ALREADY_EXISTS', 'User already exists', 409);

    const pairs = generateUserKeyPairs();
    const user = await User.create({
      username,
      email: normalizedEmail,
      phone,
      bio,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'user',
      verified: false,
      cryptoPublicKeyPem: pairs.cryptoPublicKeyPem,
      cryptoPrivateKeyEnc: encryptText(pairs.cryptoPrivateKeyPem),
      chatPublicKeyPem: pairs.chatPublicKeyPem,
      chatPrivateKeyEnc: encryptText(pairs.chatPrivateKeyPem)
    });

    await Otp.deleteMany({ email: normalizedEmail, purpose: 'verify' });
    const otp = generateOtp();
    await Otp.create({
      email: normalizedEmail,
      otpHash: await bcrypt.hash(otp, 10),
      otpDevPlain: env.NODE_ENV === 'production' ? null : otp,
      purpose: 'verify',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });
    await audit({ actorId: user._id, action: 'auth.register', target: user.email, correlationId: req.correlationId });

    const payload = { ok: true, message: 'Registered. Verify OTP.' };
    if (env.NODE_ENV !== 'production') payload.devOtp = otp;
    res.status(201).json(payload);
  } catch (e) { next(e); }
});

router.post('/admin/bootstrap', async (req, res, next) => {
  try {
    const { token, username, email, password } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();
    if (token !== env.ADMIN_BOOTSTRAP_TOKEN) throw new AppError('FORBIDDEN', 'Invalid bootstrap token', 403);
    const hasAdmin = await User.exists({ role: 'admin' });
    if (hasAdmin) throw new AppError('BOOTSTRAP_LOCKED', 'Admin already bootstrapped', 409);
    if (!isStrongPassword(password || '')) throw new AppError('WEAK_PASSWORD', 'Weak password');

    const pairs = generateUserKeyPairs();
    const admin = await User.create({
      username,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'admin',
      adminApproved: true,
      approvedAt: new Date(),
      verified: true,
      cryptoPublicKeyPem: pairs.cryptoPublicKeyPem,
      cryptoPrivateKeyEnc: encryptText(pairs.cryptoPrivateKeyPem),
      chatPublicKeyPem: pairs.chatPublicKeyPem,
      chatPrivateKeyEnc: encryptText(pairs.chatPrivateKeyPem)
    });
    await audit({ actorId: admin._id, action: 'auth.admin_bootstrap', target: admin.email, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});


router.post('/admin/register', async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();
    if (!username || !normalizedEmail || !password) throw new AppError('VALIDATION_ERROR', 'username, email and password are required');
    const pwPolicy = passwordMeetsPolicy(password);
    if (!isStrongPassword(password)) {
      throw new AppError('WEAK_PASSWORD', 'Password does not meet policy', 400, pwPolicy);
    }
    const exists = await User.findOne({ $or: [{ email: normalizedEmail }, { username }] });
    if (exists) throw new AppError('ALREADY_EXISTS', 'Admin already exists with this email/username', 409);

    const pairs = generateUserKeyPairs();
    const pendingAdmin = await User.create({
      username,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'admin',
      adminApproved: false,
      verified: true,
      cryptoPublicKeyPem: pairs.cryptoPublicKeyPem,
      cryptoPrivateKeyEnc: encryptText(pairs.cryptoPrivateKeyPem),
      chatPublicKeyPem: pairs.chatPublicKeyPem,
      chatPrivateKeyEnc: encryptText(pairs.chatPrivateKeyPem)
    });

    await audit({ actorId: pendingAdmin._id, action: 'auth.admin_register', target: pendingAdmin.email, correlationId: req.correlationId });
    res.status(201).json({ ok: true, message: 'Admin registration submitted. Waiting for superadmin approval.' });
  } catch (e) { next(e); }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) throw new AppError('INVALID_CREDENTIALS', 'Invalid credentials', 401);
    if (user.disabled) throw new AppError('ACCOUNT_DISABLED', 'Account disabled', 403);

    const ok = await bcrypt.compare(password || '', user.passwordHash);
    if (!ok) {
      await audit({ actorId: user._id, action: 'auth.login', target: email, outcome: 'failure', correlationId: req.correlationId });
      throw new AppError('INVALID_CREDENTIALS', 'Invalid credentials', 401);
    }
    if (user.role === 'admin' && !user.adminApproved) {
      throw new AppError('ADMIN_PENDING_APPROVAL', 'Admin account pending superadmin approval', 403);
    }
    if (user.role === 'user' && !user.verified) {
      throw new AppError('OTP_REQUIRED', 'OTP verification required', 403);
    }

    const accessToken = signAccessToken(user);
    const refreshToken = await createSession(user, req.headers['user-agent'] || '', req.ip);
    res.cookie('refreshToken', refreshToken, cookieOptions());
    await audit({ actorId: user._id, action: 'auth.login', target: email, correlationId: req.correlationId });
    res.json({
      accessToken,
      user: { id: user._id, email: user.email, username: user.username, role: user.role, verified: user.verified }
    });
  } catch (e) { next(e); }
});

router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) throw new AppError('UNAUTHORIZED', 'Missing refresh token', 401);
    const payload = await verifyRefreshToken(refreshToken);
    const user = await User.findById(payload.sub);
    if (!user || user.disabled) throw new AppError('UNAUTHORIZED', 'User not available', 401);

    // rotate token
    await Session.updateOne({ tokenHash: hashToken(refreshToken), revoked: false }, { $set: { revoked: true } });
    const nextRefresh = await createSession(user, req.headers['user-agent'] || '', req.ip);
    const accessToken = signAccessToken(user);
    res.cookie('refreshToken', nextRefresh, cookieOptions());
    res.json({
      accessToken,
      user: { id: user._id, email: user.email, username: user.username, role: user.role, verified: user.verified }
    });
  } catch (e) { next(e); }
});

router.post('/logout', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      await Session.updateOne({ tokenHash: hashToken(refreshToken), revoked: false }, { $set: { revoked: true } });
    }
    res.clearCookie('refreshToken', cookieOptions());
    await audit({ actorId: req.currentUser._id, action: 'auth.logout', target: req.currentUser.email, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/logout-others', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    const keepHash = refreshToken ? hashToken(refreshToken) : null;
    await Session.updateMany({ user: req.currentUser._id, tokenHash: { $ne: keepHash }, revoked: false }, { $set: { revoked: true } });
    await audit({ actorId: req.currentUser._id, action: 'auth.logout_others', target: req.currentUser.email, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.get('/me', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    res.json({
      id: req.currentUser._id,
      email: req.currentUser.email,
      username: req.currentUser.username,
      role: req.currentUser.role,
      verified: req.currentUser.verified,
      disabled: req.currentUser.disabled
    });
  } catch (e) { next(e); }
});

module.exports = router;
