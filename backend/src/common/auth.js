const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const env = require('../config/env');
const Session = require('../modules/auth/session.model');
const { AppError } = require('./errors');

function signAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, email: user.email },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.ACCESS_TOKEN_TTL }
  );
}
function signRefreshToken(user, jti) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, jti },
    env.JWT_REFRESH_SECRET,
    { expiresIn: `${env.REFRESH_TOKEN_TTL_DAYS}d` }
  );
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
async function createSession(user, userAgent, ip) {
  const jti = crypto.randomUUID();
  const refreshToken = signRefreshToken(user, jti);
  await Session.create({
    user: user._id,
    tokenHash: hashToken(refreshToken),
    userAgent,
    ip,
    expiresAt: new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000)
  });
  return refreshToken;
}

async function verifyRefreshToken(refreshToken) {
  try {
    const payload = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET);
    const found = await Session.findOne({
      user: payload.sub,
      tokenHash: hashToken(refreshToken),
      revoked: false,
      expiresAt: { $gt: new Date() }
    });
    if (!found) throw new AppError('SESSION_INVALID', 'Session invalid', 401);
    return payload;
  } catch (e) {
    if (e instanceof AppError) throw e;
    throw new AppError('TOKEN_INVALID', 'Invalid refresh token', 401);
  }
}

module.exports = {
  signAccessToken,
  createSession,
  verifyRefreshToken,
  hashToken
};
