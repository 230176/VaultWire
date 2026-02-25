const express = require('express');
const bcrypt = require('bcryptjs');
const Otp = require('./otp.model');
const User = require('../users/user.model');
const env = require('../../config/env');
const { AppError } = require('../../common/errors');
const { audit } = require('../audit/audit.service');

const router = express.Router();

function generateOtp() {
  return `${Math.floor(100000 + Math.random() * 900000)}`;
}

router.post('/verify', async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    const row = await Otp.findOne({ email, purpose: 'verify' }).sort({ createdAt: -1 });
    if (!row) throw new AppError('OTP_NOT_FOUND', 'OTP not found', 404);
    if (row.expiresAt < new Date()) throw new AppError('OTP_EXPIRED', 'OTP expired', 400);
    if (row.attempts >= 5) throw new AppError('OTP_LOCKED', 'Too many attempts', 429);

    const ok = await bcrypt.compare(otp || '', row.otpHash);
    if (!ok) {
      row.attempts += 1;
      await row.save();
      throw new AppError('OTP_INVALID', 'OTP invalid', 400);
    }
    await User.updateOne({ email }, { $set: { verified: true } });
    await Otp.deleteMany({ email, purpose: 'verify' });
    const user = await User.findOne({ email });
    await audit({ actorId: user?._id, action: 'otp.verify', target: email, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/resend', async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new AppError('NOT_FOUND', 'User not found', 404);
    const otp = generateOtp();
    await Otp.create({
      email,
      otpHash: await bcrypt.hash(otp, 10),
      otpDevPlain: env.NODE_ENV === 'production' ? null : otp,
      purpose: 'verify',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });
    const payload = { ok: true };
    if (env.NODE_ENV !== 'production') payload.devOtp = otp;
    res.json(payload);
  } catch (e) { next(e); }
});

router.get('/dev/:email', async (req, res, next) => {
  try {
    if (env.NODE_ENV === 'production') throw new AppError('FORBIDDEN', 'Disabled in production', 403);
    const row = await Otp.findOne({ email: req.params.email, purpose: 'verify' }).sort({ createdAt: -1 });
    if (!row) throw new AppError('NOT_FOUND', 'OTP not found', 404);
    res.json({ otp: row.otpDevPlain, expiresAt: row.expiresAt });
  } catch (e) { next(e); }
});

module.exports = router;
