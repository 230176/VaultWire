const express = require('express');
const { requireAuth, attachCurrentUser } = require('../../common/middleware');
const Session = require('../auth/session.model');
const { hashToken } = require('../../common/auth');

const router = express.Router();

router.get('/me', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const sessions = await Session.find({ user: req.currentUser._id, revoked: false, expiresAt: { $gt: new Date() } })
      .sort({ updatedAt: -1 })
      .select('_id userAgent ip createdAt updatedAt');
    res.json(sessions);
  } catch (e) { next(e); }
});

router.delete('/me/:id', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    await Session.updateOne({ _id: req.params.id, user: req.currentUser._id }, { $set: { revoked: true } });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

module.exports = router;
