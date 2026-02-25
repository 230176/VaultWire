const express = require('express');
const { requireAuth, attachCurrentUser } = require('../../common/middleware');
const User = require('../users/user.model');
const { AppError } = require('../../common/errors');
const { audit } = require('../audit/audit.service');

const router = express.Router();

router.get('/me', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const u = req.currentUser;
    res.json({
      id: u._id, username: u.username, email: u.email, phone: u.phone, bio: u.bio, avatarUrl: u.avatarUrl, privacy: u.privacy, role: u.role
    });
  } catch (e) { next(e); }
});

router.patch('/me', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const allowed = ['username', 'phone', 'bio', 'avatarUrl', 'privacy'];
    const update = {};
    for (const key of allowed) if (req.body[key] !== undefined) update[key] = req.body[key];
    if (update.username) {
      const exists = await User.findOne({ username: update.username, _id: { $ne: req.currentUser._id } });
      if (exists) throw new AppError('ALREADY_EXISTS', 'Username already used', 409);
    }
    const user = await User.findByIdAndUpdate(req.currentUser._id, { $set: update }, { new: true });
    await audit({ actorId: req.currentUser._id, action: 'profile.update', target: req.currentUser._id.toString(), correlationId: req.correlationId });
    res.json({
      id: user._id, username: user.username, email: user.email, phone: user.phone, bio: user.bio, avatarUrl: user.avatarUrl, privacy: user.privacy
    });
  } catch (e) { next(e); }
});

router.get('/:id', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const u = await User.findById(req.params.id);
    if (!u) throw new AppError('NOT_FOUND', 'User not found', 404);
    const isSelf = u._id.toString() === req.currentUser._id.toString();
    const isFriend = req.currentUser.friends.some((f) => f.toString() === u._id.toString());
    const globalPrivate = u.privacy?.global === 'private' && !isSelf && !isFriend;
    const view = {
      id: u._id,
      username: u.username,
      avatarUrl: u.avatarUrl
    };
    if (!globalPrivate) {
      if (u.privacy?.bio === 'public' || isSelf || isFriend) view.bio = u.bio;
      if (u.privacy?.phone === 'public' || isSelf || isFriend) view.phone = u.phone;
      if (u.privacy?.email === 'public' || isSelf || isFriend) view.email = u.email;
    }
    res.json(view);
  } catch (e) { next(e); }
});

module.exports = router;
