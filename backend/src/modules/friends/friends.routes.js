const express = require('express');
const { requireAuth, attachCurrentUser } = require('../../common/middleware');
const User = require('../users/user.model');
const FriendRequest = require('./friendRequest.model');
const { AppError } = require('../../common/errors');
const { emitToUser } = require('../realtime/socket');
const { audit } = require('../audit/audit.service');

const router = express.Router();

function statusFor(usersMap, currentUserId, targetUserId) {
  const req = usersMap.find((r) =>
    (r.fromUser.toString() === currentUserId && r.toUser.toString() === targetUserId) ||
    (r.toUser.toString() === currentUserId && r.fromUser.toString() === targetUserId));
  if (!req) return 'none';
  if (req.status === 'accepted') return 'friends';
  if (req.fromUser.toString() === currentUserId && req.status === 'pending') return 'requested';
  if (req.toUser.toString() === currentUserId && req.status === 'pending') return 'incoming';
  return req.status;
}

router.get('/search', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const q = (req.query.q || '').toString().trim();
    if (!q) return res.json([]);
    const users = await User.find({
      role: 'user',
      _id: { $ne: req.currentUser._id },
      $or: [{ username: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }]
    }).limit(10).select('_id username email avatarUrl');
    const ids = users.map((u) => u._id);
    const reqs = await FriendRequest.find({
      $or: [
        { fromUser: req.currentUser._id, toUser: { $in: ids } },
        { toUser: req.currentUser._id, fromUser: { $in: ids } }
      ]
    });
    res.json(users.map((u) => ({
      id: u._id,
      username: u.username,
      email: u.email,
      avatarUrl: u.avatarUrl,
      relation: statusFor(reqs, req.currentUser._id.toString(), u._id.toString())
    })));
  } catch (e) { next(e); }
});

router.post('/request', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const { toUserId } = req.body;
    if (!toUserId) throw new AppError('VALIDATION_ERROR', 'toUserId required');
    if (toUserId === req.currentUser._id.toString()) throw new AppError('VALIDATION_ERROR', 'Cannot friend yourself');
    const toUser = await User.findById(toUserId);
    if (!toUser || toUser.role !== 'user') throw new AppError('NOT_FOUND', 'Target user not found', 404);

    const existing = await FriendRequest.findOne({ fromUser: req.currentUser._id, toUser: toUserId });
    if (existing && existing.status === 'pending') throw new AppError('ALREADY_EXISTS', 'Request already pending', 409);
    if (existing) {
      existing.status = 'pending';
      await existing.save();
    } else {
      await FriendRequest.create({ fromUser: req.currentUser._id, toUser: toUserId, status: 'pending' });
    }
    emitToUser(toUserId, 'friend:request', { fromUserId: req.currentUser._id, username: req.currentUser.username });
    await audit({ actorId: req.currentUser._id, action: 'friend.request', target: toUserId, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/cancel', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const { toUserId } = req.body;
    const fr = await FriendRequest.findOne({ fromUser: req.currentUser._id, toUser: toUserId, status: 'pending' });
    if (!fr) throw new AppError('NOT_FOUND', 'Pending request not found', 404);
    fr.status = 'cancelled';
    await fr.save();
    emitToUser(toUserId, 'friend:cancelled', { fromUserId: req.currentUser._id.toString() });
    await audit({ actorId: req.currentUser._id, action: 'friend.cancel', target: toUserId, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/respond', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const { fromUserId, action } = req.body;
    if (!['accept', 'reject'].includes(action)) throw new AppError('VALIDATION_ERROR', 'Invalid action');
    const fr = await FriendRequest.findOne({ fromUser: fromUserId, toUser: req.currentUser._id, status: 'pending' });
    if (!fr) throw new AppError('NOT_FOUND', 'Request not found', 404);
    fr.status = action === 'accept' ? 'accepted' : 'rejected';
    await fr.save();
    if (action === 'accept') {
      await User.updateOne({ _id: req.currentUser._id }, { $addToSet: { friends: fromUserId } });
      await User.updateOne({ _id: fromUserId }, { $addToSet: { friends: req.currentUser._id } });
    }
    emitToUser(fromUserId, 'friend:updated', { by: req.currentUser._id.toString(), action });
    await audit({ actorId: req.currentUser._id, action: `friend.${action}`, target: fromUserId, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.get('/list', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const users = await User.find({ _id: { $in: req.currentUser.friends } }).select('_id username email avatarUrl');
    res.json(users.map((u) => ({ id: u._id, username: u.username, email: u.email, avatarUrl: u.avatarUrl })));
  } catch (e) { next(e); }
});

router.get('/requests', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have friends module', 403);
    const incoming = await FriendRequest.find({ toUser: req.currentUser._id, status: 'pending' }).populate('fromUser', 'username email avatarUrl');
    const outgoing = await FriendRequest.find({ fromUser: req.currentUser._id, status: 'pending' }).populate('toUser', 'username email avatarUrl');
    res.json({
      incoming: incoming.map((r) => ({ id: r._id, from: r.fromUser })),
      outgoing: outgoing.map((r) => ({ id: r._id, to: r.toUser }))
    });
  } catch (e) { next(e); }
});

module.exports = router;
