const express = require('express');
const { stringify } = require('csv-stringify/sync');
const { requireAuth, attachCurrentUser, requireRole } = require('../../common/middleware');
const User = require('../users/user.model');
const AuditLog = require('../audit/auditLog.model');
const Revocation = require('../pki/revocation.model');
const RateLimitEvent = require('./rateLimitEvent.model');
const Session = require('../auth/session.model');
const { AppError } = require('../../common/errors');
const { audit } = require('../audit/audit.service');

const router = express.Router();
router.use(requireAuth, attachCurrentUser, requireRole('admin'));


function requireSuperadmin(req, _res, next) {
  if (req.currentUser.role !== 'superadmin') return next(new AppError('FORBIDDEN', 'Superadmin only', 403));
  next();
}


router.get('/risk/summary', async (req, res, next) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const failedLogins = await AuditLog.countDocuments({ action: 'auth.login', outcome: 'failure', createdAt: { $gte: since } });
    const revokedCount = await Revocation.countDocuments({});
    const rateLimitHits = await RateLimitEvent.countDocuments({ createdAt: { $gte: since } });
    const disabledUsers = await User.countDocuments({ role: 'user', disabled: true });
    res.json({ failedLogins24h: failedLogins, revokedCount, rateLimitHits24h: rateLimitHits, disabledUsers });
  } catch (e) { next(e); }
});

router.get('/users', async (_req, res, next) => {
  try {
    const users = await User.find({ role: 'user' }).select('_id username email disabled verified createdAt');
    res.json(users);
  } catch (e) { next(e); }
});

router.post('/users/:id/disable', async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { $set: { disabled: true } }, { new: true });
    if (!user) throw new AppError('NOT_FOUND', 'User not found', 404);
    await Session.updateMany({ user: user._id, revoked: false }, { $set: { revoked: true } });
    await audit({ actorId: req.currentUser._id, action: 'admin.disable_user', target: user._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/users/:id/force-logout', async (req, res, next) => {
  try {
    await Session.updateMany({ user: req.params.id, revoked: false }, { $set: { revoked: true } });
    await audit({ actorId: req.currentUser._id, action: 'admin.force_logout', target: req.params.id, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.get('/audit', async (req, res, next) => {
  try {
    const { action, outcome, q } = req.query;
    const filter = {};
    if (action) filter.action = action;
    if (outcome) filter.outcome = outcome;
    if (q) filter.$or = [{ action: { $regex: q, $options: 'i' } }, { target: { $regex: q, $options: 'i' } }];
    const rows = await AuditLog.find(filter).sort({ createdAt: -1 }).limit(1000);
    res.json(rows);
  } catch (e) { next(e); }
});

router.get('/audit/export.json', async (_req, res, next) => {
  try {
    const rows = await AuditLog.find({}).sort({ createdAt: -1 }).limit(5000);
    res.json(rows);
  } catch (e) { next(e); }
});

router.get('/audit/export.csv', async (_req, res, next) => {
  try {
    const rows = await AuditLog.find({}).sort({ createdAt: -1 }).limit(5000).lean();
    const data = rows.map((r) => ({
      createdAt: r.createdAt?.toISOString?.() || r.createdAt,
      actorId: r.actorId || '',
      action: r.action || '',
      target: r.target || '',
      outcome: r.outcome || '',
      correlationId: r.correlationId || ''
    }));
    const csv = stringify(data, { header: true });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="audit.csv"');
    res.send(csv);
  } catch (e) { next(e); }
});

router.get('/rate-limit/metrics', async (_req, res, next) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const rows = await RateLimitEvent.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: '$path', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(rows);
  } catch (e) { next(e); }
});


router.get('/admins/pending', requireSuperadmin, async (_req, res, next) => {
  try {
    const pending = await User.find({ role: 'admin', adminApproved: false, disabled: false })
      .select('_id username email createdAt');
    res.json(pending);
  } catch (e) { next(e); }
});

router.get('/admins', requireSuperadmin, async (_req, res, next) => {
  try {
    const admins = await User.find({ role: { $in: ['admin', 'superadmin'] } })
      .select('_id username email role adminApproved disabled createdAt approvedAt');
    res.json(admins);
  } catch (e) { next(e); }
});

router.post('/admins/:id/approve', requireSuperadmin, async (req, res, next) => {
  try {
    const admin = await User.findById(req.params.id);
    if (!admin || admin.role !== 'admin') throw new AppError('NOT_FOUND', 'Admin not found', 404);
    admin.adminApproved = true;
    admin.approvedAt = new Date();
    admin.approvedBy = req.currentUser._id;
    await admin.save();
    await audit({ actorId: req.currentUser._id, action: 'admin.approve_admin', target: admin._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/admins/:id/reject', requireSuperadmin, async (req, res, next) => {
  try {
    const admin = await User.findById(req.params.id);
    if (!admin || admin.role !== 'admin') throw new AppError('NOT_FOUND', 'Admin not found', 404);
    admin.disabled = true;
    await admin.save();
    await audit({ actorId: req.currentUser._id, action: 'admin.reject_admin', target: admin._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});


module.exports = router;
