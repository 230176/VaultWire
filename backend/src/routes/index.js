const express = require('express');
const authRoutes = require('../modules/auth/auth.routes');
const otpRoutes = require('../modules/otp/otp.routes');
const profileRoutes = require('../modules/profiles/profiles.routes');
const friendRoutes = require('../modules/friends/friends.routes');
const pkiRoutes = require('../modules/pki/pki.routes');
const vaultRoutes = require('../modules/vault/vault.routes');
const messageRoutes = require('../modules/messages/messages.routes');
const sigRoutes = require('../modules/signatures/signatures.routes');
const adminRoutes = require('../modules/admin/admin.routes');
const sessionsRoutes = require('../modules/sessions/sessions.routes');

const router = express.Router();

router.get('/health', (_req, res) => res.json({ ok: true }));

router.use('/auth', authRoutes);
router.use('/otp', otpRoutes);
router.use('/profiles', profileRoutes);
router.use('/friends', friendRoutes);
router.use('/pki', pkiRoutes);
router.use('/vault', vaultRoutes);
router.use('/messages', messageRoutes);
router.use('/signatures', sigRoutes);
router.use('/sessions', sessionsRoutes);
router.use('/admin', adminRoutes);

module.exports = router;
