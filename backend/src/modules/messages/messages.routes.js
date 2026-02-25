const express = require('express');
const crypto = require('crypto');
const { requireAuth, attachCurrentUser, requireValidCert } = require('../../common/middleware');
const { AppError } = require('../../common/errors');
const Message = require('./message.model');
const ReplayCache = require('./replayCache.model');
const User = require('../users/user.model');
const { encryptText, decryptText } = require('../../common/crypto');
const { emitToUser } = require('../realtime/socket');
const { audit } = require('../audit/audit.service');

const router = express.Router();

function presetToMs(p) {
  const map = { '10s': 10_000, '1m': 60_000, '10m': 600_000, '1h': 3_600_000, '1d': 86_400_000 };
  if (!map[p]) throw new AppError('VALIDATION_ERROR', 'Invalid expiry preset');
  return map[p];
}
function hkdfKey(secret, salt) {
  return crypto.hkdfSync('sha256', secret, salt, Buffer.from('vaultwire-msg'), 32);
}
function encryptMsg(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const c = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { c, iv, tag };
}
function decryptMsg(ciphertextB64, ivB64, tagB64, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const p = Buffer.concat([decipher.update(Buffer.from(ciphertextB64, 'base64')), decipher.final()]);
  return p.toString('utf8');
}
function areFriends(sender, toUserId) {
  return sender.friends.map(String).includes(String(toUserId));
}

router.post('/send', requireAuth, attachCurrentUser, requireValidCert, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not have messaging', 403);
    const { toUserId, text, expiryPreset, messageId, nonce } = req.body;
    if (!toUserId || !text || !messageId || !nonce) throw new AppError('VALIDATION_ERROR', 'toUserId,text,messageId,nonce required');
    if (!areFriends(req.currentUser, toUserId)) throw new AppError('FORBIDDEN', 'Messaging allowed only with friends');
    const replayExpires = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    const existingReplay = await ReplayCache.findOne({ $or: [{ messageId }, { nonce }] });
    if (existingReplay) throw new AppError('REPLAY_DETECTED', 'Duplicate messageId or nonce', 409);
    await ReplayCache.create({ messageId, nonce, expiresAt: replayExpires });

    const toUser = await User.findById(toUserId);
    if (!toUser) throw new AppError('NOT_FOUND', 'Recipient not found', 404);

    const eph = crypto.generateKeyPairSync('x25519');
    const recipientPub = crypto.createPublicKey(toUser.chatPublicKeyPem);
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
    const salt = crypto.randomBytes(16);
    const key = hkdfKey(shared, salt);
    const enc = encryptMsg(text, key);

    const expiresAt = new Date(Date.now() + presetToMs(expiryPreset || '1h'));
    const msg = await Message.create({
      fromUser: req.currentUser._id,
      toUser: toUser._id,
      messageId,
      nonce,
      timestamp: new Date(),
      ciphertext: enc.c.toString('base64'),
      iv: enc.iv.toString('base64'),
      tag: enc.tag.toString('base64'),
      salt: salt.toString('base64'),
      ephPublicPem: eph.publicKey.export({ type: 'spki', format: 'pem' }),
      ephPrivateEnc: encryptText(eph.privateKey.export({ type: 'pkcs8', format: 'pem' })),
      expiresAt
    });

    emitToUser(toUser._id.toString(), 'message:new', { id: msg._id, fromUserId: req.currentUser._id, preview: 'Encrypted message', expiresAt });
    await audit({ actorId: req.currentUser._id, action: 'message.send', target: toUser._id.toString(), correlationId: req.correlationId });
    res.status(201).json({ ok: true, id: msg._id, expiresAt });
  } catch (e) { next(e); }
});

async function decryptForUser(msg, me, peer) {
  if (msg.expiresAt < new Date()) return null;
  if (msg.toUser.toString() === me._id.toString()) {
    const myPriv = crypto.createPrivateKey(decryptText(me.chatPrivateKeyEnc));
    const ephPub = crypto.createPublicKey(msg.ephPublicPem);
    const shared = crypto.diffieHellman({ privateKey: myPriv, publicKey: ephPub });
    const key = hkdfKey(shared, Buffer.from(msg.salt, 'base64'));
    return decryptMsg(msg.ciphertext, msg.iv, msg.tag, key);
  }
  if (msg.fromUser.toString() === me._id.toString()) {
    const ephPriv = crypto.createPrivateKey(decryptText(msg.ephPrivateEnc));
    const peerPub = crypto.createPublicKey(peer.chatPublicKeyPem);
    const shared = crypto.diffieHellman({ privateKey: ephPriv, publicKey: peerPub });
    const key = hkdfKey(shared, Buffer.from(msg.salt, 'base64'));
    return decryptMsg(msg.ciphertext, msg.iv, msg.tag, key);
  }
  return null;
}

router.get('/thread/:peerId', requireAuth, attachCurrentUser, requireValidCert, async (req, res, next) => {
  try {
    const peer = await User.findById(req.params.peerId);
    if (!peer) throw new AppError('NOT_FOUND', 'Peer not found', 404);
    if (!areFriends(req.currentUser, peer._id)) throw new AppError('FORBIDDEN', 'Not friends', 403);

    const msgs = await Message.find({
      $or: [
        { fromUser: req.currentUser._id, toUser: peer._id },
        { fromUser: peer._id, toUser: req.currentUser._id }
      ]
    }).sort({ createdAt: 1 }).limit(300);

    const out = [];
    for (const m of msgs) {
      const text = await decryptForUser(m, req.currentUser, peer);
      if (text === null) continue;
      out.push({
        id: m._id,
        fromUser: m.fromUser,
        toUser: m.toUser,
        text,
        expiresAt: m.expiresAt,
        createdAt: m.createdAt
      });
    }
    res.json(out);
  } catch (e) { next(e); }
});

module.exports = router;
