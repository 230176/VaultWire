const express = require('express');
const forge = require('node-forge');
const crypto = require('crypto');
const { requireAuth, attachCurrentUser, requireRole } = require('../../common/middleware');
const CAState = require('./caState.model');
const Certificate = require('./certificate.model');
const Revocation = require('./revocation.model');
const User = require('../users/user.model');
const { AppError } = require('../../common/errors');
const { encryptText, decryptText } = require('../../common/crypto');
const { audit } = require('../audit/audit.service');

const router = express.Router();

function createSerial() {
  return crypto.randomBytes(16).toString('hex');
}

function pemFingerprint(pem) {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pem))).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  return md.digest().toHex().match(/.{1,2}/g).join(':');
}

function ensureAdmin(user) {
  if (!['admin', 'superadmin'].includes(user.role)) throw new AppError('FORBIDDEN', 'Admin only', 403);
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

async function issueCertForUser(user, ca, options = {}) {
  const caCert = forge.pki.certificateFromPem(ca.certPem);
  const caPriv = forge.pki.privateKeyFromPem(decryptText(ca.privateKeyEnc));
  const userPub = forge.pki.publicKeyFromPem(user.cryptoPublicKeyPem);
  const serial = createSerial();

  const cert = forge.pki.createCertificate();
  cert.publicKey = userPub;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + (options.validDays || 365) * 24 * 60 * 60 * 1000);
  cert.setSubject([
    { name: 'commonName', value: user.username },
    { name: 'emailAddress', value: user.email }
  ]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true, keyEncipherment: true }]);
  cert.sign(caPriv, forge.md.sha256.create());

  const pem = forge.pki.certificateToPem(cert);
  const issued = await Certificate.create({
    user: user._id,
    serial,
    pem,
    issuedAt: cert.validity.notBefore,
    expiresAt: cert.validity.notAfter,
    issuer: 'VaultWire Root CA',
    status: 'issued'
  });

  return issued;
}


router.post('/admin/init-ca', requireAuth, attachCurrentUser, requireRole('admin'), async (req, res, next) => {
  try {
    ensureAdmin(req.currentUser);
    const exists = await CAState.findOne();
    if (exists) throw new AppError('CA_ALREADY_INITIALIZED', 'CA already initialized', 409);

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = createSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000);
    const attrs = [{ name: 'commonName', value: 'VaultWire Root CA' }, { name: 'organizationName', value: 'VaultWire' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const privPem = forge.pki.privateKeyToPem(keys.privateKey);
    const row = await CAState.create({
      certPem,
      privateKeyEnc: encryptText(privPem),
      fingerprint: pemFingerprint(certPem)
    });
    await audit({ actorId: req.currentUser._id, action: 'pki.ca_init', target: row._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true, fingerprint: row.fingerprint, certPem });
  } catch (e) { next(e); }
});

router.get('/ca', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const ca = await CAState.findOne();
    if (!ca) throw new AppError('CA_NOT_READY', 'CA not initialized', 404);
    res.json({ certPem: ca.certPem, fingerprint: ca.fingerprint });
  } catch (e) { next(e); }
});

router.post('/admin/issue/:userId', requireAuth, attachCurrentUser, requireRole('admin'), async (req, res, next) => {
  try {
    ensureAdmin(req.currentUser);
    const ca = await CAState.findOne();
    if (!ca) throw new AppError('CA_NOT_READY', 'CA not initialized', 404);
    const user = await User.findById(req.params.userId);
    if (!user) throw new AppError('NOT_FOUND', 'User not found', 404);

    const issued = await issueCertForUser(user, ca, { validDays: 365 });
    await audit({ actorId: req.currentUser._id, action: 'pki.issue_cert', target: user._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true, serial: issued.serial, pem: issued.pem });
  } catch (e) { next(e); }
});

router.post('/admin/renew/:userId', requireAuth, attachCurrentUser, requireRole('admin'), async (req, res, next) => {
  try {
    ensureAdmin(req.currentUser);
    const ca = await CAState.findOne();
    if (!ca) throw new AppError('CA_NOT_READY', 'CA not initialized', 404);
    const user = await User.findById(req.params.userId);
    if (!user) throw new AppError('NOT_FOUND', 'User not found', 404);

    const old = await Certificate.findOne({ user: user._id, status: 'issued' }).sort({ createdAt: -1 });
    if (old) {
      const alreadyRevoked = await Revocation.findOne({ serial: old.serial });
      if (!alreadyRevoked) {
        await Revocation.create({ serial: old.serial, reason: 'renewed', revokedBy: req.currentUser._id });
      }
      old.status = 'revoked';
      await old.save();
    }

    const issued = await issueCertForUser(user, ca, { validDays: 365 });
    await audit({ actorId: req.currentUser._id, action: 'pki.renew_cert', target: user._id.toString(), correlationId: req.correlationId });
    res.json({ ok: true, renewedFrom: old?.serial || null, serial: issued.serial, pem: issued.pem });
  } catch (e) { next(e); }
});

router.post('/me/rotate-keys', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    if (req.currentUser.role !== 'user') throw new AppError('FORBIDDEN', 'Admins do not rotate end-user keys here', 403);

    const pairs = generateUserKeyPairs();
    const user = await User.findByIdAndUpdate(
      req.currentUser._id,
      {
        $set: {
          cryptoPublicKeyPem: pairs.cryptoPublicKeyPem,
          cryptoPrivateKeyEnc: encryptText(pairs.cryptoPrivateKeyPem),
          chatPublicKeyPem: pairs.chatPublicKeyPem,
          chatPrivateKeyEnc: encryptText(pairs.chatPrivateKeyPem)
        }
      },
      { new: true }
    );

    const currentIssued = await Certificate.find({ user: user._id, status: 'issued' });
    for (const cert of currentIssued) {
      const alreadyRevoked = await Revocation.findOne({ serial: cert.serial });
      if (!alreadyRevoked) {
        await Revocation.create({ serial: cert.serial, reason: 'key_rotation', revokedBy: req.currentUser._id });
      }
      cert.status = 'revoked';
      await cert.save();
    }

    await audit({ actorId: req.currentUser._id, action: 'pki.rotate_keys', target: user._id.toString(), correlationId: req.correlationId });
    res.json({
      ok: true,
      message: 'Keys rotated. Ask admin to issue a new certificate.',
      revokedSerials: currentIssued.map((c) => c.serial)
    });
  } catch (e) { next(e); }
});

router.get('/my-cert', requireAuth, attachCurrentUser, async (req, res, next) => {
  try {
    const cert = await Certificate.findOne({ user: req.currentUser._id }).sort({ createdAt: -1 });
    if (!cert) throw new AppError('CERT_NOT_FOUND', 'No certificate issued', 404);
    const revoked = await Revocation.findOne({ serial: cert.serial });
    res.json({
      serial: cert.serial,
      pem: cert.pem,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      status: revoked ? 'revoked' : cert.status
    });
  } catch (e) { next(e); }
});

router.post('/admin/revoke', requireAuth, attachCurrentUser, requireRole('admin'), async (req, res, next) => {
  try {
    ensureAdmin(req.currentUser);
    const { serial, reason = 'unspecified' } = req.body;
    const cert = await Certificate.findOne({ serial });
    if (!cert) throw new AppError('NOT_FOUND', 'Cert not found', 404);
    const existing = await Revocation.findOne({ serial });
    if (existing) return res.json({ ok: true, already: true });

    await Revocation.create({ serial, reason, revokedBy: req.currentUser._id });
    cert.status = 'revoked';
    await cert.save();
    await audit({ actorId: req.currentUser._id, action: 'pki.revoke_cert', target: serial, correlationId: req.correlationId });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.get('/admin/crl.json', requireAuth, attachCurrentUser, requireRole('admin'), async (req, res, next) => {
  try {
    ensureAdmin(req.currentUser);
    const rows = await Revocation.find().sort({ revokedAt: -1 });
    res.json({ revoked: rows.map((r) => ({ serial: r.serial, reason: r.reason, revokedAt: r.revokedAt })) });
  } catch (e) { next(e); }
});

module.exports = router;
