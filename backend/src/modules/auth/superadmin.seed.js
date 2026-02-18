const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const forge = require('node-forge');
const User = require('../users/user.model');
const { encryptText } = require('../../common/crypto');
const logger = require('../../common/logger');

const SUPERADMIN = {
  username: 'ritesh',
  email: 'ritesh@admin.com',
  password: 'ritesh123'
};

function generateUserKeyPairs() {
  const rsa = forge.pki.rsa.generateKeyPair(2048);
  const cryptoPublicKeyPem = forge.pki.publicKeyToPem(rsa.publicKey);
  const cryptoPrivateKeyPem = forge.pki.privateKeyToPem(rsa.privateKey);

  const ec = crypto.generateKeyPairSync('x25519');
  const chatPublicKeyPem = ec.publicKey.export({ type: 'spki', format: 'pem' });
  const chatPrivateKeyPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' });

  return { cryptoPublicKeyPem, cryptoPrivateKeyPem, chatPublicKeyPem, chatPrivateKeyPem };
}

async function ensureSuperAdmin() {
  const existing = await User.findOne({ email: SUPERADMIN.email.toLowerCase() });
  if (existing) {
    if (existing.role !== 'superadmin' || !existing.adminApproved || !existing.verified) {
      existing.role = 'superadmin';
      existing.adminApproved = true;
      existing.verified = true;
      existing.disabled = false;
      existing.approvedAt = new Date();
      if (!existing.cryptoPublicKeyPem || !existing.cryptoPrivateKeyEnc || !existing.chatPublicKeyPem || !existing.chatPrivateKeyEnc) {
        const pairs = generateUserKeyPairs();
        existing.cryptoPublicKeyPem = pairs.cryptoPublicKeyPem;
        existing.cryptoPrivateKeyEnc = encryptText(pairs.cryptoPrivateKeyPem);
        existing.chatPublicKeyPem = pairs.chatPublicKeyPem;
        existing.chatPrivateKeyEnc = encryptText(pairs.chatPrivateKeyPem);
      }
      await existing.save();
      logger.info('superadmin_promoted_existing', { email: SUPERADMIN.email });
    }
    return existing;
  }

  const pairs = generateUserKeyPairs();
  const row = await User.create({
    username: SUPERADMIN.username,
    email: SUPERADMIN.email.toLowerCase(),
    passwordHash: await bcrypt.hash(SUPERADMIN.password, 12),
    role: 'superadmin',
    verified: true,
    adminApproved: true,
    approvedAt: new Date(),
    cryptoPublicKeyPem: pairs.cryptoPublicKeyPem,
    cryptoPrivateKeyEnc: encryptText(pairs.cryptoPrivateKeyPem),
    chatPublicKeyPem: pairs.chatPublicKeyPem,
    chatPrivateKeyEnc: encryptText(pairs.chatPrivateKeyPem)
  });
  logger.info('superadmin_seeded', { email: SUPERADMIN.email });
  return row;
}

module.exports = { ensureSuperAdmin, SUPERADMIN };
