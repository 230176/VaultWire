const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const {
  requireAuth,
  attachCurrentUser,
  requireValidCert,
} = require("../../common/middleware");
const { AppError } = require("../../common/errors");
const User = require("../users/user.model");
const VaultFile = require("./vaultFile.model");
const { uploadBuffer, downloadBuffer } = require("./gridfs");
const {
  encryptBuffer,
  decryptBuffer,
  decryptText,
} = require("../../common/crypto");
const { audit } = require("../audit/audit.service");
const { v4: uuidv4 } = require("uuid");

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

function isFriend(currentUser, targetId) {
  return currentUser.friends
    .map((x) => x.toString())
    .includes(targetId.toString());
}
function presetToMs(preset) {
  const map = {
    "10m": 10 * 60 * 1000,
    "1h": 60 * 60 * 1000,
    "1d": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
  };
  return map[preset] || map["1h"];
}

function wrapKeyForUser(aesKey, user) {
  const pub = crypto.createPublicKey(user.cryptoPublicKeyPem);
  return crypto
    .publicEncrypt(
      {
        key: pub,
        oaepHash: "sha256",
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      aesKey,
    )
    .toString("base64");
}
function unwrapKeyForUser(wrappedB64, user) {
  const privPem = decryptText(user.cryptoPrivateKeyEnc);
  const priv = crypto.createPrivateKey(privPem);
  return crypto.privateDecrypt(
    {
      key: priv,
      oaepHash: "sha256",
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(wrappedB64, "base64"),
  );
}

async function resolveRecipientUsers(recipientIds, currentUser) {
  if (!Array.isArray(recipientIds))
    throw new AppError("VALIDATION_ERROR", "recipientIds must be an array");

  const uniqueIds = [...new Set(recipientIds.map((x) => String(x)))];
  for (const rid of uniqueIds) {
    if (!isFriend(currentUser, rid))
      throw new AppError("FORBIDDEN", "Can only share with friends", 403);
  }

  if (uniqueIds.length === 0) return [];
  const users = await User.find({ _id: { $in: uniqueIds } });
  if (users.length !== uniqueIds.length) {
    throw new AppError(
      "VALIDATION_ERROR",
      "One or more recipients are invalid",
    );
  }
  return users;
}

router.post(
  "/upload",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  upload.single("file"),
  async (req, res, next) => {
    try {
      if (req.currentUser.role !== "user")
        throw new AppError("FORBIDDEN", "Admins do not have vault", 403);
      const file = req.file;
      if (!file) throw new AppError("VALIDATION_ERROR", "File is required");

      const recipientIds = JSON.parse(req.body.recipientIds || "[]");
      const recipients = await resolveRecipientUsers(
        recipientIds,
        req.currentUser,
      );

      const aesKey = crypto.randomBytes(32);
      const enc = encryptBuffer(file.buffer, aesKey);
      const gridFsId = await uploadBuffer(
        enc.encrypted,
        file.originalname,
        file.mimetype,
      );
      const hash = crypto
        .createHash("sha256")
        .update(file.buffer)
        .digest("hex");

      const wrappedKeys = new Map();
      wrappedKeys.set(
        req.currentUser._id.toString(),
        wrapKeyForUser(aesKey, req.currentUser),
      );
      for (const r of recipients)
        wrappedKeys.set(r._id.toString(), wrapKeyForUser(aesKey, r));

      const doc = await VaultFile.create({
        owner: req.currentUser._id,
        recipients: recipients.map((r) => r._id),
        title: req.body.title || file.originalname,
        versions: [
          {
            version: 1,
            filename: file.originalname,
            mimeType: file.mimetype,
            size: file.size,
            gridFsId,
            hash,
            iv: enc.iv.toString("base64"),
            tag: enc.tag.toString("base64"),
            wrappedKeys,
          },
        ],
      });

      await audit({
        actorId: req.currentUser._id,
        action: "vault.upload",
        target: doc._id.toString(),
        correlationId: req.correlationId,
      });
      res.status(201).json({ ok: true, id: doc._id, hash, version: 1 });
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  "/:id/new-version",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  upload.single("file"),
  async (req, res, next) => {
    try {
      const doc = await VaultFile.findById(req.params.id);
      if (!doc) throw new AppError("NOT_FOUND", "File not found", 404);
      if (doc.owner.toString() !== req.currentUser._id.toString())
        throw new AppError("FORBIDDEN", "Only owner can add version", 403);

      const file = req.file;
      if (!file) throw new AppError("VALIDATION_ERROR", "File required");

      const aesKey = crypto.randomBytes(32);
      const enc = encryptBuffer(file.buffer, aesKey);
      const gridFsId = await uploadBuffer(
        enc.encrypted,
        file.originalname,
        file.mimetype,
      );
      const hash = crypto
        .createHash("sha256")
        .update(file.buffer)
        .digest("hex");

      const recipients = await User.find({
        _id: { $in: [doc.owner, ...doc.recipients] },
      });
      const wrappedKeys = new Map();
      for (const u of recipients)
        wrappedKeys.set(u._id.toString(), wrapKeyForUser(aesKey, u));

      const nextVersion = doc.versions.length + 1;
      doc.versions.push({
        version: nextVersion,
        filename: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        gridFsId,
        hash,
        iv: enc.iv.toString("base64"),
        tag: enc.tag.toString("base64"),
        wrappedKeys,
      });

      await doc.save();
      await audit({
        actorId: req.currentUser._id,
        action: "vault.new_version",
        target: doc._id.toString(),
        correlationId: req.correlationId,
      });
      res.json({ ok: true, version: nextVersion, hash });
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  "/:id/share-recipients",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  async (req, res, next) => {
    try {
      const doc = await VaultFile.findById(req.params.id);
      if (!doc) throw new AppError("NOT_FOUND", "File not found", 404);
      if (doc.owner.toString() !== req.currentUser._id.toString()) {
        throw new AppError("FORBIDDEN", "Only owner can update sharing", 403);
      }

      const recipientIds = req.body.recipientIds || [];
      const recipients = await resolveRecipientUsers(
        recipientIds,
        req.currentUser,
      );

      const ownerId = req.currentUser._id.toString();
      for (const version of doc.versions) {
        const ownerWrapped = version.wrappedKeys?.get(ownerId);
        if (!ownerWrapped) {
          throw new AppError(
            "CRYPTO_ERROR",
            "Owner key wrapper missing for a version",
          );
        }
        const aesKey = unwrapKeyForUser(ownerWrapped, req.currentUser);
        const newWrapped = new Map();
        newWrapped.set(ownerId, wrapKeyForUser(aesKey, req.currentUser));
        for (const r of recipients) {
          newWrapped.set(r._id.toString(), wrapKeyForUser(aesKey, r));
        }
        version.wrappedKeys = Object.fromEntries(newWrapped);
      }

      doc.recipients = recipients.map((r) => r._id);
      await doc.save();

      await audit({
        actorId: req.currentUser._id,
        action: "vault.update_recipients",
        target: doc._id.toString(),
        details: { recipientIds: recipients.map((r) => r._id.toString()) },
        correlationId: req.correlationId,
      });

      res.json({ ok: true, recipients: doc.recipients.map(String) });
    } catch (e) {
      next(e);
    }
  },
);

router.get(
  "/list",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  async (req, res, next) => {
    try {
      const docs = await VaultFile.find({
        $or: [
          { owner: req.currentUser._id },
          { recipients: req.currentUser._id },
        ],
      }).sort({ updatedAt: -1 });

      res.json(
        docs.map((d) => ({
          id: d._id,
          owner: d.owner,
          recipients: d.recipients,
          title: d.title,
          latestVersion: d.versions[d.versions.length - 1]?.version || 0,
          versions: d.versions.map((v) => ({
            version: v.version,
            filename: v.filename,
            hash: v.hash,
            createdAt: v.createdAt,
          })),
        })),
      );
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  "/:id/share-link",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  async (req, res, next) => {
    try {
      const doc = await VaultFile.findById(req.params.id);
      if (!doc) throw new AppError("NOT_FOUND", "File not found", 404);
      if (doc.owner.toString() !== req.currentUser._id.toString())
        throw new AppError("FORBIDDEN", "Only owner can create link", 403);

      const token = uuidv4().replace(/-/g, "") + uuidv4().replace(/-/g, "");
      const preset = req.body.expiryPreset || "1h";
      const expiresAt = new Date(Date.now() + presetToMs(preset));
      const latest = doc.versions[doc.versions.length - 1];
      doc.shareLinks.push({ token, expiresAt, version: latest.version });
      await doc.save();

      res.json({ token, expiresAt });
    } catch (e) {
      next(e);
    }
  },
);

router.get("/share/:token", async (req, res, next) => {
  try {
    const doc = await VaultFile.findOne({
      "shareLinks.token": req.params.token,
    });
    if (!doc) throw new AppError("NOT_FOUND", "Invalid link", 404);

    const link = doc.shareLinks.find((s) => s.token === req.params.token);
    if (!link || link.expiresAt < new Date())
      throw new AppError("LINK_EXPIRED", "Share link expired", 410);

    const version = doc.versions.find((v) => v.version === link.version);
    if (!version) throw new AppError("NOT_FOUND", "Version not found", 404);

    const encrypted = await downloadBuffer(version.gridFsId);
    res.json({
      title: doc.title,
      version: version.version,
      filename: version.filename,
      mimeType: version.mimeType,
      iv: version.iv,
      tag: version.tag,
      encryptedDataBase64: encrypted.toString("base64"),
      note: "Encrypted payload only. Decryption requires authorized private key.",
    });
  } catch (e) {
    next(e);
  }
});

router.post(
  "/:id/decrypt",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  async (req, res, next) => {
    try {
      const doc = await VaultFile.findById(req.params.id);
      if (!doc) throw new AppError("NOT_FOUND", "File not found", 404);

      const allowed =
        doc.owner.toString() === req.currentUser._id.toString() ||
        doc.recipients.map(String).includes(req.currentUser._id.toString());
      if (!allowed) throw new AppError("FORBIDDEN", "Not authorized", 403);

      const versionNum =
        Number(req.body.version || 0) ||
        doc.versions[doc.versions.length - 1].version;
      const version = doc.versions.find((v) => v.version === versionNum);
      if (!version) throw new AppError("NOT_FOUND", "Version not found", 404);

      const wrapped = version.wrappedKeys.get(req.currentUser._id.toString());
      if (!wrapped) throw new AppError("FORBIDDEN", "No key for user", 403);

      const aesKey = unwrapKeyForUser(wrapped, req.currentUser);
      const encrypted = await downloadBuffer(version.gridFsId);
      const plain = decryptBuffer(
        encrypted,
        Buffer.from(version.iv, "base64"),
        Buffer.from(version.tag, "base64"),
        aesKey,
      );

      await audit({
        actorId: req.currentUser._id,
        action: "vault.decrypt",
        target: doc._id.toString(),
        correlationId: req.correlationId,
      });
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${version.filename}"`,
      );
      res.setHeader(
        "Content-Type",
        version.mimeType || "application/octet-stream",
      );
      res.send(plain);
    } catch (e) {
      next(e);
    }
  },
);

module.exports = router;
