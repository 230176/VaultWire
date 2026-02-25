const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const {
  requireAuth,
  attachCurrentUser,
  requireValidCert,
} = require("../../common/middleware");
const { AppError } = require("../../common/errors");
const { decryptText } = require("../../common/crypto");
const Certificate = require("../pki/certificate.model");
const CAState = require("../pki/caState.model");
const Revocation = require("../pki/revocation.model");
const { audit } = require("../audit/audit.service");

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

router.post(
  "/sign",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  upload.single("file"),
  async (req, res, next) => {
    try {
      const file = req.file;
      if (!file) throw new AppError("VALIDATION_ERROR", "File required");
      const cert = await Certificate.findOne({
        user: req.currentUser._id,
      }).sort({ createdAt: -1 });
      if (!cert)
        throw new AppError("CERT_NOT_FOUND", "Certificate missing", 404);

      const hash = crypto
        .createHash("sha256")
        .update(file.buffer)
        .digest("hex");
      const sign = crypto.createSign("RSA-SHA256");
      sign.update(hash);
      sign.end();
      const priv = crypto.createPrivateKey(
        decryptText(req.currentUser.cryptoPrivateKeyEnc),
      );
      const signature = sign.sign(priv).toString("base64");

      const ca = await CAState.findOne();
      const crl = await Revocation.find().sort({ revokedAt: -1 }).limit(500);
      const bundle = {
        filename: file.originalname,
        hash,
        signature,
        signerCertPem: cert.pem,
        serial: cert.serial,
        caCertPem: ca?.certPem || null,
        crl: crl.map((r) => ({
          serial: r.serial,
          reason: r.reason,
          revokedAt: r.revokedAt,
        })),
      };
      await audit({
        actorId: req.currentUser._id,
        action: "signature.sign",
        target: file.originalname,
        correlationId: req.correlationId,
      });
      res.json(bundle);
    } catch (e) {
      next(e);
    }
  },
);

function verifyCommon(buffer, hash, signature, certPem) {
  const calc = crypto.createHash("sha256").update(buffer).digest("hex");
  if (calc !== hash) return { ok: false, reason: "HASH_MISMATCH" };
  const pub = crypto.createPublicKey(certPem);
  const v = crypto.createVerify("RSA-SHA256");
  v.update(hash);
  v.end();
  const ok = v.verify(pub, Buffer.from(signature, "base64"));
  return ok ? { ok: true } : { ok: false, reason: "SIGNATURE_INVALID" };
}

router.post(
  "/verify",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  upload.single("file"),
  async (req, res, next) => {
    try {
      const file = req.file;
      const { hash, signature, certPem } = req.body;
      if (!file || !hash || !signature || !certPem)
        throw new AppError(
          "VALIDATION_ERROR",
          "file,hash,signature,certPem required",
        );
      const result = verifyCommon(file.buffer, hash, signature, certPem);
      res.json(result);
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  "/verify-bundle",
  requireAuth,
  attachCurrentUser,
  requireValidCert,
  upload.single("file"),
  async (req, res, next) => {
    try {
      const file = req.file;
      const { bundleJson } = req.body;
      if (!file || !bundleJson)
        throw new AppError("VALIDATION_ERROR", "file and bundleJson required");
      const bundle = JSON.parse(bundleJson);
      const isRevoked = bundle.crl?.some((r) => r.serial === bundle.serial);
      if (isRevoked)
        return res.json({ ok: false, reason: "CERT_REVOKED_IN_BUNDLE" });
      const result = verifyCommon(
        file.buffer,
        bundle.hash,
        bundle.signature,
        bundle.signerCertPem,
      );
      res.json(result);
    } catch (e) {
      next(e);
    }
  },
);

module.exports = router;
