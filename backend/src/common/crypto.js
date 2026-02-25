const crypto = require("crypto");
const env = require("../config/env");

function getMasterKey() {
  // 64 hex chars -> 32 bytes
  const keyHex = env.SERVER_MASTER_KEY;
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error("SERVER_MASTER_KEY must be 64 hex chars");
  }
  return Buffer.from(keyHex, "hex");
}

function encryptText(plain) {
  const iv = crypto.randomBytes(12);
  const key = getMasterKey();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([
    cipher.update(Buffer.from(plain, "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: enc.toString("base64"),
  };
}

function normalizeEncObject(encObj) {
  // Backward compatibility: if stored as JSON string, parse it.
  if (typeof encObj === "string") {
    try {
      return JSON.parse(encObj);
    } catch {
      throw new Error("Encrypted payload is a string but not valid JSON");
    }
  }
  if (!encObj || typeof encObj !== "object") {
    throw new Error("Encrypted payload must be an object");
  }
  if (!encObj.iv || !encObj.tag || !encObj.data) {
    throw new Error("Encrypted payload missing iv/tag/data");
  }
  return encObj;
}

function decryptText(encObj) {
  const normalized = normalizeEncObject(encObj);
  const key = getMasterKey();
  const iv = Buffer.from(normalized.iv, "base64");
  const tag = Buffer.from(normalized.tag, "base64");
  const data = Buffer.from(normalized.data, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

function encryptBuffer(buf, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { encrypted, iv, tag };
}

function decryptBuffer(encrypted, iv, tag, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function passwordMeetsPolicy(pwd) {
  return {
    minLength: pwd.length >= 8,
    lower: /[a-z]/.test(pwd),
    upper: /[A-Z]/.test(pwd),
    number: /\d/.test(pwd),
    special: /[^A-Za-z0-9]/.test(pwd),
  };
}
function isStrongPassword(pwd) {
  const p = passwordMeetsPolicy(pwd);
  return Object.values(p).every(Boolean);
}

module.exports = {
  encryptText,
  decryptText,
  encryptBuffer,
  decryptBuffer,
  passwordMeetsPolicy,
  isStrongPassword,
};
