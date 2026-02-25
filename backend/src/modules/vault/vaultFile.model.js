const mongoose = require('mongoose');

const versionSchema = new mongoose.Schema({
  version: Number,
  filename: String,
  mimeType: String,
  size: Number,
  gridFsId: String,
  hash: String,
  iv: String,
  tag: String,
  wrappedKeys: { type: Map, of: String }, // userId -> wrapped aes key b64
  algorithm: { type: String, default: 'AES-256-GCM + RSA-OAEP' },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const shareLinkSchema = new mongoose.Schema({
  token: String,
  expiresAt: Date,
  version: Number
}, { _id: false });

const schema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  recipients: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  title: String,
  versions: [versionSchema],
  shareLinks: [shareLinkSchema]
}, { timestamps: true });

module.exports = mongoose.model('VaultFile', schema);
