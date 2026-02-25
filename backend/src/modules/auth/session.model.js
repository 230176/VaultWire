const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  tokenHash: { type: String, required: true, index: true },
  userAgent: String,
  ip: String,
  revoked: { type: Boolean, default: false },
  expiresAt: { type: Date, index: { expires: 0 } }
}, { timestamps: true });

module.exports = mongoose.model('Session', sessionSchema);
