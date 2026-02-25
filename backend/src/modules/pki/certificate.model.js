const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  serial: { type: String, unique: true, index: true },
  pem: String,
  issuedAt: Date,
  expiresAt: Date,
  issuer: String,
  status: { type: String, enum: ['issued', 'revoked', 'expired'], default: 'issued' }
}, { timestamps: true });
module.exports = mongoose.model('Certificate', schema);
