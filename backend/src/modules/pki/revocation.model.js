const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  serial: { type: String, unique: true, index: true },
  reason: String,
  revokedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  revokedAt: { type: Date, default: Date.now }
}, { timestamps: true });
module.exports = mongoose.model('Revocation', schema);
