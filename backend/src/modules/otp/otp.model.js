const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: { type: String, index: true },
  otpHash: { type: String, required: true },
  otpDevPlain: { type: String, default: null },
  purpose: { type: String, default: 'verify' },
  attempts: { type: Number, default: 0 },
  expiresAt: { type: Date, index: { expires: 0 } }
}, { timestamps: true });


module.exports = mongoose.model('Otp', otpSchema);
