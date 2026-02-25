const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  messageId: { type: String, unique: true, index: true },
  nonce: { type: String, unique: true, index: true },
  expiresAt: { type: Date, index: { expires: 0 } }
}, { timestamps: true });


module.exports = mongoose.model('ReplayCache', schema);
