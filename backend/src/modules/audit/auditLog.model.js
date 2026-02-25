const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  action: { type: String, index: true },
  target: String,
  outcome: { type: String, enum: ['success', 'failure'], default: 'success' },
  meta: mongoose.Schema.Types.Mixed,
  correlationId: String
}, { timestamps: true });
module.exports = mongoose.model('AuditLog', schema);
