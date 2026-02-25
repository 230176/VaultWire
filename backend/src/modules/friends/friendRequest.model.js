const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  fromUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  toUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'cancelled'], default: 'pending' }
}, { timestamps: true });

schema.index({ fromUser: 1, toUser: 1 }, { unique: true });

module.exports = mongoose.model('FriendRequest', schema);
