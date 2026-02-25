const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  ip: String,
  path: String,
  method: String
}, { timestamps: true });
module.exports = mongoose.model('RateLimitEvent', schema);
