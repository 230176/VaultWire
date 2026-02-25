const mongoose = require('mongoose');

const privacySchema = new mongoose.Schema({
  phone: { type: String, enum: ['public', 'private'], default: 'private' },
  bio: { type: String, enum: ['public', 'private'], default: 'public' },
  email: { type: String, enum: ['public', 'private'], default: 'private' },
  global: { type: String, enum: ['public', 'private'], default: 'public' }
}, { _id: false });

const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, trim: true },
    email: { type: String, unique: true, required: true, lowercase: true },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: ["user", "admin", "superadmin"],
      default: "user",
    },
    adminApproved: { type: Boolean, default: true },
    approvedAt: { type: Date, default: null },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    verified: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    phone: { type: String, default: "" },
    bio: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    privacy: { type: privacySchema, default: () => ({}) },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    cryptoPublicKeyPem: { type: String, required: true },
    cryptoPrivateKeyEnc: { type: mongoose.Schema.Types.Mixed, required: true },
    chatPublicKeyPem: { type: String, required: true },
    chatPrivateKeyEnc: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true },
);

module.exports = mongoose.model('User', userSchema);
