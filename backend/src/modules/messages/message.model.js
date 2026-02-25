const mongoose = require("mongoose");

const encryptedBlobSchema = new mongoose.Schema(
  {
    iv: { type: String, required: true },
    tag: { type: String, required: true },
    data: { type: String, required: true },
  },
  { _id: false },
);

const schema = new mongoose.Schema(
  {
    fromUser: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    toUser: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    messageId: { type: String, unique: true, index: true },
    nonce: { type: String, index: true },
    timestamp: Date,
    ciphertext: String,
    iv: String,
    tag: String,
    salt: String,
    ephPublicPem: String,
    ephPrivateEnc: { type: encryptedBlobSchema, required: true },
    expiresAt: { type: Date, index: { expires: 0 } },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Message", schema);
