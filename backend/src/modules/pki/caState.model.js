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
    certPem: { type: String, required: true },
    privateKeyEnc: { type: encryptedBlobSchema, required: true },
    fingerprint: { type: String, required: true },
  },
  { timestamps: true },
);

module.exports = mongoose.model("CAState", schema);
