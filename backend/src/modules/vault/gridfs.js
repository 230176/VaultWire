const mongoose = require('mongoose');
const { GridFSBucket } = require('mongodb');

function getBucket() {
  const db = mongoose.connection.db;
  if (!db) throw new Error('DB not connected');
  return new GridFSBucket(db, { bucketName: 'vault_files' });
}

async function uploadBuffer(buffer, filename, contentType = 'application/octet-stream') {
  const bucket = getBucket();
  return new Promise((resolve, reject) => {
    const stream = bucket.openUploadStream(filename, { contentType });
    stream.end(buffer);
    stream.on('finish', () => resolve(stream.id.toString()));
    stream.on('error', reject);
  });
}

async function downloadBuffer(fileId) {
  const bucket = getBucket();
  return new Promise((resolve, reject) => {
    const chunks = [];
    const stream = bucket.openDownloadStream(new mongoose.Types.ObjectId(fileId));
    stream.on('data', (d) => chunks.push(d));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

module.exports = { uploadBuffer, downloadBuffer };
