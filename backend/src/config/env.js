const dotenv = require('dotenv');
dotenv.config();

function required(name, fallback) {
  const value = process.env[name] || fallback;
  if (!value) throw new Error(`Missing env ${name}`);
  return value;
}

function validateMasterKey(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('Invalid SERVER_MASTER_KEY: must be exactly 64 hex chars (32 bytes)');
  }
  return hex.toLowerCase();
}

const SERVER_MASTER_KEY = validateMasterKey(required('SERVER_MASTER_KEY'));

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: Number(process.env.PORT || 5000),
  MONGODB_URI: required('MONGODB_URI'),
  JWT_ACCESS_SECRET: required('JWT_ACCESS_SECRET'),
  JWT_REFRESH_SECRET: required('JWT_REFRESH_SECRET'),
  ACCESS_TOKEN_TTL: process.env.ACCESS_TOKEN_TTL || '15m',
  REFRESH_TOKEN_TTL_DAYS: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7),
  SERVER_MASTER_KEY,
  ADMIN_BOOTSTRAP_TOKEN: required('ADMIN_BOOTSTRAP_TOKEN'),
  CORS_ORIGIN: process.env.CORS_ORIGIN || 'http://localhost:5173',
  RATE_LIMIT_WINDOW_MS: Number(process.env.RATE_LIMIT_WINDOW_MS || 60000),
  RATE_LIMIT_MAX: Number(process.env.RATE_LIMIT_MAX || 120),
  AUTH_RATE_LIMIT_MAX: Number(process.env.AUTH_RATE_LIMIT_MAX || 30)
};
