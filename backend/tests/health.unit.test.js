const request = require('supertest');

describe('health endpoint', () => {
  let app;
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    process.env.MONGODB_URI = 'mongodb://invalid';
    process.env.JWT_ACCESS_SECRET = 'access';
    process.env.JWT_REFRESH_SECRET = 'refresh';
    process.env.ACCESS_TOKEN_TTL = '15m';
    process.env.REFRESH_TOKEN_TTL_DAYS = '7';
    process.env.SERVER_MASTER_KEY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    process.env.ADMIN_BOOTSTRAP_TOKEN = 'token';
    process.env.CORS_ORIGIN = 'http://localhost:5173';
    const { createApp } = require('../src/app');
    app = createApp();
  });

  test('GET /health', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});
