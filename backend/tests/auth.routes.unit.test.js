const request = require('supertest');
jest.mock('../src/modules/users/user.model', () => ({
  findOne: jest.fn(),
  create: jest.fn(),
  updateOne: jest.fn(),
  exists: jest.fn(),
  findById: jest.fn()
}));
jest.mock('../src/modules/otp/otp.model', () => ({
  deleteMany: jest.fn(),
  create: jest.fn(),
  findOne: jest.fn()
}));
jest.mock('../src/modules/auth/session.model', () => ({
  create: jest.fn(),
  findOne: jest.fn(),
  updateOne: jest.fn(),
  updateMany: jest.fn()
}));
jest.mock('../src/modules/audit/audit.service', () => ({
  audit: jest.fn(async () => {})
}));

const User = require('../src/modules/users/user.model');
const Otp = require('../src/modules/otp/otp.model');
const Session = require('../src/modules/auth/session.model');

describe('auth routes', () => {
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

  beforeEach(() => {
    jest.resetAllMocks();
  });

  test('register rejects weak password', async () => {
    const res = await request(app).post('/api/v1/auth/register').send({
      username: 'a', email: 'a@a.com', password: 'weak'
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.code).toBe('WEAK_PASSWORD');
  });

  test('register success', async () => {
    User.findOne.mockResolvedValue(null);
    User.create.mockResolvedValue({ _id: '507f1f77bcf86cd799439011', email: 'a@a.com' });
    const res = await request(app).post('/api/v1/auth/register').send({
      username: 'alice', email: 'a@a.com', password: 'Str0ng!Pass'
    });
    expect(res.statusCode).toBe(201);
    expect(Otp.create).toHaveBeenCalled();
  });

  test('login invalid credentials', async () => {
    User.findOne.mockResolvedValue(null);
    const res = await request(app).post('/api/v1/auth/login').send({ email: 'x@y.com', password: 'abc' });
    expect(res.statusCode).toBe(401);
  });
});
