jest.mock('../src/modules/auth/session.model', () => ({
  create: jest.fn(async () => ({})),
  findOne: jest.fn(async () => ({ _id: 's1' })),
  updateOne: jest.fn(async () => ({}))
}));

const jwt = require('jsonwebtoken');
const Session = require('../src/modules/auth/session.model');
const { signAccessToken, createSession, verifyRefreshToken } = require('../src/common/auth');

describe('auth common', () => {
  beforeAll(() => {
    process.env.JWT_ACCESS_SECRET = 'access';
    process.env.JWT_REFRESH_SECRET = 'refresh';
    process.env.ACCESS_TOKEN_TTL = '15m';
    process.env.REFRESH_TOKEN_TTL_DAYS = '7';
  });

  test('sign access token', () => {
    const token = signAccessToken({ _id: '507f1f77bcf86cd799439011', role: 'user', email: 'a@b.com' });
    const payload = jwt.verify(token, 'access');
    expect(payload.role).toBe('user');
  });

  test('create and verify refresh token', async () => {
    const user = { _id: '507f1f77bcf86cd799439011', role: 'user' };
    const refresh = await createSession(user, 'jest', '127.0.0.1');
    expect(Session.create).toHaveBeenCalled();
    const payload = await verifyRefreshToken(refresh);
    expect(payload.sub).toBe(user._id);
  });
});
