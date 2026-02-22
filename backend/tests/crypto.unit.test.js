const { encryptText, decryptText, passwordMeetsPolicy, isStrongPassword, encryptBuffer, decryptBuffer } = require('../src/common/crypto');
const crypto = require('crypto');

describe('common crypto', () => {
  beforeAll(() => {
    process.env.SERVER_MASTER_KEY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  });

  test('encrypt/decrypt text', () => {
    const enc = encryptText('hello');
    const out = decryptText(enc);
    expect(out).toBe('hello');
  });

  test('password policy', () => {
    const p = passwordMeetsPolicy('Abcdef1!');
    expect(Object.values(p).every(Boolean)).toBe(true);
    expect(isStrongPassword('weak')).toBe(false);
  });

  test('encrypt/decrypt buffer with random key', () => {
    const key = crypto.randomBytes(32);
    const plain = Buffer.from('binary-data');
    const out = encryptBuffer(plain, key);
    const dec = decryptBuffer(out.encrypted, out.iv, out.tag, key);
    expect(dec.toString()).toBe('binary-data');
  });
});
