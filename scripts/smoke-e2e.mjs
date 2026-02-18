#!/usr/bin/env node
/*
  VaultWire end-to-end smoke test (local or docker)
  Prereq:
  - Backend running
  - Mongo running
  - NODE_ENV not production (for /otp/dev helper)
*/

const API = process.env.API_URL || 'http://localhost:5000/api/v1';
const SUPERADMIN_EMAIL = process.env.SMOKE_ADMIN_EMAIL || 'ritesh@admin.com';
const SUPERADMIN_PASSWORD = process.env.SMOKE_ADMIN_PASSWORD || 'ritesh123';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function randomId(prefix = 'u') {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 99999)}`;
}

class Client {
  constructor(name) {
    this.name = name;
    this.token = null;
    this.cookie = '';
  }

  setToken(token) {
    this.token = token;
  }

  async req(path, { method = 'GET', json, form, text, headers = {}, expect = 'json', unauthenticated = false } = {}) {
    const url = `${API}${path}`;
    const h = { ...headers };

    let body;
    if (json !== undefined) {
      h['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    } else if (form) {
      body = form;
    } else if (text !== undefined) {
      body = text;
    }

    if (!unauthenticated) {
      if (this.token) h.Authorization = `Bearer ${this.token}`;
      if (this.cookie) h.Cookie = this.cookie;
    }

    const res = await fetch(url, { method, headers: h, body });

    // Keep latest cookie (refresh token rotation etc.)
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      this.cookie = setCookie.split(';')[0];
    }

    const ct = res.headers.get('content-type') || '';
    let payload;
    if (expect === 'buffer') {
      payload = Buffer.from(await res.arrayBuffer());
    } else if (ct.includes('application/json')) {
      payload = await res.json();
    } else {
      payload = await res.text();
    }

    if (!res.ok) {
      const msg = typeof payload === 'string' ? payload : JSON.stringify(payload);
      throw new Error(`[${this.name}] ${method} ${path} -> ${res.status} ${msg}`);
    }

    return payload;
  }
}

function ok(cond, message) {
  if (!cond) throw new Error(`Assertion failed: ${message}`);
  console.log(`✅ ${message}`);
}

async function registerVerifyAndLogin({ email, username, password }) {
  const anon = new Client('anon');
  await anon.req('/auth/register', { method: 'POST', json: { email, username, password } });
  const otpRow = await anon.req(`/otp/dev/${encodeURIComponent(email)}`, { method: 'GET' });
  ok(!!otpRow.otp, `OTP generated for ${email}`);
  await anon.req('/otp/verify', { method: 'POST', json: { email, otp: otpRow.otp } });

  const c = new Client(username);
  const login = await c.req('/auth/login', { method: 'POST', json: { email, password } });
  c.setToken(login.accessToken);
  ok(login.user?.role === 'user', `${username} logged in as user`);
  return c;
}

async function main() {
  console.log(`\nVaultWire smoke test started against ${API}\n`);
  const anon = new Client('anon');

  const health = await anon.req('/health', { method: 'GET', unauthenticated: true });
  ok(health.ok === true, 'Health endpoint returns ok=true');

  const suffix = randomId('smoke');

  // 1) Superadmin login (pre-seeded on server startup)
  const admin = new Client('superadmin');
  const adminLogin = await admin.req('/auth/login', {
    method: 'POST',
    json: { email: SUPERADMIN_EMAIL, password: SUPERADMIN_PASSWORD },
    unauthenticated: true
  });
  admin.setToken(adminLogin.accessToken);
  ok(['admin', 'superadmin'].includes(adminLogin.user?.role), 'Superadmin/admin login works');

  // 2) Register a new admin and approve as superadmin
  const pendingAdminEmail = `${suffix}_pending_admin@local.test`;
  const pendingAdminUser = `${suffix}_pending_admin`;
  await anon.req('/auth/admin/register', {
    method: 'POST',
    json: { username: pendingAdminUser, email: pendingAdminEmail, password: 'Adm1n#Pass' },
    unauthenticated: true
  });

  const pending = await admin.req('/admin/admins/pending', { method: 'GET' });
  const pendingRow = pending.find((x) => x.email === pendingAdminEmail);
  ok(!!pendingRow, 'Pending admin appears for superadmin verification');
  await admin.req(`/admin/admins/${pendingRow._id}/approve`, { method: 'POST', json: {} });

  const approvedAdmin = new Client('approved_admin');
  const approvedLogin = await approvedAdmin.req('/auth/login', {
    method: 'POST',
    json: { email: pendingAdminEmail, password: 'Adm1n#Pass' },
    unauthenticated: true
  });
  approvedAdmin.setToken(approvedLogin.accessToken);
  ok(['admin', 'superadmin'].includes(approvedLogin.user?.role), 'Approved admin can login');

  // 3) CA init (idempotent)
  try {
    const caInit = await admin.req('/pki/admin/init-ca', { method: 'POST', json: {} });
    ok(!!caInit.fingerprint, 'CA initialized');
  } catch (e) {
    if (!String(e.message).includes('CA_ALREADY_INITIALIZED')) throw e;
    console.log('ℹ️  CA already initialized (continuing)');
  }

  // 4) Two users register + OTP verify + login
  const user1Email = `${suffix}_alice@local.test`;
  const user2Email = `${suffix}_bob@local.test`;
  const password = 'Str0ng!Pass';

  const alice = await registerVerifyAndLogin({
    email: user1Email,
    username: `${suffix}_alice`,
    password
  });
  const bob = await registerVerifyAndLogin({
    email: user2Email,
    username: `${suffix}_bob`,
    password
  });

  // 5) Admin issues certs
  const users = await admin.req('/admin/users', { method: 'GET' });
  const u1 = users.find((u) => u.email === user1Email);
  const u2 = users.find((u) => u.email === user2Email);
  ok(!!u1 && !!u2, 'Admin can list new users');

  const issue1 = await admin.req(`/pki/admin/issue/${u1._id}`, { method: 'POST', json: {} });
  const issue2 = await admin.req(`/pki/admin/issue/${u2._id}`, { method: 'POST', json: {} });
  ok(!!issue1.serial && !!issue2.serial, 'Certificates issued for both users');

  // 6) Friend flow
  await alice.req('/friends/request', { method: 'POST', json: { toUserId: u2._id } });
  const bobReq = await bob.req('/friends/requests', { method: 'GET' });
  ok((bobReq.incoming || []).length >= 1, 'Bob received friend request');
  await bob.req('/friends/respond', { method: 'POST', json: { fromUserId: u1._id, action: 'accept' } });
  const aliceFriends = await alice.req('/friends/list', { method: 'GET' });
  ok(aliceFriends.some((f) => f.id === u2._id), 'Friend request accepted');

  // 7) Disappearing message flow
  const messageId = randomId('msg');
  const nonce = randomId('nonce');
  await alice.req('/messages/send', {
    method: 'POST',
    json: {
      toUserId: u2._id,
      text: 'Hello Bob (encrypted)!',
      expiryPreset: '1h',
      messageId,
      nonce
    }
  });
  const thread = await bob.req(`/messages/thread/${u1._id}`, { method: 'GET' });
  ok(thread.some((m) => m.text === 'Hello Bob (encrypted)!'), 'Encrypted message decrypted in thread');

  // 8) Vault upload + integrity + share link + decrypt
  const plainContent = `VaultWire smoke content ${Date.now()}`;
  const uploadForm = new FormData();
  uploadForm.append('title', 'smoke-secret.txt');
  uploadForm.append('recipientIds', JSON.stringify([u2._id]));
  uploadForm.append('file', new Blob([plainContent], { type: 'text/plain' }), 'smoke-secret.txt');

  const uploadRes = await alice.req('/vault/upload', { method: 'POST', form: uploadForm });
  ok(!!uploadRes.id && !!uploadRes.hash, 'Vault upload success with integrity hash');

  const decryptRes = await alice.req(`/vault/${uploadRes.id}/decrypt`, { method: 'POST', json: {}, expect: 'buffer' });
  ok(decryptRes.toString('utf8') === plainContent, 'Vault decrypt returns original content');

  const linkRes = await alice.req(`/vault/${uploadRes.id}/share-link`, { method: 'POST', json: { expiryPreset: '10m' } });
  ok(!!linkRes.token, 'Share link created');
  const sharePayload = await anon.req(`/vault/share/${linkRes.token}`, { method: 'GET', unauthenticated: true });
  ok(!!sharePayload.encryptedDataBase64, 'Encrypted share payload accessible by token');

  // 9) Signature sign + verify bundle
  const signForm = new FormData();
  signForm.append('file', new Blob([plainContent], { type: 'text/plain' }), 'to-sign.txt');
  const signBundle = await alice.req('/signatures/sign', { method: 'POST', form: signForm });
  ok(!!signBundle.signature && !!signBundle.hash, 'Digital signature bundle generated');

  const verifyForm = new FormData();
  verifyForm.append('file', new Blob([plainContent], { type: 'text/plain' }), 'to-sign.txt');
  verifyForm.append('bundleJson', JSON.stringify(signBundle));
  const verify = await bob.req('/signatures/verify-bundle', { method: 'POST', form: verifyForm });
  ok(verify.ok === true, 'Signature verification succeeds for untampered file');

  // 10) Session + logout other sessions
  const sessionsBefore = await alice.req('/sessions/me', { method: 'GET' });
  ok(Array.isArray(sessionsBefore), 'Session listing works');
  await alice.req('/auth/logout-others', { method: 'POST', json: {} });
  ok(true, 'Logout other sessions endpoint works');

  // 11) Key rotation + renewal workflow
  const rotate = await alice.req('/pki/me/rotate-keys', { method: 'POST', json: {} });
  ok(rotate.ok === true, 'User key rotation completed');
  const renew = await admin.req(`/pki/admin/renew/${u1._id}`, { method: 'POST', json: {} });
  ok(renew.ok === true && !!renew.serial, 'Admin certificate renewal completed');

  // 12) Admin observability endpoints
  const risk = await admin.req('/admin/risk/summary', { method: 'GET' });
  ok(typeof risk.failedLogins24h === 'number', 'Admin risk summary available');
  const auditJson = await admin.req('/admin/audit/export.json', { method: 'GET' });
  ok(Array.isArray(auditJson), 'Audit JSON export works');
  const auditCsv = await admin.req('/admin/audit/export.csv', { method: 'GET' });
  ok(typeof auditCsv === 'string' && auditCsv.includes('createdAt'), 'Audit CSV export works');
  const rates = await admin.req('/admin/rate-limit/metrics', { method: 'GET' });
  ok(Array.isArray(rates), 'Rate-limit metrics endpoint works');

  // Optional: wait a bit to flush async writes in some environments
  await sleep(200);

  console.log('\n🎉 Smoke test completed successfully.');
  console.log(`Users created: ${user1Email}, ${user2Email}`);
}

main().catch((err) => {
  console.error('\n❌ Smoke test failed');
  console.error(err.message || err);
  process.exit(1);
});
