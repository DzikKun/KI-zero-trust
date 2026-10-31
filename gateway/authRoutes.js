'use strict';
// gateway/authRoutes.js
// [R2] Endpoint /auth/* - Policy Administrator / token issuance di gateway (bagian 7).
// Semua response /auth/selalu ditulis ke audit log, termasuk kegagalan login.

const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const db = require('../shared/db');
const config = require('../shared/config');
const { signAccessToken, signServiceToken, ttlKeDetik } = require('./tokens');
const { logDecision } = require('./audit');

const router = express.Router();

// Refresh token: acak 64 hex; yang DISIMPAN hanya hash SHA-256 (token mentah tidak pernah disimpan)
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Atur device: [R7] device wajib terdaftar untuk user yang bersangkutan
function deviceTerdaftar(userId, deviceId) {
  return !!db
    .prepare('SELECT id FROM devices WHERE user_id = ? AND device_id = ?')
    .get(userId, deviceId);
}

// Helper: audit + kirim error
// endpoint: baseUrl + path agar mencatat '/auth/login' lengkap, dan nama tanpa query
function namaEndpoint(req) {
  return (req.baseUrl || '/auth') + req.path;
}

function tolak(res, req, subjek, status, alasan) {
  logDecision({
    subjek,
    method: req.method,
    endpoint: namaEndpoint(req),
    device: req.get('X-Device-ID') ?? null,
    hasil: 'deny',
    alasan,
    status,
  });
  return res.status(status).json({ error: alasan });
}

function allow(res, req, subjek, body) {
  logDecision({
    subjek,
    method: req.method,
    endpoint: namaEndpoint(req),
    device: req.get('X-Device-ID') ?? null,
    hasil: 'allow',
    alasan: 'policy_ok',
    status: 200,
  });
  return res.json(body);
}

// POST /auth/login
// Kredensial dicek DULU, baru device (supaya tidak membocorkan keberadaan device tertentu)
router.post('/login', (req, res) => {
  const { username, password } = req.body ?? {};
  const user = username ? db.prepare('SELECT * FROM users WHERE username = ?').get(username) : null;

  // password salah / user tidak ada -> 401 invalid_credentials (subjek tetap anonymous bila user tak dikenal)
  if (!user || !password || !bcrypt.compareSync(password, user.password_hash)) {
    return tolak(res, req, user ? `user:${user.username}` : 'anonymous', 401, 'invalid_credentials');
  }

  const deviceId = req.get('X-Device-ID');
  if (!deviceId) {
    return tolak(res, req, `user:${user.username}`, 403, 'device_header_missing');
  }
  if (!deviceTerdaftar(user.id, deviceId)) {
    return tolak(res, req, `user:${user.username}`, 403, 'device_not_registered');
  }

  // [R1] access token 10 menit (TTL dari env) + [R2] refresh token disimpan sebagai hash
  const refresh = crypto.randomBytes(32).toString('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + config.refreshTokenTTLSec;
  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)',
  ).run(user.id, hashToken(refresh), expiresAt, new Date().toISOString());

  return allow(res, req, `user:${user.username}`, {
    access_token: signAccessToken(user),
    refresh_token: refresh,
    token_type: 'Bearer',
    expires_in: ttlKeDetik(config.accessTokenTTL),
  });
});

// POST /auth/refresh - tukar refresh token yang masih hidup dengan access token baru
router.post('/refresh', (req, res) => {
  const { refresh_token: refreshToken } = req.body ?? {};
  if (!refreshToken) return tolak(res, req, 'anonymous', 401, 'refresh_invalid');

  const baris = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashToken(refreshToken));
  if (!baris) return tolak(res, req, 'anonymous', 401, 'refresh_invalid');
  if (baris.revoked === 1) {
    return tolak(res, req, 'anonymous', 401, 'refresh_revoked');
  }
  if (Math.floor(Date.now() / 1000) >= baris.expires_at) {
    return tolak(res, req, 'anonymous', 401, 'refresh_expired');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(baris.user_id);
  if (!user) return tolak(res, req, 'anonymous', 401, 'refresh_invalid');

  return allow(res, req, `user:${user.username}`, {
    access_token: signAccessToken(user),
    token_type: 'Bearer',
    expires_in: ttlKeDetik(config.accessTokenTTL),
  });
});

// POST /auth/logout - mencabut refresh token di DB (R2)
router.post('/logout', (req, res) => {
  const { refresh_token: refreshToken } = req.body ?? {};
  if (!refreshToken) return tolak(res, req, 'anonymous', 401, 'refresh_invalid');

  const baris = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashToken(refreshToken));
  if (!baris) return tolak(res, req, 'anonymous', 401, 'refresh_invalid');

  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(baris.id);
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(baris.user_id);

  return allow(res, req, user ? `user:${user.username}` : 'anonymous', {
    message: 'refresh token dicabut',
  });
});

// POST /auth/service - [R3] token service 5 menit untuk komunikasi service -> gateway
router.post('/service', (req, res) => {
  const { client_id: clientId, client_secret: clientSecret } = req.body ?? {};

  const idBenar = clientId === config.serviceClientId;
  const secretBenar =
    typeof clientSecret === 'string' &&
    clientSecret.length > 0 &&
    crypto.timingSafeEqual(
      crypto.createHash('sha256').update(clientSecret).digest(),
      crypto.createHash('sha256').update(config.serviceClientSecret).digest(),
    );

  if (!idBenar || !secretBenar) {
    return tolak(res, req, clientId ? `service:${clientId}` : 'anonymous', 401, 'service_credentials_invalid');
  }

  return allow(res, req, `service:${config.serviceClientId}`, {
    access_token: signServiceToken(),
    token_type: 'Bearer',
    expires_in: ttlKeDetik(config.serviceTokenTTL), // 300 detik
  });
});

module.exports = router;
