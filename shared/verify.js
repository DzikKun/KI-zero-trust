'use strict';
// shared/verify.js
// Middleware WAJIB di kedua service (R4, R5), urutan sesuai bagian 8:
//   1. [R4] Cek X-Gateway-Secret lewat timingSafeEqual -> 403 gateway_secret_invalid bila salah/tidak ada
//   2. [R5] Verifikasi ULANG JWT (tanda tangan + exp, algoritma terkunci ['HS256']) -> 401 bila gagal.
//           Token valid tetap wajib walau gateway secret benar (assume breach: gateway bisa jebol).
//   3. Pasang req.auth = { sub, role } dari token. Header lain (X-User-*) TIDAK pernah dipercaya.

const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const config = require('./config');

// perbandingan waktu-konstan; digest SHA-256 membuat panjang keduanya selalu sama (syarat timingSafeEqual)
function samaSecaraKonstan(a, b) {
  const dA = crypto.createHash('sha256').update(String(a ?? '')).digest();
  const dB = crypto.createHash('sha256').update(String(b ?? '')).digest();
  return crypto.timingSafeEqual(dA, dB);
}

// [R4] Gerbang pertama di service: lalu lintas hanya dari gateway yang membawa X-Gateway-Secret.
// Kalau klien mencoba langsung ke :3001 / :3002, langsung ditolak di sini (segmentasi).
function cekGatewaySecret(req, res, next) {
  const diberikan = req.get('X-Gateway-Secret');
  if (!diberikan || !samaSecaraKonstan(diberikan, config.gatewaySecret)) {
    return res.status(403).json({ error: 'gateway_secret_invalid' });
  }
  next();
}

// [R5] Gerbang kedua: verifikasi ulang token. JWT.selalu diverifikasi dengan algoritma terkunci
// ke HS256 agar serangan `alg: none` atau penggantian algoritma gagal (aturan 1 poin 5).
function verifikasiToken(req, res, next) {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'token_missing' });

  try {
    const payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
    req.auth = { sub: String(payload.sub), role: payload.role };
    next();
  } catch (err) {
    if (err && err.name === 'TokenExpiredError') return res.status(401).json({ error: 'token_expired' });
    return res.status(401).json({ error: 'token_invalid' });
  }
}

module.exports = { cekGatewaySecret, verifikasiToken, samaSecaraKonstan };
