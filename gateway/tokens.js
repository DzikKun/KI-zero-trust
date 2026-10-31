'use strict';
// gateway/tokens.js
// Penerbitan dan verifikasi token (R1, R3) - satu-satunya tempat jsonwebtoken dipakai di gateway.
//
// [R1] Access token user:   { sub: "<user.id>", role }      TTL dari ACCESS_TOKEN_TTL (default 10 menit)
// [R3] Token service:       { sub: "<client_id>", role: "service" } TTL dari SERVICE_TOKEN_TTL (default 5 menit)
// Token SADARISI TIDAK memuat NIM/kelas (aturan 7): kepemilikan diputuskan dari DB di policy.js.

const jwt = require('jsonwebtoken');
const config = require('../shared/config');

// Konversi "10m" / "5m" / "15s" menjadi detik, untuk field expires_in pada response
function ttlKeDetik(ttl) {
  const cocok = /^(\d+)([smhd])$/.exec(String(ttl).trim());
  if (!cocok) return Number(ttl);
  const satu = { s: 1, m: 60, h: 3600, d: 86400 }[cocok[2]];
  return Number(cocok[1]) * satu;
}

// [R1] Access token user
function signAccessToken(user) {
  return jwt.sign({ sub: String(user.id), role: user.role }, config.jwtSecret, {
    expiresIn: config.accessTokenTTL,
    algorithm: 'HS256',
  });
}

// [R3] Token service (role "service")
function signServiceToken() {
  return jwt.sign({ sub: config.serviceClientId, role: 'service' }, config.jwtSecret, {
    expiresIn: config.serviceTokenTTL,
    algorithm: 'HS256',
  });
}

// Verifikasi token (access user maupun token service memakai secret yang sama).
// [R5] algoritma TERKUNCI ke HS256 supaya serangan `alg: none` / pergantian algoritma gagal.
function verifikasiToken(token) {
  return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
}

module.exports = { signAccessToken, signServiceToken, verifikasiToken, ttlKeDetik };
