'use strict';
// shared/config.js
// Membaca konfigurasi dari environment variable (dipakai lewat `node --env-file=.env`)
// dan memvalidasinya sebelum dipakai.
//
// Prinsip zero trust yang relevan:
// - Tidak ada secret yang di-hardcode atau punya nilai default di kode (bagian 1 aturan 3).
//   Aplikasi gagal start jika secret wajib masih kosong / masih placeholder.

const required = ['JWT_SECRET', 'GATEWAY_SECRET', 'SERVICE_CLIENT_ID', 'SERVICE_CLIENT_SECRET'];

function intOrThrow(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n) || n <= 0) {
    console.error(`[config] Nilai ${name} tidak valid: "${raw}"`);
    process.exit(1);
  }
  return n;
}

function loadConfig() {
  // Secret wajib harus terisi dan bukan placeholder dari .env.example
  const invalid = required.filter(
    (k) => !process.env[k] || process.env[k].trim() === '' || process.env[k].includes('GANTI_DENGAN_ACAK'),
  );
  if (invalid.length > 0) {
    console.error(
      `[config] SECRET wajib belum diisi dengan benar di .env: ${invalid.join(', ')}\n` +
        `         Buat nilai acak: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
    );
    process.exit(1);
  }

  return {
    // Port dan URL (selalu 127.0.0.1, bukan localhost, agar tidak terkena IPv6 ::1)
    gatewayPort: intOrThrow('GATEWAY_PORT', 3000),
    serviceNilaiPort: intOrThrow('SERVICE_NILAI_PORT', 3001),
    serviceTranskripPort: intOrThrow('SERVICE_TRANSKRIP_PORT', 3002),
    gatewayUrl: process.env.GATEWAY_URL || 'http://127.0.0.1:3000',
    serviceNilaiUrl: process.env.SERVICE_NILAI_URL || 'http://127.0.0.1:3001',
    serviceTranskripUrl: process.env.SERVICE_TRANSKRIP_URL || 'http://127.0.0.1:3002',

    // Secret (wajib berisi nilai acak, lihat validasi di atas)
    jwtSecret: process.env.JWT_SECRET,
    gatewaySecret: process.env.GATEWAY_SECRET,
    serviceClientId: process.env.SERVICE_CLIENT_ID,
    serviceClientSecret: process.env.SERVICE_CLIENT_SECRET,

    // Masa berlaku token. Format dipakai langsung oleh jsonwebtoken ("10m", "5m").
    accessTokenTTL: process.env.ACCESS_TOKEN_TTL || '10m',
    serviceTokenTTL: process.env.SERVICE_TOKEN_TTL || '5m',
    refreshTokenTTLSec: intOrThrow('REFRESH_TOKEN_TTL_SECONDS', 86400),

    // Lokasi database SQLite bersama
    dbPath: process.env.DB_PATH || './data/nilai.db',
  };
}

module.exports = loadConfig();
