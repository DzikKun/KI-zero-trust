'use strict';
// gateway/server.js
// [R10] API Gateway (:3000) adalah SATU-SATUNYA pintu masuk (PEP) ke sistem nilai.
//
// Urutan pemrosesan request non-/auth/* (bagian 4):
//   1. Verifikasi Bearer token (tanda tangan + exp)                      -> 401
//   2. Cek user masih ada di DB                                          -> 401 user_not_found
//   3. [R7] Device terdaftar untuk token tersebut (kecuali role service)  -> 403
//   4. [R6] policy.decide()                                              -> allow/deny + alasan
//   5. [R9] Audit log (allow maupun deny, termasuk langkah 1-3) - satu request = satu baris
//   6. Deny -> balas { error: alasan }; Allow -> proxy + X-Gateway-Secret [R4]
//
// Endpoint /auth/* ditangani di authRoutes.js (Policy Administrator), audit juga di sana.

const express = require('express');
const db = require('../shared/db');
const config = require('../shared/config');
const { verifikasiToken } = require('./tokens');
const { logDecision } = require('./audit');
const policy = require('./policy');
const { teruskan } = require('./proxy');

const app = express();

// express.json HANYA untuk router /auth (body yang sudah dibaca akan merusak proxy)
app.use('/auth', express.json(), require('./authRoutes'));

// ==========================================================================
//                   PEP: Policy Enforcement Point (R10)
// ==========================================================================
app.use((req, res, next) => {
  const url = new URL(req.originalUrl, 'http://lokal');
  const path = url.pathname;
  const query = Object.fromEntries(url.searchParams);
  const endpoint = path; // catat tanpa query agar audit ringkas

  const audit = (subjek, hasil, alasan, status) =>
    logDecision({
      subjek,
      method: req.method,
      endpoint,
      device: req.get('X-Device-ID') ?? null,
      hasil,
      alasan,
      status,
    });

  // --- Langkah 1: verifikasi Bearer token (~R1, verifikasi ~R5 di sisi gateway) ---
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) {
    audit('anonymous', 'deny', 'token_missing', 401);
    return res.status(401).json({ error: 'token_missing' });
  }

  let payload;
  try {
    payload = verifikasiToken(token); // algoritma terkunci HS256 (aturan 5)
  } catch (err) {
    const alasan = err && err.name === 'TokenExpiredError' ? 'token_expired' : 'token_invalid';
    audit('anonymous', 'deny', alasan, 401);
    return res.status(401).json({ error: alasan });
  }

  // --- Langkah 2: user masih ada di DB (hanya untuk token user; token service tidak punya baris users) ---
  let user = null;
  let subjek;
  if (payload.role === 'service') {
    subjek = `service:${payload.sub}`;
  } else {
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
    subjek = user ? `user:${user.username}` : 'anonymous';
    if (!user) {
      audit(subjek, 'deny', 'user_not_found', 401);
      return res.status(401).json({ error: 'user_not_found' });
    }
  }

  // --- Langkah 3: [R7] device terdaftar (kecuali role service) ---
  if (payload.role !== 'service') {
    const deviceId = req.get('X-Device-ID');
    if (!deviceId) {
      audit(subjek, 'deny', 'device_header_missing', 403);
      return res.status(403).json({ error: 'device_header_missing' });
    }
    const terdaftar = !!db
      .prepare('SELECT id FROM devices WHERE user_id = ? AND device_id = ?')
      .get(user.id, deviceId);
    if (!terdaftar) {
      audit(subjek, 'deny', 'device_not_registered', 403);
      return res.status(403).json({ error: 'device_not_registered' });
    }
  }

  // --- Langkah 4: [R6] keputusan dari ONE policy engine ---
  const keputusan = policy.decide({ method: req.method, path, query, sub: payload.sub, role: payload.role });

  // --- Langkah 5 & 6 ---
  if (!keputusan.allow) {
    audit(subjek, 'deny', keputusan.reason, keputusan.status);
    return res.status(keputusan.status).json({ error: keputusan.reason });
  }

  // Allow: audit ditulis setelah response selesai, jadi status hilir yang sebenarnya tercatat
  res.on('finish', () => {
    audit(subjek, 'allow', keputusan.reason, res.statusCode);
  });

  return next();
});

// Requests yang diizinkan diteruskan ke service (path tetap lengkap) + X-Gateway-Secret [R4]
app.use(teruskan);

// Pengaman terakhir (default deny): seharusnya tidak pernah dicapai karena
// policy menolak semua path yang tidak cocok. Tetap dipasang agar tidak ada backdoor
// yang lolos lewat celah pendaftaran route baru.
app.use((req, res) => {
  logDecision({
    subjek: 'anonymous',
    method: req.method,
    endpoint: req.path,
    device: req.get('X-Device-ID') ?? null,
    hasil: 'deny',
    alasan: 'no_matching_policy',
    status: 403,
  });
  return res.status(403).json({ error: 'no_matching_policy' });
});
// ==========================================================================

const PORT = config.gatewayPort;
app.listen(PORT, () => {
  console.log(`[gateway] PEP menyala di http://127.0.0.1:${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[gateway] Port ${PORT} sudah dipakai. Tutup proses lain atau ubah GATEWAY_PORT di .env.`);
    process.exit(1);
  }
  throw err;
});
