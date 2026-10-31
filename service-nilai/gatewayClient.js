'use strict';
// service-nilai/gatewayClient.js
// Sinkronisasi transkrip TIDAK langsung ke Service Transkrip, melainkan lewat gateway (R10):
//   1. [R3] Minta token service: POST {GATEWAY_URL}/auth/service  (client_id + client_secret)
//   2. Kirim payload: POST {GATEWAY_URL}/transkrip/sinkron dengan Authorization: Bearer <token service>
//      dan TANPA X-Device-ID (device hanya untuk manusia; token service tidak diikat device).

const config = require('../shared/config');

// Cache token service sampai mendekati masa berlaku (exp) agar tidak minta token tiap finalisasi
let cacheToken = null; // { token, expEpochDetik }

async function ambilTokenService() {
  const masihHidup = cacheToken && cacheToken.exp - Math.floor(Date.now() / 1000) > 10; // sisa > 10 detik
  if (masihHidup) return cacheToken.token;

  const resp = await fetch(`${config.gatewayUrl}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: config.serviceClientId, client_secret: config.serviceClientSecret }),
  });
  if (!resp.ok) {
    const pesan = await resp.text();
    throw new Error(`gagal ambil token service (${resp.status}): ${pesan}`);
  }
  const body = await resp.json();
  const payload = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64').toString('utf8'));
  cacheToken = { token: body.access_token, exp: payload.exp };
  return cacheToken.token;
}

async function sinkronKeGateway(kelasId, items) {
  const token = await ambilTokenService();
  const resp = await fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`, // sengaja TANPA X-Device-ID
    },
    body: JSON.stringify({ kelas_id: kelasId, items }),
  });
  if (!resp.ok) {
    const pesan = await resp.text();
    throw new Error(`sinkron ditolak (${resp.status}): ${pesan}`);
  }
  return resp.json();
}

module.exports = { sinkronKeGateway, ambilTokenService };
