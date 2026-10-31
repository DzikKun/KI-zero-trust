'use strict';
// service-transkrip/server.js
// Service Transkrip (:3002), hanya listen di 127.0.0.1 (segmentasi).
// Lapis pertahanan di service (R4, R5): X-Gateway-Secret + verifikasi ulang JWT.
// GET /transkrip/:nim hanya role mahasiswa (NIM miliknya dari DB) atau admin.
// POST /transkrip/sinkron HANYA role service (token user mana pun ditolak).

const express = require('express');
const db = require('../shared/db');
const config = require('../shared/config');
const { cekGatewaySecret, verifikasiToken } = require('../shared/verify');

const app = express();
app.use(express.json());

// [R4] hanya lalu lintas dari gateway, lalu [R5] verifikasi ulang token
app.use(cekGatewaySecret);
app.use(verifikasiToken);

// GET /transkrip/:nim
app.get('/transkrip/:nim', (req, res) => {
  const { sub, role } = req.auth;
  if (role !== 'mahasiswa' && role !== 'admin') {
    return res.status(403).json({ error: 'role_not_permitted' });
  }

  const nim = req.params.nim;

  // Mahasiswa hanya boleh melihat transkrip miliknya sendiri (NIM dicocokkan dari DB, bukan dari token)
  if (role === 'mahasiswa') {
    const saya = db.prepare('SELECT nim FROM users WHERE id = ?').get(sub);
    if (!saya || saya.nim !== nim) return res.status(403).json({ error: 'not_own_data' });
  }

  const pemilik = db.prepare('SELECT nama FROM users WHERE nim = ?').get(nim);
  const baris = db
    .prepare(
      `SELECT kode_mk, nama_mk, nilai_angka, huruf
       FROM transkrip WHERE nim = ? ORDER BY kelas_id`,
    )
    .all(nim);

  return res.json({ nim, nama: pemilik ? pemilik.nama : null, mata_kuliah: baris });
});

// POST /transkrip/sinkron - hanya token service
app.post('/transkrip/sinkron', (req, res) => {
  if (req.auth.role !== 'service') {
    return res.status(403).json({ error: 'user_token_not_allowed' });
  }

  const kelasId = req.body?.kelas_id;
  const items = req.body?.items;
  if (!Number.isInteger(kelasId) || !Array.isArray(items)) {
    return res.status(400).json({ error: 'invalid_payload' });
  }

  const sekarang = new Date().toISOString();
  // Upsert berdasarkan (nim, kelas_id): finalisasi ulang tidak menduplikasi baris
  const upsert = db.prepare(`
    INSERT INTO transkrip (nim, kelas_id, kode_mk, nama_mk, nilai_angka, huruf, synced_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(nim, kelas_id) DO UPDATE SET
      kode_mk = excluded.kode_mk,
      nama_mk = excluded.nama_mk,
      nilai_angka = excluded.nilai_angka,
      huruf = excluded.huruf,
      synced_at = excluded.synced_at
  `);

  db.exec('BEGIN');
  try {
    for (const it of items) {
      upsert.run(String(it.nim), kelasId, it.kode_mk, it.nama_mk, it.nilai_angka, it.huruf, sekarang);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    return res.status(400).json({ error: 'invalid_items' });
  }

  return res.json({ ok: true, jumlah: items.length });
});

const PORT = config.serviceTranskripPort;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[service-transkrip] menyala di http://127.0.0.1:${PORT} (hanya lokal)`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(
      `[service-transkrip] Port ${PORT} sudah dipakai. Tutup proses lain atau ubah SERVICE_TRANSKRIP_PORT di .env.`,
    );
    process.exit(1);
  }
  throw err;
});
