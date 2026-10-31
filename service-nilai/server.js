'use strict';
// service-nilai/server.js
// Service Nilai (:3001), hanya listen di 127.0.0.1 (segmentasi: tidak boleh terjangkau langsung).
// Lapis pertahanan di service (R4, R5): X-Gateway-Secret + verifikasi ulang JWT.
// Pemeriksaan kasar peran di bawah adalah "pertahanan berlapis", BUKAN pengganti Policy Engine.
// Kepemilikan tetap dihitung dari DATABASE (users/kelas/nilai), bukan dari isi token (aturan 7).

const express = require('express');
const db = require('../shared/db');
const config = require('../shared/config');
const { cekGatewaySecret, verifikasiToken } = require('../shared/verify');
const { sinkronKeGateway } = require('./gatewayClient');

const app = express();
app.use(express.json());

// [R4] hanya lalu lintas dari gateway, lalu [R5] verifikasi ulang token
app.use(cekGatewaySecret);
app.use(verifikasiToken);

// Bentuk baris nilai yang dikirim service ke klien
const KOLONEN_NILAI = `
  n.id AS nilai_id, n.kelas_id, k.kode_mk, k.nama_mk,
  m.nim, m.nama AS nama_mahasiswa,
  n.nilai_angka, n.status`;

// GET /nilai
// mahasiswa: hanya nilai miliknya sendiri (mahasiswa_id = sub dari DB)
// dosen: hanya nilai kelas yang diampu (kelas.dosen_id = sub dari DB)
app.get('/nilai', (req, res) => {
  const { sub, role } = req.auth;

  if (role === 'mahasiswa') {
    const baris = db
      .prepare(
        `SELECT ${KOLONEN_NILAI}
         FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users m ON m.id = n.mahasiswa_id
         WHERE n.mahasiswa_id = ? ORDER BY n.id`,
      )
      .all(sub);
    return res.json(baris);
  }

  if (role === 'dosen') {
    const kelasId = req.query.kelas_id;
    const baris = db
      .prepare(
        `SELECT ${KOLONEN_NILAI}
         FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users m ON m.id = n.mahasiswa_id
         WHERE k.dosen_id = ? AND (? IS NULL OR n.kelas_id = ?) ORDER BY n.id`,
      )
      .all(sub, kelasId ?? null, kelasId ?? null);
    return res.json(baris);
  }

  // role lain (admin/service) tidak diterima service ini -> pertahanan terakhir
  return res.status(403).json({ error: 'role_not_permitted' });
});

// PUT /nilai/:id - hanya dosen yang mengampu kelas tersebut
app.put('/nilai/:id', (req, res) => {
  const { sub, role } = req.auth;
  if (role !== 'dosen') return res.status(403).json({ error: 'role_not_permitted' });

  const nilaiId = Number(req.params.id);
  const nilai = db
    .prepare(
      `SELECT n.*, k.dosen_id
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id
       WHERE n.id = ?`,
    )
    .get(nilaiId);
  if (!nilai) return res.status(404).json({ error: 'grade_not_found' });
  if (nilai.dosen_id !== Number(sub)) return res.status(403).json({ error: 'class_not_owned' });
  if (nilai.status === 'final') return res.status(403).json({ error: 'grade_already_final' });

  const angka = req.body?.nilai_angka;
  if (typeof angka !== 'number' || Number.isNaN(angka)) {
    return res.status(400).json({ error: 'invalid_value' });
  }

  db.prepare('UPDATE nilai SET nilai_angka = ? WHERE id = ?').run(angka, nilaiId);
  const baru = db.prepare('SELECT * FROM nilai WHERE id = ?').get(nilaiId);
  return res.json({ message: 'nilai diperbarui', nilai: baru });
});

// POST /kelas/:id/finalisasi - finalisasi kelas lalu sinkron transkrip via gateway
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const { sub, role } = req.auth;
  if (role !== 'dosen') return res.status(403).json({ error: 'role_not_permitted' });

  const kelasId = Number(req.params.id);
  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasId);
  if (!kelas) return res.status(404).json({ error: 'kelas_not_found' });
  if (kelas.dosen_id !== Number(sub)) return res.status(403).json({ error: 'class_not_owned' });

  // Ambil seluruh nilai kelas ini + NIM mahasiswa untuk payload sinkron
  const baris = db
    .prepare(
      `SELECT n.id, n.nilai_angka, m.nim
       FROM nilai n JOIN users m ON m.id = n.mahasiswa_id
       WHERE n.kelas_id = ? ORDER BY n.id`,
    )
    .all(kelasId);

  // Kalau sudah final semua, tetap boleh dipanggil ulang (upsert transkrip idempoten)
  const items = baris.map((n) => ({
    nim: n.nim,
    kode_mk: kelas.kode_mk,
    nama_mk: kelas.nama_mk,
    nilai_angka: n.nilai_angka,
    huruf: konversiHuruf(n.nilai_angka),
  }));

  // Catatan penting: transaksi tulis TIDAK dipasang selama sinkron. Gateway menulis
  // audit_log untuk setiap request (R9) dan hanya boleh SATU penulis SQLite aktif.
  // Kalau kita masih memegang kunci tulis saat menunggu sinkron, gateway/singleton
  // lain akan menabrak "database is locked".
  //  1) tandai final dulu (otokommit),
  //  2) sinkron lewat gateway,
  //  3) bila sinkron gagal -> kembalikan status nilai ke 'draft' lalu 502.
  db.prepare("UPDATE nilai SET status = 'final' WHERE kelas_id = ?").run(kelasId);

  try {
    // Sinkron hanya boleh lewat gateway (satu titik kontrol, R10).
    const hasilSinkron = await sinkronKeGateway(kelasId, items);

    return res.json({
      message: 'kelas difinalisasi dan transkrip disinkronkan',
      kelas_id: kelasId,
      jumlah_nilai: items.length,
      sinkron: hasilSinkron,
    });
  } catch (err) {
    // Sinkron gagal: status nilai kembali ke 'draft' dan klien diberi 502
    db.prepare("UPDATE nilai SET status = 'draft' WHERE kelas_id = ?").run(kelasId);
    console.error('[service-nilai] sinkron gagal:', err.message);
    return res.status(502).json({ error: 'sync_failed' });
  }
});

// Konversi huruf (bagian 6): dipakai Service Nilai saat sinkron
function konversiHuruf(angka) {
  if (angka >= 85) return 'A';
  if (angka >= 70) return 'B';
  if (angka >= 55) return 'C';
  if (angka >= 40) return 'D';
  return 'E';
}

const PORT = config.serviceNilaiPort;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[service-nilai] menyala di http://127.0.0.1:${PORT} (hanya lokal)`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[service-nilai] Port ${PORT} sudah dipakai. Tutup proses lain atau ubah SERVICE_NILAI_PORT di .env.`);
    process.exit(1);
  }
  throw err;
});
