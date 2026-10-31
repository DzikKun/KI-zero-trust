'use strict';
// scripts/seed.js
// Mengisi ulang seluruh isi database: DROP + CREATE semua tabel, lalu isi data seed (bagian 6).
// Aman dijalankan berkali-kali dan tetap aman saat server hidup (WAL memungkinkan proses lain membaca).
//
// Pemakaian:
//   npm run seed
//   atau dipanggil sebagai fungsi dari test/run-tests.js agar data bersih sebelum pengujian.

const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const db = require('../shared/db');

// Skema lengkap (bagian 6). DELETE dulu supaya skrip bisa dijalankan berulang tanpa duplikat.
const SCHEMA_SQL = `
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS transkrip;
DROP TABLE IF EXISTS nilai;
DROP TABLE IF EXISTS kelas;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  nama TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('mahasiswa','dosen','admin')),
  nim TEXT UNIQUE            -- hanya untuk mahasiswa
);
CREATE TABLE devices (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL, UNIQUE(user_id, device_id)
);
CREATE TABLE kelas (
  id INTEGER PRIMARY KEY, kode_mk TEXT NOT NULL, nama_mk TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE nilai (
  id INTEGER PRIMARY KEY, kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai_angka REAL, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','final')),
  UNIQUE(kelas_id, mahasiswa_id)
);
CREATE TABLE transkrip (
  id INTEGER PRIMARY KEY, nim TEXT NOT NULL, kelas_id INTEGER NOT NULL,
  kode_mk TEXT NOT NULL, nama_mk TEXT NOT NULL, nilai_angka REAL NOT NULL,
  huruf TEXT NOT NULL, synced_at TEXT NOT NULL, UNIQUE(nim, kelas_id)
);
CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT UNIQUE NOT NULL,   -- SHA-256 dari token; token mentah tidak disimpan
  expires_at INTEGER NOT NULL,       -- epoch detik
  revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY, waktu TEXT NOT NULL,   -- ISO 8601
  subjek TEXT NOT NULL,       -- 'user:dosen1' | 'service:service-nilai' | 'anonymous'
  method TEXT NOT NULL, endpoint TEXT NOT NULL, device TEXT,
  hasil TEXT NOT NULL CHECK(hasil IN ('allow','deny')),
  alasan TEXT NOT NULL, status INTEGER
);
`;

const USERS = [
  { id: 1, username: 'admin', password: 'Admin#123', nama: 'Administrator', role: 'admin', nim: null, deviceId: 'DEV-ADMIN-01' },
  { id: 2, username: 'dosen1', password: 'Dosen#123', nama: 'Dosen Satu', role: 'dosen', nim: null, deviceId: 'DEV-DOSEN1-01' },
  { id: 3, username: 'dosen2', password: 'Dosen#123', nama: 'Dosen Dua', role: 'dosen', nim: null, deviceId: 'DEV-DOSEN2-01' },
  { id: 4, username: 'mhs1', password: 'Mhs#123', nama: 'Mahasiswa Satu', role: 'mahasiswa', nim: '2210001', deviceId: 'DEV-MHS1-01' },
  { id: 5, username: 'mhs2', password: 'Mhs#123', nama: 'Mahasiswa Dua', role: 'mahasiswa', nim: '2210002', deviceId: 'DEV-MHS2-01' },
  { id: 6, username: 'mhs3', password: 'Mhs#123', nama: 'Mahasiswa Tiga', role: 'mahasiswa', nim: '2210003', deviceId: 'DEV-MHS3-01' },
];

const KELAS = [
  { id: 1, kode_mk: 'KP70065004', nama_mk: 'Keamanan Informasi', dosen_id: 2 },
  { id: 2, kode_mk: 'IF30021', nama_mk: 'Basis Data', dosen_id: 3 },
];

const NILAI = [
  { kelas_id: 1, mahasiswa_id: 4, nilai_angka: 85 },
  { kelas_id: 1, mahasiswa_id: 5, nilai_angka: 72 },
  { kelas_id: 1, mahasiswa_id: 6, nilai_angka: 60 },
  { kelas_id: 2, mahasiswa_id: 4, nilai_angka: 90 },
  { kelas_id: 2, mahasiswa_id: 5, nilai_angka: 65 },
  { kelas_id: 2, mahasiswa_id: 6, nilai_angka: 78 },
];

function seedDatabase() {
  db.exec(SCHEMA_SQL);

  db.exec('BEGIN');
  try {
    const pUser = db.prepare(
      'INSERT INTO users (id, username, password_hash, nama, role, nim) VALUES (?, ?, ?, ?, ?, ?)',
    );
    const pDevice = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?, ?)');
    const pKelas = db.prepare('INSERT INTO kelas (id, kode_mk, nama_mk, dosen_id) VALUES (?, ?, ?, ?)');
    const pNilai = db.prepare(
      "INSERT INTO nilai (kelas_id, mahasiswa_id, nilai_angka, status) VALUES (?, ?, ?, 'draft')",
    );

    for (const u of USERS) {
      // Password praktikum di-hash dengan bcryptjs (aturan 10: bukan bcrypt native)
      pUser.run(u.id, u.username, bcrypt.hashSync(u.password, 10), u.nama, u.role, u.nim);
      pDevice.run(u.id, u.deviceId);
    }

    for (const k of KELAS) pKelas.run(k.id, k.kode_mk, k.nama_mk, k.dosen_id);
    for (const n of NILAI) pNilai.run(n.kelas_id, n.mahasiswa_id, n.nilai_angka);

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function printSeedSummary() {
  const akun = db
    .prepare(
      `SELECT u.id, u.username, u.role, u.nim, u.nama, d.device_id AS 'device terdaftar'
       FROM users u JOIN devices d ON d.user_id = u.id ORDER BY u.id`,
    )
    .all();
  console.log('== Akun & device seed ==');
  console.table(akun);

  const kelas = db.prepare('SELECT id, kode_mk, nama_mk, dosen_id FROM kelas ORDER BY id').all();
  console.log('== Kelas ==');
  console.table(kelas);

  const nilai = db
    .prepare(
      `SELECT n.id, n.kelas_id, u.username AS mahasiswa, n.nilai_angka, n.status
       FROM nilai n JOIN users u ON u.id = n.mahasiswa_id ORDER BY n.id`,
    )
    .all();
  console.log('== Nilai (semua draft) ==');
  console.table(nilai);
}

module.exports = { seedDatabase };

// Dipanggil langsung lewat `npm run seed` -> jalankan dan tampilkan ringkasan.
// Dipanggil dari test/run-tests.js -> hanya fungsi seedDatabase() yang diimpor.
if (require.main === module) {
  seedDatabase();
  printSeedSummary();
  console.log('[seed] Database siap.');
}
