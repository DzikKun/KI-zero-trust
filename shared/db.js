'use strict';
// shared/db.js
// Satu modul tunggal untuk membuka database SQLite bersama (node:sqlite, tanpa dependensi native).
// Dibuka oleh 3 proses sekaligus (gateway :3000, service nilai :3001, service transkrip :3002),
// sehingga WAJIB memakai journal_mode=WAL dan busy_timeout.

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const config = require('./config');

// Pastikan folder data/ ada sebelum membuka file DB
fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });

const db = new DatabaseSync(config.dbPath);

// WAL: pembaca dan penulis tidak saling blokir saat bebarengan di beberapa proses.
// busy_timeout: tunggu hingga 5 detik bila DB sedang dipakai proses lain, bukan langsung gagal.
db.exec('PRAGMA journal_mode=WAL;');
db.exec('PRAGMA busy_timeout=5000;');

module.exports = db;
