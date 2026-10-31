'use strict';
// scripts/show-audit.js
// [R9] Menampilkan 30 baris TERAKHIR dari tabel audit_log sebagai tabel di konsol.
// Dipakai saat demo: deteksi tanpa respons tidak ada artinya - tamplian lognya.
//   npm run audit

const db = require('../shared/db');

const baris = db
  .prepare(
    `SELECT waktu, subjek, method, endpoint, device, hasil, alasan, status
     FROM audit_log ORDER BY id DESC LIMIT 30`,
  )
  .all()
  .reverse(); // tampil kronologis (paling lama di atas)

if (baris.length === 0) {
  console.log('[audit] audit_log masih kosong. Kirim beberapa request lewat gateway :3000 dulu.');
  process.exit(0);
}

const jumlah = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;
console.log(`[audit] Menampilkan 30 baris terakhir dari total ${jumlah} baris audit_log:\n`);
console.table(
  baris.map((r) => ({
    waktu: r.waktu,
    subjek: r.subjek,
    method: r.method,
    endpoint: r.endpoint,
    device: r.device ?? '-',
    hasil: r.hasil,
    alasan: r.alasan,
    status: r.status,
  })),
);
