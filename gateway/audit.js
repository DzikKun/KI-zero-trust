'use strict';
// gateway/audit.js
// [R9] Audit log: satu request ke gateway = satu baris di tabel audit_log.
// Menulis barisnya (allow maupun deny) dan menampilkannya sebagai ringkasan di konsol
// agar anomali langsung terlihat saat demo (deteksi tanpa respons tidak ada artinya).

const db = require('../shared/db');

const pInsert = db.prepare(
  `INSERT INTO audit_log (waktu, subjek, method, endpoint, device, hasil, alasan, status)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
);

function logDecision({ subjek, method, endpoint, device, hasil, alasan, status }) {
  const waktu = new Date().toISOString();
  pInsert.run(waktu, subjek, method, endpoint, device ?? null, hasil, alasan, status ?? null);
  const simbol = hasil === 'allow' ? '✓' : '✗';
  console.log(
    `[audit] ${simbol} ${String(status ?? '-')} ${method} ${endpoint} ${subjek} device=${device ?? '-'} (${alasan})`,
  );
}

module.exports = { logDecision };
