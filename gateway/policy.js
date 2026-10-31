'use strict';
// gateway/policy.js
// [R6] SATU-SATUNYA tempat keputusan akses (Policy Engine) - seluruh isi Tabel 3 (bagian 6).
//  - Token HANYA menyumbang `sub` dan `role` (aturan 7): kepemilikan selalu dikonfirmasi ke DATABASE.
//  - DEFAULT DENY (aturan 2): request yang tidak cocok dengan aturan mana pun ditolak `no_matching_policy`.
//  - Pengecekan berurutan di dalam tiap aturan; berhenti pada kegagalan pertama.

const fs = require('node:fs');
const path = require('node:path');
const db = require('../shared/db');

// [R8] Jam akses dibaca dari config/access-hours.json PADA SETIAP KEPUTUSAN (bukan di-cache),
// sehingga bisa diubah saat demo tanpa restart server.
function bacaJamAkses() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'access-hours.json'), 'utf8'));
}

// [R8] Izinkan jika start <= sekarang < end (zona waktu dari file, default Asia/Jakarta)
function dalamJamAkses() {
  const cfg = bacaJamAkses();
  const sekarang = new Intl.DateTimeFormat('en-GB', {
    timeZone: cfg.timezone || 'Asia/Jakarta',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).format(new Date());
  const { start, end } = cfg;
  if (start <= end) return start <= sekarang && sekarang < end;
  return sekarang >= start || sekarang < end; // jendela lintas tengah malam
}

/**
 * Keputusan akses.
 * @param {{method: string, path: string, query: object, sub: string, role: string}} input
 * @returns {{allow: boolean, status: number, reason: string}}
 */
function decide({ method, path, query, sub, role }) {
  const deny = (status, reason) => ({ allow: false, status, reason });
  const allow = () => ({ allow: true, status: 200, reason: 'policy_ok' });

  // ------------------------- GET /nilai -------------------------
  if (method === 'GET' && path === '/nilai') {
    if (role === 'mahasiswa') {
      const saya = db.prepare('SELECT nim FROM users WHERE id = ?').get(sub);
      // Mahasiswa: bila ada ?nim=, harus sama dengan NIM miliknya (dari DB)
      if (query.nim && (!saya || saya.nim !== query.nim)) return deny(403, 'not_own_data');
      return allow();
    }
    if (role === 'dosen') {
      // Dosen: wajib ?kelas_id=, kelas ada, dan diampu sub (dari DB)
      const kelasId = query.kelas_id;
      if (!kelasId) return deny(400, 'kelas_id_required');
      const kelas = db.prepare('SELECT dosen_id FROM kelas WHERE id = ?').get(kelasId);
      if (!kelas) return deny(404, 'kelas_not_found');
      if (kelas.dosen_id !== Number(sub)) return deny(403, 'class_not_owned');
      return allow();
    }
    return deny(403, 'role_not_permitted');
  }

  // ------------------------- PUT /nilai/:id -------------------------
  const mPut = method === 'PUT' && /^\/nilai\/(\d+)$/.exec(path);
  if (mPut) {
    if (role !== 'dosen') return deny(403, 'role_not_permitted');
    const nilai = db
      .prepare('SELECT n.status, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?')
      .get(mPut[1]);
    if (!nilai) return deny(404, 'grade_not_found');
    if (nilai.dosen_id !== Number(sub)) return deny(403, 'class_not_owned');
    if (nilai.status === 'final') return deny(403, 'grade_already_final');
    if (!dalamJamAkses()) return deny(403, 'outside_access_hours');
    return allow();
  }

  // ------------------------- POST /kelas/:id/finalisasi -------------------------
  const mFin = method === 'POST' && /^\/kelas\/(\d+)\/finalisasi$/.exec(path);
  if (mFin) {
    if (role !== 'dosen') return deny(403, 'role_not_permitted');
    const kelas = db.prepare('SELECT dosen_id FROM kelas WHERE id = ?').get(mFin[1]);
    if (!kelas) return deny(404, 'kelas_not_found');
    if (kelas.dosen_id !== Number(sub)) return deny(403, 'class_not_owned');
    if (!dalamJamAkses()) return deny(403, 'outside_access_hours');
    return allow();
  }

  // ------------------------- GET /transkrip/:nim -------------------------
  const mTr = method === 'GET' && /^\/transkrip\/([^/]+)$/.exec(path);
  if (mTr) {
    if (role === 'mahasiswa') {
      const saya = db.prepare('SELECT nim FROM users WHERE id = ?').get(sub);
      // Mahasiswa: hanya transkrip miliknya sendiri (NIM dicocokkan dari DB)
      if (!saya || saya.nim !== mTr[1]) return deny(403, 'not_own_data');
      return allow();
    }
    if (role === 'admin') return allow(); // admin: semua
    return deny(403, 'role_not_permitted');
  }

  // ------------------------- POST /transkrip/sinkron -------------------------
  // Hanya role service; token user mana pun ditolak
  if (method === 'POST' && path === '/transkrip/sinkron') {
    if (role === 'service') return allow();
    return deny(403, 'user_token_not_allowed');
  }

  // ------------------------- default deny -------------------------
  return deny(403, 'no_matching_policy');
}

module.exports = { decide, dalamJamAkses };
