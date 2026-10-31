'use strict';
// test/run-tests.js
// Pengujian otomatis seluruh skenario (bagian 11), dijalankan dengan `npm test`
// saat KETIGA server sudah menyala (`npm start` di terminal lain sebelumnya).
//
// - Mengawali dengan re-seed (fungsi dari scripts/seed.js) agar data bersih.
// - Mencetak PASS/FAIL per skenario (kode T) + ringkasan di akhir.
// - process.exit(1) bila ada yang gagal.
// - Skenario jam akses mengubah config/access-hours.json sementara (try/finally).

const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const db = require('../shared/db');
const config = require('../shared/config');
const { ttlKeDetik } = require('../gateway/tokens');
const { seedDatabase } = require('../scripts/seed');

const GATEWAY = config.gatewayUrl;
const SISTEM_NILAI = config.serviceNilaiUrl;
const SISTEM_TRANSKRIP = config.serviceTranskripUrl;
const FILE_JAM = path.join(__dirname, '..', 'config', 'access-hours.json');

let gagal = 0;
let pass = 0;

async function req(method, url, headers = {}, body) {
  const resp = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await resp.json(); } catch { /* bukan JSON */ }
  return { status: resp.status, body: json };
}

function cek(kode, ok, detail) {
  if (ok) pass++;
  else gagal++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${kode}  -> ${JSON.stringify(detail)}`);
}

// Helper login: kembalikan {status, body}
const login = (username, password, deviceId) =>
  req('POST', `${GATEWAY}/auth/login`, {
    'Content-Type': 'application/json',
    'X-Device-ID': deviceId,
  }, { username, password });

const headBearer = (token, device) => {
  const h = { Authorization: `Bearer ${token}` };
  if (device) h['X-Device-ID'] = device;
  return h;
};

// Jam akses: sementara set lalu selalu kembalikan (dipakai di try/finally)
const configJamAsal = fs.readFileSync(FILE_JAM, 'utf8');
const setJam = (start, end) => fs.writeFileSync(FILE_JAM, JSON.stringify({ start, end, timezone: 'Asia/Jakarta' }));

// Pilih jendela 1 jam yang dimulai 30 menit ke depan -> dijamin TIDAK memuat waktu sekarang
function jendelaTutup() {
  const sekarang = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Jakarta', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(new Date());
  const [h, m] = sekarang.split(':').map(Number);
  const menitTotal = h * 60 + m;
  const fmtJam = (x) => `${String(Math.floor(x / 60) % 24).padStart(2, '0')}:${String(x % 60).padStart(2, '0')}`;
  const mulai = menitTotal + 30;  // 30 menit dari sekarang
  const selesai = mulai + 60;     // jendela 1 jam
  return [fmtJam(mulai), fmtJam(selesai)];
}

async function serverMenyala(url, nama) {
  try {
    await fetch(url, { method: 'GET' });
    return true;
  } catch {
    console.error(`[test] Server ${nama} (${url}) TIDAK menyala. Jalankan 'npm start' di terminal lain, lalu 'npm test'.`);
    return false;
  }
}

(async () => {
  console.log('== memastikan server menyala ==');
  if (!(await serverMenyala(GATEWAY, 'gateway'))) process.exit(1);
  if (!(await serverMenyala(SISTEM_NILAI, 'service-nilai'))) process.exit(1);
  if (!(await serverMenyala(SISTEM_TRANSKRIP, 'service-transkrip'))) process.exit(1);

  console.log('== re-seed data bersih ==');
  seedDatabase();
  const jumlahAuditAwal = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;

  try {
    // ========================================================================
    // T01-T09: auth di gateway
    // ========================================================================
    const b01 = await login('dosen1', 'Dosen#123', 'DEV-DOSEN1-01');
    cek('T01', b01.status === 200 && !!b01.body.access_token && !!b01.body.refresh_token && b01.body.token_type === 'Bearer',
      { status: b01.status, ada_access: !!b01.body.access_token, ada_refresh: !!b01.body.refresh_token });
    const tokDosen1 = b01.body.access_token;
    const refreshPertama = b01.body.refresh_token;

    const b02 = await login('dosen1', 'SALAH', 'DEV-DOSEN1-01');
    cek('T02', b02.status === 401, b02);

    const b03 = await login('dosen1', 'Dosen#123', 'DEV-XXX');
    cek('T03', b03.status === 403 && b03.body.error === 'device_not_registered', b03);

    const b04 = await login('mhs1', 'Mhs#123', 'DEV-DOSEN1-01'); // device milik dosen1
    cek('T04', b04.status === 403 && b04.body.error === 'device_not_registered', b04);

    const b05 = await req('POST', `${GATEWAY}/auth/refresh`, { 'Content-Type': 'application/json' }, { refresh_token: refreshPertama });
    cek('T05', b05.status === 200 && !!b05.body.access_token, b05);
    const tokDosen1b = b05.body.access_token;

    const b06 = await req('POST', `${GATEWAY}/auth/refresh`, { 'Content-Type': 'application/json' }, { refresh_token: 'a'.repeat(64) });
    cek('T06', b06.status === 401, b06);

    // logout dengan refresh token TERPISAH, lalu coba refresh sama
    const b07login = await login('dosen1', 'Dosen#123', 'DEV-DOSEN1-01');
    const refreshUntukLogout = b07login.body.refresh_token;
    const b07logout = await req('POST', `${GATEWAY}/auth/logout`, { 'Content-Type': 'application/json' }, { refresh_token: refreshUntukLogout });
    const b07re = await req('POST', `${GATEWAY}/auth/refresh`, { 'Content-Type': 'application/json' }, { refresh_token: refreshUntukLogout });
    const b07db = db
      .prepare('SELECT revoked FROM refresh_tokens WHERE token_hash = ?')
      .get(crypto.createHash('sha256').update(refreshUntukLogout).digest('hex'));
    cek('T07',
      b07logout.status === 200 && b07re.status === 401 && b07re.body.error === 'refresh_revoked' && b07db?.revoked === 1,
      { logout: b07logout.status, refresh_setelah_logout: b07re.body, revoked_di_db: b07db?.revoked });

    const b08a = await req('POST', `${GATEWAY}/auth/service`, { 'Content-Type': 'application/json' }, { client_id: 'service-nilai', client_secret: 'SALAH' });
    const b08b = await req('POST', `${GATEWAY}/auth/service`, { 'Content-Type': 'application/json' }, { client_id: 'service-nilai', client_secret: config.serviceClientSecret });
    cek('T08', b08a.status === 401 && b08b.status === 200 && !!b08b.body.access_token, { salah: b08a.status, benar: b08b.status });
    const tokSvc = b08b.body.access_token;

    const pAkses = jwt.decode(tokDosen1);
    const pSvc = jwt.decode(tokSvc);
    cek('T09',
      !!pAkses && pAkses.exp - pAkses.iat === ttlKeDetik(config.accessTokenTTL) && 'sub' in pAkses && 'role' in pAkses
      && !!pSvc && pSvc.exp - pSvc.iat === ttlKeDetik(config.serviceTokenTTL) && pSvc.role === 'service',
      {
        user: pAkses ? { sub: pAkses.sub, role: pAkses.role, ttl: pAkses.exp - pAkses.iat } : null,
        service_token: pSvc ? { sub: pSvc.sub, role: pSvc.role, ttl: pSvc.exp - pSvc.iat } : null,
      });

    // ========================================================================
    // T10-T24: policy + device + token di gateway
    // ========================================================================
    const tokMhs1 = (await login('mhs1', 'Mhs#123', 'DEV-MHS1-01')).body.access_token;
    const tokDosen2 = (await login('dosen2', 'Dosen#123', 'DEV-DOSEN2-01')).body.access_token;
    const tokAdmin = (await login('admin', 'Admin#123', 'DEV-ADMIN-01')).body.access_token;
    const tokRusak = jwt.sign({ sub: '2', role: 'dosen' }, 'secret-lain-percuma', { expiresIn: '10m' });
    const tokKedaluwarsa = jwt.sign({ sub: '2', role: 'dosen' }, config.jwtSecret, { expiresIn: -10 });

    setJam('00:00', '23:59'); // buka jam untuk T10-T23

    const b10 = await req('GET', `${GATEWAY}/nilai`);
    cek('T10', b10.status === 401 && b10.body.error === 'token_missing', b10);
    const b11 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokKedaluwarsa, 'DEV-DOSEN1-01'));
    cek('T11', b11.status === 401 && b11.body.error === 'token_expired', b11);
    const b12 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokRusak, 'DEV-DOSEN1-01'));
    cek('T12', b12.status === 401 && b12.body.error === 'token_invalid', b12);
    const b13 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokDosen1, 'DEV-XXX'));
    cek('T13', b13.status === 403 && b13.body.error === 'device_not_registered', b13);
    const b14 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokDosen1, null));
    cek('T14', b14.status === 403 && b14.body.error === 'device_header_missing', b14);

    const b15 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokMhs1, 'DEV-MHS1-01'));
    cek('T15', b15.status === 200 && Array.isArray(b15.body) && b15.body.length === 2 && b15.body.every((x) => x.nim === '2210001'),
      { jumlah: b15.body?.length, nim: [...new Set((b15.body ?? []).map((x) => x.nim))] });
    const b16 = await req('GET', `${GATEWAY}/nilai?nim=2210002`, headBearer(tokMhs1, 'DEV-MHS1-01'));
    cek('T16', b16.status === 403 && b16.body.error === 'not_own_data', b16);
    const b17 = await req('GET', `${GATEWAY}/nilai?kelas_id=1`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    cek('T17', b17.status === 200 && Array.isArray(b17.body) && b17.body.length === 3, { jumlah: b17.body?.length });
    const b18 = await req('GET', `${GATEWAY}/nilai?kelas_id=2`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    cek('T18', b18.status === 403 && b18.body.error === 'class_not_owned', b18);
    const b19 = await req('GET', `${GATEWAY}/nilai`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    cek('T19', b19.status === 400 && b19.body.error === 'kelas_id_required', b19);
    const b20 = await req('GET', `${GATEWAY}/nilai?kelas_id=1`, headBearer(tokAdmin, 'DEV-ADMIN-01'));
    cek('T20', b20.status === 403 && b20.body.error === 'role_not_permitted', b20);

    const b21 = await req('PUT', `${GATEWAY}/nilai/1`, { ...headBearer(tokDosen1b, 'DEV-DOSEN1-01'), 'Content-Type': 'application/json' }, { nilai_angka: 88 });
    cek('T21', b21.status === 200 && b21.body?.nilai?.nilai_angka === 88, b21);
    const b22 = await req('PUT', `${GATEWAY}/nilai/4`, { ...headBearer(tokDosen1b, 'DEV-DOSEN1-01'), 'Content-Type': 'application/json' }, { nilai_angka: 88 });
    cek('T22', b22.status === 403 && b22.body.error === 'class_not_owned', b22);
    const b23 = await req('PUT', `${GATEWAY}/nilai/1`, { ...headBearer(tokMhs1, 'DEV-MHS1-01'), 'Content-Type': 'application/json' }, { nilai_angka: 88 });
    cek('T23', b23.status === 403 && b23.body.error === 'role_not_permitted', b23);

    const [jamTutup1Awal, jamTutup1Akhir] = jendelaTutup();
    setJam(jamTutup1Awal, jamTutup1Akhir);
    const b24 = await req('PUT', `${GATEWAY}/nilai/1`, { ...headBearer(tokDosen1b, 'DEV-DOSEN1-01'), 'Content-Type': 'application/json' }, { nilai_angka: 99 });
    cek('T24', b24.status === 403 && b24.body.error === 'outside_access_hours',
      { jam_tutup: `${jamTutup1Awal}-${jamTutup1Akhir}`, hasil: b24.body ?? null });

    // ========================================================================
    // T25-T36: finalisasi end-to-end + sinkron
    // ========================================================================
    setJam('00:00', '23:59');
    const b25 = await req('POST', `${GATEWAY}/kelas/1/finalisasi`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    const statusKelas1 = db.prepare('SELECT status FROM nilai WHERE kelas_id = 1').all();
    const transKelas1 = db.prepare('SELECT nim, kode_mk FROM transkrip WHERE kelas_id = 1').all();
    cek('T25',
      b25.status === 200 && b25.body?.sinkron?.ok === true
      && statusKelas1.length === 3 && statusKelas1.every((x) => x.status === 'final')
      && transKelas1.length === 3 && transKelas1.every((x) => x.kode_mk === 'KP70065004'),
      { status_http: b25.status, sinkron: b25.body?.sinkron ?? null, status_nilai: statusKelas1.map((x) => x.status), transkrip: transKelas1.length });

    const b26 = await req('PUT', `${GATEWAY}/nilai/1`, { ...headBearer(tokDosen1b, 'DEV-DOSEN1-01'), 'Content-Type': 'application/json' }, { nilai_angka: 88 });
    cek('T26', b26.status === 403 && b26.body.error === 'grade_already_final', b26);

    const b27 = await req('POST', `${GATEWAY}/kelas/1/finalisasi`, headBearer(tokDosen2, 'DEV-DOSEN2-01'));
    cek('T27', b27.status === 403 && b27.body.error === 'class_not_owned', b27);
    const b28 = await req('POST', `${GATEWAY}/kelas/2/finalisasi`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    cek('T28', b28.status === 403 && b28.body.error === 'class_not_owned', b28);

    const [jamTutup2Awal, jamTutup2Akhir] = jendelaTutup();
    setJam(jamTutup2Awal, jamTutup2Akhir);
    const b29 = await req('POST', `${GATEWAY}/kelas/2/finalisasi`, headBearer(tokDosen2, 'DEV-DOSEN2-01'));
    cek('T29', b29.status === 403 && b29.body.error === 'outside_access_hours',
      { jam_tutup: `${jamTutup2Awal}-${jamTutup2Akhir}`, hasil: b29.body ?? null });

    setJam('00:00', '23:59');
    const b30 = await req('GET', `${GATEWAY}/transkrip/2210001`, headBearer(tokMhs1, 'DEV-MHS1-01'));
    cek('T30', b30.status === 200 && JSON.stringify(b30.body).includes('KP70065004'), b30);
    const b31 = await req('GET', `${GATEWAY}/transkrip/2210002`, headBearer(tokMhs1, 'DEV-MHS1-01'));
    cek('T31', b31.status === 403 && b31.body.error === 'not_own_data', b31);
    const b32a = await req('GET', `${GATEWAY}/transkrip/2210002`, headBearer(tokAdmin, 'DEV-ADMIN-01'));
    const b32b = await req('GET', `${GATEWAY}/transkrip/2210003`, headBearer(tokAdmin, 'DEV-ADMIN-01'));
    cek('T32', b32a.status === 200 && b32b.status === 200, { 2210002: b32a.status, 2210003: b32b.status });
    const b33 = await req('GET', `${GATEWAY}/transkrip/2210001`, headBearer(tokDosen1b, 'DEV-DOSEN1-01'));
    cek('T33', b33.status === 403 && b33.body.error === 'role_not_permitted', b33);

    // payload kosong cukup untuk uji TOKEN (policy memeriksa role sebelum isi body)
    const payloadUji = { kelas_id: 2, items: [] };
    const b34a = await req('POST', `${GATEWAY}/transkrip/sinkron`, { ...headBearer(tokDosen1b, 'DEV-DOSEN1-01'), 'Content-Type': 'application/json' }, payloadUji);
    const b34b = await req('POST', `${GATEWAY}/transkrip/sinkron`, { ...headBearer(tokAdmin, 'DEV-ADMIN-01'), 'Content-Type': 'application/json' }, payloadUji);
    const b34c = await req('POST', `${GATEWAY}/transkrip/sinkron`, { ...headBearer(tokMhs1, 'DEV-MHS1-01'), 'Content-Type': 'application/json' }, payloadUji);
    cek('T34',
      [b34a, b34b, b34c].every((r) => r.status === 403 && r.body.error === 'user_token_not_allowed'),
      { dosen1: b34a.body?.error, admin: b34b.body?.error, mhs1: b34c.body?.error });

    const b35 = await req('POST', `${GATEWAY}/transkrip/sinkron`, { ...headBearer(tokSvc, null), 'Content-Type': 'application/json' }, {
      kelas_id: 2,
      items: [{ nim: '2210001', kode_mk: 'IF30021', nama_mk: 'Basis Data', nilai_angka: 90, huruf: 'A' }],
    });
    cek('T35', b35.status === 200 && b35.body?.ok === true, b35);

    const b36 = await req('GET', `${GATEWAY}/nilai?kelas_id=1`, headBearer(tokSvc, null));
    cek('T36', b36.status === 403 && b36.body.error === 'role_not_permitted', b36);

    // ========================================================================
    // T40-T44: akses LANGSUNG ke service (harus ditolak tanpa gateway)
    // ========================================================================
    const secret = config.gatewaySecret;
    const t40 = await req('GET', `${SISTEM_NILAI}/nilai`);
    cek('T40', t40.status === 403 && t40.body.error === 'gateway_secret_invalid', t40);
    const t41 = await req('GET', `${SISTEM_NILAI}/nilai`, { 'X-Gateway-Secret': secret });
    cek('T41', t41.status === 401, t41);
    const t42 = await req('GET', `${SISTEM_NILAI}/nilai`, { 'X-Gateway-Secret': secret, Authorization: `Bearer ${tokKedaluwarsa}` });
    cek('T42', t42.status === 401, t42);
    const t43 = await req('POST', `${SISTEM_TRANSKRIP}/transkrip/sinkron`, { 'X-Gateway-Secret': secret, Authorization: `Bearer ${tokDosen1b}`, 'Content-Type': 'application/json' }, payloadUji);
    cek('T43', t43.status === 403, t43);
    const t44 = await req('GET', `${SISTEM_TRANSKRIP}/transkrip/2210001`);
    cek('T44', t44.status === 403 && t44.body.error === 'gateway_secret_invalid', t44);

    // ========================================================================
    // T50: audit log lengkap (setelah semua skenario)
    // ========================================================================
    const audit = db
      .prepare('SELECT waktu, subjek, method, endpoint, device, hasil, alasan, status FROM audit_log ORDER BY id')
      .all();
    const adaAllow = audit.some((r) => r.hasil === 'allow');
    const adaDeny = audit.some((r) => r.hasil === 'deny');
    const kolomLengkap = audit.every(
      (r) => r.waktu && r.subjek && r.method && r.endpoint && r.hasil && r.alasan && r.status !== null,
    );
    const bertambah = audit.length > jumlahAuditAwal;
    const denyAwal = audit.filter((r) =>
      ['token_missing', 'token_expired', 'token_invalid', 'device_not_registered', 'device_header_missing'].includes(r.alasan));
    cek('T50',
      adaAllow && adaDeny && kolomLengkap && bertambah && denyAwal.length >= 5,
      { total_baris: audit.length, awal: jumlahAuditAwal, ada_allow: adaAllow, ada_deny: adaDeny, kolom_lengkap: kolomLengkap, deny_tahap_awal: denyAwal.length });
  } finally {
    // Selalu kembalikan config jam seperti sebelum pengujian
    fs.writeFileSync(FILE_JAM, configJamAsal);
    console.log(`\n== RINGKASAN: ${pass} PASS, ${gagal} FAIL ==`);
    if (gagal > 0) process.exitCode = 1;
  }
})().catch((err) => {
  console.error('[test] gagal tak terduga:', err);
  process.exit(1);
});
