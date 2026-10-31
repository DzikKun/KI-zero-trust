'use strict';
// scripts/set-hours.js
// Bantu demo R8: menulis ulang config/access-hours.json tanpa restart server.
//   npm run set-hours -- 07:00 21:00
//   npm run set-hours -- 00:00 23:59
// Zona waktu opsional sebagai argumen ke-3 (default Asia/Jakarta).

const fs = require('node:fs');
const path = require('node:path');

const FILE = path.join(__dirname, '..', 'config', 'access-hours.json');
const FORMAT_JAM = /^\d{2}:\d{2}$/;

const [, , start, end, timezone] = process.argv;

if (!start || !end || !FORMAT_JAM.test(start) || !FORMAT_JAM.test(end)) {
  console.error('Pemakaian: npm run set-hours -- HH:MM HH:MM [zona_waktu]');
  console.error('Contoh:    npm run set-hours -- 00:00 23:59');
  process.exit(1);
}

fs.writeFileSync(
  FILE,
  JSON.stringify({ start, end, timezone: timezone || 'Asia/Jakarta' }, null, 2) + '\n',
);
console.log(`[set-hours] Jam akses disimpan: ${start} - ${end} (zona ${timezone || 'Asia/Jakarta'})`);
console.log('[set-hours] Dibaca ulang pada setiap keputusan - tidak perlu restart server.');
