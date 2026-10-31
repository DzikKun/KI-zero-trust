'use strict';
// gateway/proxy.js
// [R4][R10] Meneruskan request yang sudah DIIZINKAN policy dari gateway ke service hilir,
// lalu menyuntik header X-Gateway-Secret (nilai kiriman klien otomatis ditimpa).
// Authorization tetap diteruskan sehingga service bisa memverifikasi ulang token (R5).

const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('../shared/config');

// Header hop-by-hop yang tidak perlu diteruskan (Authorization tetap dipertahankan)
const HOP_BY_HOP = ['connection', 'keep-alive', 'upgrade'];

function buatProxyKe(targetUrl) {
  return createProxyMiddleware({
    target: targetUrl,
    selfHandleResponse: false,
    on: {
      proxyReq: (proxyReq, req) => {
        // [R4] Service hanya menerima lalu lintas yang membawa secret ini dari gateway
        proxyReq.setHeader('X-Gateway-Secret', config.gatewaySecret);
        for (const h of HOP_BY_HOP) {
          if (proxyReq.getHeader(h)) proxyReq.removeHeader(h);
        }
      },
    },
  });
}

const proxyNilai = buatProxyKe(config.serviceNilaiUrl);
const proxyTranskrip = buatProxyKe(config.serviceTranskripUrl);

// Dispatch manual per prefix supaya path yang diteruskan TETAP LENGKAP
// (/nilai?kelas_id=1, /kelas/1/finalisasi, /transkrip/2210001, dst).
function teruskan(req, res, next) {
  const p = req.path;
  if (p.startsWith('/nilai') || p.startsWith('/kelas')) return proxyNilai(req, res, next);
  if (p.startsWith('/transkrip')) return proxyTranskrip(req, res, next);
  // Policy default deny tidak pernah melewatkan path lain; ini pengaman terakhir
  return next();
}

module.exports = { teruskan };
