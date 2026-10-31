# Sistem Nilai — Zero Trust (Praktikum Keamanan Informasi)

Sistem Nilai dengan prinsip **zero trust** (*never trust, always verify*; *least privilege*; *assume breach*) di level aplikasi, mengikuti arsitektur NIST SP 800-207. Yang dinilai adalah **mekanisme kontrol akses**, bukan tampilan - tidak ada frontend; pengujian memakai curl/Thunder Client/skrip Node.

## Prasyarat

- **Windows 11**, **Node.js >= 22** (cek: `node -v`). Pada proyek ini teruji dengan Node v24.
- Tidak memakai Docker; database SQLite bawaan Node (`node:sqlite`).

## Cara menjalankan (Windows)

1. Salin env lalu isi secret acak sekali saja (di CMD maupun PowerShell):

   ```bat
   :: CMD
   copy .env.example .env
   ```
   ```powershell
   # PowerShell
   Copy-Item .env.example .env
   ```

   Ganti semua `GANTI_DENGAN_ACAK` dengan nilai acak:

   ```
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. Pasang dependensi dan siapkan database:

   ```bat
   npm install
   npm run seed
   ```

3. Jalankan **tiga proses sekaligus** (gateway :3000, service nilai :3001, service transkrip :3002):

   ```bat
   npm start
   ```

   Atau di terminal terpisah bila lebih rapi: `npm run start:gateway`, `start:nilai`, `start:transkrip`.

4. Uji otomatis (server harus menyala, `npm test` akan re-seed data dulu):

   ```bat
   npm test
   ```

## Akun & device seed

Password per role (khusus praktikum): admin `Admin#123`, dosen `Dosen#123`, mahasiswa `Mhs#123`.

| id | username | role      | nama            | NIM     | Device ID terdaftar |
|----|----------|-----------|-----------------|---------|---------------------|
| 1  | admin    | admin     | Administrator   | -       | `DEV-ADMIN-01`      |
| 2  | dosen1   | dosen     | Dosen Satu      | -       | `DEV-DOSEN1-01`     |
| 3  | dosen2   | dosen     | Dosen Dua       | -       | `DEV-DOSEN2-01`     |
| 4  | mhs1     | mahasiswa | Mahasiswa Satu  | 2210001 | `DEV-MHS1-01`       |
| 5  | mhs2     | mahasiswa | Mahasiswa Dua   | 2210002 | `DEV-MHS2-01`       |
| 6  | mhs3     | mahasiswa | Mahasiswa Tiga  | 2210003 | `DEV-MHS3-01`       |

Kelas: id 1 `KP70065004` Keamanan Informasi (dosen1), id 2 `IF30021` Basis Data (dosen2). Semua nilai awal `draft`.

## Arsitektur

```
Client (Thunder Client / curl)
   | Authorization: Bearer <access token> + X-Device-ID
   v
API GATEWAY (PEP) :3000   -- /auth/*, /nilai/*, /kelas/*, /transkrip/*
   |-- Policy Engine / Policy Administrator (modul policy.js + authRoutes.js)
   |        login, token, keputusan allow/deny, baca atribut dari DB
   |-- Audit Log (tabel audit_log)
   | jika allow + X-Gateway-Secret
   +--> Service Nilai :3001      (verifikasi secret + token)
   +--> Service Transkrip :3002  (verifikasi secret + token)
               \__ Database SQLite bersama (data/nilai.db, WAL) __/

Finalisasi: Service Nilai -> POST gateway:3000/auth/service  (ambil token service)
            Service Nilai -> POST gateway:3000/transkrip/sinkron (Bearer token service)
            Gateway: allow hanya role=service -> teruskan ke Service Transkrip
```

Semua service hanya `listen` di `127.0.0.1` (segmentasi) - satu-satunya pintu masuk dari luar adalah gateway (PEP, R10).

## Peta kode (R1-R10 -> file: fungsi, nomor baris)

| Kode | Kebutuhan | Letak implementasi (file: fungsi :: baris) |
|------|-----------|--------------------------------------------|
| R1 | Access token JWT 10 menit (`sub`, `role`), lewat `Authorization: Bearer` | `gateway/tokens.js` : `signAccessToken(user)` :: 21-26 (TTL dari env); kirim via header `/auth/login` di `gateway/authRoutes.js` :: 62-93 |
| R2 | Refresh token 1 hari disimpan di DB (hash SHA-256), logout mencabut | `gateway/authRoutes.js` : `/refresh` :: 95-117, `/logout` :: 119-133, `hashToken` :: 17-19; tabel `refresh_tokens` (`scripts/seed.js`) |
| R3 | Token service 5 menit dari `POST /auth/service` (client ID + secret) | `gateway/tokens.js` : `signServiceToken()` :: 29-34; `gateway/authRoutes.js` : `/service` :: 135-158 (perbandingan secret `timingSafeEqual`) |
| R4 | Gateway menyuntik `X-Gateway-Secret`; service menolak tanpa header ini | `gateway/proxy.js` : `proxyReq.proxy.setHeader(...)` :: 20; `shared/verify.js` : `cekGatewaySecret` :: 22-27 |
| R5 | Verifikasi ulang token di service (tanda tangan + exp; alg. terkunci HS256) | `shared/verify.js` : `verifikasiToken` :: 32-46; dipasang di kedua service, dan `gateway/tokens.js` : `verifikasiToken` :: 38-43 |
| R6 | Kebijakan akses (Tabel instruksi) memakai atribut dari DB | `gateway/policy.js` : `decide()` :: 37-130 (satu-satunya tempat keputusan) |
| R7 | Device terdaftar (`X-Device-ID`) | `gateway/server.js` : langkah 3 PEP :: 79-91; `gateway/authRoutes.js` : `deviceTerdaftar()` :: 22-24 |
| R8 | Jam akses 07.00-21.00, diatur lewat konfigurasi (tanpa restart) | `gateway/policy.js` : `dalamJamAkses()` :: 19-33 (baca ulang tiap keputusan), `bacaJamAkses()` :: 14-16; config `config/access-hours.json`; skrip `scripts/set-hours.js` |
| R9 | Audit log (waktu, subjek, endpoint, device, hasil, alasan) | `gateway/audit.js` : `logDecision()` :: 14-24; tabel `audit_log`; tampil via `scripts/show-audit.js` (`npm run audit`) |
| R10 | Gateway satu-satunya pintu (PEP); terpisah dari service | `gateway/server.js` : PEP middleware :: 31-111, proxy :: 113; kedua service bind `127.0.0.1` |

## Endpoint & contoh request

Semua panggilan user ke **gateway :3000** membawa `Authorization: Bearer <access_token>` dan `X-Device-ID: <device terdaftar>`.

### Auth

```bash
curl.exe -X POST http://localhost:3000/auth/login ^
  -H "Content-Type: application/json" -H "X-Device-ID: DEV-DOSEN1-01" ^
  -d "{\"username\":\"dosen1\",\"password\":\"Dosen#123\"}"
```

| Endpoint | Body | Sukses | Gagal |
|----------|------|--------|-------|
| `POST /auth/login` | `{username,password}` + header `X-Device-ID` | 200 `{access_token, refresh_token, token_type:"Bearer", expires_in}` | 401 `invalid_credentials`; 403 `device_header_missing`/`device_not_registered` |
| `POST /auth/refresh` | `{refresh_token}` | 200 `{access_token, expires_in}` | 401 `refresh_invalid` / `refresh_expired` / `refresh_revoked` |
| `POST /auth/logout` | `{refresh_token}` | 200 `{message}` (revoked=1 di DB) | 401 |
| `POST /auth/service` | `{client_id, client_secret}` | 200 `{access_token, expires_in:300}` (role `service`) | 401 `service_credentials_invalid` |

### Nilai / Kelas / Transkrip

| Endpoint | Role yang diizinkan | Contoh | Kegagalan utama |
|----------|---------------------|--------|-----------------|
| `GET /nilai` | mahasiswa / dosen | `?nim=2210001` (mhs) / `?kelas_id=1` (dosen) | `role_not_permitted`, `not_own_data`, `kelas_id_required` (400), `kelas_not_found` (404), `class_not_owned` |
| `PUT /nilai/:id` | dosen pengampu | body `{"nilai_angka":88}` | `grade_not_found` (404), `class_not_owned`, `grade_already_final`, `outside_access_hours` |
| `POST /kelas/:id/finalisasi` | dosen pengampu | - | `class_not_owned`, `kelas_not_found` (404), `outside_access_hours` |
| `GET /transkrip/:nim` | mahasiswa (sendiri) / admin | `/transkrip/2210001` | `not_own_data`, `role_not_permitted` |
| `POST /transkrip/sinkron` | **hanya token service** | dibangun Service Nilai saat finalisasi | `user_token_not_allowed` |

Retry finalisasi bila sinkron gagal: service mengembalikan status nilai ke `draft` dan merespons **502**.

## Cara demo

- **Jam akses (R8)**: `npm run set-hours -- 00:00 23:59` membuka semua jam; kembalikan dengan `npm run set-hours -- 07:00 21:00`. Dibaca ulang pada SETIAP keputusan - server tidak perlu di-restart.
- **Audit (R9)**: `npm run audit` menampilkan 30 baris audit_log terakhir (allow maupun deny, lengkap dengan alasannya).
- **Masa berlaku token**: perpendek di `.env`, mis. `ACCESS_TOKEN_TTL=15s`, lalu `npm start` ulang dan tunjukkan `token_expired` setelah 15 detik.
- **Akhir**: `npm run seed` mengembalikan data awal (aman saat server masih hidup).

## Panduan demo video (6-9 menit)

| Menit | Isi | Kode yang ditunjukkan |
|-------|-----|------------------------|
| 0:00-0:45 | Arsitektur, PEP/PE/PA, prinsip zero trust | `gateway/server.js` (R10) |
| 0:45-2:15 | Login, access token 10 menit, refresh, logout mencabut refresh, token service 5 menit | R1, R2, R3 |
| 2:15-3:45 | Gateway secret, akses langsung :3001 ditolak, token valid tetap wajib | R4, R5 |
| 3:45-5:45 | Tabel kebijakan: mahasiswa vs dosen vs admin, kepemilikan dari DB, finalisasi & sinkron | R6 |
| 5:45-7:15 | Device tidak terdaftar, ubah jam akses via config | R7, R8 |
| 7:15-8:15 | Audit log (`npm run audit`) | R9 |
| 8:15-9:00 | Penutup: default deny, segmentasi, assume breach | - |

## Catatan teknis (Windows/Node)

- `node:sqlite` mencetak `ExperimentalWarning` - abaikan.
- 3 proses mengakses SQLite bersamaan: `PRAGMA journal_mode=WAL` + `busy_timeout=5000` (`shared/db.js`).
- URL internal memakai `127.0.0.1` (bukan `localhost`) agar tak jatuh ke IPv6.
- Port 3000-3002 bentrok? Pesan `EADDRINUSE` dijelaskan di konsol; ubah port di `.env`.
- `.env` dan `data/` tidak ikut repo (lihat `.gitignore`).
- Koleksi Thunder Client: variabel `baseUrl=http://localhost:3000`, `token`, `refresh`, `serviceToken`, `device`; semua request user membawa `Authorization: Bearer {{token}}` dan `X-Device-ID: {{device}}`.
