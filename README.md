# CryptoPic

Sembunyikan pesan terenkripsi di dalam gambar (PNG, JPEG, WebP, GIF, BMP, AVIF;
output selalu PNG), tanpa server, tanpa akun.
Seluruh proses berjalan di browser: enkripsi AES-GCM, kunci dari Argon2id, lalu
penyisipan payload ke bit piksel paling rendah (LSB) memakai matrix embedding.
Server Go hanya menyajikan berkas statis.

Hanya ada satu format gambar (V4). Gambar dari versi lama tidak lagi bisa
dibuka; minta pengirim membuat ulang gambarnya dengan versi terbaru.

## Menjalankan

```bash
go run .
# buka http://127.0.0.1:8080
```

## Alur

- **Sembunyikan** — pilih gambar (PNG/JPEG/WebP/GIF/BMP/AVIF), tulis pesan, kata
  sandi, dan petunjuk (wajib, terlihat publik). Semua format dan kedalaman bit
  dikonversi otomatis ke PNG 8-bit sebelum pesan disisipkan, jadi hasil unduhan
  selalu PNG. Kata sandi lemah tetap diizinkan agar Anda tidak terkunci, tetapi
  sangat tidak disarankan karena penyerang dapat menebaknya secara offline;
  indikator kekuatan hanya saran. Kata sandi gambar **tidak peka huruf
  besar/kecil** ("Rahasia", "rahasia", dan "RAHASIA" sama), tetapi spasi dan
  urutan karakter tetap dihitung. Lihat
  [Format gambar](#format-gambar--konversi).
- **Buka** — unggah PNG hasil CryptoPic, masukkan kata sandi. Pesan hanya
  muncul jika tag autentikasi AES-GCM cocok. Setiap pesan yang berhasil dibuka
  otomatis dicatat sebagai memo lokal. Hanya PNG 8-bit yang diterima; format
  lain dan PNG 16-bit ditolak dengan pesan jelas.
- **Memo** — memo disimpan di IndexedDB. PIN memo (minimal 8 karakter) membuat
  seluruh memo terenkripsi dengan Argon2id + AES-GCM. PIN memo tetap
  case-sensitive seperti sebelumnya. "Hapus semua" hanya menghapus memo, bukan
  PIN. Vault lama yang masih memakai PBKDF2 akan dimigrasikan otomatis ke
  Argon2id saat pertama kali dibuka dengan PIN yang benar.
- **Gunakan Lagi** — setelah pesan dibuka, tombol ini membersihkan gambar lama
  lalu membukanya di tab Sembunyikan untuk dipakai menyisipkan pesan baru.

## Keamanan "Gunakan Lagi"

Saat sebuah gambar dipakai ulang, payload lama **dihancurkan**, bukan sekadar
ditimpa sebagian:

1. Seluruh LSB kanal R, G, dan B ditimpa bit acak dari CSPRNG (alpha diratakan
   ke 255).
2. Gambar di-encode ulang ke PNG, lalu dibaca kembali.
3. Payload lama harus benar-benar tidak bisa diekstrak/di-parse. Jika masih
   terbaca, proses diulang (maksimal 3 kali) dan gagal dengan aman jika tidak
   berhasil.

Perubahan visual maksimal 1 per kanal, jadi gambar tetap terlihat sama.

**Catatan privasi:** pembersihan ini menghapus pesan, bukan identitas foto.
Gambar hasil pembersihan masih foto yang sama, sehingga orang yang membandingkan
foto asli dan foto baru bisa mengenalinya (atau mencocokkan metadata visual).
Jangan pakai ulang foto yang isinya sendiri sensitif atau mudah dikenali.
CryptoPic juga tidak menghapus metadata EXIF karena gambar selalu diproses
ulang menjadi kanvas, tetapi bukan berarti foto menjadi anonim.

## Format gambar & konversi

Kanvas browser bekerja pada 8-bit per kanal, sehingga pesan CryptoPic selalu
ditulis ke PNG 8-bit. Semua format masuk dinormalisasi lewat kanvas **sebelum**
payload disisipkan:

- **Didukung (mode Sembunyikan):** PNG (semua kedalaman bit, tipe warna, dan
  profil ICC), JPEG, WebP, GIF, BMP, AVIF.
- **Output:** selalu PNG 8-bit, apa pun format asalnya.
- **Buka:** hanya PNG 8-bit. PNG 16-bit dan format lain ditolak dengan pesan
  jelas, karena payload CryptoPic hanya pernah ditulis pada PNG 8-bit.
- **Penanda konversi** di pratinjau menampilkan asal gambar, mis.
  `JPEG → PNG 8-bit`, `WebP → PNG 8-bit`, `PNG 16-bit → 8-bit`,
  `4-bit → 8-bit`, atau `ICC → sRGB 8-bit`. PNG 8-bit sRGB biasa hanya
  menampilkan dimensi.
- **Transparansi** diratakan ke putih dan notice transparansi muncul, sama
  seperti sebelumnya.
- **Animasi** (GIF/WebP/APNG) dipakai sebagai satu frame saja (biasanya frame
  pertama), hasilnya PNG statis.
- **Batas ukuran:** maksimal 16.384 px per sisi dan 64 megapiksel. Gambar lebih
  besar ditolak agar decode/konversi tidak menghabiskan memori.
- **Ditolak:** SVG (vektor + potensi konten aktif), TIFF, HEIC, PDF, dan file
  yang tidak bisa didekode browser.

Konversi berjalan sepenuhnya di browser: tidak ada upload, dan payload baru
disisipkan setelah piksel dinormalisasi. Karena itu dukungan format tambahan
tidak mengubah model keamanan. Metadata/EXIF ikut hilang saat re-encode, tetapi
gambar tetap foto yang sama — bukan berarti anonim.

## Batas parameter KDF

Header gambar V4 membawa parameter Argon2id. Agar gambar jahat tidak memaksa
browser menghitung terlalu lama, parameter di luar batas berikut ditolak:
memori 8–256 MiB, iterasi 1–8, paralelisme 1–8, dan
`memori × iterasi ≤ 512 MiB·iter`. Vault memo memakai
Argon2id 64 MiB, 3 iterasi, paralelisme 1.

## Catatan browser

- Chrome, Edge, dan Brave (semuanya Chromium) didukung.
- **Brave:** Shields mengacak piksel canvas (anti-fingerprinting) sehingga
  steganografi LSB tidak bisa dipakai. CryptoPic mendeteksi ini dan menampilkan
  peringatan; klik ikon Brave Shields lalu pilih **Shields down** untuk situs
  ini, kemudian muat ulang halaman. Uji otomatis Brave memakai
  `CRYPTOPIC_PROFILE` yang menyiapkan profil dengan Shields dimatikan.
- Brave: matikan juga **"Forget me when I close this site"** untuk alamat
  CryptoPic, atau kecualikan situs ini dari pembersihan data saat keluar. Jika
  data situs dibersihkan, memo dan PIN memo ikut hilang (memang tidak ada
  salinan di server).
- Mode privat/incognito tetap bisa dipakai, tetapi penyimpanan bisa terhapus
  saat tab ditutup.
- Perhitungan Argon2id berjalan di Web Worker terpisah. Jika worker tidak
  merespons dalam 45 detik (mis. gagal memuat skrip secara sesaat atau
  kehabisan memori), CryptoPic memakai satu worker baru untuk mencoba sekali
  lagi. Bila tetap gagal, muncul pesan error yang jelas, bukan spinner tanpa
  akhir. Percobaan ulang aman karena Argon2id selalu menghasilkan kunci yang
  sama untuk input yang sama.
- Animasi "Gunakan Lagi" mengikuti pengaturan `prefers-reduced-motion` dan bisa
  ditutup dengan Esc.

## Pengujian

```bash
# Enkripsi, steganografi, sanitasi, batas KDF
node tools/crypto-roundtrip-test.mjs

# Node 26 + hash-wasm in-process menumpuk memori WASM setelah puluhan
# panggilan Argon2id (aplikasi browser tidak terkena karena tiap panggilan
# memakai worker baru). Bila suite terhenti dengan "Invalid typed array
# length", jalankan per rentang grup dalam proses terpisah:
CRYPTOPIC_TEST_RANGE=1-8 node tools/crypto-roundtrip-test.mjs
CRYPTOPIC_TEST_RANGE=9-18 node tools/crypto-roundtrip-test.mjs

# Go
go test ./...
go vet ./...

# E2E browser sungguhan (butuh playwright-core)
npm i playwright-core
node tools/browser-e2e-test.mjs

# Matriks banyak variasi gambar (ukuran, tipe warna, 8/16-bit, PNG/JPEG/WebP/
# GIF/BMP, tekstur) di fitur Sembunyikan: sembunyikan -> unduh -> buka ->
# bandingkan pesan. Setiap input harus menghasilkan PNG 8-bit yang bisa dibuka.
node tools/browser-image-matrix.mjs
```

Variabel lingkungan E2E:

- `CRYPTOPIC_URL` — default `http://127.0.0.1:8080`
- `CRYPTOPIC_BROWSER` — path ke `chrome.exe`, `msedge.exe`, atau `brave.exe`
  (contoh Brave: `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`)
- `CRYPTOPIC_PROFILE` — folder profil sementara; wajib untuk Brave agar Shields
  dimatikan otomatis untuk origin uji
- `RUNS` — jumlah iterasi desktop dan mobile per mode (default 5)
- `REPEATS` — jumlah pengulangan seluruh matriks gambar (default 2,
  hanya untuk `browser-image-matrix.mjs`)
- `ONLY` — filter nama kasus matriks berdasarkan substring (opsional)
