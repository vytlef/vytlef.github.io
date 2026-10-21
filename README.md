# CryptoPic

Sembunyikan pesan terenkripsi di dalam gambar PNG, tanpa server, tanpa akun.
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

- **Sembunyikan** — pilih PNG, tulis pesan, kata sandi, dan petunjuk opsional.
  Hasilnya PNG baru yang bisa diunduh. Kata sandi minimal 8 karakter. Kata sandi
  gambar **tidak peka huruf besar/kecil** ("Rahasia", "rahasia", dan "RAHASIA"
  sama), tetapi spasi dan urutan karakter tetap dihitung.
- **Buka** — unggah PNG hasil CryptoPic, masukkan kata sandi. Pesan hanya
  muncul jika tag autentikasi AES-GCM cocok. Setiap pesan yang berhasil dibuka
  otomatis dicatat sebagai memo lokal.
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
- Animasi "Gunakan Lagi" mengikuti pengaturan `prefers-reduced-motion` dan bisa
  ditutup dengan Esc.

## Pengujian

```bash
# Enkripsi, steganografi, sanitasi, batas KDF
node tools/crypto-roundtrip-test.mjs

# Go
go test ./...
go vet ./...

# E2E browser sungguhan (butuh playwright-core)
npm i playwright-core
node tools/browser-e2e-test.mjs
```

Variabel lingkungan E2E:

- `CRYPTOPIC_URL` — default `http://127.0.0.1:8080`
- `CRYPTOPIC_BROWSER` — path ke `chrome.exe`, `msedge.exe`, atau `brave.exe`
  (contoh Brave: `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`)
- `CRYPTOPIC_PROFILE` — folder profil sementara; wajib untuk Brave agar Shields
  dimatikan otomatis untuk origin uji
- `RUNS` — jumlah iterasi desktop dan mobile per mode (default 5)
