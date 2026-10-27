/*
 * Uji matriks gambar untuk fitur Sembunyikan: banyak variasi PNG (ukuran, tipe
 * warna, kedalaman bit, tekstur) plus JPEG/WebP/BMP/GIF dijalankan nyata di
 * Chrome/Brave melalui Playwright. Setiap input harus dikonversi ke PNG 8-bit,
 * bisa dibuka kembali, dan memunculkan penanda konversi yang sesuai.
 *
 * Jalankan server lebih dulu (mis. PORT=8099 go run .), lalu:
 *   CRYPTOPIC_URL=http://127.0.0.1:8099 \
 *   CRYPTOPIC_BROWSER="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" \
 *   node tools/browser-image-matrix.mjs
 *
 * Variabel lingkungan:
 *   CRYPTOPIC_URL       default http://127.0.0.1:8080
 *   CRYPTOPIC_BROWSER   path chrome.exe / brave.exe
 *   CRYPTOPIC_PROFILE   folder profil khusus (Brave; Shields dimatikan)
 *   REPEATS             jumlah pengulangan seluruh matriks (default 2)
 *   ONLY                filter nama kasus (substring, opsional)
 */
import { chromium } from "playwright-core";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import zlib from "node:zlib";

const BASE_URL = process.env.CRYPTOPIC_URL || "http://127.0.0.1:8080";
const BROWSER_PATH =
  process.env.CRYPTOPIC_BROWSER ||
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PROFILE_DIR = process.env.CRYPTOPIC_PROFILE || "";
const REPEATS = Number(process.env.REPEATS || 2);
const ONLY = process.env.ONLY || "";
const PASSWORD = "Sandi Matriks 2026!";

/* ----------------------------- PNG builder ----------------------------- */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i++) c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBytes = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 0);
  return Buffer.concat([length, typeBytes, data, crc]);
}
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** Pembangkit nilai sampel per pola, dalam rentang 0..255. */
const PATTERNS = {
  noise: (x, y, rand) => (x * 3 + y * 2 + (rand() & 0x1f)) & 0xff,
  gradient: (x, y, rand, w, h) => Math.floor(((x / w) * 255 + (y / h) * 120) % 256),
  flat: () => 128,
  lines: (x, y) => ((x >> 2) % 2 === 0 ? 240 : 16),
  checker: (x, y) => (((x >> 3) + (y >> 3)) % 2 === 0 ? 250 : 5),
};

/**
 * Membuat PNG 8-bit atau 16-bit.
 * colorType: 0 grayscale, 2 RGB, 6 RGBA. alpha: hanya untuk RGBA.
 */
function makePng({ width, height, bitDepth, colorType, pattern, seed = 1, alpha = false, iccp = false }) {
  const channels = colorType === 0 ? 1 : colorType === 2 ? 3 : 4;
  const bytesPerSample = bitDepth === 16 ? 2 : 1;
  const stride = width * channels * bytesPerSample;
  const raw = Buffer.alloc((stride + 1) * height);
  let state = (seed * 2654435761) >>> 0;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  const gen = PATTERNS[pattern] || PATTERNS.noise;
  for (let y = 0; y < height; y++) {
    const row = y * (stride + 1);
    raw[row] = 0;
    for (let x = 0; x < width; x++) {
      const sample = gen(x, y, rand, width, height);
      for (let c = 0; c < channels; c++) {
        const o = row + 1 + (x * channels + c) * bytesPerSample;
        const value = c === 3 ? (alpha ? sample : 255) : sample;
        if (bitDepth === 16) raw.writeUInt16BE((value * 257) & 0xffff, o);
        else raw[o] = value & 0xff;
      }
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = bitDepth;
  ihdr[9] = colorType;
  const chunks = [pngChunk("IHDR", ihdr)];
  if (iccp) {
    // iCCP: nama (NUL) + metode kompresi 0 + data terkompresi.
    const profileName = Buffer.from("Test Profile\0", "latin1");
    const compressed = zlib.deflateSync(Buffer.alloc(64, 7));
    chunks.push(pngChunk("iCCP", Buffer.concat([profileName, Buffer.from([0]), compressed])));
  }
  chunks.push(pngChunk("IDAT", zlib.deflateSync(raw)));
  chunks.push(pngChunk("IEND", Buffer.alloc(0)));
  return Buffer.concat([PNG_SIGNATURE, ...chunks]);
}

/* ------------------------------- Cases -------------------------------- */

function buildCases(dir) {
  return [
    { name: "8bit rgb noise 800x600", file: "a.png", png: { width: 800, height: 600, bitDepth: 8, colorType: 2, pattern: "noise" }, expectOpen: true },
    { name: "8bit rgba noise 512x512", file: "b.png", png: { width: 512, height: 512, bitDepth: 8, colorType: 6, pattern: "noise" }, expectOpen: true },
    { name: "8bit rgba gradient 640x480 (banding)", file: "c.png", png: { width: 640, height: 480, bitDepth: 8, colorType: 6, pattern: "gradient" }, expectOpen: true },
    { name: "8bit gray flat 400x400", file: "d.png", png: { width: 400, height: 400, bitDepth: 8, colorType: 0, pattern: "flat" }, expectOpen: true },
    { name: "8bit rgb lines 900x300", file: "e.png", png: { width: 900, height: 300, bitDepth: 8, colorType: 2, pattern: "lines" }, expectOpen: true },
    { name: "8bit rgba checker 1000x1000", file: "f.png", png: { width: 1000, height: 1000, bitDepth: 8, colorType: 6, pattern: "checker" }, expectOpen: true },
    { name: "8bit rgba alpha (transparency) 300x300", file: "g.png", png: { width: 300, height: 300, bitDepth: 8, colorType: 6, pattern: "noise", alpha: true }, expectOpen: true, expectTransparency: true },
    { name: "8bit tiny 64x64 (near capacity)", file: "h.png", png: { width: 64, height: 64, bitDepth: 8, colorType: 6, pattern: "noise" }, expectOpen: true, tiny: true },
    { name: "16bit rgb noise 800x600", file: "i.png", png: { width: 800, height: 600, bitDepth: 16, colorType: 2, pattern: "noise" }, expectOpen: true, expectConvert: true },
    { name: "16bit rgba gradient 512x512", file: "j.png", png: { width: 512, height: 512, bitDepth: 16, colorType: 6, pattern: "gradient" }, expectOpen: true, expectConvert: true },
    { name: "16bit rgba dengan transparansi 320x240", file: "m.png", png: { width: 320, height: 240, bitDepth: 16, colorType: 6, pattern: "noise", alpha: true }, expectOpen: true, expectConvert: true, expectTransparency: true },
    { name: "8bit rgba with iCCP (auto-convert ke sRGB)", file: "k.png", png: { width: 300, height: 300, bitDepth: 8, colorType: 6, pattern: "noise", iccp: true }, expectOpen: true, expectMarker: /ICC\s*→\s*sRGB/ },
    { name: "4bit palette (auto-convert ke 8-bit)", file: "l.png", custom: "4bit", width: 400, height: 400, expectOpen: true, expectMarker: /4-bit\s*→\s*8-bit/ },
    { name: "JPEG 900x600 (auto-convert)", file: "n.jpg", width: 900, height: 600, expectOpen: true, expectMarker: /JPEG\s*→\s*PNG 8-bit/ },
    { name: "WebP 640x480 (auto-convert)", file: "o.webp", width: 640, height: 480, expectOpen: true, expectMarker: /WebP\s*→\s*PNG 8-bit/ },
    { name: "BMP 400x300 (auto-convert)", file: "p.bmp", custom: "bmp", width: 400, height: 300, expectOpen: true, expectMarker: /BMP\s*→\s*PNG 8-bit/ },
    { name: "GIF 320x240 (auto-convert)", file: "q.gif", custom: "gif", width: 320, height: 240, expectOpen: true, expectMarker: /GIF\s*→\s*PNG 8-bit/ },
    { name: "PNG 20000x100 (ditolak: batas sisi)", file: "s.png", png: { width: 20000, height: 100, bitDepth: 8, colorType: 6, pattern: "lines" }, expectReject: true, rejectPattern: /terlalu besar/i },
    { name: "SVG (ditolak)", file: "t.svg", custom: "svg", expectReject: true, rejectPattern: /didukung/i },
    { name: "TIFF (ditolak)", file: "u.tiff", custom: "tiff", expectReject: true, rejectPattern: /didukung/i },
    { name: "HEIC (ditolak)", file: "v.heic", custom: "heic", expectReject: true, rejectPattern: /didukung/i },
    { name: "file rusak (must be rejected)", file: "r.jpg", custom: "corrupt", expectReject: true, rejectPattern: /rusak|didukung/i },
  ].map((c) => ({ ...c, path: join(dir, c.file) }));
}

function buildFourBitPng(width = 400, height = 400) {
  // 4-bit palette: bit depth 4, color type 3 (PLTE wajib), 16 warna grayscale.
  const rowBytes = Math.ceil((width * 4) / 8);
  const raw = Buffer.alloc((rowBytes + 1) * height);
  let state = 987654321;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let y = 0; y < height; y++) {
    const row = y * (rowBytes + 1);
    for (let x = 0; x < width; x++) {
      const index = rand() & 0x0f;
      const pos = row + 1 + (x >> 1);
      if (x % 2 === 0) raw[pos] = (raw[pos] & 0x0f) | (index << 4);
      else raw[pos] = (raw[pos] & 0xf0) | index;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 4;
  ihdr[9] = 3;
  const plte = Buffer.alloc(16 * 3);
  for (let i = 0; i < 16; i++) {
    plte[i * 3] = i * 17;
    plte[i * 3 + 1] = i * 17;
    plte[i * 3 + 2] = i * 17;
  }
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", ihdr),
    pngChunk("PLTE", plte),
    pngChunk("IDAT", zlib.deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

/** BMP 24-bit (bottom-up) dari pola noise yang sama dengan PNG. */
function makeBmp({ width, height, seed = 1 }) {
  const rowSize = (width * 3 + 3) & ~3;
  const pixelSize = rowSize * height;
  const header = Buffer.alloc(54);
  header.write("BM", 0, "ascii");
  header.writeUInt32LE(54 + pixelSize, 2);
  header.writeUInt32LE(54, 10);
  header.writeUInt32LE(40, 14);
  header.writeInt32LE(width, 18);
  header.writeInt32LE(height, 22);
  header.writeUInt16LE(1, 26);
  header.writeUInt16LE(24, 28);
  header.writeUInt32LE(pixelSize, 34);
  header.writeInt32LE(2835, 38);
  header.writeInt32LE(2835, 42);
  const pixels = Buffer.alloc(pixelSize);
  let state = (seed * 2654435761) >>> 0;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let y = 0; y < height; y++) {
    const row = (height - 1 - y) * rowSize;
    for (let x = 0; x < width; x++) {
      const noise = rand() & 0x1f;
      const r = (x * 3 + y * 2 + noise) & 0xff;
      const g = (y * 5 + (x >> 1) + noise) & 0xff;
      const b = ((x ^ y) * 7 + noise) & 0xff;
      const o = row + x * 3;
      pixels[o] = b;
      pixels[o + 1] = g;
      pixels[o + 2] = r;
    }
  }
  return Buffer.concat([header, pixels]);
}

/** LZW encoder GIF (code size 8, LSB-first) untuk satu frame grayscale. */
function gifLzw(indices) {
  const clear = 256;
  const end = 257;
  const minCodeSize = 8;
  let codeSize = minCodeSize + 1;
  let next = end + 1;
  const dict = new Map();
  const bytes = [];
  let bitBuffer = 0;
  let bitCount = 0;
  const emit = (code) => {
    bitBuffer |= code << bitCount;
    bitCount += codeSize;
    while (bitCount >= 8) {
      bytes.push(bitBuffer & 0xff);
      bitBuffer >>>= 8;
      bitCount -= 8;
    }
  };
  emit(clear);
  let prefix = indices[0];
  for (let i = 1; i < indices.length; i++) {
    const k = indices[i];
    const key = prefix * 256 + k;
    const found = dict.get(key);
    if (found !== undefined) {
      prefix = found;
      continue;
    }
    emit(prefix);
    if (next < 4096) {
      dict.set(key, next);
      next++;
      if (next === 1 << codeSize && codeSize < 12) codeSize++;
    } else {
      emit(clear);
      dict.clear();
      next = end + 1;
      codeSize = minCodeSize + 1;
    }
    prefix = k;
  }
  emit(prefix);
  emit(end);
  if (bitCount > 0) bytes.push(bitBuffer & 0xff);
  return Buffer.from(bytes);
}

/** GIF89a statis dengan palette grayscale 256 warna. */
function makeGif({ width, height, seed = 1 }) {
  const palette = Buffer.alloc(256 * 3);
  for (let i = 0; i < 256; i++) {
    palette[i * 3] = i;
    palette[i * 3 + 1] = i;
    palette[i * 3 + 2] = i;
  }
  const indices = new Uint8Array(width * height);
  let state = (seed * 2654435761) >>> 0;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      indices[y * width + x] = (x * 3 + y * 2 + (rand() & 0x1f)) & 0xff;
    }
  }
  const lzw = gifLzw(indices);
  const header = Buffer.alloc(13);
  header.write("GIF89a", 0, "ascii");
  header.writeUInt16LE(width, 6);
  header.writeUInt16LE(height, 8);
  header[10] = 0xf7; // global color table, 256 warna
  header[11] = 0;
  header[12] = 0;
  const descriptor = Buffer.alloc(10);
  descriptor[0] = 0x2c;
  descriptor.writeUInt16LE(0, 1);
  descriptor.writeUInt16LE(0, 3);
  descriptor.writeUInt16LE(width, 5);
  descriptor.writeUInt16LE(height, 7);
  const blocks = [Buffer.from([8])];
  for (let i = 0; i < lzw.length; i += 255) {
    const chunk = lzw.subarray(i, i + 255);
    blocks.push(Buffer.from([chunk.length]), chunk);
  }
  blocks.push(Buffer.from([0]));
  return Buffer.concat([header, palette, descriptor, ...blocks, Buffer.from([0x3b])]);
}

/**
 * JPEG & WebP dibuat lewat kanvas Chromium (tidak ada encoder di Node), lalu
 * disimpan sebagai fixture. Dipakai untuk menguji konversi format asing.
 */
async function generateEncodedFixtures(workDir) {
  const browser = await chromium.launch({ executablePath: BROWSER_PATH, headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(BASE_URL, { waitUntil: "domcontentloaded" });
    const encode = async (mime, quality, width, height, seed) => {
      const base64 = await page.evaluate(
        ({ mime, quality, width, height, seed }) => {
          const canvas = document.createElement("canvas");
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext("2d");
          const image = ctx.createImageData(width, height);
          let state = (seed * 2654435761) >>> 0;
          const rand = () => {
            state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
            return state;
          };
          for (let y = 0; y < height; y++) {
            for (let x = 0; x < width; x++) {
              const o = (y * width + x) * 4;
              const noise = rand() & 0x1f;
              image.data[o] = (x * 3 + y * 2 + noise) & 0xff;
              image.data[o + 1] = (y * 5 + (x >> 1) + noise) & 0xff;
              image.data[o + 2] = ((x ^ y) * 7 + noise) & 0xff;
              image.data[o + 3] = 255;
            }
          }
          ctx.putImageData(image, 0, 0);
          return canvas.toDataURL(mime, quality).split(",")[1];
        },
        { mime, quality, width, height, seed }
      );
      if (!base64) throw new Error(`Encoder ${mime} tidak tersedia di browser ini.`);
      return Buffer.from(base64, "base64");
    };
    await writeFile(join(workDir, "n.jpg"), await encode("image/jpeg", 0.92, 900, 600, 21));
    await writeFile(join(workDir, "o.webp"), await encode("image/webp", 0.95, 640, 480, 22));
  } finally {
    await browser.close();
  }
}

/* ------------------------------ Harness ------------------------------- */

let passed = 0;
const failures = [];
const results = [];

function record(ok, label, detail) {
  if (ok) {
    passed++;
    results.push({ label, ok: true, detail: "" });
  } else {
    failures.push({ label, detail });
    results.push({ label, ok: false, detail });
  }
  console.log(`${ok ? "PASS" : "FAIL"}: ${label}${ok ? "" : ` — ${detail}`}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function prepareShieldsProfile(dir) {
  const key = `${new URL(BASE_URL).origin},*`;
  const now = String(Date.now() * 1000);
  const prefs = {
    profile: {
      content_settings: {
        exceptions: {
          braveShields: { [key]: { setting: 1, last_modified: now } },
          brave_webcompat_canvas: { [key]: { setting: 1, last_modified: now } },
        },
      },
    },
  };
  await mkdir(join(dir, "Default"), { recursive: true });
  await writeFile(join(dir, "Default", "Preferences"), JSON.stringify(prefs));
}

/** Reset state hide agar hasil kasus sebelumnya tidak membuat deteksi palsu. */
async function resetHide(page) {
  await page.evaluate(() => {
    document.querySelectorAll("#toast-container .toast").forEach((toast) => toast.remove());
    const status = document.querySelector("#hide-status");
    if (status) {
      status.hidden = true;
      status.textContent = "";
      status.classList.remove("error");
    }
  });
  const replace = page.locator("#hide-replace");
  if (await replace.isVisible()) await replace.click();
}

/** Reset state open agar panel hasil/error lama tidak terbaca sebagai hasil baru. */
async function resetOpen(page) {
  await page.evaluate(() => {
    document.querySelectorAll("#toast-container .toast").forEach((toast) => toast.remove());
    const error = document.querySelector("#open-error");
    if (error) {
      error.hidden = true;
      error.textContent = "";
    }
  });
  const replace = page.locator("#open-replace");
  if (await replace.isVisible()) await replace.click();
}

async function hideOn(page, coverPath, message, hint) {
  await page.click("#tab-hide");
  await resetHide(page);
  await page.setInputFiles("#hide-file", coverPath);
  await page.waitForFunction(
    () => {
      const wrap = document.querySelector("#hide-preview-wrap");
      const err = document.querySelector("#hide-status");
      const toast = document.querySelector("#toast-container .toast.error");
      return (wrap && !wrap.hidden) || (err && !err.hidden) || !!toast;
    },
    null,
    { timeout: 30000 }
  );
  const rejected = await page.evaluate(() => {
    const status = document.querySelector("#hide-status");
    const wrap = document.querySelector("#hide-preview-wrap");
    const toast = document.querySelector("#toast-container .toast.error");
    return {
      previewShown: !!wrap && !wrap.hidden,
      error:
        (status && !status.hidden ? status.textContent : "") ||
        (toast ? toast.textContent : ""),
      dims: document.querySelector("#hide-file-dims").textContent || "",
    };
  });
  if (!rejected.previewShown) return { rejected: true, error: rejected.error };

  await page.fill("#secret-text", message);
  await page.fill("#hide-hint", hint);
  await page.fill("#hide-password", PASSWORD);
  await page.waitForFunction(() => !document.querySelector("#btn-encrypt").disabled, null, {
    timeout: 15000,
  });
  await page.click("#btn-encrypt");
  await page.waitForFunction(
    () => {
      const result = document.querySelector("#hide-result");
      const status = document.querySelector("#hide-status");
      return !result.hidden || (!status.hidden && status.classList.contains("error"));
    },
    null,
    { timeout: 120000 }
  );
  const failure = await page.evaluate(() => {
    const status = document.querySelector("#hide-status");
    return status.hidden ? "" : status.textContent || "";
  });
  return { rejected: false, error: failure, dims: rejected.dims };
}

async function openOn(page, stegoPath, password) {
  await page.click("#tab-open");
  await resetOpen(page);
  await page.setInputFiles("#open-file", stegoPath);
  await page.waitForFunction(
    () => {
      const status = document.querySelector("#open-status");
      const err = document.querySelector("#open-error");
      const field = document.querySelector("#open-password-field");
      return (status && status.hidden) || (err && !err.hidden) || (field && !field.hidden);
    },
    null,
    { timeout: 60000 }
  );
  const ready = await page.evaluate(() => {
    const field = document.querySelector("#open-password-field");
    const err = document.querySelector("#open-error");
    return {
      canDecrypt: !!field && !field.hidden,
      error: err && !err.hidden ? err.textContent || "" : "",
    };
  });
  if (!ready.canDecrypt) return { opened: false, error: ready.error };
  await page.fill("#open-password", password);
  await page.waitForFunction(() => !document.querySelector("#btn-decrypt").disabled, null, {
    timeout: 10000,
  });
  await page.click("#btn-decrypt");
  await page.waitForFunction(
    () => {
      const result = document.querySelector("#open-result");
      const err = document.querySelector("#open-error");
      return !result.hidden || !err.hidden;
    },
    null,
    { timeout: 120000 }
  );
  const state = await page.evaluate(() => {
    const result = document.querySelector("#open-result");
    const err = document.querySelector("#open-error");
    return {
      done: !!result && !result.hidden,
      error: err && !err.hidden ? err.textContent || "" : "",
    };
  });
  if (!state.done) return { opened: false, error: state.error };
  return { opened: true, message: await page.textContent("#open-message") };
}

async function runMatrix(browser, cases, workDir, repeat) {
  const context = browser.isPersistent
    ? browser
    : await browser.newContext({
        viewport: { width: 1440, height: 900 },
        acceptDownloads: true,
      });
  const page = await context.newPage();
  const pageErrors = [];
  const kdfRetries = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "warning" && /mencoba ulang/i.test(message.text())) {
      kdfRetries.push(message.text());
    }
  });
  page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
  await page.goto(BASE_URL, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#tab-hide", { timeout: 30000 });
  // Pastikan modul app.js selesai dijalankan (init() memasang semua listener).
  await page.waitForFunction(() => document.readyState === "complete", null, { timeout: 30000 });

  for (const testCase of cases) {
    const label = `[run ${repeat}] ${testCase.name}`;
    try {
      const message = `Matriks ${testCase.name} #${repeat} — ${Date.now()}`;
      const hideResult = await hideOn(page, testCase.path, message, `hint ${testCase.name}`);

      if (testCase.expectReject) {
        assert(hideResult.rejected, `harus ditolak tetapi diterima`);
        assert(
          (testCase.rejectPattern || /didukung|terlalu besar|16-bit|kedalaman|profil warna|8-bit/i).test(
            hideResult.error
          ),
          `pesan tolak tidak informatif: ${hideResult.error}`
        );
        record(true, label, "");
        continue;
      }

      assert(!hideResult.rejected, `ditolak tak terduga: ${hideResult.error}`);
      assert(!hideResult.error, `enkripsi gagal: ${hideResult.error}`);

      // Pastikan pratinjau benar-benar memuat gambar kasus ini (bukan sisa kasus
      // sebelumnya), lalu bahwa hasil unduhan memuat pesan yang tepat.
      const expectedDims = testCase.png
        ? `${testCase.png.width}×${testCase.png.height}px`
        : testCase.width
          ? `${testCase.width}×${testCase.height}px`
          : "";
      if (expectedDims) {
        assert(
          hideResult.dims.startsWith(expectedDims),
          `pratinjau salah gambar: dapat ${hideResult.dims}, harus diawali ${expectedDims}`
        );
      }

      if (testCase.expectConvert) {
        assert(
          /16-bit\s*→\s*8-bit/.test(hideResult.dims),
          `penanda konversi 16-bit tidak muncul: ${hideResult.dims}`
        );
      }

      if (testCase.expectMarker) {
        assert(
          testCase.expectMarker.test(hideResult.dims),
          `penanda konversi tidak muncul: ${hideResult.dims}`
        );
      }

      if (testCase.expectTransparency) {
        const noticeShown = await page.evaluate(
          () => !document.querySelector("#transparency-notice").hidden
        );
        assert(noticeShown, "notice transparansi tidak muncul");
      }

      await page.waitForSelector("#btn-download:not([hidden])", { timeout: 15000 });
      // Hasil selalu PNG: jangan pertahankan ekstensi sumber (.jpg/.gif) agar
      // mode Buka tidak menolak berdasarkan MIME/ekstensi.
      const stem = testCase.file.replace(/\.[^.]+$/, "");
      const stegoPath = join(workDir, `stego-${repeat}-${stem}.png`);
      const [download] = await Promise.all([
        page.waitForEvent("download", { timeout: 30000 }),
        page.click("#btn-download"),
      ]);
      await download.saveAs(stegoPath);

      const opened = await openOn(page, stegoPath, PASSWORD);
      assert(opened.opened, `buka gagal: ${opened.error}`);
      assert(opened.message === message, `pesan tidak cocok: ${opened.message}`);
      record(true, label, "");
    } catch (error) {
      record(false, label, error && error.message ? error.message : String(error));
    }
  }

  if (pageErrors.length > 0) record(false, `[run ${repeat}] tanpa error halaman`, pageErrors.join(" | "));
  if (kdfRetries.length > 0) {
    console.log(`NOTE: [run ${repeat}] watchdog Argon2id mencoba ulang ${kdfRetries.length}×`);
  }
  if (browser.isPersistent) {
    await browser.close();
  } else {
    await context.close();
    await browser.close();
  }
}

async function main() {
  const workDir = await mkdtemp(join(tmpdir(), "cryptopic-matrix-"));
  let cases = buildCases(workDir);
  if (ONLY) cases = cases.filter((c) => c.name.includes(ONLY));
  const needsEncoded = cases.some((c) => c.file.endsWith(".jpg") || c.file.endsWith(".webp"));
  if (needsEncoded) await generateEncodedFixtures(workDir);
  for (const testCase of cases) {
    if (testCase.custom === "4bit") await writeFile(testCase.path, buildFourBitPng(testCase.width, testCase.height));
    else if (testCase.custom === "bmp") await writeFile(testCase.path, makeBmp({ width: testCase.width, height: testCase.height, seed: 5 }));
    else if (testCase.custom === "gif") await writeFile(testCase.path, makeGif({ width: testCase.width, height: testCase.height, seed: 5 }));
    else if (testCase.custom === "corrupt") await writeFile(testCase.path, Buffer.from("ini bukan file gambar"));
    else if (testCase.custom === "svg")
      await writeFile(
        testCase.path,
        '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#000"/></svg>'
      );
    else if (testCase.custom === "tiff")
      await writeFile(testCase.path, Buffer.from([0x49, 0x49, 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00]));
    else if (testCase.custom === "heic")
      await writeFile(testCase.path, Buffer.from("ftypheic-heic-bukan-gambar-valid"));
    else if (testCase.png) await writeFile(testCase.path, makePng({ seed: 5, ...testCase.png }));
  }

  // Tiap pengulangan memakai proses browser baru: meniru sesi pengguna yang
  // benar-benar terpisah dan membebaskan memori WASM/worker antar putaran.
  // Tanpa ini, belasan panggilan Argon2id 64 MiB berturut-turut dalam satu
  // proses Chromium bisa membuat satu worker macet tanpa error (timeout).
  for (let repeat = 1; repeat <= REPEATS; repeat++) {
    let browser = null;
    if (PROFILE_DIR) {
      const profile = join(PROFILE_DIR, `run-${repeat}`);
      await prepareShieldsProfile(profile);
      browser = await chromium.launchPersistentContext(profile, {
        executablePath: BROWSER_PATH,
        headless: true,
        acceptDownloads: true,
      });
      browser.isPersistent = true;
    } else {
      browser = await chromium.launch({ executablePath: BROWSER_PATH, headless: true });
    }
    await runMatrix(browser, cases, workDir, repeat);
  }

  console.log(`\n${passed} lulus, ${failures.length} gagal.`);
  if (failures.length > 0) {
    for (const failure of failures) console.error(`\n[${failure.label}]\n${failure.detail}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
