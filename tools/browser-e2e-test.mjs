/*
 * Uji end-to-end di browser sungguhan (Chrome/Edge/Brave via Playwright) untuk
 * alur sembunyikan -> unduh -> buka -> dekripsi, "Gunakan Lagi", dan vault Memo.
 *
 * Jalankan server lebih dulu, mis.:
 *   go run .            (PORT default 8080)
 *
 * Lalu:
 *   npm i playwright-core
 *   node tools/browser-e2e-test.mjs
 *
 * Variabel lingkungan:
 *   CRYPTOPIC_URL       default http://127.0.0.1:8080
 *   CRYPTOPIC_BROWSER   path ke chrome.exe / msedge.exe / brave.exe
 *                       contoh Brave:
 *                       "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
 *   CRYPTOPIC_PROFILE   folder profil khusus (mis. untuk Brave). Jika diisi, uji
 *                       memakai persistent context dan menyiapkan profil dengan
 *                       Shields dimatikan untuk origin uji (farbling Brave
 *                       merusak LSB steganografi). Gunakan folder sementara.
 *   RUNS                jumlah iterasi per mode (default 5)
 */
import { chromium } from "playwright-core";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import zlib from "node:zlib";

const BASE_URL = process.env.CRYPTOPIC_URL || "http://127.0.0.1:8080";
const BROWSER_PATH =
  process.env.CRYPTOPIC_BROWSER ||
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const RUNS = Number(process.env.RUNS || 5);
const PROFILE_DIR = process.env.CRYPTOPIC_PROFILE || "";
let sharedContext = null;
const PASSWORD = "Sandi Uji Kuat 2026!";

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

/** Membuat PNG RGBA 8-bit bertekstur (tanpa profil warna) untuk uji. */
function makeCoverPng(width, height, seed = 1) {
  const raw = Buffer.alloc((width * 4 + 1) * height);
  let state = (seed * 2654435761) >>> 0;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let y = 0; y < height; y++) {
    const row = y * (width * 4 + 1);
    raw[row] = 0;
    for (let x = 0; x < width; x++) {
      const o = row + 1 + x * 4;
      const noise = rand() & 0x1f;
      raw[o] = (x * 3 + y * 2 + noise) & 0xff;
      raw[o + 1] = (y * 5 + (x >> 1) + noise) & 0xff;
      raw[o + 2] = (((x ^ y) * 7) + noise) & 0xff;
      raw[o + 3] = 255;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Membuat PNG RGBA 16-bit bertekstur (tanpa profil warna) untuk uji konversi. */
function makeCoverPng16Bit(width, height, seed = 1) {
  const raw = Buffer.alloc((width * 8 + 1) * height);
  let state = (seed * 2654435761) >>> 0;
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let y = 0; y < height; y++) {
    const row = y * (width * 8 + 1);
    raw[row] = 0;
    for (let x = 0; x < width; x++) {
      const o = row + 1 + x * 8;
      const noise = rand() & 0x1f;
      raw.writeUInt16BE(((x * 3 + y * 2 + noise) * 257) & 0xffff, o);
      raw.writeUInt16BE(((y * 5 + (x >> 1) + noise) * 257) & 0xffff, o + 2);
      raw.writeUInt16BE((((x ^ y) * 7 + noise) * 257) & 0xffff, o + 4);
      raw.writeUInt16BE(0xffff, o + 6);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 16; // bit depth
  ihdr[9] = 6; // RGBA
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

let passed = 0;
const failures = [];

async function step(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`PASS: ${name}`);
  } catch (error) {
    failures.push({ name, error });
    console.log(`FAIL: ${name} — ${error && error.message ? error.message : error}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function newPage(browser, viewport, options = {}) {
  if (sharedContext) {
    const page = await sharedContext.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
    await page.setViewportSize(viewport);
    if (options.isMobile) {
      const cdp = await sharedContext.newCDPSession(page);
      await cdp.send("Emulation.setDeviceMetricsOverride", {
        width: viewport.width,
        height: viewport.height,
        deviceScaleFactor: options.deviceScaleFactor || 1,
        mobile: true,
      });
      await cdp.send("Emulation.setTouchEmulationEnabled", {
        enabled: !!options.hasTouch,
        maxTouchPoints: 5,
      });
    }
    await page.goto(BASE_URL, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("#tab-hide", { timeout: 30000 });
    return { context: null, page, pageErrors, close: () => page.close() };
  }

  const context = await browser.newContext({
    viewport,
    acceptDownloads: true,
    isMobile: !!options.isMobile,
    hasTouch: !!options.hasTouch,
    deviceScaleFactor: options.deviceScaleFactor || 1,
  });
  const page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
  await page.goto(BASE_URL, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#tab-hide", { timeout: 30000 });
  return { context, page, pageErrors, close: () => context.close() };
}

async function hideMessage(page, coverPath, message, hint) {
  await page.click("#tab-hide");
  await page.setInputFiles("#hide-file", coverPath);
  await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 30000 });
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
  assert(!failure, `Enkripsi gagal: ${failure}`);
  await page.waitForSelector("#hide-result:not([hidden])", { timeout: 15000 });
  await page.waitForSelector("#btn-download:not([hidden])", { timeout: 15000 });
}

async function downloadResult(page, targetPath) {
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 30000 }),
    page.click("#btn-download"),
  ]);
  await download.saveAs(targetPath);
}

async function openMessage(page, stegoPath, password) {
  await page.click("#tab-open");
  await page.setInputFiles("#open-file", stegoPath);
  await page.waitForFunction(
    () => {
      const status = document.querySelector("#open-status");
      return status && status.hidden;
    },
    null,
    { timeout: 60000 }
  );
  await page.fill("#open-password", password);
  await page.waitForFunction(() => !document.querySelector("#btn-decrypt").disabled, null, {
    timeout: 10000,
  });
  await page.click("#btn-decrypt");
  await page.waitForSelector("#open-result:not([hidden])", { timeout: 120000 });
  return page.textContent("#open-message");
}

async function runFlow(browser, { label, viewport, isMobile, hasTouch, deviceScaleFactor }, coverPath, workDir, iteration) {
  const { page, pageErrors, close } = await newPage(browser, viewport, {
    isMobile,
    hasTouch,
    deviceScaleFactor,
  });
  try {
    const message = `Pesan ${label} #${iteration} — rahasia 🔐 ${Date.now()}`;
    const hint = `petunjuk ${label} ${iteration}`;
    await hideMessage(page, coverPath, message, hint);
    const stegoPath = join(workDir, `stego-${label}-${iteration}.png`);
    await downloadResult(page, stegoPath);

    // Sandi harus dibersihkan dari DOM setelah berhasil.
    const clearedPassword = await page.inputValue("#hide-password");
    assert(clearedPassword === "", "Kata sandi hide tidak dibersihkan setelah enkripsi.");

    // Sandi salah harus ditolak.
    await page.click("#tab-open");
    await page.setInputFiles("#open-file", stegoPath);
    await page.waitForFunction(
      () => {
        const status = document.querySelector("#open-status");
        return status && status.hidden;
      },
      null,
      { timeout: 60000 }
    );
    await page.fill("#open-password", "Sandi Salah Sekali 2026");
    await page.waitForFunction(() => !document.querySelector("#btn-decrypt").disabled);
    await page.click("#btn-decrypt");
    await page.waitForSelector("#open-error:not([hidden])", { timeout: 120000 });
    await page.click("#open-replace");

    const got = await openMessage(page, stegoPath, PASSWORD);
    assert(got === message, `Pesan tidak cocok.\nHarap: ${message}\nDapat: ${got}`);
    const hintText = await page.textContent("#open-hint-text");
    assert(hintText === hint, `Petunjuk tidak cocok: ${hintText}`);
    const clearedOpen = await page.inputValue("#open-password");
    assert(clearedOpen === "", "Kata sandi open tidak dibersihkan setelah dekripsi.");

    // Sandi V4 tidak peka huruf besar/kecil: bentuk kapitalisasi beda tetap membuka.
    await page.click("#open-replace");
    const gotLower = await openMessage(page, stegoPath, PASSWORD.toLowerCase());
    assert(
      gotLower === message,
      `Sandi huruf kecil tidak membuka gambar V4.\nHarap: ${message}\nDapat: ${gotLower}`
    );
    await page.click("#open-replace");
    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

/**
 * PNG 16-bit: di mode Sembunyikan harus dikonversi otomatis ke 8-bit dengan
 * penanda "16-bit → 8-bit" di metadata pratinjau, dan hasilnya tetap dapat
 * dibuka. Di mode Buka harus ditolak dengan pesan jelas (bukan konversi
 * diam-diam), karena payload hanya ada di PNG 8-bit.
 */
async function runBitDepth16Flow(browser, viewport, cover16bitPath, workDir) {
  const { page, pageErrors, close } = await newPage(browser, viewport);
  try {
    const message = `Pesan dari cover 16-bit ${Date.now()}`;
    await page.click("#tab-hide");
    await page.setInputFiles("#hide-file", cover16bitPath);
    await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 30000 });

    // Penanda konversi harus tampil di metadata pratinjau dan menyebut 16-bit.
    await page.waitForFunction(
      () => /16-bit/.test(document.querySelector("#hide-file-dims").textContent),
      null,
      { timeout: 15000 }
    );
    const dims = await page.textContent("#hide-file-dims");
    assert(/16-bit\s*→\s*8-bit/.test(dims), `Penanda konversi tidak menyebut 16-bit: ${dims}`);

    await page.fill("#secret-text", message);
    await page.fill("#hide-hint", "hint 16-bit");
    await page.fill("#hide-password", PASSWORD);
    await page.waitForFunction(() => !document.querySelector("#btn-encrypt").disabled, null, {
      timeout: 15000,
    });
    await page.click("#btn-encrypt");
    await page.waitForSelector("#hide-result:not([hidden])", { timeout: 120000 });
    const stegoPath = join(workDir, "stego-from-16bit.png");
    await downloadResult(page, stegoPath);

    // Hasil konversi harus terbaca kembali seperti biasa.
    const opened = await openMessage(page, stegoPath, PASSWORD);
    assert(opened === message, `Dekripsi hasil konversi gagal.\nHarap: ${message}\nDapat: ${opened}`);

    // Membuka PNG 16-bit harus DITOLAK dengan pesan jelas.
    await page.click("#open-replace");
    await page.click("#tab-open");
    await page.setInputFiles("#open-file", cover16bitPath);
    await page.waitForSelector("#open-error:not([hidden])", { timeout: 60000 });
    const errorText = await page.textContent("#open-error");
    assert(/16-bit/.test(errorText), `Pesan tolak 16-bit tidak sesuai: ${errorText}`);

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

/**
 * Format asing (JPEG/WebP): dibuat lewat kanvas Chromium (tanpa encoder Node),
 * lalu diuji: konversi otomatis ke PNG 8-bit, hasil bisa dibuka, dan mode Buka
 * menolak format asing dengan pesan jelas.
 */
async function writeCanvasFixture(page, outPath, mime, quality, width, height, seed) {
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
  assert(base64, `Browser tidak bisa mengenkode ${mime}.`);
  await writeFile(outPath, Buffer.from(base64, "base64"));
}

async function runForeignFormatFlow(browser, viewport, workDir) {
  const { page, pageErrors, close } = await newPage(browser, viewport);
  try {
    const cases = [
      {
        name: "JPEG",
        path: join(workDir, "cover.jpg"),
        mime: "image/jpeg",
        quality: 0.92,
        marker: /JPEG\s*→\s*PNG 8-bit/,
      },
      {
        name: "WebP",
        path: join(workDir, "cover.webp"),
        mime: "image/webp",
        quality: 0.95,
        marker: /WebP\s*→\s*PNG 8-bit/,
      },
    ];

    for (const item of cases) {
      await writeCanvasFixture(page, item.path, item.mime, item.quality, 640, 480, 99);
      const message = `Pesan ${item.name} → PNG ${Date.now()}`;

      await page.click("#tab-hide");
      await page.setInputFiles("#hide-file", item.path);
      await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 30000 });
      const dims = await page.textContent("#hide-file-dims");
      assert(item.marker.test(dims), `Penanda konversi ${item.name} tidak muncul: ${dims}`);

      await page.fill("#secret-text", message);
      await page.fill("#hide-hint", `hint ${item.name}`);
      await page.fill("#hide-password", PASSWORD);
      await page.waitForFunction(() => !document.querySelector("#btn-encrypt").disabled, null, {
        timeout: 15000,
      });
      await page.click("#btn-encrypt");
      await page.waitForSelector("#hide-result:not([hidden])", { timeout: 120000 });

      const stegoPath = join(workDir, `stego-from-${item.name.toLowerCase()}.png`);
      await downloadResult(page, stegoPath);

      // Hasil wajib PNG (signature IEND tetap PNG apa pun format masuknya).
      const bytes = await readFile(stegoPath);
      assert(
        bytes.length > 8 &&
          bytes[0] === 0x89 &&
          bytes[1] === 0x50 &&
          bytes[2] === 0x4e &&
          bytes[3] === 0x47,
        `Hasil konversi ${item.name} bukan PNG.`
      );

      const opened = await openMessage(page, stegoPath, PASSWORD);
      assert(
        opened === message,
        `Dekripsi hasil ${item.name} gagal.\nHarap: ${message}\nDapat: ${opened}`
      );

      // Mode Buka hanya menerima PNG: format asing harus ditolak.
      await page.click("#open-replace");
      await page.setInputFiles("#open-file", item.path);
      await page.waitForSelector("#toast-container .toast.error", { timeout: 15000 });
      const toast = await page.textContent("#toast-container .toast.error");
      assert(
        /selalu PNG/i.test(toast),
        `Pesan tolak mode Buka untuk ${item.name} tidak sesuai: ${toast}`
      );
      await page.evaluate(() =>
        document.querySelectorAll("#toast-container .toast").forEach((toast) => toast.remove())
      );
    }

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

/**
 * Teks & tata letak: placeholder sandi, label petunjuk, footer, subjudul daftar
 * buka, catatan unggah, hilangnya callout lama, tagline privasi yang selalu
 * center, dan label risiko deteksi yang seragam serta selalu center (desktop,
 * mobile, dan setelah resize).
 */
async function runUiTextFlow(browser, viewport, options, coverPath, label) {
  const { page, pageErrors, close } = await newPage(browser, viewport, options);
  try {
    const placeholder = await page.getAttribute("#hide-password", "placeholder");
    assert(
      placeholder === "Contoh sandi: %uY(/<mN#^#1L`N",
      `Placeholder sandi salah: ${placeholder}`
    );

    const hintLabel = await page.evaluate(() =>
      document.querySelector("#hide-hint").closest("label").querySelector(".field-label").textContent.trim()
    );
    assert(hintLabel === "Petunjuk", `Label petunjuk harus "Petunjuk": ${hintLabel}`);

    const hintFoot = await page.evaluate(() =>
      document.querySelector("#hide-hint").closest("label").querySelector(".field-hint").textContent.trim()
    );
    assert(
      hintFoot === "Terlihat sebelum sandi dimasukkan. Jangan tulis sandi di sini.",
      `Keterangan petunjuk salah: ${hintFoot}`
    );

    const footer = (await page.textContent(".app-footer p")).trim();
    assert(
      footer === "CryptoPic — Lindungi Privasi Anda,Tanpa Server,Tanpa Akun,Semua Ditangan Anda",
      `Footer salah: ${footer}`
    );

    assert((await page.$("#open-start-note")) === null, "Callout #open-start-note masih ada");

    const openSubtitle = (await page.textContent("#view-open .card-sub")).trim();
    assert(
      openSubtitle === "Unggah Gambar PNG, Masukkan Kata Sandi, Berdasarkan Hint/Petunjuk.",
      `Subjudul buka salah: ${openSubtitle}`
    );

    const uploadNote = (await page.textContent("#open-drop .upload-note")).replace(/\s+/g, " ").trim();
    assert(
      uploadNote === "Hanya gambar PNG hasil CryptoPic. Format Lain Tidak Didukung.",
      `Catatan unggah salah: ${uploadNote}`
    );

    // Tampilkan meter risiko dengan gambar + pesan kecil (rasio rendah).
    await page.click("#tab-hide");
    await page.setInputFiles("#hide-file", coverPath);
    await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 30000 });
    await page.fill("#secret-text", "pesan kecil");
    await page.waitForSelector("#stealth-meter:not([hidden])", { timeout: 15000 });
    const stealthText = (await page.textContent("#stealth-label")).trim();
    assert(stealthText === "Resiko Terdeteksi: Rendah", `Label risiko salah: ${stealthText}`);

    const layout = () =>
      page.evaluate(() => {
        const stealth = document.querySelector("#stealth-label");
        const tagline = document.querySelector(".privacy-tagline");
        const card = tagline.closest(".card");
        const tagRect = tagline.getBoundingClientRect();
        const cardRect = card.getBoundingClientRect();
        const cardStyle = getComputedStyle(card);
        const padLeft = parseFloat(cardStyle.paddingLeft);
        const padRight = parseFloat(cardStyle.paddingRight);
        const contentCenter = cardRect.left + padLeft + (cardRect.width - padLeft - padRight) / 2;
        const tagCenter = tagRect.left + tagRect.width / 2;
        const header = document.querySelector(".header-inner");
        const headerRect = header.getBoundingClientRect();
        const headerStyle = getComputedStyle(header);
        const headerRight = headerRect.right - parseFloat(headerStyle.paddingRight);
        const toggleRect = document.querySelector("#theme-toggle").getBoundingClientRect();
        const brandRect = document.querySelector(".brand").getBoundingClientRect();
        return {
          align: getComputedStyle(stealth).textAlign,
          taglineAlign: getComputedStyle(tagline).textAlign,
          taglineCenterDelta: Math.abs(tagCenter - contentCenter),
          taglineText: tagline.textContent.replace(/\s+/g, " ").trim(),
          toggleRightDelta: Math.abs(toggleRect.right - headerRight),
          toggleBrandGap: toggleRect.left - brandRect.right,
          overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
        };
      });

    let check = await layout();
    assert(check.align === "center", `Label risiko tidak center (${label}): ${check.align}`);
    assert(!check.overflow, `Ada overflow horizontal (${label})`);
    assert(
      check.taglineText ===
        "No Server, No Database, Just Run On your Device, We Respect Your Privacy",
      `Teks tagline privasi salah: ${check.taglineText}`
    );
    assert(
      check.taglineAlign === "center",
      `Tagline privasi tidak center (${label}): ${check.taglineAlign}`
    );
    assert(
      check.taglineCenterDelta <= 1.5,
      `Tagline privasi tidak di tengah kartu (${label}): selisih ${check.taglineCenterDelta}px`
    );
    assert(
      check.toggleRightDelta <= 1.5,
      `Tombol tema tidak menempel di ujung kanan header (${label}): selisih ${check.toggleRightDelta}px`
    );
    assert(
      check.toggleBrandGap >= 24,
      `Tombol tema terlalu dekat dengan logo (${label}): jarak ${check.toggleBrandGap}px`
    );

    // Simulasi layar digeser/diperkecil: tetap center dan tanpa overflow.
    await page.setViewportSize({
      width: Math.max(280, viewport.width - 120),
      height: viewport.height,
    });
    await page.waitForTimeout(150);
    check = await layout();
    assert(check.align === "center", `Label risiko tidak center setelah resize (${label})`);
    assert(!check.overflow, `Ada overflow horizontal setelah resize (${label})`);
    assert(
      check.taglineAlign === "center",
      `Tagline privasi tidak center setelah resize (${label}): ${check.taglineAlign}`
    );
    assert(
      check.taglineCenterDelta <= 1.5,
      `Tagline privasi tidak di tengah kartu setelah resize (${label}): selisih ${check.taglineCenterDelta}px`
    );
    assert(
      check.toggleRightDelta <= 1.5,
      `Tombol tema tidak di ujung kanan header setelah resize (${label}): selisih ${check.toggleRightDelta}px`
    );
    assert(
      check.toggleBrandGap >= 24,
      `Tombol tema terlalu dekat dengan logo setelah resize (${label}): jarak ${check.toggleBrandGap}px`
    );

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

/**
 * Sandi lemah (di bawah 8 karakter) harus tetap bisa dipakai, tetapi tombol
 * enkripsi baru aktif setelah gambar, pesan, sandi, dan petunjuk terisi.
 */
async function runWeakPasswordFlow(browser, viewport, coverPath, workDir) {
  const { page, pageErrors, close } = await newPage(browser, viewport);
  try {
    const message = `Pesan sandi lemah ${Date.now()}`;
    await page.click("#tab-hide");
    await page.setInputFiles("#hide-file", coverPath);
    await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 30000 });

    const isDisabled = () => page.evaluate(() => document.querySelector("#btn-encrypt").disabled);
    assert(await isDisabled(), "Tombol enkripsi harus disabled sebelum pesan diisi");

    await page.fill("#secret-text", message);
    assert(await isDisabled(), "Tombol enkripsi harus disabled tanpa sandi dan petunjuk");

    await page.fill("#hide-password", "abc");
    assert(await isDisabled(), "Tombol enkripsi harus disabled saat petunjuk kosong");

    const strength = (await page.textContent("#pw-strength-label")).trim();
    assert(
      strength === "Terlalu Lemah, Sandi Dapat Ditembus Dengan Cepat",
      `Label kekuatan sandi lemah salah: ${strength}`
    );

    await page.fill("#hide-hint", "petunjuk untuk sandi lemah");
    await page.waitForFunction(() => !document.querySelector("#btn-encrypt").disabled, null, {
      timeout: 15000,
    });

    await page.click("#btn-encrypt");
    await page.waitForSelector("#hide-result:not([hidden])", { timeout: 120000 });
    const stegoPath = join(workDir, "stego-weak-password.png");
    await downloadResult(page, stegoPath);

    const opened = await openMessage(page, stegoPath, "abc");
    assert(
      opened === message,
      `Sandi lemah gagal membuka pesan.\nHarap: ${message}\nDapat: ${opened}`
    );
    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

async function runReuseFlow(browser, viewport, coverPath, workDir) {
  const { page, pageErrors, close } = await newPage(browser, viewport);
  try {
    const first = `Pesan pertama ${Date.now()}`;
    await hideMessage(page, coverPath, first, "hint pertama");
    const firstPath = join(workDir, "stego-reuse-1.png");
    await downloadResult(page, firstPath);

    const openedFirst = await openMessage(page, firstPath, PASSWORD);
    assert(openedFirst === first, "Dekripsi gambar pertama gagal.");

    // Tombol di kartu hasil.
    await page.click("#btn-reuse");
    await page.waitForSelector("#cleanse-overlay:not([hidden])", { timeout: 15000 });
    await page.waitForFunction(() => document.querySelector("#cleanse-overlay").hidden, null, {
      timeout: 120000,
    });
    await page.waitForSelector("#view-hide.active", { timeout: 15000 });
    await page.waitForSelector("#hide-preview-wrap:not([hidden])", { timeout: 15000 });
    const cleanName = await page.textContent("#hide-file-name");
    assert(
      cleanName.startsWith("cryptopic-bersih-"),
      `Nama file hasil pembersihan tidak sesuai: ${cleanName}`
    );
    assert(
      (await page.inputValue("#hide-password")) === "",
      "Kata sandi hide harus kosong setelah Gunakan Lagi."
    );

    // Pesan baru di gambar yang sudah dibersihkan.
    const second = `Pesan kedua ${Date.now()}`;
    await page.fill("#secret-text", second);
    await page.fill("#hide-hint", "hint kedua");
    await page.fill("#hide-password", PASSWORD);
    await page.waitForFunction(() => !document.querySelector("#btn-encrypt").disabled, null, {
      timeout: 15000,
    });
    await page.click("#btn-encrypt");
    await page.waitForSelector("#hide-result:not([hidden])", { timeout: 120000 });
    const secondPath = join(workDir, "stego-reuse-2.png");
    await downloadResult(page, secondPath);

    const openedSecond = await openMessage(page, secondPath, PASSWORD);
    assert(openedSecond === second, "Dekripsi gambar hasil pemakaian ulang gagal.");
    const hintSecond = await page.textContent("#open-hint-text");
    assert(hintSecond === "hint kedua", `Petunjuk tidak cocok: ${hintSecond}`);

    // Tombol di area pratinjau (gambar stego kedua masih terbuka).
    await page.click("#btn-reuse-preview");
    await page.waitForSelector("#cleanse-overlay:not([hidden])", { timeout: 15000 });
    await page.waitForFunction(() => document.querySelector("#cleanse-overlay").hidden, null, {
      timeout: 120000,
    });
    await page.waitForSelector("#view-hide.active", { timeout: 15000 });

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

async function runLegacyVaultMigration(browser, viewport) {
  const { page, pageErrors, close } = await newPage(browser, viewport);
  const LEGACY_PIN = "246810";
  try {
    // Tulis vault lama (PBKDF2, tanpa field kdf) langsung ke IndexedDB.
    await page.evaluate(async (pin) => {
      const enc = new TextEncoder();
      const openDb = () =>
        new Promise((resolve, reject) => {
          const req = indexedDB.open("cryptopic", 1);
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains("memos")) {
              req.result.createObjectStore("memos", { keyPath: "id" });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });

      const db = await openDb();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, [
        "deriveKey",
      ]);
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const encryptString = async (text) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new Uint8Array(
          await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text))
        );
        return { iv, data };
      };

      const verifier = await encryptString("cryptopic-memo-vault-v1");
      const memo = await encryptString(
        JSON.stringify({ text: "Memo lama sebelum migrasi", hint: "legacy", fileName: "lama.png" })
      );

      await new Promise((resolve, reject) => {
        const tx = db.transaction("memos", "readwrite");
        const store = tx.objectStore("memos");
        store.clear();
        store.put({
          id: "__vault__",
          salt,
          verifierIv: verifier.iv,
          verifier: verifier.data,
        });
        store.put({
          id: "legacy-memo-1",
          createdAt: new Date().toISOString(),
          enc: 1,
          iv: memo.iv,
          data: memo.data,
        });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      db.close();
    }, LEGACY_PIN);

    // Muat ulang agar vault lama terbaca, lalu buka dengan PIN 6 karakter.
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector("#tab-memo", { timeout: 30000 });
    await page.click("#tab-memo");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terkunci"),
      null,
      { timeout: 30000 }
    );
    await page.click("#btn-vault-primary");
    await page.fill("#vault-pin", LEGACY_PIN);
    await page.click("#btn-vault-submit");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terbuka"),
      null,
      { timeout: 60000 }
    );
    await page.waitForSelector(".memo-item", { timeout: 20000 });

    // Record vault harus sudah dimigrasikan ke Argon2id.
    const migrated = await page.evaluate(async () => {
      const db = await new Promise((resolve, reject) => {
        const req = indexedDB.open("cryptopic", 1);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      const record = await new Promise((resolve, reject) => {
        const req = db.transaction("memos", "readonly").objectStore("memos").get("__vault__");
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      db.close();
      return record
        ? { v: record.v, kdf: record.kdf || null, hasSalt: !!record.salt }
        : null;
    });
    assert(migrated && migrated.v === 2 && migrated.hasSalt, "Vault tidak bermigrasi ke v2.");
    assert(
      migrated.kdf && migrated.kdf.memorySize === 65536 && migrated.kdf.iterations === 3,
      "Parameter KDF hasil migrasi tidak sesuai Argon2id."
    );

    // Setelah reload, PIN yang sama harus tetap membuka vault baru.
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector("#tab-memo", { timeout: 30000 });
    await page.click("#tab-memo");
    await page.click("#btn-vault-primary");
    await page.fill("#vault-pin", LEGACY_PIN);
    await page.click("#btn-vault-submit");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terbuka"),
      null,
      { timeout: 60000 }
    );
    await page.waitForSelector(".memo-item", { timeout: 20000 });

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

async function runMemoVault(browser, viewport, coverPath, workDir) {
  const { page, pageErrors, close } = await newPage(browser, viewport, {
    isMobile: true,
    hasTouch: true,
    deviceScaleFactor: 3,
  });
  try {
    // Siapkan satu gambar stego lebih dulu.
    const message = `Memo vault ${Date.now()}`;
    await hideMessage(page, coverPath, message, "vault hint");
    const stegoPath = join(workDir, "stego-vault.png");
    await downloadResult(page, stegoPath);

    // Aktifkan PIN memo.
    await page.click("#tab-memo");
    await page.click("#btn-vault-primary");
    await page.fill("#vault-pin", "24681024");
    await page.fill("#vault-pin-confirm", "24681024");
    await page.click("#btn-vault-submit");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terbuka"),
      null,
      { timeout: 60000 }
    );

    // Buka pesan -> memo tersimpan otomatis (terenkripsi).
    const opened = await openMessage(page, stegoPath, PASSWORD);
    assert(opened === message, "Dekripsi untuk memo gagal.");
    await page.click("#tab-memo");
    await page.waitForSelector(".memo-item", { timeout: 20000 });
    const preview = await page.textContent(".memo-preview");
    assert(preview.includes("Memo vault"), "Memo tidak tampil setelah disimpan.");

    // Muat ulang: memo harus terkunci, bukan teks biasa.
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector("#tab-memo", { timeout: 30000 });
    await page.click("#tab-memo");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terkunci"),
      null,
      { timeout: 30000 }
    );
    const listHidden = await page.evaluate(() => document.querySelector("#memo-list").hidden);
    assert(listHidden, "Daftar memo harus tersembunyi saat terkunci.");

    // PIN salah ditolak, PIN benar membuka.
    await page.click("#btn-vault-primary");
    await page.fill("#vault-pin", "000000");
    await page.click("#btn-vault-submit");
    await page.waitForSelector("#vault-error:not([hidden])", { timeout: 30000 });
    await page.fill("#vault-pin", "24681024");
    await page.click("#btn-vault-submit");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("terbuka"),
      null,
      { timeout: 60000 }
    );
    await page.waitForSelector(".memo-item", { timeout: 20000 });

    // Matikan PIN -> kembali teks biasa.
    await page.click("#btn-vault-disable");
    await page.waitForFunction(
      () => document.querySelector("#vault-desc").textContent.includes("teks biasa"),
      null,
      { timeout: 30000 }
    );

    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await close();
  }
}

/**
 * Brave mengacak piksel canvas (anti-fingerprinting) sehingga LSB stego rusak.
 * Untuk uji Brave, siapkan profil yang mematikan Shields untuk origin ini.
 */
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

async function main() {
  const workDir = await mkdtemp(join(tmpdir(), "cryptopic-e2e-"));
  const coverPath = join(workDir, "cover.png");
  await writeFile(coverPath, makeCoverPng(512, 512, 7));
  const cover16bitPath = join(workDir, "cover-16bit.png");
  await writeFile(cover16bitPath, makeCoverPng16Bit(512, 512, 11));

  let browser = null;
  if (PROFILE_DIR) {
    await prepareShieldsProfile(PROFILE_DIR);
    sharedContext = await chromium.launchPersistentContext(PROFILE_DIR, {
      executablePath: BROWSER_PATH,
      headless: true,
      acceptDownloads: true,
    });
  } else {
    browser = await chromium.launch({ executablePath: BROWSER_PATH, headless: true });
  }

  const desktop = { label: "desktop", viewport: { width: 1440, height: 900 } };
  const mobile = {
    label: "mobile",
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
    deviceScaleFactor: 3,
  };

  // Pemanasan: pastikan server & aset siap.
  await step("Halaman utama memuat tanpa error", async () => {
    const { page, pageErrors, close } = await newPage(browser, desktop.viewport);
    try {
      await page.click("#tab-open");
      await page.waitForSelector("#open-drop", { timeout: 15000 });
      assert(pageErrors.length === 0, `Error halaman: ${pageErrors.join(" | ")}`);
    } finally {
      await close();
    }
  });

  for (let i = 1; i <= RUNS; i++) {
    await step(`Desktop hide/open round-trip #${i}`, () =>
      runFlow(browser, desktop, coverPath, workDir, i)
    );
    await step(`Mobile hide/open round-trip #${i}`, () =>
      runFlow(browser, mobile, coverPath, workDir, i)
    );
  }

  await step("PNG 16-bit: konversi otomatis saat sembunyikan, ditolak jelas saat buka", () =>
    runBitDepth16Flow(browser, desktop.viewport, cover16bitPath, workDir)
  );

  await step("Teks & label risiko: desktop, center dan tanpa overflow", () =>
    runUiTextFlow(browser, desktop.viewport, {}, coverPath, "desktop")
  );

  await step("Teks & label risiko: mobile, center dan tanpa overflow", () =>
    runUiTextFlow(
      browser,
      mobile.viewport,
      { isMobile: true, hasTouch: true, deviceScaleFactor: 3 },
      coverPath,
      "mobile"
    )
  );

  await step("Sandi lemah + petunjuk wajib: enkripsi dan buka kembali", () =>
    runWeakPasswordFlow(browser, desktop.viewport, coverPath, workDir)
  );

  await step("Format asing (JPEG/WebP): konversi ke PNG, bisa dibuka, mode Buka menolak", () =>
    runForeignFormatFlow(browser, desktop.viewport, workDir)
  );

  await step("Gunakan Lagi: gambar lama dibersihkan lalu dipakai untuk pesan baru", () =>
    runReuseFlow(browser, desktop.viewport, coverPath, workDir)
  );

  await step("Vault Memo (PIN): simpan, kunci, buka, matikan PIN", () =>
    runMemoVault(browser, mobile.viewport, coverPath, workDir)
  );

  await step("Vault lama (PBKDF2) otomatis bermigrasi ke Argon2id", () =>
    runLegacyVaultMigration(browser, mobile.viewport)
  );

  await step("Header keamanan & service worker tidak error", async () => {
    const { page, pageErrors, close } = await newPage(browser, desktop.viewport);
    try {
      await page.waitForTimeout(1500);
      const controlled = await page.evaluate(async () => {
        if (!("serviceWorker" in navigator)) return "unsupported";
        const reg = await navigator.serviceWorker.getRegistration();
        return reg ? "registered" : "none";
      });
      assert(controlled === "registered" || controlled === "unsupported", `Service worker: ${controlled}`);
      const health = await page.evaluate(async () => {
        const res = await fetch("/healthz", { cache: "no-store" });
        return res.status + ":" + (await res.text());
      });
      assert(health === "200:ok", `Health check gagal: ${health}`);
      assert(pageErrors.length === 0, `Error halaman: ${pageErrors.join(" | ")}`);
    } finally {
      await close();
    }
  });

  await step("Mode offline: shell dimuat dari service worker", async () => {
    const { page, pageErrors, close } = await newPage(browser, desktop.viewport);
    try {
      await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 30000 });
      await page.context().setOffline(true);
      await page.reload({ waitUntil: "domcontentloaded" });
      await page.waitForSelector("#tab-hide", { timeout: 30000 });
      assert(pageErrors.length === 0, `Error halaman offline: ${pageErrors.join(" | ")}`);
    } finally {
      await page.context().setOffline(false).catch(() => {});
      await close();
    }
  });

  if (sharedContext) await sharedContext.close();
  else await browser.close();

  console.log(`\n${passed} langkah lulus, ${failures.length} gagal.`);
  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`\n[${failure.name}]`);
      console.error(failure.error && failure.error.stack ? failure.error.stack : failure.error);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
