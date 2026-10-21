/*
 * Uji end-to-end di browser sungguhan (Chrome/Edge via Playwright) untuk
 * alur sembunyikan -> unduh -> buka -> dekripsi, serta vault Memo (PIN).
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
 *   CRYPTOPIC_BROWSER   path ke chrome.exe / msedge.exe
 *   RUNS                jumlah iterasi per mode (default 5)
 */
import { chromium } from "playwright-core";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import zlib from "node:zlib";

const BASE_URL = process.env.CRYPTOPIC_URL || "http://127.0.0.1:8080";
const BROWSER_PATH =
  process.env.CRYPTOPIC_BROWSER ||
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const RUNS = Number(process.env.RUNS || 5);
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
  return { context, page, pageErrors };
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
  await page.waitForSelector("#hide-result:not([hidden])", { timeout: 120000 });
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
  const { context, page, pageErrors } = await newPage(browser, viewport, {
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
    assert(pageErrors.length === 0, `Ada error halaman: ${pageErrors.join(" | ")}`);
  } finally {
    await context.close();
  }
}

async function runMemoVault(browser, viewport, coverPath, workDir) {
  const { context, page, pageErrors } = await newPage(browser, viewport, {
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
    await page.fill("#vault-pin", "246810");
    await page.fill("#vault-pin-confirm", "246810");
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
    await page.fill("#vault-pin", "246810");
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
    await context.close();
  }
}

async function main() {
  const workDir = await mkdtemp(join(tmpdir(), "cryptopic-e2e-"));
  const coverPath = join(workDir, "cover.png");
  await writeFile(coverPath, makeCoverPng(512, 512, 7));

  const browser = await chromium.launch({ executablePath: BROWSER_PATH, headless: true });

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
    const { context, page, pageErrors } = await newPage(browser, desktop.viewport);
    try {
      await page.click("#tab-open");
      await page.waitForSelector("#open-drop", { timeout: 15000 });
      assert(pageErrors.length === 0, `Error halaman: ${pageErrors.join(" | ")}`);
    } finally {
      await context.close();
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

  await step("Vault Memo (PIN): simpan, kunci, buka, matikan PIN", () =>
    runMemoVault(browser, mobile.viewport, coverPath, workDir)
  );

  await step("Header keamanan & service worker tidak error", async () => {
    const { context, page, pageErrors } = await newPage(browser, desktop.viewport);
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
      await context.close();
    }
  });

  await step("Mode offline: shell dimuat dari service worker", async () => {
    const { context, page, pageErrors } = await newPage(browser, desktop.viewport);
    try {
      await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 30000 });
      await context.setOffline(true);
      await page.reload({ waitUntil: "domcontentloaded" });
      await page.waitForSelector("#tab-hide", { timeout: 30000 });
      assert(pageErrors.length === 0, `Error halaman offline: ${pageErrors.join(" | ")}`);
    } finally {
      await context.setOffline(false).catch(() => {});
      await context.close();
    }
  });

  await browser.close();

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
