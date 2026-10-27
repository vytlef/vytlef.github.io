import {
  encryptPayload,
  parsePayload,
  decryptPayload,
  deriveKeys,
  CryptoPicError,
} from "./crypto.js";
import {
  validatePNGFile,
  validatePNGStructure,
  readFileBytes,
  pngRejectMessage,
  imageImportRejectMessage,
  isSupportedImageFile,
  detectImportFormat,
  readPngInfo,
  prepareImageForEmbedding,
  loadImageFromFile,
  imageToImageData,
  is16BitPng,
  maxMessageBytes,
  embedPayload,
  extractPayload,
  extractProtectedBody,
  imageDataToPngBlob,
  sanitizeToPngBlob,
  StegoError,
} from "./stego.js";
import {
  listMemos,
  saveMemo,
  deleteMemos,
  getUsage,
  storageAvailable,
  requestPersistentStorage,
  initStorage,
  formatBytes,
  MAX_BYTES,
  vaultEnabled,
  isUnlocked,
  enableMemoPin,
  unlockMemos,
  lockMemos,
  disableMemoPin,
  MIN_PIN_LENGTH,
} from "./memo.js";

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();

/* ---------------- Verifikasi hasil embed ---------------- */

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Self-check: baca ulang PNG hasil, ekstrak payload, dan bandingkan dengan
 * payload semula sebelum file ditawarkan untuk diunduh.
 */
async function verifyEmbedding(blob, expectedPayload, stegoKey) {
  let imageData;
  try {
    const img = await loadImageFromFile(blob);
    imageData = imageToImageData(img).imageData;
  } catch {
    throw new StegoError("VERIFY_FAILED", "Gambar hasil tidak dapat dibaca ulang untuk diverifikasi.");
  }
  let extracted;
  try {
    const prefix = extractPayload(imageData);
    const parsed = parsePayload(prefix);
    // extractPayload hanya mengembalikan header; body diambil terpisah.
    const body = await extractProtectedBody(imageData, parsed, stegoKey);
    const full = new Uint8Array(prefix.length + body.length);
    full.set(prefix);
    full.set(body, prefix.length);
    extracted = full;
  } catch (err) {
    throw new StegoError(
      "VERIFY_FAILED",
      `Pesan tidak dapat diekstrak ulang dari gambar hasil (${err.message}).`
    );
  }
  if (!bytesEqual(extracted, expectedPayload)) {
    throw new StegoError(
      "VERIFY_FAILED",
      "Pesan pada gambar hasil tidak sama dengan pesan asli. File tidak diunduh."
    );
  }
  return true;
}

/* ---------------- Toast ---------------- */

function showToast(message, type = "ok", duration = 3500) {
  const container = $("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  }, duration);
}

/* ---------------- Tema ---------------- */

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("cryptopic:theme", theme);
  } catch {
    /* ignore */
  }
  $("theme-color-meta").content = theme === "dark" ? "#0e1424" : "#f4f6fb";
}

function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem("cryptopic:theme");
  } catch {
    /* ignore */
  }
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  applyTheme(saved === "dark" || saved === "light" ? saved : prefersDark ? "dark" : "light");
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme;
  const next = current === "dark" ? "light" : "dark";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const root = document.documentElement;

  if (!document.startViewTransition || reduce) {
    applyTheme(next);
    return;
  }

  root.classList.add("theme-animating");
  const cleanup = () => root.classList.remove("theme-animating");

  const transition = document.startViewTransition(() => applyTheme(next));
  transition.finished.finally(cleanup);
}

/* ---------------- Tab routing ---------------- */

function switchView(name) {
  for (const section of document.querySelectorAll(".view")) {
    const active = section.id === `view-${name}`;
    section.classList.toggle("active", active);
    section.hidden = !active;
  }
  for (const tab of document.querySelectorAll(".tab")) {
    const active = tab.dataset.view === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  }
  if (name === "memo") refreshMemoView();
}

/* ---------------- Upload zone ---------------- */

function setupUploadZone(zone, input, onFile) {
  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      input.click();
    }
  });
  input.addEventListener("change", () => {
    if (input.files && input.files[0]) onFile(input.files[0]);
    input.value = "";
  });
  for (const evt of ["dragenter", "dragover"]) {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add("dragover");
    });
  }
  for (const evt of ["dragleave", "drop"]) {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.remove("dragover");
    });
  }
  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) onFile(file);
  });
}

/* ---------------- Tombol lihat sandi ---------------- */

function setupPwToggles() {
  for (const btn of document.querySelectorAll(".pw-toggle")) {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      input.type = input.type === "password" ? "text" : "password";
      btn.setAttribute("aria-label", input.type === "password" ? "Tampilkan sandi" : "Sembunyikan sandi");
    });
  }
}

/* ---------------- Alur: Sembunyikan ---------------- */

const hideState = { img: null, width: 0, height: 0, fileName: "", stegoUrl: null, hasTransparency: false };
let hidePreviewUrl = null;
let openPreviewUrl = null;

function hideAvailable() {
  if (!hideState.img) return 0;
  const hint = $("hide-hint").value.trim();
  return maxMessageBytes(hideState.width, hideState.height, hint);
}

/* ---------------- Kekuatan sandi & meter stealth ---------------- */

function estimatePasswordStrength(password) {
  if (!password) return { score: 0, level: "weak", label: "" };
  let score = Math.min(50, password.length * 4);
  if (/[a-z]/.test(password)) score += 5;
  if (/[A-Z]/.test(password)) score += 5;
  if (/[0-9]/.test(password)) score += 5;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;
  if (password.length >= 16) score += 10;
  if (password.length >= 24) score += 10;
  if (/^(.)\1+$/.test(password)) score -= 40;
  if (/^(123456|12345678|password|qwerty|admin|sandi|rahasia|iloveyou)/i.test(password)) score -= 40;
  if (password.length < 8) score = Math.min(score, 25);
  score = Math.max(0, Math.min(100, score));

  let level = "weak";
  if (score >= 70) level = "good";
  else if (score >= 40) level = "fair";

  let label;
  if (level === "good") {
    label = "Kuat.";
  } else if (level === "fair") {
    label = "Cukup — pertimbangkan frasa yang lebih panjang.";
  } else {
    label = "Terlalu Lemah, Sandi Dapat Ditembus Dengan Cepat";
  }
  return { score, level, label };
}

function updatePasswordStrength() {
  const password = $("hide-password").value;
  const wrap = $("pw-strength");
  const fill = $("pw-strength-fill");
  const label = $("pw-strength-label");
  if (!password) {
    wrap.hidden = true;
    return;
  }
  const { score, level, label: text } = estimatePasswordStrength(password);
  wrap.hidden = false;
  wrap.dataset.level = level;
  fill.style.width = `${Math.max(6, score)}%`;
  label.textContent = text;
}

function updateStealthMeter(bytes, avail) {
  const meter = $("stealth-meter");
  const fill = $("stealth-fill");
  const label = $("stealth-label");
  if (!hideState.img || avail <= 0) {
    meter.hidden = true;
    return;
  }
  const ratio = Math.min(1, bytes / avail);
  const percent = ratio * 100;
  let level, text;
  if (ratio <= 0.1) {
    level = "low";
    text = "Resiko Terdeteksi: Rendah";
  } else if (ratio <= 0.3) {
    level = "medium";
    text = "Resiko Terdeteksi: Sedang";
  } else {
    level = "high";
    text = "Resiko Terdeteksi: Tinggi";
  }
  meter.hidden = false;
  meter.dataset.level = level;
  fill.style.width = `${Math.max(4, percent)}%`;
  label.textContent = text;
}



function updateHideUi() {
  const secret = $("secret-text").value;
  const bytes = encoder.encode(secret).length;
  const avail = hideAvailable();

  // Pesan tidak bisa diketik sebelum gambar dipilih (mode Sembunyikan).
  if (!hideState.img) {
    $("secret-text").disabled = true;
  } else {
    $("secret-text").disabled = false;
  }

  if (hideState.img) {
    $("hide-capacity").textContent = `Kapasitas pesan maks. ${formatBytes(avail)}`;
  }

  $("secret-counter").textContent = `${formatBytes(bytes)}`;
  const counter = $("secret-counter");
  if (bytes > avail && hideState.img) {
    counter.classList.add("over");
    $("secret-cap-info").textContent = `Melebihi kapasitas (${formatBytes(avail)} tersedia)`;
  } else {
    counter.classList.remove("over");
    $("secret-cap-info").textContent = hideState.img ? `${formatBytes(avail)} tersedia` : "";
  }

  updateStealthMeter(bytes, avail);
  updatePasswordStrength();
  $("hint-visibility-warning").hidden = !$("hide-hint").value.trim();

  const password = $("hide-password").value;
  const hint = $("hide-hint").value.trim();
  const canEncrypt =
    !!hideState.img &&
    secret.trim().length > 0 &&
    password.length > 0 &&
    hint.length > 0 &&
    bytes <= avail;
  $("btn-encrypt").disabled = !canEncrypt;
}

function conversionMarker(format, pngInfo) {
  if (!format) return "";
  if (format.label !== "PNG") return `${format.label} → PNG 8-bit`;
  if (!pngInfo) return "";
  const parts = [];
  if (pngInfo.bitDepth !== 8) parts.push(`${pngInfo.bitDepth}-bit`);
  if (pngInfo.hasIccp) parts.push("ICC");
  if (parts.length === 0) return "";
  return pngInfo.hasIccp ? `${parts.join(" + ")} → sRGB 8-bit` : `${parts.join(" + ")} → 8-bit`;
}

async function readPngInfoSafe(file) {
  try {
    return readPngInfo(await readFileBytes(file));
  } catch {
    return null;
  }
}

async function handleHideFile(file) {
  if (!isSupportedImageFile(file)) {
    showToast(imageImportRejectMessage(file), "error", 6000);
    return;
  }
  try {
    const format = detectImportFormat(file);
    // Label konversi butuh info IHDR PNG (kedalaman/ICC). Format lain cukup
    // didekode lewat kanvas tanpa membaca seluruh byte di JS.
    const pngInfo = format && format.label === "PNG" ? await readPngInfoSafe(file) : null;

    // Semua input dinormalisasi ke PNG 8-bit SEBELUM payload disisipkan.
    const prepared = await prepareImageForEmbedding(file);

    hideState.img = prepared.img;
    hideState.imageData = prepared.imageData;
    hideState.hasTransparency = prepared.hasTransparency;
    hideState.width = prepared.width;
    hideState.height = prepared.height;
    hideState.fileName = file.name;
    if (hidePreviewUrl) URL.revokeObjectURL(hidePreviewUrl);
    // Pratinjau memakai berkas PNG hasil normalisasi, sesuai hasil nyata.
    hidePreviewUrl = URL.createObjectURL(prepared.blob);
    $("hide-preview-img").src = hidePreviewUrl;
    $("hide-file-name").textContent = file.name;
    const dims = `${prepared.width}×${prepared.height}px`;
    const marker = conversionMarker(format, pngInfo);
    $("hide-file-dims").textContent = marker ? `${dims} · ${marker}` : dims;
    $("hide-capacity").textContent = `Kapasitas pesan maks. ${formatBytes(maxMessageBytes(prepared.width, prepared.height, $("hide-hint").value.trim()))}`;
    $("transparency-notice").hidden = !prepared.hasTransparency;
    $("hide-drop").hidden = true;
    $("hide-preview-wrap").hidden = false;
    $("hide-result").hidden = true;
    $("btn-download").hidden = true;
    updateHideUi();
  } catch (err) {
    showToast(err.message, "error", 6000);
  }
}

function resetHideImage() {
  hideState.img = null;
  hideState.imageData = null;
  hideState.fileName = "";
  hideState.hasTransparency = false;
  if (hideState.stegoUrl) {
    URL.revokeObjectURL(hideState.stegoUrl);
    hideState.stegoUrl = null;
  }
  if (hidePreviewUrl) {
    URL.revokeObjectURL(hidePreviewUrl);
    hidePreviewUrl = null;
  }
  $("hide-preview-img").removeAttribute("src");
  $("stego-preview").removeAttribute("src");
  $("hide-drop").hidden = false;
  $("hide-preview-wrap").hidden = true;
  $("hide-result").hidden = true;
  $("btn-download").hidden = true;
  $("transparency-notice").hidden = true;
  updateHideUi();
}

async function doEncrypt() {
  if (!ensureCanvasStable()) return;
  const secret = $("secret-text").value;
  const password = $("hide-password").value;
  const hint = $("hide-hint").value.trim();

  if (!hideState.img || !secret.trim() || !password || !hint) return;

  const status = $("hide-status");
  status.hidden = false;
  status.classList.remove("error");
  status.innerHTML = '<span class="spinner"></span> Mengolah Argon2id dan menyisipkan pesan…';
  $("btn-encrypt").disabled = true;

  try {
    const imageData = hideState.imageData || imageToImageData(hideState.img).imageData;
    const { payload, stegoKey } = await encryptPayload(password, secret, hint);
    const embedded = await embedPayload(imageData, payload, stegoKey);
    const blob = await imageDataToPngBlob(embedded);

    status.innerHTML = '<span class="spinner"></span> Memverifikasi hasil…';
    await verifyEmbedding(blob, payload, stegoKey);

    if (hideState.stegoUrl) URL.revokeObjectURL(hideState.stegoUrl);
    hideState.stegoUrl = URL.createObjectURL(blob);

    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const downloadName = `cryptopic-${stamp}.png`;
    const link = $("btn-download");
    link.href = hideState.stegoUrl;
    link.download = downloadName;

    $("stego-preview").src = hideState.stegoUrl;
    $("hide-result").hidden = false;
    $("hide-preview-wrap").hidden = true;
    link.hidden = false;
    status.hidden = true;
    $("hide-password").value = "";
    if (hideState.hasTransparency) {
      showToast("Pesan berhasil disembunyikan. Area transparan diratakan ke putih pada hasil.", "ok", 5000);
    } else {
      showToast("Pesan berhasil disembunyikan. Unduh gambar PNG-nya.", "ok");
    }
  } catch (err) {
    status.textContent = err.message;
    status.classList.add("error");
    if (!(err instanceof CryptoPicError || err instanceof StegoError)) {
      console.error(err);
    }
  } finally {
    updateHideUi();
  }
}

/* ---------------- Alur: Buka ---------------- */

const openState = { parsed: null, imageData: null, fileName: "" };

function resetOpen() {
  openState.parsed = null;
  openState.imageData = null;
  openState.fileName = "";
  if (openPreviewUrl) {
    URL.revokeObjectURL(openPreviewUrl);
    openPreviewUrl = null;
  }
  $("open-preview-img").removeAttribute("src");
  $("open-drop").hidden = false;
  $("open-preview-wrap").hidden = true;
  $("open-hint-box").hidden = true;
  $("open-password-field").hidden = true;
  $("open-password").value = "";
  $("btn-decrypt").disabled = true;
  $("open-error").hidden = true;
  $("open-status").hidden = true;
  $("open-result").hidden = true;
  $("open-result-placeholder").hidden = false;
}

async function handleOpenFile(file) {
  resetOpen();
  if (!validatePNGFile(file)) {
    showToast(pngRejectMessage(file), "error", 6000);
    return;
  }
  const status = $("open-status");
  status.hidden = false;
  status.classList.remove("error");
  status.innerHTML = '<span class="spinner"></span> Membaca piksel gambar…';

  try {
    const bytes = await readFileBytes(file);
    // 16-bit ditolak dengan pesan khusus: pesan CryptoPic hanya ada di PNG 8-bit,
    // jadi gambar 16-bit tidak mungkin berisi payload. Jangan konversi diam-diam.
    if (is16BitPng(bytes)) {
      throw new StegoError(
        "BIT_DEPTH",
        "PNG ini 16-bit per channel. Pesan CryptoPic hanya ditulis pada PNG 8-bit, jadi gambar ini tidak mungkin berisi " +
          "pesan CryptoPic. Minta pengirim menyimpan ulang gambar hasil sebagai PNG 8-bit."
      );
    }
    validatePNGStructure(bytes);
    const img = await loadImageFromFile(file);
    const { imageData } = imageToImageData(img);
    const payload = extractPayload(imageData);
    const parsed = parsePayload(payload);

    openState.parsed = parsed;
    openState.imageData = imageData;
    openState.fileName = file.name;

    if (openPreviewUrl) URL.revokeObjectURL(openPreviewUrl);
    openPreviewUrl = URL.createObjectURL(file);
    $("open-preview-img").src = openPreviewUrl;
    $("open-file-name").textContent = file.name;
    $("open-file-dims").textContent = `${img.naturalWidth}×${img.naturalHeight}px`;
    $("open-drop").hidden = true;
    $("open-preview-wrap").hidden = false;

    if (parsed.hint) {
      $("open-hint-text").textContent = parsed.hint;
      $("open-hint-box").hidden = false;
    }
    $("open-password-hint").textContent =
      "Gambar V4: huruf besar/kecil tidak dibedakan; spasi tetap dihitung.";
    $("open-password-field").hidden = false;
    status.hidden = true;
    $("open-password").focus();
  } catch (err) {
    status.hidden = true;
    const box = $("open-error");
    box.textContent = err instanceof StegoError || err instanceof CryptoPicError ? err.message : "Gagal membaca gambar.";
    box.hidden = false;
    if (!(err instanceof CryptoPicError || err instanceof StegoError)) console.error(err);
  }
}

function updateDecryptButton() {
  $("btn-decrypt").disabled = !(openState.parsed && $("open-password").value.length > 0);
}

async function doDecrypt() {
  if (!openState.parsed) return;
  if (!ensureCanvasStable()) return;
  const password = $("open-password").value;
  const status = $("open-status");
  status.hidden = false;
  status.classList.remove("error");
  status.innerHTML = '<span class="spinner"></span> Memeriksa sandi dan membuka pesan…';
  $("btn-decrypt").disabled = true;
  $("open-error").hidden = true;

  try {
    const keys = await deriveKeys(password, openState.parsed.salt, openState.parsed.kdf);
    const ciphertext = await extractProtectedBody(openState.imageData, openState.parsed, keys.stegoKey);
    const message = await decryptPayload(password, openState.parsed, ciphertext, keys);

    $("open-message").textContent = message;
    const when = new Date().toLocaleString("id-ID", {
      day: "numeric",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
    $("open-result-meta").textContent = `${openState.fileName} · ${when}`;
    $("open-result").hidden = false;
    $("open-result-placeholder").hidden = true;
    status.hidden = true;
    $("open-password").value = "";

    autoSaveMemo(message);
  } catch (err) {
    status.hidden = true;
    const box = $("open-error");
    box.textContent = err instanceof CryptoPicError || err instanceof StegoError ? err.message : "Gagal mendekripsi.";
    box.hidden = false;
    if (!(err instanceof CryptoPicError || err instanceof StegoError)) console.error(err);
  } finally {
    updateDecryptButton();
  }
}

async function autoSaveMemo(message) {
  const result = await saveMemo({
    text: message,
    hint: openState.parsed ? openState.parsed.hint : "",
    fileName: openState.fileName,
  });

  if (result.ok) {
    updateMemoBadge();
    if ($("view-memo").classList.contains("active")) refreshMemoView();
    const pct = Math.round(result.usage.percent);
    if (pct >= 95) {
      showToast(`Tersimpan ke Memo — penyimpanan kritis (${pct}%). Segera hapus memo lama.`, "warn", 5500);
    } else if (pct >= 80) {
      showToast(`Tersimpan ke Memo — penyimpanan hampir penuh (${pct}%).`, "warn", 5000);
    } else {
      showToast("Pesan berhasil dibuka & tersimpan ke Memo.", "ok");
    }
  } else if (result.reason === "LOCKED") {
    showToast(
      "Pesan dibuka, tetapi Memo sedang terkunci sehingga tidak tersimpan otomatis. Buka kunci Memo di tab Memo untuk menyimpannya.",
      "warn",
      6000
    );
  } else if (result.reason === "FULL" || result.reason === "QUOTA") {
    showToast(
      "Penyimpanan memo penuh — pesan tidak tersimpan otomatis. Hapus memo lama di tab Memo; pesan tetap tampil di layar.",
      "error",
      6500
    );
    updateMemoBadge();
  } else {
    showToast("Penyimpanan browser tidak tersedia (mode privat?) — memo tidak dapat disimpan.", "warn", 5000);
  }
}

/* ---------------- Alur: Gunakan Lagi ---------------- */

let reuseBusy = false;

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

async function handleReuseImage() {
  if (reuseBusy || !openState.imageData) return;

  const hasTypedContent =
    $("secret-text").value.trim() !== "" ||
    $("hide-hint").value.trim() !== "" ||
    $("hide-password").value !== "";
  if (hideState.img || hasTypedContent) {
    if (!confirm("Gambar dan isian yang sedang ada di tab Sembunyikan akan diganti. Lanjutkan?")) {
      return;
    }
  }

  reuseBusy = true;
  $("btn-reuse").disabled = true;
  $("btn-reuse-preview").disabled = true;

  const overlay = $("cleanse-overlay");
  const stage = $("cleanse-stage");
  const started = Date.now();
  const minDuration = prefersReducedMotion() ? 350 : 1500;

  $("cleanse-thumb").src = $("open-preview-img").getAttribute("src") || "";
  stage.textContent = "Membaca piksel…";
  overlay.hidden = false;
  document.body.classList.add("cleansing");

  try {
    await waitMs(120);
    stage.textContent = "Menyucikan piksel…";
    const blob = await sanitizeToPngBlob(openState.imageData);

    stage.textContent = "Menyiapkan gambar bersih…";
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const file = new File([blob], `cryptopic-bersih-${stamp}.png`, { type: "image/png" });

    const remaining = minDuration - (Date.now() - started);
    if (remaining > 0) await waitMs(remaining);

    resetHideImage();
    $("secret-text").value = "";
    $("hide-password").value = "";
    $("hide-hint").value = "";
    await handleHideFile(file);
    if (!hideState.img) {
      throw new Error("Gambar hasil pembersihan tidak dapat dimuat.");
    }

    switchView("hide");
    showToast("Gambar sudah bersih. Siap dipakai lagi.", "ok", 4000);
    await waitMs(150);
    $("secret-text").focus();
  } catch (err) {
    const message = err instanceof StegoError || err instanceof Error
      ? err.message
      : "Gagal membersihkan gambar.";
    showToast(message, "error", 6000);
    if (!(err instanceof StegoError)) console.error(err);
  } finally {
    overlay.hidden = true;
    document.body.classList.remove("cleansing");
    reuseBusy = false;
    $("btn-reuse").disabled = false;
    $("btn-reuse-preview").disabled = false;
  }
}

/* ---------------- Memo ---------------- */

let selectMode = false;

function updateMemoBadge() {
  const badge = $("memo-badge");
  if (!storageAvailable()) {
    badge.hidden = true;
    return;
  }
  const count = listMemos().length;
  badge.hidden = count === 0;
  badge.textContent = String(count);
}

function formatMemoDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return "";
  return d.toLocaleString("id-ID", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function refreshMemoView() {
  const usage = getUsage();
  const storageText = $("storage-text");
  const fill = $("storage-fill");
  const bar = $("storage-progress");
  const warning = $("storage-warning");
  const warningText = $("storage-warning-text");

  if (!storageAvailable()) {
    storageText.textContent = "Penyimpanan tidak tersedia";
    fill.style.width = "0%";
    bar.setAttribute("aria-valuenow", "0");
    warning.hidden = false;
    warningText.textContent =
      "Browser tidak mengizinkan penyimpanan lokal (kemungkinan mode privat). Memo tidak dapat disimpan.";
    fill.className = "storage-fill";
  } else {
    storageText.textContent = `Terpakai ${formatBytes(usage.usedBytes)} dari ${formatBytes(MAX_BYTES)}`;
    const pct = Math.min(100, usage.percent);
    fill.style.width = `${pct}%`;
    bar.setAttribute("aria-valuenow", String(Math.round(usage.percent)));
    fill.className = "storage-fill";
    if (usage.level === "warn" || usage.level === "critical" || usage.level === "full") {
      fill.classList.add(usage.level === "critical" || usage.level === "full" ? "critical" : "warn");
    }
    if (usage.level === "warn") {
      warning.hidden = false;
      warningText.textContent = `Penyimpanan hampir penuh (${Math.round(usage.percent)}%). Hapus beberapa memo lama agar tetap muat.`;
    } else if (usage.level === "critical") {
      warning.hidden = false;
      warningText.textContent = `Penyimpanan kritis (${Math.round(usage.percent)}%). Segera hapus memo lama — memo baru mungkin gagal tersimpan.`;
    } else if (usage.level === "full") {
      warning.hidden = false;
      warningText.textContent = "Penyimpanan penuh. Memo baru tidak akan tersimpan otomatis sampai Anda menghapus memo lama.";
    } else {
      warning.hidden = true;
    }
  }

  const locked = vaultEnabled() && !isUnlocked();
  $("toolbar-normal").hidden = locked || selectMode;
  $("toolbar-select").hidden = locked || !selectMode;
  refreshVaultUi();
  renderMemoList();
  updateMemoBadge();
}

const TRASH_SVG =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M5 7h14M10 7V5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2M8 7l1 12a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1l1-12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M10.5 11v5M13.5 11v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';

function renderMemoList() {
  const list = $("memo-list");
  const empty = $("memo-empty");
  list.textContent = "";

  if (vaultEnabled() && !isUnlocked()) {
    $("memo-count").textContent = "";
    list.hidden = true;
    empty.hidden = false;
    const line = empty.querySelector("p");
    if (line) {
      line.textContent = "Memo terkunci dan terenkripsi. Buka kunci dengan PIN untuk melihat memo tersimpan.";
    }
    return;
  }

  const memos = listMemos();
  const line = empty.querySelector("p");
  if (line) {
    line.textContent = "Belum ada memo. Memo otomatis tersimpan setiap kali Anda berhasil membuka pesan.";
  }

  $("memo-count").textContent = memos.length > 0 ? `(${memos.length})` : "";
  empty.hidden = memos.length > 0;
  list.hidden = memos.length === 0;

  for (const memo of memos) {
    const li = document.createElement("li");
    li.className = "memo-item";
    li.dataset.id = memo.id;

    const summary = document.createElement("div");
    summary.className = "memo-summary";

    const check = document.createElement("input");
    check.type = "checkbox";
    check.className = "memo-check";
    check.hidden = !selectMode;
    check.setAttribute("aria-label", "Pilih memo ini");

    const body = document.createElement("div");
    body.className = "memo-body";
    body.tabIndex = 0;
    body.setAttribute("role", "button");
    body.setAttribute("aria-expanded", "false");

    const preview = document.createElement("p");
    preview.className = "memo-preview";
    preview.textContent = memo.text.length > 140 ? memo.text.slice(0, 140) + "…" : memo.text;

    const meta = document.createElement("div");
    meta.className = "memo-meta";
    const dateSpan = document.createElement("span");
    dateSpan.textContent = formatMemoDate(memo.createdAt);
    meta.appendChild(dateSpan);
    if (memo.fileName) {
      const fileSpan = document.createElement("span");
      fileSpan.textContent = `🖼 ${memo.fileName}`;
      meta.appendChild(fileSpan);
    }
    if (memo.hint) {
      const hintSpan = document.createElement("span");
      hintSpan.className = "memo-hint-inline";
      hintSpan.textContent = `💡 ${memo.hint}`;
      meta.appendChild(hintSpan);
    }

    body.append(preview, meta);

    const del = document.createElement("button");
    del.type = "button";
    del.className = "memo-delete";
    del.innerHTML = TRASH_SVG;
    del.setAttribute("aria-label", "Hapus memo ini");
    del.hidden = selectMode;
    del.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (confirm("Hapus memo ini? Tindakan ini tidak bisa dibatalkan.")) {
        await deleteMemos([memo.id]);
        refreshMemoView();
        showToast("Memo dihapus.", "ok", 2500);
      }
    });

    check.addEventListener("click", (e) => e.stopPropagation());
    check.addEventListener("change", () => {
      li.classList.toggle("selected", check.checked);
      updateSelectAllState();
      updateDeleteSelectedButton();
    });

    const full = document.createElement("div");
    full.className = "memo-full";
    full.hidden = true;

    if (memo.hint) {
      const hintBlock = document.createElement("p");
      hintBlock.className = "memo-hint-block";
      const strong = document.createElement("strong");
      strong.textContent = "Petunjuk: ";
      hintBlock.append(strong, document.createTextNode(memo.hint));
      full.appendChild(hintBlock);
    }

    const messageBox = document.createElement("pre");
    messageBox.className = "message-box";
    messageBox.textContent = memo.text;
    full.appendChild(messageBox);

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-ghost btn-sm";
    copyBtn.textContent = "Salin teks";
    copyBtn.style.marginTop = "10px";
    copyBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      copyText(memo.text);
    });
    full.appendChild(copyBtn);

    function toggleFull() {
      full.hidden = !full.hidden;
      body.setAttribute("aria-expanded", String(!full.hidden));
    }
    body.addEventListener("click", toggleFull);
    body.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleFull();
      }
    });

    summary.append(check, body, del);
    li.append(summary, full);
    list.appendChild(li);
  }

  updateSelectAllState();
  updateDeleteSelectedButton();
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(
      () => showToast("Teks disalin.", "ok", 2000),
      () => fallbackCopy(text)
    );
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    showToast("Teks disalin.", "ok", 2000);
  } catch {
    showToast("Gagal menyalin teks.", "error");
  }
  ta.remove();
}

function setSelectMode(on) {
  selectMode = on;
  $("toolbar-normal").hidden = on;
  $("toolbar-select").hidden = !on;
  if (!on) $("select-all").checked = false;
  renderMemoList();
}

function updateSelectAllState() {
  const checks = [...document.querySelectorAll(".memo-check")];
  const selectAll = $("select-all");
  const checkedCount = checks.filter((c) => c.checked).length;
  selectAll.checked = checks.length > 0 && checkedCount === checks.length;
  selectAll.indeterminate = checkedCount > 0 && checkedCount < checks.length;
}

function updateDeleteSelectedButton() {
  const checkedCount = document.querySelectorAll(".memo-check:checked").length;
  $("btn-delete-selected").disabled = checkedCount === 0;
  $("btn-delete-selected").textContent = checkedCount > 0 ? `Hapus (${checkedCount})` : "Hapus";
}

/* ---------------- Memo vault (PIN) ---------------- */

let vaultMode = null;
let vaultError = "";

function vaultErrorMessage(reason) {
  switch (reason) {
    case "WEAK":
      return `PIN minimal ${MIN_PIN_LENGTH} karakter.`;
    case "ALREADY":
      return "PIN sudah aktif.";
    case "LOCKED":
      return "Memo sedang terkunci.";
    case "QUOTA":
      return "Gagal menyimpan karena penyimpanan penuh.";
    case "UNAVAILABLE":
      return "Penyimpanan tidak tersedia.";
    case "CRYPTO":
      return "Modul kriptografi tidak tersedia. Muat ulang halaman lalu coba lagi.";
    default:
      return "Terjadi kesalahan.";
  }
}

function refreshVaultUi() {
  const desc = $("vault-desc");
  if (!desc) return;
  const primary = $("btn-vault-primary");
  const disable = $("btn-vault-disable");
  const form = $("vault-form");
  const pin = $("vault-pin");
  const confirmPin = $("vault-pin-confirm");
  const submit = $("btn-vault-submit");
  const errorEl = $("vault-error");

  errorEl.hidden = !vaultError;
  errorEl.textContent = vaultError;

  if (!storageAvailable()) {
    desc.textContent = "Penyimpanan memo tidak tersedia di browser ini.";
    primary.hidden = true;
    disable.hidden = true;
    form.hidden = true;
    return;
  }

  if (vaultEnabled() && !isUnlocked()) {
    desc.textContent = "Memo dienkripsi dengan PIN dan sedang terkunci. Masukkan PIN untuk membuka.";
    primary.textContent = "Buka Kunci";
    primary.hidden = vaultMode === "unlock";
    disable.hidden = true;
    if (vaultMode === "unlock") {
      form.hidden = false;
      confirmPin.hidden = true;
      submit.textContent = "Buka Kunci";
      pin.placeholder = "PIN memo";
      pin.autocomplete = "current-password";
    } else {
      form.hidden = true;
    }
    return;
  }

  if (vaultEnabled() && isUnlocked()) {
    desc.textContent = "Memo dienkripsi dengan PIN (terbuka). Kunci kembali saat selesai memakainya.";
    primary.textContent = "Kunci Sekarang";
    primary.hidden = false;
    disable.hidden = false;
    form.hidden = true;
    return;
  }

  desc.textContent = "Memo disimpan sebagai teks biasa di browser ini. Aktifkan PIN untuk mengenkripsinya saat disimpan.";
  primary.textContent = "Aktifkan PIN";
  primary.hidden = vaultMode === "enable";
  disable.hidden = true;
  if (vaultMode === "enable") {
    form.hidden = false;
    confirmPin.hidden = false;
    submit.textContent = "Aktifkan";
    pin.placeholder = `PIN memo (min. ${MIN_PIN_LENGTH} karakter)`;
    pin.autocomplete = "new-password";
  } else {
    form.hidden = true;
  }
}

function resetVaultForm() {
  vaultMode = null;
  vaultError = "";
  $("vault-pin").value = "";
  $("vault-pin-confirm").value = "";
  refreshVaultUi();
}

function handleVaultPrimary() {
  if (vaultEnabled() && isUnlocked()) {
    lockMemos();
    vaultMode = null;
    vaultError = "";
    refreshMemoView();
    showToast("Memo dikunci.", "ok", 2500);
    return;
  }
  vaultMode = vaultEnabled() ? "unlock" : "enable";
  vaultError = "";
  refreshVaultUi();
  setTimeout(() => $("vault-pin").focus(), 0);
}

async function handleVaultSubmit() {
  const pin = $("vault-pin").value;
  vaultError = "";

  if (vaultMode === "enable") {
    if (pin.length < MIN_PIN_LENGTH) {
      vaultError = `PIN minimal ${MIN_PIN_LENGTH} karakter.`;
      refreshVaultUi();
      return;
    }
    if (pin !== $("vault-pin-confirm").value) {
      vaultError = "PIN dan ulangan PIN tidak sama.";
      refreshVaultUi();
      return;
    }
    const result = await enableMemoPin(pin);
    if (!result.ok) {
      vaultError = vaultErrorMessage(result.reason);
      refreshVaultUi();
      return;
    }
    $("vault-pin").value = "";
    $("vault-pin-confirm").value = "";
    vaultMode = null;
    refreshMemoView();
    showToast("PIN aktif. Memo baru akan dienkripsi.", "ok", 4000);
    return;
  }

  if (vaultMode === "unlock") {
    const result = await unlockMemos(pin);
    if (!result.ok) {
      vaultError = "PIN salah.";
      refreshVaultUi();
      return;
    }
    $("vault-pin").value = "";
    vaultMode = null;
    refreshMemoView();
    if (result.migrated) {
      showToast("Memo terbuka. Keamanan memo ditingkatkan ke Argon2id.", "ok", 4000);
    } else {
      showToast("Memo terbuka.", "ok", 2500);
    }
  }
}

async function handleVaultDisable() {
  if (!confirm("Matikan PIN dan simpan memo sebagai teks biasa? Tindakan ini mengurangi keamanan.")) {
    return;
  }
  const result = await disableMemoPin();
  if (!result.ok) {
    showToast(vaultErrorMessage(result.reason), "error", 5000);
    return;
  }
  refreshMemoView();
  showToast("PIN dimatikan. Memo kembali tersimpan sebagai teks biasa.", "warn", 5000);
}

/**
 * Deteksi perlindungan fingerprinting yang mengacak piksel canvas
 * (mis. Brave Shields). Steganografi LSB tidak akan bertahan di lingkungan itu.
 */
function canvasPixelsAreStable() {
  try {
    const size = 16;
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return true;
    const source = new Uint8ClampedArray(size * size * 4);
    for (let i = 0; i < source.length; i++) source[i] = (i * 37 + 11) & 0xff;
    for (let i = 3; i < source.length; i += 4) source[i] = 255;
    ctx.putImageData(new ImageData(source, size, size), 0, 0);
    const read = ctx.getImageData(0, 0, size, size).data;
    for (let i = 0; i < source.length; i++) {
      if (read[i] !== source[i]) return false;
    }
    return true;
  } catch {
    return true;
  }
}

let canvasStable = true;

function ensureCanvasStable() {
  canvasStable = canvasPixelsAreStable();
  $("pixel-warning").hidden = canvasStable;
  if (!canvasStable) {
    showToast(
      "Browser mengacak piksel canvas. Matikan Shields untuk situs ini, lalu muat ulang halaman.",
      "error",
      8000
    );
  }
  return canvasStable;
}

/* ---------------- Init ---------------- */

function init() {
  initTheme();
  setupPwToggles();
  requestPersistentStorage();
  canvasStable = canvasPixelsAreStable();
  $("pixel-warning").hidden = canvasStable;

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
  $("theme-toggle").addEventListener("click", toggleTheme);

  setupUploadZone($("hide-drop"), $("hide-file"), handleHideFile);
  $("hide-replace").addEventListener("click", resetHideImage);
  $("hide-replace-result").addEventListener("click", resetHideImage);
  $("secret-text").addEventListener("input", updateHideUi);
  $("hide-password").addEventListener("input", updateHideUi);
  $("hide-hint").addEventListener("input", updateHideUi);
  $("btn-encrypt").addEventListener("click", doEncrypt);

  setupUploadZone($("open-drop"), $("open-file"), handleOpenFile);
  $("open-replace").addEventListener("click", resetOpen);
  $("open-password").addEventListener("input", updateDecryptButton);
  $("open-password").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !$("btn-decrypt").disabled) doDecrypt();
  });
  $("btn-decrypt").addEventListener("click", doDecrypt);
  $("btn-copy-message").addEventListener("click", () => copyText($("open-message").textContent));
  $("btn-reuse").addEventListener("click", handleReuseImage);
  $("btn-reuse-preview").addEventListener("click", handleReuseImage);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("cleanse-overlay").hidden) {
      $("cleanse-overlay").hidden = true;
      document.body.classList.remove("cleansing");
    }
  });
  $("btn-close-result").addEventListener("click", () => {
    $("open-result").hidden = true;
  });

  $("btn-select-mode").addEventListener("click", () => setSelectMode(true));
  $("btn-cancel-select").addEventListener("click", () => setSelectMode(false));
  $("select-all").addEventListener("change", (e) => {
    for (const check of document.querySelectorAll(".memo-check")) {
      check.checked = e.target.checked;
      check.closest(".memo-item").classList.toggle("selected", check.checked);
    }
    updateDeleteSelectedButton();
  });
  $("btn-delete-selected").addEventListener("click", async () => {
    const ids = [...document.querySelectorAll(".memo-check:checked")].map((c) => c.closest(".memo-item").dataset.id);
    if (ids.length === 0) return;
    if (confirm(`Hapus ${ids.length} memo terpilih? Tindakan ini tidak bisa dibatalkan.`)) {
      await deleteMemos(ids);
      setSelectMode(false);
      refreshMemoView();
      showToast(`${ids.length} memo dihapus.`, "ok", 2500);
    }
  });

  $("btn-vault-primary").addEventListener("click", handleVaultPrimary);
  $("btn-vault-disable").addEventListener("click", handleVaultDisable);
  $("btn-vault-submit").addEventListener("click", handleVaultSubmit);
  $("btn-vault-cancel").addEventListener("click", resetVaultForm);
  $("vault-pin").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleVaultSubmit();
  });
  $("vault-pin-confirm").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleVaultSubmit();
  });

  updateHideUi();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js?v=" + Date.now(), { updateViaCache: "none" }).catch(() => {
      /* SW belum tersedia / HTTP non-localhost — abaikan */
    });

    watchBuildVersion();
  }

  initStorage().then(() => {
    updateMemoBadge();
    refreshVaultUi();
    if (document.getElementById("view-memo").classList.contains("active")) refreshMemoView();
  });
}

function watchBuildVersion() {
  const meta = document.querySelector('meta[name="cryptopic-build"]');
  const current = meta ? meta.content : "";
  if (!current || current.includes("__BUILD_VERSION__")) return;

  let reloading = false;
  let lastSeen = current;

  const reloadOnce = () => {
    if (reloading) return;
    reloading = true;
    window.location.reload();
  };

  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!navigator.serviceWorker.controller) return;
    if (lastSeen !== current) reloadOnce();
  });

  const check = async () => {
    if (reloading) return;
    try {
      const res = await fetch("index.html?t=" + Date.now(), { cache: "no-store" });
      const html = await res.text();
      const match = html.match(/name="cryptopic-build" content="([^"]+)"/);
      if (
        match &&
        !match[1].includes("__BUILD_VERSION__") &&
        match[1] !== lastSeen
      ) {
        lastSeen = match[1];
        reloadOnce();
      }
    } catch {
      /* offline — abaikan */
    }
  };

  setInterval(check, 20000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") check();
  });
}

init();
