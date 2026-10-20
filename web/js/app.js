import {
  encryptPayload,
  parsePayload,
  decryptPayload,
  overheadBytes,
  CryptoPicError,
} from "./crypto.js";
import {
  validatePNGFile,
  pngRejectMessage,
  loadImageFromFile,
  imageToImageData,
  capacityBytes,
  embedPayload,
  extractPayload,
  imageDataToPngBlob,
  StegoError,
} from "./stego.js";
import {
  listMemos,
  saveMemo,
  deleteMemos,
  getUsage,
  storageAvailable,
  requestPersistentStorage,
  formatBytes,
  MAX_BYTES,
} from "./memo.js";

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();

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
  if (document.startViewTransition) {
    document.documentElement.classList.add("vt-supported");
  }
}

function toggleTheme(event) {
  const current = document.documentElement.dataset.theme;
  const next = current === "dark" ? "light" : "dark";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (document.startViewTransition && !reduce) {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const radius = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
    const root = document.documentElement;
    root.style.setProperty("--tx", `${x}px`);
    root.style.setProperty("--ty", `${y}px`);
    root.style.setProperty("--radius", `${radius}px`);
    root.classList.add("theme-animating");
    const transition = document.startViewTransition(() => applyTheme(next));
    transition.finished.finally(() => root.classList.remove("theme-animating"));
  } else {
    applyTheme(next);
  }
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

const hideState = { img: null, width: 0, height: 0, fileName: "", stegoUrl: null };

function hideAvailable() {
  if (!hideState.img) return 0;
  const total = capacityBytes(hideState.width, hideState.height);
  const hint = $("hide-hint").value.trim();
  return Math.max(0, total - overheadBytes(hint));
}

function updateHideUi() {
  const secret = $("secret-text").value;
  const bytes = encoder.encode(secret).length;
  const avail = hideAvailable();

  $("secret-counter").textContent = `${formatBytes(bytes)}`;
  const counter = $("secret-counter");
  if (bytes > avail && hideState.img) {
    counter.classList.add("over");
    $("secret-cap-info").textContent = `Melebihi kapasitas (${formatBytes(avail)} tersedia)`;
  } else {
    counter.classList.remove("over");
    $("secret-cap-info").textContent = hideState.img ? `${formatBytes(avail)} tersedia` : "";
  }

  const canEncrypt =
    !!hideState.img && secret.trim().length > 0 && $("hide-password").value.length > 0 && bytes <= avail;
  $("btn-encrypt").disabled = !canEncrypt;
}

async function handleHideFile(file) {
  if (!validatePNGFile(file)) {
    showToast(pngRejectMessage(file), "error", 6000);
    return;
  }
  try {
    const img = await loadImageFromFile(file);
    hideState.img = img;
    hideState.width = img.naturalWidth;
    hideState.height = img.naturalHeight;
    hideState.fileName = file.name;
    $("hide-preview-img").src = URL.createObjectURL(file);
    $("hide-file-name").textContent = file.name;
    $("hide-file-dims").textContent = `${img.naturalWidth}×${img.naturalHeight}px`;
    $("hide-capacity").textContent = `Kapasitas ${formatBytes(capacityBytes(img.naturalWidth, img.naturalHeight))}`;
    $("hide-drop").hidden = true;
    $("hide-preview-wrap").hidden = false;
    $("hide-result").hidden = true;
    updateHideUi();
  } catch (err) {
    showToast(err.message, "error", 6000);
  }
}

function resetHideImage() {
  hideState.img = null;
  hideState.fileName = "";
  $("hide-drop").hidden = false;
  $("hide-preview-wrap").hidden = true;
  $("hide-result").hidden = true;
  updateHideUi();
}

async function doEncrypt() {
  const secret = $("secret-text").value;
  const password = $("hide-password").value;
  const hint = $("hide-hint").value.trim();

  if (!hideState.img || !secret.trim() || !password) return;

  const status = $("hide-status");
  status.hidden = false;
  status.classList.remove("error");
  status.innerHTML = '<span class="spinner"></span> Mengenkripsi & menyisipkan pesan…';
  $("btn-encrypt").disabled = true;

  try {
    const img = hideState.img;
    const { imageData } = imageToImageData(img);
    const payload = await encryptPayload(password, secret, hint);
    const embedded = embedPayload(imageData, payload);
    const blob = await imageDataToPngBlob(embedded);

    if (hideState.stegoUrl) URL.revokeObjectURL(hideState.stegoUrl);
    hideState.stegoUrl = URL.createObjectURL(blob);

    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const downloadName = `cryptopic-${stamp}.png`;
    const link = $("btn-download");
    link.href = hideState.stegoUrl;
    link.download = downloadName;

    $("stego-preview").src = hideState.stegoUrl;
    $("hide-result").hidden = false;
    status.hidden = true;
    $("hide-result").scrollIntoView({ behavior: "smooth", block: "nearest" });
    showToast("Pesan berhasil disembunyikan. Unduh gambar PNG-nya.", "ok");
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
  $("open-drop").hidden = false;
  $("open-preview-wrap").hidden = true;
  $("open-hint-box").hidden = true;
  $("open-password-field").hidden = true;
  $("open-password").value = "";
  $("btn-decrypt").disabled = true;
  $("open-error").hidden = true;
  $("open-status").hidden = true;
  $("open-result").hidden = true;
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
    const img = await loadImageFromFile(file);
    const { imageData } = imageToImageData(img);
    const payload = extractPayload(imageData);
    const parsed = parsePayload(payload);

    openState.parsed = parsed;
    openState.imageData = imageData;
    openState.fileName = file.name;

    $("open-preview-img").src = URL.createObjectURL(file);
    $("open-file-name").textContent = file.name;
    $("open-file-dims").textContent = `${img.naturalWidth}×${img.naturalHeight}px`;
    $("open-drop").hidden = true;
    $("open-preview-wrap").hidden = false;

    if (parsed.hint) {
      $("open-hint-text").textContent = parsed.hint;
      $("open-hint-box").hidden = false;
    }
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
  const password = $("open-password").value;
  const status = $("open-status");
  status.hidden = false;
  status.classList.remove("error");
  status.innerHTML = '<span class="spinner"></span> Mendekripsi…';
  $("btn-decrypt").disabled = true;
  $("open-error").hidden = true;

  try {
    const message = await decryptPayload(password, openState.parsed);

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
    status.hidden = true;
    $("open-result").scrollIntoView({ behavior: "smooth", block: "nearest" });

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

function autoSaveMemo(message) {
  const result = saveMemo({
    text: message,
    hint: openState.parsed ? openState.parsed.hint : "",
    fileName: openState.fileName,
  });

  if (result.ok) {
    updateMemoBadge();
    const pct = Math.round(result.usage.percent);
    if (pct >= 95) {
      showToast(`Tersimpan ke Memo — penyimpanan kritis (${pct}%). Segera hapus memo lama.`, "warn", 5500);
    } else if (pct >= 80) {
      showToast(`Tersimpan ke Memo — penyimpanan hampir penuh (${pct}%).`, "warn", 5000);
    } else {
      showToast("Pesan berhasil dibuka & tersimpan ke Memo.", "ok");
    }
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

  renderMemoList();
  updateMemoBadge();
}

const TRASH_SVG =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M5 7h14M10 7V5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2M8 7l1 12a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1l1-12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M10.5 11v5M13.5 11v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';

function renderMemoList() {
  const list = $("memo-list");
  const empty = $("memo-empty");
  list.textContent = "";
  const memos = listMemos();

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
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      if (confirm("Hapus memo ini? Tindakan ini tidak bisa dibatalkan.")) {
        deleteMemos([memo.id]);
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

/* ---------------- Init ---------------- */

function init() {
  initTheme();
  setupPwToggles();
  requestPersistentStorage();

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
  $("theme-toggle").addEventListener("click", toggleTheme);

  setupUploadZone($("hide-drop"), $("hide-file"), handleHideFile);
  $("hide-replace").addEventListener("click", resetHideImage);
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
  $("btn-delete-selected").addEventListener("click", () => {
    const ids = [...document.querySelectorAll(".memo-check:checked")].map((c) => c.closest(".memo-item").dataset.id);
    if (ids.length === 0) return;
    if (confirm(`Hapus ${ids.length} memo terpilih? Tindakan ini tidak bisa dibatalkan.`)) {
      deleteMemos(ids);
      setSelectMode(false);
      refreshMemoView();
      showToast(`${ids.length} memo dihapus.`, "ok", 2500);
    }
  });

  updateMemoBadge();
  updateHideUi();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* SW belum tersedia / HTTP non-localhost — abaikan */
    });
  }
}

init();
