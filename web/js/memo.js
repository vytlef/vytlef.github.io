const DB_NAME = "cryptopic";
const DB_VERSION = 1;
const STORE = "memos";
const LEGACY_INDEX_KEY = "cryptopic:index";
const LEGACY_MEMO_PREFIX = "cryptopic:memo:";
const VAULT_ID = "__vault__";
const VAULT_CHECK = "cryptopic-memo-vault-v1";
const PBKDF2_ITERATIONS = 600000;

export const MAX_BYTES = 200 * 1024 * 1024;
const WARN_PERCENT = 80;
const CRITICAL_PERCENT = 95;
export const MIN_PIN_LENGTH = 6;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let dbPromise = null;
let ready = false;
let cache = [];
let vaultRecord = null;
let vaultKey = null;
let unlocked = false;
let rawEncrypted = [];

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    if (!("indexedDB" in window)) {
      resolve(null);
      return;
    }
    let req;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: "id" });
        store.createIndex("createdAt", "createdAt");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  });
  return dbPromise;
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function normalizeMemo(memo) {
  return {
    id: memo.id,
    text: typeof memo.text === "string" ? memo.text : "",
    hint: typeof memo.hint === "string" ? memo.hint : "",
    fileName: typeof memo.fileName === "string" ? memo.fileName : "",
    createdAt: typeof memo.createdAt === "string" ? memo.createdAt : "",
  };
}

function sortMemos(list) {
  return list.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
}

/* ---------------- Enkripsi memo (PIN + AES-GCM) ---------------- */

function toBytes(text) {
  return encoder.encode(text);
}

async function deriveVaultKey(pin, salt) {
  const base = await crypto.subtle.importKey("raw", toBytes(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptString(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, toBytes(text))
  );
  return { iv, data };
}

async function decryptString(key, iv, data) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    key,
    new Uint8Array(data)
  );
  return decoder.decode(new Uint8Array(plain));
}

function encryptedSize(record) {
  const data = record && record.data;
  return (data && data.byteLength ? data.byteLength : 0) + 96;
}

function normalizeEncrypted(record) {
  return {
    id: record.id,
    createdAt: typeof record.createdAt === "string" ? record.createdAt : "",
    iv: record.iv,
    data: record.data,
  };
}

export function vaultEnabled() {
  return vaultRecord !== null;
}

export function isUnlocked() {
  return unlocked;
}

export async function enableMemoPin(pin) {
  if (!ready) return { ok: false, reason: "UNAVAILABLE" };
  if (vaultRecord) return { ok: false, reason: "ALREADY" };
  if (typeof pin !== "string" || pin.length < MIN_PIN_LENGTH) {
    return { ok: false, reason: "WEAK" };
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveVaultKey(pin, salt);
  const verifier = await encryptString(key, VAULT_CHECK);

  const records = [];
  for (const memo of cache) {
    const payload = await encryptString(
      key,
      JSON.stringify({ text: memo.text, hint: memo.hint, fileName: memo.fileName })
    );
    records.push({
      id: memo.id,
      createdAt: memo.createdAt,
      enc: 1,
      iv: payload.iv,
      data: payload.data,
    });
  }

  try {
    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    store.clear();
    store.put({ id: VAULT_ID, salt, verifierIv: verifier.iv, verifier: verifier.data });
    for (const record of records) store.put(record);
    await txDone(tx);
  } catch {
    return { ok: false, reason: "QUOTA" };
  }

  vaultRecord = { salt, verifierIv: verifier.iv, verifier: verifier.data };
  vaultKey = key;
  unlocked = true;
  rawEncrypted = records;
  return { ok: true };
}

export async function unlockMemos(pin) {
  if (!ready) return { ok: false, reason: "UNAVAILABLE" };
  if (!vaultRecord) return { ok: true };
  if (typeof pin !== "string" || pin.length === 0) return { ok: false, reason: "WRONG_PIN" };

  const key = await deriveVaultKey(pin, vaultRecord.salt);
  try {
    const check = await decryptString(key, vaultRecord.verifierIv, vaultRecord.verifier);
    if (check !== VAULT_CHECK) return { ok: false, reason: "WRONG_PIN" };
  } catch {
    return { ok: false, reason: "WRONG_PIN" };
  }

  try {
    const db = await openDB();
    const all = await idbRequest(db.transaction(STORE, "readonly").objectStore(STORE).getAll());
    const decoded = [];
    const raw = [];
    for (const record of all) {
      if (!record || record.id === VAULT_ID || record.enc !== 1) continue;
      raw.push(normalizeEncrypted(record));
      try {
        const json = await decryptString(key, record.iv, record.data);
        const obj = JSON.parse(json);
        decoded.push({
          id: record.id,
          text: typeof obj.text === "string" ? obj.text : "",
          hint: typeof obj.hint === "string" ? obj.hint : "",
          fileName: typeof obj.fileName === "string" ? obj.fileName : "",
          createdAt: typeof record.createdAt === "string" ? record.createdAt : "",
        });
      } catch {
        /* entri korup — lewati */
      }
    }
    cache = sortMemos(decoded);
    rawEncrypted = sortMemos(raw);
  } catch {
    return { ok: false, reason: "UNAVAILABLE" };
  }

  vaultKey = key;
  unlocked = true;
  return { ok: true };
}

export function lockMemos() {
  if (!vaultRecord) return;
  vaultKey = null;
  unlocked = false;
  cache = [];
}

export async function disableMemoPin() {
  if (!ready) return { ok: false, reason: "UNAVAILABLE" };
  if (!vaultRecord) return { ok: true };
  if (!unlocked || !vaultKey) return { ok: false, reason: "LOCKED" };

  const plainMemos = cache.map((memo) => normalizeMemo(memo));
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    store.clear();
    for (const memo of plainMemos) store.put(memo);
    await txDone(tx);
  } catch {
    return { ok: false, reason: "QUOTA" };
  }

  vaultRecord = null;
  vaultKey = null;
  unlocked = true;
  rawEncrypted = [];
  cache = plainMemos;
  return { ok: true };
}

/* ---------------- Migrasi data lama ---------------- */

function migrateLegacy() {
  try {
    const rawIndex = localStorage.getItem(LEGACY_INDEX_KEY);
    if (!rawIndex) return [];
    const ids = JSON.parse(rawIndex);
    if (!Array.isArray(ids)) return [];
    const migrated = [];
    for (const id of ids) {
      if (typeof id !== "string") continue;
      const raw = localStorage.getItem(LEGACY_MEMO_PREFIX + id);
      if (!raw) continue;
      try {
        const memo = JSON.parse(raw);
        if (memo && typeof memo.text === "string") migrated.push(normalizeMemo(memo));
      } catch {
        /* entry korup — lewati */
      }
    }
    for (const id of ids) {
      if (typeof id === "string") localStorage.removeItem(LEGACY_MEMO_PREFIX + id);
    }
    localStorage.removeItem(LEGACY_INDEX_KEY);
    return migrated;
  } catch {
    return [];
  }
}

export async function initStorage() {
  const db = await openDB();
  if (!db) {
    ready = false;
    cache = [];
    vaultRecord = null;
    unlocked = false;
    return false;
  }

  try {
    const all = await idbRequest(db.transaction(STORE, "readonly").objectStore(STORE).getAll());
    const storedVault = all.find((record) => record && record.id === VAULT_ID);

    if (storedVault && storedVault.salt && storedVault.verifier) {
      vaultRecord = {
        salt: new Uint8Array(storedVault.salt),
        verifierIv: new Uint8Array(storedVault.verifierIv),
        verifier: new Uint8Array(storedVault.verifier),
      };
      vaultKey = null;
      unlocked = false;
      cache = [];
      rawEncrypted = sortMemos(
        all.filter((record) => record && record.id !== VAULT_ID && record.enc === 1).map(normalizeEncrypted)
      );
    } else {
      vaultRecord = null;
      vaultKey = null;
      unlocked = true;

      const migrated = migrateLegacy();
      const existingIds = new Set(all.map((memo) => memo.id));
      const toStore = migrated.filter((memo) => !existingIds.has(memo.id));
      if (toStore.length > 0) {
        const tx = db.transaction(STORE, "readwrite");
        const store = tx.objectStore(STORE);
        for (const memo of toStore) store.put(memo);
        await txDone(tx);
      }
      const plain = toStore.length > 0
        ? await idbRequest(db.transaction(STORE, "readonly").objectStore(STORE).getAll())
        : all;
      cache = sortMemos(
        plain.filter((memo) => memo && memo.id !== VAULT_ID).map(normalizeMemo)
      );
      rawEncrypted = [];
    }

    ready = true;
    return true;
  } catch {
    ready = false;
    cache = [];
    vaultRecord = null;
    unlocked = false;
    return false;
  }
}

export function storageAvailable() {
  return ready;
}

export function listMemos() {
  return cache;
}

export function getUsage() {
  if (!ready) {
    return { usedBytes: 0, maxBytes: MAX_BYTES, percent: 0, level: "unavailable" };
  }
  let used = 0;
  if (vaultRecord && !unlocked) {
    for (const record of rawEncrypted) used += encryptedSize(record);
  } else {
    for (const memo of cache) used += encoder.encode(JSON.stringify(memo)).length;
  }
  const percent = (used / MAX_BYTES) * 100;
  let level = "ok";
  if (percent >= 100) level = "full";
  else if (percent >= CRITICAL_PERCENT) level = "critical";
  else if (percent >= WARN_PERCENT) level = "warn";
  return { usedBytes: used, maxBytes: MAX_BYTES, percent, level };
}

function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

export async function saveMemo({ text, hint = "", fileName = "" }) {
  if (!ready) return { ok: false, reason: "UNAVAILABLE" };
  if (vaultRecord && !unlocked) return { ok: false, reason: "LOCKED" };

  const memo = {
    id: newId(),
    text,
    hint,
    fileName,
    createdAt: new Date().toISOString(),
  };

  try {
    if (vaultRecord) {
      const payload = await encryptString(
        vaultKey,
        JSON.stringify({ text: memo.text, hint: memo.hint, fileName: memo.fileName })
      );
      const record = {
        id: memo.id,
        createdAt: memo.createdAt,
        enc: 1,
        iv: payload.iv,
        data: payload.data,
      };
      const usage = getUsage();
      if (usage.usedBytes + encryptedSize(record) > MAX_BYTES) {
        return { ok: false, reason: "FULL", usage };
      }
      const db = await openDB();
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(record);
      await txDone(tx);
      rawEncrypted = sortMemos([record, ...rawEncrypted]);
      cache = [memo, ...cache];
      return { ok: true, memo, usage: getUsage() };
    }

    const usage = getUsage();
    const size = encoder.encode(JSON.stringify(memo)).length;
    if (usage.usedBytes + size > MAX_BYTES) {
      return { ok: false, reason: "FULL", usage };
    }

    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(memo);
    await txDone(tx);
    cache = [memo, ...cache];
    return { ok: true, memo, usage: getUsage() };
  } catch {
    return { ok: false, reason: "QUOTA" };
  }
}

export async function deleteMemos(ids) {
  if (!ready) return;
  const idSet = new Set(ids);
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    for (const id of idSet) store.delete(id);
    await txDone(tx);
    cache = cache.filter((memo) => !idSet.has(memo.id));
    rawEncrypted = rawEncrypted.filter((record) => !idSet.has(record.id));
  } catch {
    /* ignore */
  }
}

export async function clearAll() {
  if (!ready) return;
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    for (const memo of cache) store.delete(memo.id);
    for (const record of rawEncrypted) store.delete(record.id);
    await txDone(tx);
    cache = [];
    rawEncrypted = [];
  } catch {
    /* ignore */
  }
}

export async function requestPersistentStorage() {
  try {
    if (navigator.storage && navigator.storage.persist) {
      await navigator.storage.persist();
    }
  } catch {
    /* mode privat / browser tanpa dukungan — abaikan */
  }
}

export function formatBytes(n) {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(2).replace(".", ",") + " MB";
  if (n >= 1024) return (n / 1024).toFixed(1).replace(".", ",") + " KB";
  return n + " B";
}
