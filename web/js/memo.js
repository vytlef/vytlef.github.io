const DB_NAME = "cryptopic";
const DB_VERSION = 1;
const STORE = "memos";
const LEGACY_INDEX_KEY = "cryptopic:index";
const LEGACY_MEMO_PREFIX = "cryptopic:memo:";

export const MAX_BYTES = 200 * 1024 * 1024;
const WARN_PERCENT = 80;
const CRITICAL_PERCENT = 95;

const encoder = new TextEncoder();

let dbPromise = null;
let ready = false;
let cache = [];

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
    return false;
  }
  const migrated = migrateLegacy();
  try {
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const existing = await idbRequest(store.getAll());
    const existingIds = new Set(existing.map((m) => m.id));
    for (const memo of migrated) {
      if (!existingIds.has(memo.id)) store.put(memo);
    }
    await txDone(tx);
    const all = await idbRequest(db.transaction(STORE, "readonly").objectStore(STORE).getAll());
    cache = all.map(normalizeMemo).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    ready = true;
    return true;
  } catch {
    ready = false;
    cache = [];
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
  for (const memo of cache) {
    used += encoder.encode(JSON.stringify(memo)).length;
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

  const memo = {
    id: newId(),
    text,
    hint,
    fileName,
    createdAt: new Date().toISOString(),
  };

  const usage = getUsage();
  const size = encoder.encode(JSON.stringify(memo)).length;
  if (usage.usedBytes + size > MAX_BYTES) {
    return { ok: false, reason: "FULL", usage };
  }

  try {
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
    cache = cache.filter((m) => !idSet.has(m.id));
  } catch {
    /* ignore */
  }
}

export async function clearAll() {
  if (!ready) return;
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    await txDone(tx);
    cache = [];
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
