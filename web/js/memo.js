const INDEX_KEY = "cryptopic:index";
const MEMO_PREFIX = "cryptopic:memo:";
export const MAX_BYTES = 2 * 1024 * 1024;
const WARN_PERCENT = 80;
const CRITICAL_PERCENT = 95;

const encoder = new TextEncoder();

let available = null;

export function storageAvailable() {
  if (available !== null) return available;
  try {
    const probe = "cryptopic:probe";
    localStorage.setItem(probe, "1");
    localStorage.removeItem(probe);
    available = true;
  } catch {
    available = false;
  }
  return available;
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

function memoKey(id) {
  return MEMO_PREFIX + id;
}

function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function readIndex() {
  try {
    const raw = localStorage.getItem(INDEX_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function writeIndex(ids) {
  localStorage.setItem(INDEX_KEY, JSON.stringify(ids));
}

export function listMemos() {
  if (!storageAvailable()) return [];
  const memos = [];
  for (const id of readIndex()) {
    try {
      const raw = localStorage.getItem(memoKey(id));
      if (!raw) continue;
      const memo = JSON.parse(raw);
      if (memo && typeof memo.text === "string") {
        memos.push({
          id,
          text: memo.text,
          hint: typeof memo.hint === "string" ? memo.hint : "",
          fileName: typeof memo.fileName === "string" ? memo.fileName : "",
          createdAt: typeof memo.createdAt === "string" ? memo.createdAt : "",
        });
      }
    } catch {
      /* entry korup — lewati */
    }
  }
  return memos;
}

export function getUsage() {
  if (!storageAvailable()) {
    return { usedBytes: 0, maxBytes: MAX_BYTES, percent: 0, level: "unavailable" };
  }
  let used = 0;
  used += encoder.encode(localStorage.getItem(INDEX_KEY) || "[]").length;
  for (const id of readIndex()) {
    const raw = localStorage.getItem(memoKey(id));
    if (raw) used += encoder.encode(raw).length;
  }
  const percent = (used / MAX_BYTES) * 100;
  let level = "ok";
  if (percent >= 100) level = "full";
  else if (percent >= CRITICAL_PERCENT) level = "critical";
  else if (percent >= WARN_PERCENT) level = "warn";
  return { usedBytes: used, maxBytes: MAX_BYTES, percent, level };
}

export function saveMemo({ text, hint = "", fileName = "" }) {
  if (!storageAvailable()) return { ok: false, reason: "UNAVAILABLE" };

  const memo = {
    id: newId(),
    text,
    hint,
    fileName,
    createdAt: new Date().toISOString(),
  };
  const json = JSON.stringify(memo);
  const size = encoder.encode(json).length;
  const usage = getUsage();
  if (usage.usedBytes + size > MAX_BYTES) {
    return { ok: false, reason: "FULL", usage };
  }

  const index = readIndex();
  try {
    localStorage.setItem(memoKey(memo.id), json);
    index.unshift(memo.id);
    writeIndex(index);
  } catch {
    try {
      localStorage.removeItem(memoKey(memo.id));
    } catch {
      /* ignore */
    }
    return { ok: false, reason: "QUOTA" };
  }
  return { ok: true, memo, usage: getUsage() };
}

export function deleteMemos(ids) {
  if (!storageAvailable()) return;
  const idSet = new Set(ids);
  for (const id of idSet) {
    try {
      localStorage.removeItem(memoKey(id));
    } catch {
      /* ignore */
    }
  }
  writeIndex(readIndex().filter((id) => !idSet.has(id)));
}

export function formatBytes(n) {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(2).replace(".", ",") + " MB";
  if (n >= 1024) return (n / 1024).toFixed(1).replace(".", ",") + " KB";
  return n + " B";
}
