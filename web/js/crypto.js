const MAGIC = new Uint8Array([0x43, 0x50, 0x49, 0x43]);
const VERSION = 1;
const FLAG_HINT = 1 << 0;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_FIXED = 40;
const PBKDF2_ITERATIONS = 310000;

export class CryptoPicError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CryptoPicError";
    this.code = code;
  }
}

export function normalizePassword(password) {
  return password.toLowerCase();
}

function toBytes(text) {
  return new TextEncoder().encode(text);
}

function fromBytes(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBytes(normalizePassword(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export function overheadBytes(hint) {
  const hintLen = hint ? toBytes(hint).length : 0;
  return HEADER_FIXED + hintLen + TAG_LEN;
}

export async function encryptPayload(password, message, hint = "") {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, toBytes(message))
  );

  const hintBytes = hint ? toBytes(hint) : new Uint8Array(0);
  if (hintBytes.length > 0xffff) {
    throw new CryptoPicError("HINT_TOO_LONG", "Petunjuk terlalu panjang (maks 65.535 byte).");
  }

  const total = HEADER_FIXED + hintBytes.length + ciphertext.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);

  out.set(MAGIC, 0);
  out[4] = VERSION;
  out[5] = hintBytes.length > 0 ? FLAG_HINT : 0;
  view.setUint32(6, total, false);
  out.set(salt, 10);
  out.set(iv, 26);
  view.setUint16(38, hintBytes.length, false);
  out.set(hintBytes, HEADER_FIXED);
  out.set(ciphertext, HEADER_FIXED + hintBytes.length);

  return out;
}

export function parsePayload(payload) {
  if (payload.length < HEADER_FIXED) {
    throw new CryptoPicError("NOT_CRYPTOPIC", "Data gambar terlalu pendek — bukan gambar CryptoPic.");
  }
  for (let i = 0; i < 4; i++) {
    if (payload[i] !== MAGIC[i]) {
      throw new CryptoPicError(
        "NOT_CRYPTOPIC",
        "Header CryptoPic tidak ditemukan. Gambar ini bukan hasil CryptoPic, atau pikselnya telah rusak karena kompresi/resize/screenshot/konversi format."
      );
    }
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const version = payload[4];
  if (version !== VERSION) {
    throw new CryptoPicError("BAD_VERSION", `Versi payload tidak didukung (v${version}). Perbarui CryptoPic.`);
  }
  const flags = payload[5];
  const total = view.getUint32(6, false);
  const hintLen = view.getUint16(38, false);
  if (total > payload.length || HEADER_FIXED + hintLen + TAG_LEN > total) {
    throw new CryptoPicError("CORRUPT", "Struktur pesan rusak — gambar kemungkinan telah diubah atau dikompresi.");
  }

  const salt = payload.slice(10, 26);
  const iv = payload.slice(26, 38);
  let hint = "";
  if (flags & FLAG_HINT) {
    try {
      hint = fromBytes(payload.slice(HEADER_FIXED, HEADER_FIXED + hintLen));
    } catch {
      throw new CryptoPicError("CORRUPT", "Petunjuk pada gambar rusak.");
    }
  }
  const ciphertext = payload.slice(HEADER_FIXED + hintLen, total);

  return { hint, salt, iv, ciphertext };
}

export async function decryptPayload(password, parsed) {
  const key = await deriveKey(password, parsed.salt);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: parsed.iv },
      key,
      parsed.ciphertext
    );
    try {
      return fromBytes(new Uint8Array(plain));
    } catch {
      throw new CryptoPicError("CORRUPT", "Pesan terbuka tetapi tidak teks UTF-8 yang valid.");
    }
  } catch (err) {
    if (err instanceof CryptoPicError) throw err;
    throw new CryptoPicError(
      "WRONG_PASSWORD",
      "Kata sandi salah, atau pesan di dalam gambar telah rusak."
    );
  }
}
