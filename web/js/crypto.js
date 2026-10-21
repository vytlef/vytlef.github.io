const MAGIC = new Uint8Array([0x43, 0x50, 0x49, 0x43]);
const VERSION_V1 = 1;
const VERSION_V2 = 2;
const FLAG_HINT = 1 << 0;
const V1_SALT_LEN = 16;
const V1_IV_LEN = 12;
const V1_HEADER_FIXED = 40;
const V2_SALT_LEN = 16;
const V2_IV_LEN = 12;
const V2_HEADER_FIXED = 34;
const TAG_LEN = 16;
export const V2_KDF = Object.freeze({ memorySize: 65536, iterations: 3, parallelism: 4 });

const VERSION_V3 = 3;
const V3_SALT_LEN = 16;
const V3_IV_LEN = 12;
const V3_NONCE_LEN = 8;
const V3_HEADER_FIXED = 53;
export const V3_KDF = Object.freeze({ memorySize: 65536, iterations: 3, parallelism: 4 });

const encoder = new TextEncoder();

export class CryptoPicError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CryptoPicError";
    this.code = code;
  }
}

function normalizeV1Password(password) {
  return password.toLowerCase();
}

function normalizeV2Password(password) {
  return password.normalize("NFC");
}

function toBytes(text) {
  return encoder.encode(text);
}

function fromBytes(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function requireArgon2() {
  const argon2id = globalThis.hashwasm && globalThis.hashwasm.argon2id;
  if (!argon2id) {
    throw new CryptoPicError(
      "CRYPTO_UNAVAILABLE",
      "Modul kriptografi tidak tersedia. Muat ulang CryptoPic saat perangkat terhubung."
    );
  }
  return argon2id;
}

function deriveArgon2Root(password, salt, kdf) {
  if (import.meta.url.startsWith("data:")) {
    return requireArgon2()({
      password,
      salt,
      iterations: kdf.iterations,
      parallelism: kdf.parallelism,
      memorySize: kdf.memorySize,
      hashLength: 32,
      outputType: "binary",
    });
  }

  if (typeof Worker !== "function") {
    throw new CryptoPicError("CRYPTO_UNAVAILABLE", "Browser ini tidak mendukung Web Worker yang diperlukan untuk menjalankan Argon2id.");
  }

  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("./argon2-worker.js", import.meta.url), { name: "cryptopic-argon2" });
    } catch (error) {
      reject(new CryptoPicError("CRYPTO_UNAVAILABLE", `Tidak dapat memulai worker Argon2id: ${error.message}`));
      return;
    }

    const finish = (callback, value) => {
      worker.terminate();
      callback(value);
    };
    worker.onmessage = (event) => {
      if (event.data && event.data.error) {
        finish(reject, new CryptoPicError("KDF_FAILED", event.data.error));
      } else if (event.data && event.data.root instanceof ArrayBuffer) {
        finish(resolve, new Uint8Array(event.data.root));
      } else {
        finish(reject, new CryptoPicError("KDF_FAILED", "Worker Argon2id mengembalikan hasil yang tidak valid."));
      }
    };
    worker.onerror = (event) => {
      event.preventDefault();
      finish(reject, new CryptoPicError("KDF_FAILED", "Worker Argon2id gagal. Muat ulang aplikasi dan coba lagi."));
    };

    const passwordCopy = new Uint8Array(password);
    const saltCopy = new Uint8Array(salt);
    worker.postMessage(
      {
        password: passwordCopy,
        salt: saltCopy,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
        memorySize: kdf.memorySize,
      },
      [passwordCopy.buffer, saltCopy.buffer]
    );
  });
}

async function deriveV1Key(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBytes(normalizeV1Password(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

export async function deriveV2Keys(password, salt, kdf = V2_KDF) {
  const root = await deriveArgon2Root(toBytes(normalizeV2Password(password)), salt, kdf);

  const hkdfKey = await crypto.subtle.importKey("raw", root, "HKDF", false, ["deriveBits"]);
  const [encryptionMaterial, stegoMaterial] = await Promise.all([
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: toBytes("CryptoPic v2 encryption key") },
      hkdfKey,
      256
    ),
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: toBytes("CryptoPic v2 stego position key") },
      hkdfKey,
      256
    ),
  ]);

  const encryptionKey = await crypto.subtle.importKey(
    "raw",
    encryptionMaterial,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  const stegoKey = await crypto.subtle.importKey(
    "raw",
    stegoMaterial,
    { name: "AES-CTR" },
    false,
    ["encrypt"]
  );
  root.fill(0);
  new Uint8Array(encryptionMaterial).fill(0);
  new Uint8Array(stegoMaterial).fill(0);
  return { encryptionKey, stegoKey };
}

// Alias generik: parameter KDF kini dapat berasal dari header (V3).
export const deriveKeys = deriveV2Keys;

export function overheadBytes(hint) {
  const hintLen = hint ? toBytes(hint).length : 0;
  return V2_HEADER_FIXED + hintLen + TAG_LEN;
}

function makeV2Prefix({ total, salt, iv, hintBytes }) {
  const prefix = new Uint8Array(V2_HEADER_FIXED + hintBytes.length);
  const view = new DataView(prefix.buffer);
  view.setUint32(0, total, false);
  prefix.set(salt, 4);
  prefix.set(iv, 20);
  view.setUint16(32, hintBytes.length, false);
  prefix.set(hintBytes, V2_HEADER_FIXED);
  return prefix;
}

export async function encryptPayload(password, message, hint = "") {
  const salt = crypto.getRandomValues(new Uint8Array(V2_SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(V2_IV_LEN));
  const messageBytes = toBytes(message);
  const hintBytes = hint ? toBytes(hint) : new Uint8Array(0);
  if (hintBytes.length > 0xffff) {
    throw new CryptoPicError("HINT_TOO_LONG", "Petunjuk terlalu panjang (maks 65.535 byte).");
  }

  const total = V2_HEADER_FIXED + hintBytes.length + messageBytes.length + TAG_LEN;
  if (total > 0xffffffff) {
    throw new CryptoPicError("MESSAGE_TOO_LARGE", "Pesan terlalu besar untuk format CryptoPic.");
  }
  const prefix = makeV2Prefix({ total, salt, iv, hintBytes });
  const keys = await deriveV2Keys(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: prefix, tagLength: 128 },
      keys.encryptionKey,
      messageBytes
    )
  );
  const payload = new Uint8Array(prefix.length + ciphertext.length);
  payload.set(prefix);
  payload.set(ciphertext, prefix.length);
  return { payload, stegoKey: keys.stegoKey };
}

function hasV1Magic(payload) {
  return payload.length >= MAGIC.length && MAGIC.every((byte, index) => payload[index] === byte);
}

function makeV3Header({ total, salt, iv, nonce, hintBytes, kdf }) {
  const prefix = new Uint8Array(V3_HEADER_FIXED + hintBytes.length);
  const view = new DataView(prefix.buffer);
  prefix.set(MAGIC, 0);
  prefix[4] = VERSION_V3;
  view.setUint32(5, total, false);
  view.setUint32(9, kdf.memorySize, false);
  prefix[13] = kdf.iterations;
  prefix[14] = kdf.parallelism;
  prefix.set(nonce, 15);
  prefix.set(salt, 23);
  prefix.set(iv, 39);
  view.setUint16(51, hintBytes.length, false);
  prefix.set(hintBytes, V3_HEADER_FIXED);
  return prefix;
}

export async function encryptPayloadV3(password, message, hint = "", kdf = V3_KDF) {
  const salt = crypto.getRandomValues(new Uint8Array(V3_SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(V3_IV_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(V3_NONCE_LEN));
  const messageBytes = toBytes(message);
  const hintBytes = hint ? toBytes(hint) : new Uint8Array(0);
  if (hintBytes.length > 0xffff) {
    throw new CryptoPicError("HINT_TOO_LONG", "Petunjuk terlalu panjang (maks 65.535 byte).");
  }

  const total = V3_HEADER_FIXED + hintBytes.length + messageBytes.length + TAG_LEN;
  if (total > 0xffffffff) {
    throw new CryptoPicError("MESSAGE_TOO_LARGE", "Pesan terlalu besar untuk format CryptoPic.");
  }
  const prefix = makeV3Header({ total, salt, iv, nonce, hintBytes, kdf });
  const keys = await deriveKeys(password, salt, kdf);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: prefix, tagLength: 128 },
      keys.encryptionKey,
      messageBytes
    )
  );
  const payload = new Uint8Array(prefix.length + ciphertext.length);
  payload.set(prefix);
  payload.set(ciphertext, prefix.length);
  return { payload, stegoKey: keys.stegoKey };
}

function parseV1(payload) {
  if (payload.length < V1_HEADER_FIXED) {
    throw new CryptoPicError("CORRUPT", "Header gambar CryptoPic V1 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(6, false);
  const hintLen = view.getUint16(38, false);
  const prefixLength = V1_HEADER_FIXED + hintLen;
  if (total > payload.length || prefixLength + TAG_LEN > total) {
    throw new CryptoPicError("CORRUPT", "Struktur pesan V1 rusak atau gambar telah berubah.");
  }
  let hint = "";
  if (payload[5] & FLAG_HINT) {
    try {
      hint = fromBytes(payload.slice(V1_HEADER_FIXED, prefixLength));
    } catch {
      throw new CryptoPicError("CORRUPT", "Petunjuk pada gambar V1 rusak.");
    }
  }
  return {
    version: VERSION_V1,
    hint,
    salt: payload.slice(10, 10 + V1_SALT_LEN),
    iv: payload.slice(26, 26 + V1_IV_LEN),
    ciphertext: payload.slice(prefixLength, total),
  };
}

function parseV2(payload) {
  if (payload.length < V2_HEADER_FIXED) {
    throw new CryptoPicError("CORRUPT", "Header gambar CryptoPic V2 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(0, false);
  const hintLen = view.getUint16(32, false);
  const prefixLength = V2_HEADER_FIXED + hintLen;

  if (prefixLength > payload.length || prefixLength + TAG_LEN > total) {
    throw new CryptoPicError("CORRUPT", "Header V2 terpotong atau panjang payload tidak konsisten.");
  }

  let hint = "";
  try {
    hint = fromBytes(payload.slice(V2_HEADER_FIXED, prefixLength));
  } catch {
    throw new CryptoPicError("CORRUPT", "Petunjuk pada gambar V2 rusak.");
  }
  return {
    version: VERSION_V2,
    hint,
    salt: payload.slice(4, 4 + V2_SALT_LEN),
    iv: payload.slice(20, 20 + V2_IV_LEN),
    total,
    prefixLength,
    prefix: payload.slice(0, prefixLength),
    kdf: V2_KDF,
  };
}

function parseV3(payload) {
  if (payload.length < V3_HEADER_FIXED) {
    throw new CryptoPicError("CORRUPT", "Header gambar CryptoPic V3 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(5, false);
  const memorySize = view.getUint32(9, false);
  const iterations = payload[13];
  const parallelism = payload[14];
  const hintLen = view.getUint16(51, false);
  const prefixLength = V3_HEADER_FIXED + hintLen;

  if (prefixLength > payload.length || prefixLength + TAG_LEN > total) {
    throw new CryptoPicError("CORRUPT", "Header V3 terpotong atau panjang payload tidak konsisten.");
  }
  // Jangan percaya parameter KDF dari header: batasi agar gambar jahat tidak
  // memaksa browser mengalokasikan memori raksasa atau menghitung terlalu lama.
  if (
    memorySize < 8 ||
    memorySize > 1 << 20 ||
    iterations < 1 ||
    iterations > 64 ||
    parallelism < 1 ||
    parallelism > 16
  ) {
    throw new CryptoPicError("CORRUPT", "Parameter KDF pada gambar V3 tidak valid.");
  }

  let hint = "";
  try {
    hint = fromBytes(payload.slice(V3_HEADER_FIXED, prefixLength));
  } catch {
    throw new CryptoPicError("CORRUPT", "Petunjuk pada gambar V3 rusak.");
  }
  return {
    version: VERSION_V3,
    hint,
    salt: payload.slice(23, 23 + V3_SALT_LEN),
    iv: payload.slice(39, 39 + V3_IV_LEN),
    nonce: payload.slice(15, 15 + V3_NONCE_LEN),
    total,
    prefixLength,
    prefix: payload.slice(0, prefixLength),
    kdf: { memorySize, iterations, parallelism },
  };
}

export function parsePayload(payload) {
  if (hasV1Magic(payload)) {
    const version = payload[4];
    if (version === VERSION_V1) return parseV1(payload);
    if (version === VERSION_V3) return parseV3(payload);
    throw new CryptoPicError("BAD_VERSION", `Versi payload bertanda tidak didukung (v${version}).`);
  }
  return parseV2(payload);
}

export async function decryptPayload(password, parsed, extractedCiphertext = null, derivedKeys = null) {
  let key;
  let ciphertext;
  let additionalData;
  if (parsed.version === VERSION_V1) {
    key = await deriveV1Key(password, parsed.salt);
    ciphertext = parsed.ciphertext;
  } else {
    const keys = derivedKeys || await deriveV2Keys(password, parsed.salt, parsed.kdf);
    key = keys.encryptionKey;
    ciphertext = extractedCiphertext;
    additionalData = parsed.prefix;
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== parsed.total - parsed.prefixLength) {
      throw new CryptoPicError("CORRUPT", "Bagian pesan V2 pada gambar tidak lengkap.");
    }
  }

  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: parsed.iv, ...(additionalData ? { additionalData, tagLength: 128 } : {}) },
      key,
      ciphertext
    );
    try {
      return fromBytes(new Uint8Array(plain));
    } catch {
      throw new CryptoPicError("CORRUPT", "Pesan terdekripsi tetapi teks UTF-8-nya tidak valid.");
    }
  } catch (err) {
    if (err instanceof CryptoPicError) throw err;
    throw new CryptoPicError(
      "WRONG_PASSWORD",
      "Kata sandi tidak cocok atau data tersembunyi pada gambar telah berubah. Pastikan sandi sesuai dan gunakan PNG asli."
    );
  }
}
