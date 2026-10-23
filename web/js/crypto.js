const MAGIC = new Uint8Array([0x43, 0x50, 0x49, 0x43]);
const VERSION = 4;
const SALT_LEN = 16;
const IV_LEN = 12;
const NONCE_LEN = 8;
const HEADER_FIXED = 53;
const TAG_LEN = 16;

export const KDF = Object.freeze({ memorySize: 65536, iterations: 3, parallelism: 4 });

/**
 * Batas parameter KDF yang boleh diterima dari header gambar.
 * Tujuannya mencegah gambar jahat memaksa browser mengalokasikan memori
 * raksasa atau menghitung terlalu lama (serangan DoS).
 */
export const KDF_LIMITS = Object.freeze({
  memoryMin: 8 * 1024, // KiB → 8 MiB
  memoryMax: 256 * 1024, // KiB → 256 MiB
  iterationsMax: 8,
  parallelismMax: 8,
  workMax: 512 * 1024, // KiB·iter
});

export function isKdfAcceptable(kdf) {
  if (!kdf) return false;
  const { memorySize, iterations, parallelism } = kdf;
  if (!Number.isInteger(memorySize) || !Number.isInteger(iterations) || !Number.isInteger(parallelism)) {
    return false;
  }
  return (
    memorySize >= KDF_LIMITS.memoryMin &&
    memorySize <= KDF_LIMITS.memoryMax &&
    iterations >= 1 &&
    iterations <= KDF_LIMITS.iterationsMax &&
    parallelism >= 1 &&
    parallelism <= KDF_LIMITS.parallelismMax &&
    memorySize * iterations <= KDF_LIMITS.workMax
  );
}

const encoder = new TextEncoder();

export class CryptoPicError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CryptoPicError";
    this.code = code;
  }
}

/**
 * Sandi gambar V4 tidak peka huruf besar/kecil. Normalisasi dilakukan sebelum
 * KDF agar "Rahasia", "rahasia", dan "RAHASIA" menghasilkan kunci yang sama.
 */
function normalizePassword(password) {
  return password.normalize("NFC").toLowerCase().normalize("NFC");
}

/**
 * PIN vault Memo sengaja memakai normalisasi lama (NFC saja). Jangan diubah:
 * vault Argon2id yang sudah ada diturunkan dari bentuk ini, dan vault PBKDF2
 * lama harus tetap bisa dibuka lalu dimigrasikan.
 */
function normalizePin(pin) {
  return pin.normalize("NFC");
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

/**
 * Batas tunggu satu perhitungan Argon2id di worker. Worker bisa berhenti
 * merespons tanpa memicu onerror (mis. gagal memuat skrip secara transien atau
 * kehabisan memori). Tanpa batas ini UI akan berputar selamanya; dengan batas
 * ini pengguna mendapat pesan jelas dan dapat mencoba lagi.
 */
const KDF_WORKER_TIMEOUT_MS = 45000;

function runArgon2Worker(password, salt, kdf) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("./argon2-worker.js", import.meta.url), { name: "cryptopic-argon2" });
    } catch (error) {
      reject(new CryptoPicError("CRYPTO_UNAVAILABLE", `Tidak dapat memulai worker Argon2id: ${error.message}`));
      return;
    }

    let settled = false;
    let timer = null;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      try {
        worker.terminate();
      } catch {
        /* worker mungkin sudah mati */
      }
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

    timer = setTimeout(() => {
      finish(
        reject,
        new CryptoPicError(
          "KDF_TIMEOUT",
          "Perhitungan Argon2id terlalu lama karena worker tidak merespons. Coba lagi; bila tetap gagal, muat ulang halaman."
        )
      );
    }, KDF_WORKER_TIMEOUT_MS);

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

  // Satu percobaan ulang dengan worker baru. Argon2id deterministik, jadi
  // pengulangan tidak mengubah hasil dan aman; ini menyembuhkan kegagalan
  // startup worker yang bersifat sesaat tanpa menyembunyikan kesalahan nyata.
  const attempt = () => runArgon2Worker(password, salt, kdf);
  return attempt().catch((error) => {
    if (error instanceof CryptoPicError && (error.code === "KDF_TIMEOUT" || error.code === "KDF_FAILED")) {
      console.warn("Worker Argon2id gagal atau tidak merespons; mencoba ulang sekali.", error);
      return attempt();
    }
    throw error;
  });
}

/**
 * Turunkan kunci enkripsi dan kunci posisi steganografi dari sandi gambar V4.
 */
export async function deriveKeys(password, salt, kdf = KDF) {
  if (!isKdfAcceptable(kdf)) {
    throw new CryptoPicError("KDF_INVALID", "Parameter KDF tidak wajar.");
  }
  const root = await deriveArgon2Root(toBytes(normalizePassword(password)), salt, kdf);

  const hkdfKey = await crypto.subtle.importKey("raw", root, "HKDF", false, ["deriveBits"]);
  const [encryptionMaterial, stegoMaterial] = await Promise.all([
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: toBytes("CryptoPic v4 encryption key") },
      hkdfKey,
      256
    ),
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: toBytes("CryptoPic v4 stego position key") },
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

/**
 * Turunkan kunci mentah 32 byte untuk vault Memo.
 * Memakai normalisasi PIN (NFC saja) agar vault lama tetap dapat dibuka.
 */
export async function deriveArgon2KeyBytes(pin, salt, kdf = KDF) {
  if (!isKdfAcceptable(kdf)) {
    throw new CryptoPicError("KDF_INVALID", "Parameter KDF tidak wajar.");
  }
  return deriveArgon2Root(toBytes(normalizePin(pin)), salt, kdf);
}

function makeHeader({ total, salt, iv, nonce, hintBytes, kdf }) {
  const prefix = new Uint8Array(HEADER_FIXED + hintBytes.length);
  const view = new DataView(prefix.buffer);
  prefix.set(MAGIC, 0);
  prefix[4] = VERSION;
  view.setUint32(5, total, false);
  view.setUint32(9, kdf.memorySize, false);
  prefix[13] = kdf.iterations;
  prefix[14] = kdf.parallelism;
  prefix.set(nonce, 15);
  prefix.set(salt, 23);
  prefix.set(iv, 39);
  view.setUint16(51, hintBytes.length, false);
  prefix.set(hintBytes, HEADER_FIXED);
  return prefix;
}

export async function encryptPayload(password, message, hint = "", kdf = KDF) {
  if (!isKdfAcceptable(kdf)) {
    throw new CryptoPicError("KDF_INVALID", "Parameter KDF tidak wajar.");
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const messageBytes = toBytes(message);
  const hintBytes = hint ? toBytes(hint) : new Uint8Array(0);
  if (hintBytes.length > 0xffff) {
    throw new CryptoPicError("HINT_TOO_LONG", "Petunjuk terlalu panjang (maks 65.535 byte).");
  }

  const total = HEADER_FIXED + hintBytes.length + messageBytes.length + TAG_LEN;
  if (total > 0xffffffff) {
    throw new CryptoPicError("MESSAGE_TOO_LARGE", "Pesan terlalu besar untuk format CryptoPic.");
  }
  const prefix = makeHeader({ total, salt, iv, nonce, hintBytes, kdf });
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

export function parsePayload(payload) {
  if (payload.length < HEADER_FIXED) {
    throw new CryptoPicError("CORRUPT", "Header gambar CryptoPic V4 tidak lengkap.");
  }
  const hasMagic =
    payload[0] === MAGIC[0] &&
    payload[1] === MAGIC[1] &&
    payload[2] === MAGIC[2] &&
    payload[3] === MAGIC[3];
  if (!hasMagic) {
    throw new CryptoPicError(
      "NOT_CRYPTOPIC",
      "Gambar ini tidak berisi pesan CryptoPic V4, atau memakai format lama yang sudah tidak didukung."
    );
  }
  const version = payload[4];
  if (version !== VERSION) {
    throw new CryptoPicError(
      "LEGACY_FORMAT",
      `Gambar ini memakai format CryptoPic lama (v${version}) yang sudah tidak didukung. ` +
        "Minta pengirim membuat ulang gambar dengan versi terbaru."
    );
  }

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(5, false);
  const memorySize = view.getUint32(9, false);
  const iterations = payload[13];
  const parallelism = payload[14];
  const hintLen = view.getUint16(51, false);
  const prefixLength = HEADER_FIXED + hintLen;

  if (prefixLength > payload.length || prefixLength + TAG_LEN > total) {
    throw new CryptoPicError("CORRUPT", "Header V4 terpotong atau panjang payload tidak konsisten.");
  }
  // Jangan percaya parameter KDF dari header: batasi agar gambar jahat tidak
  // memaksa browser mengalokasikan memori raksasa atau menghitung terlalu lama.
  if (!isKdfAcceptable({ memorySize, iterations, parallelism })) {
    throw new CryptoPicError("CORRUPT", "Parameter KDF pada gambar V4 tidak wajar.");
  }

  let hint = "";
  try {
    hint = fromBytes(payload.slice(HEADER_FIXED, prefixLength));
  } catch {
    throw new CryptoPicError("CORRUPT", "Petunjuk pada gambar V4 rusak.");
  }
  return {
    version: VERSION,
    hint,
    salt: payload.slice(23, 23 + SALT_LEN),
    iv: payload.slice(39, 39 + IV_LEN),
    nonce: payload.slice(15, 15 + NONCE_LEN),
    total,
    prefixLength,
    prefix: payload.slice(0, prefixLength),
    kdf: { memorySize, iterations, parallelism },
  };
}

export async function decryptPayload(password, parsed, extractedCiphertext = null, derivedKeys = null) {
  if (!parsed || parsed.version !== VERSION) {
    throw new CryptoPicError("LEGACY_FORMAT", "Format gambar lama tidak didukung.");
  }
  if (
    !(extractedCiphertext instanceof Uint8Array) ||
    extractedCiphertext.length !== parsed.total - parsed.prefixLength
  ) {
    throw new CryptoPicError("CORRUPT", "Bagian pesan V4 pada gambar tidak lengkap.");
  }

  const keys = derivedKeys || await deriveKeys(password, parsed.salt, parsed.kdf);

  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: parsed.iv, additionalData: parsed.prefix, tagLength: 128 },
      keys.encryptionKey,
      extractedCiphertext
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
      "Kata sandi tidak cocok atau data tersembunyi pada gambar telah berubah. " +
        "Huruf besar/kecil tidak berpengaruh; pastikan spasi dan gunakan PNG asli."
    );
  }
}
