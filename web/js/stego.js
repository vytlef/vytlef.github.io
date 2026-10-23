const MAGIC = [0x43, 0x50, 0x49, 0x43];
const VERSION = 4;
const HEADER_FIXED = 53;
const BOOTSTRAP_BYTES = 8;
const BOOTSTRAP_SAMPLES = BOOTSTRAP_BYTES * 8;
const MATRIX_GROUP = 7;
const MATRIX_BITS = 3;
const ACTIVITY_MASK = 0xfc;
const ACTIVITY_THRESHOLDS = [48, 32, 24, 16, 8, 4, 0];
const TAG_LEN = 16;
const MAX_EMBEDDED_SAMPLE_RATIO = 0.5;
const RANDOM_CHUNK_BYTES = 64 * 1024;
const UINT32_RANGE = 0x100000000;

const encoder = new TextEncoder();

export class StegoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "StegoError";
    this.code = code;
  }
}

export function validatePNGFile(file) {
  if (!file) return false;
  if (file.type) {
    return file.type === "image/png";
  }
  return /\.png$/i.test(file.name || "");
}

export function pngRejectMessage(file) {
  const shown = file && file.name ? `"${file.name}"` : "File tersebut";
  return `${shown} ditolak. CryptoPic hanya menerima gambar PNG (lossless). Format lain seperti JPEG mengompresi gambar dan merusak piksel sehingga pesan tersembunyi hilang.`;
}

export function readFileBytes(file) {
  if (typeof file.arrayBuffer === "function") {
    return file.arrayBuffer();
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new StegoError("DECODE_FAILED", "File tidak dapat dibaca."));
    reader.readAsArrayBuffer(file);
  });
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/**
 * Membaca IHDR PNG pada tingkat byte: memeriksa tanda tangan, urutan chunk, dan
 * menolak profil warna ICC (canvas akan mengonversi warna dan mengubah piksel).
 * Tidak memeriksa kedalaman warna supaya pemanggil bisa memutuskan konversi.
 */
export function readPngIhdr(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  if (bytes.length < 8 || !PNG_SIGNATURE.every((b, i) => bytes[i] === b)) {
    throw new StegoError("BAD_PNG", "File bukan PNG valid (tanda tangan rusak).");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 8;
  let ihdr = null;
  while (offset + 8 <= bytes.length) {
    const length = view.getUint32(offset, false);
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
    if (offset === 8 && type !== "IHDR") {
      throw new StegoError("BAD_PNG", "Struktur PNG tidak valid (chunk IHDR tidak di awal).");
    }
    if (length > bytes.length) {
      throw new StegoError("BAD_PNG", "Struktur PNG rusak (panjang chunk tidak wajar).");
    }
    if (type === "IHDR") {
      if (length !== 13) {
        throw new StegoError("BAD_PNG", "Header IHDR PNG tidak lengkap.");
      }
      ihdr = {
        width: view.getUint32(offset + 8, false),
        height: view.getUint32(offset + 12, false),
        bitDepth: bytes[offset + 16],
        colorType: bytes[offset + 17],
        interlace: bytes[offset + 20],
      };
    } else if (type === "iCCP") {
      throw new StegoError(
        "COLOR_PROFILE",
        "PNG memiliki profil warna ICC. Browser akan mengonversi warnanya dan merusak pesan tersembunyi. " +
          "Simpan ulang PNG tanpa profil warna (konversi ke sRGB) lalu coba lagi."
      );
    }
    if (type === "IEND") break;
    offset += 12 + length;
  }
  if (!ihdr) {
    throw new StegoError("BAD_PNG", "PNG tidak memiliki header IHDR.");
  }
  return ihdr;
}

/**
 * Memvalidasi struktur PNG pada tingkat byte: menolak PNG dengan kedalaman
 * selain 8-bit (canvas akan memotong 16-bit dan merusak LSB) dan PNG dengan
 * profil warna ICC (canvas akan mengonversi warna dan mengubah piksel).
 * Mengembalikan info IHDR bila valid.
 */
export function validatePNGStructure(arrayBuffer) {
  const ihdr = readPngIhdr(arrayBuffer);
  if (ihdr.bitDepth !== 8) {
    if (ihdr.bitDepth === 16) {
      throw new StegoError(
        "BIT_DEPTH",
        "PNG ini memakai kedalaman 16-bit per channel. Kanvas browser hanya bekerja pada 8-bit sehingga LSB 16-bit " +
          "tidak dapat dipakai dengan aman. Simpan ulang PNG sebagai 8-bit lalu coba lagi."
      );
    }
    throw new StegoError(
      "BIT_DEPTH",
      `PNG menggunakan kedalaman ${ihdr.bitDepth}-bit. CryptoPic membutuhkan PNG 8-bit agar piksel tidak berubah. ` +
        "Simpan ulang PNG sebagai 8-bit lalu coba lagi."
    );
  }
  if (![0, 2, 3, 6].includes(ihdr.colorType)) {
    throw new StegoError("BAD_PNG", "PNG menggunakan tipe warna yang tidak didukung.");
  }
  return ihdr;
}

/**
 * True bila PNG valid tetapi memakai kedalaman 16-bit. Dipakai untuk memutuskan
 * apakah gambar perlu dikonversi (mode sembunyikan) atau ditolak (mode buka).
 * Sengaja membaca IHDR tanpa memanggil validatePNGStructure: fungsi itu memang
 * melempar untuk 16-bit, sedangkan pemanggil justru perlu tahu kedalamannya.
 */
export function is16BitPng(arrayBuffer) {
  return readPngIhdr(arrayBuffer).bitDepth === 16;
}

/**
 * Konversi gambar apa pun (termasuk PNG 16-bit) menjadi PNG 8-bit melalui
 * kanvas. Kanvas memotong presisi 16→8 bit, hasilnya PNG 8-bit valid yang aman
 * untuk steganografi LSB. Dipakai hanya saat menyembunyikan pesan: berkas yang
 * dihasilkan memang berkas baru, jadi konversi tidak menyesatkan.
 *
 * `hasTransparency` dihitung dari gambar asli, karena konversi meratakan alpha
 * ke putih; pemanggil perlu tahu agar notice transparansi tetap muncul.
 */
export async function convertTo8BitPngBlob(file) {
  const img = await loadImageFromFile(file);
  const { imageData, hasTransparency } = imageToImageData(img);
  const blob = await imageDataToPngBlob(imageData);
  return { blob, hasTransparency };
}

export function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new StegoError("DECODE_FAILED", "File tidak dapat dibaca sebagai gambar. Pastikan PNG tidak rusak."));
    };
    img.src = url;
  });
}

export function imageToImageData(img) {
  const canvas = document.createElement("canvas");
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  // Deteksi transparansi dari piksel asli. Menggambar di atas latar putih lebih
  // dulu akan mengomposit alpha sehingga hasilnya selalu 255; karena itu gambar
  // dibaca sekali tanpa latar, baru diratakan ke putih bila memang transparan.
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);
  let imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  let hasTransparency = false;
  for (let i = 3; i < imageData.data.length; i += 4) {
    if (imageData.data[i] !== 255) {
      hasTransparency = true;
      break;
    }
  }
  if (hasTransparency) {
    // Ratakan ke putih seperti perilaku sebelumnya agar pesan tidak rusak.
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0);
    imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  }
  for (let i = 3; i < imageData.data.length; i += 4) {
    imageData.data[i] = 255;
  }
  return { imageData, canvas, hasTransparency };
}

/**
 * Estimasi kapasitas format V4 (matrix embedding 3 bit / 7 sampel).
 * Header + bootstrap ikut dihitung dalam anggaran rasio modifikasi.
 */
export function maxMessageBytes(width, height, hint = "") {
  const totalSamples = width * height * 3;
  const prefixLength = HEADER_FIXED + encoder.encode(hint).length;
  const headerSamples = prefixLength * 8;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO) - BOOTSTRAP_SAMPLES - headerSamples;
  if (budget <= 0) return 0;
  const groups = Math.floor(budget / MATRIX_GROUP);
  const bodyBytes = Math.floor((groups * MATRIX_BITS) / 8);
  return Math.max(0, bodyBytes - TAG_LEN);
}

/* ---------------- V4: header tersebar + adaptive matrix embedding ---------------- */

function fnv1a32(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function v4Seed(nonce, width, height) {
  let label = `${width}x${height}|`;
  for (let i = 0; i < nonce.length; i++) {
    label += nonce[i].toString(16).padStart(2, "0");
  }
  return fnv1a32(label) || 0x9e3779b9;
}

function bootstrapSet() {
  const set = new Set();
  for (let i = 0; i < BOOTSTRAP_SAMPLES; i++) set.add(i);
  return set;
}

function makeSeededPicker(seed, slotCount, excluded) {
  let state = seed >>> 0 || 0x9e3779b9;
  const occupied = new Uint8Array(Math.ceil(slotCount / 8));
  const acceptedLimit = Math.floor(UINT32_RANGE / slotCount) * slotCount;
  const attemptLimit = slotCount * 6 + 8192;
  return {
    nextSample() {
      let attempts = 0;
      for (;;) {
        if (++attempts > attemptLimit) {
          throw new StegoError("CAPACITY", "Ruang posisi header V4 tidak cukup.");
        }
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        const word = state;
        if (word >= acceptedLimit) continue;
        const sample = word % slotCount;
        if (excluded && excluded.has(sample)) continue;
        const mask = 1 << (sample & 7);
        const byteIndex = sample >> 3;
        if (occupied[byteIndex] & mask) continue;
        occupied[byteIndex] |= mask;
        return sample;
      }
    },
  };
}

function writeHeaderBytes(data, bytes, picker) {
  const used = new Uint32Array(bytes.length * 8);
  for (let i = 0; i < used.length; i++) {
    const sample = picker.nextSample();
    used[i] = sample;
    writeBit(data, sample, (bytes[i >> 3] >> (7 - (i & 7))) & 1);
  }
  return used;
}

function readHeaderBytes(data, count, picker) {
  const bytes = new Uint8Array(count);
  const used = new Uint32Array(count * 8);
  for (let i = 0; i < used.length; i++) {
    const sample = picker.nextSample();
    used[i] = sample;
    bytes[i >> 3] = (bytes[i >> 3] << 1) | readBit(data, sample);
  }
  return { bytes, used };
}

function nonceEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Aktivitas lokal per piksel dari bit tinggi (mask 0xFC), sehingga tidak
 * terpengaruh perubahan LSB. Nilainya identik saat embed maupun ekstraksi.
 */
function computeActivity(imageData) {
  const { width, height, data } = imageData;
  const activity = new Uint8Array(width * height);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const p = y * width + x;
      const o = p * 4;
      let a = 0;
      if (x > 0) {
        const q = o - 4;
        a = Math.max(
          a,
          Math.abs((data[o] & ACTIVITY_MASK) - (data[q] & ACTIVITY_MASK)),
          Math.abs((data[o + 1] & ACTIVITY_MASK) - (data[q + 1] & ACTIVITY_MASK)),
          Math.abs((data[o + 2] & ACTIVITY_MASK) - (data[q + 2] & ACTIVITY_MASK))
        );
      }
      if (y > 0) {
        const q = o - width * 4;
        a = Math.max(
          a,
          Math.abs((data[o] & ACTIVITY_MASK) - (data[q] & ACTIVITY_MASK)),
          Math.abs((data[o + 1] & ACTIVITY_MASK) - (data[q + 1] & ACTIVITY_MASK)),
          Math.abs((data[o + 2] & ACTIVITY_MASK) - (data[q + 2] & ACTIVITY_MASK))
        );
      }
      activity[p] = a;
    }
  }
  return activity;
}

function chooseActivityThreshold(activity, needSamples) {
  const hist = new Uint32Array(256);
  for (let i = 0; i < activity.length; i++) hist[activity[i]]++;
  let acc = 0;
  const suffix = new Uint32Array(256);
  for (let t = 255; t >= 0; t--) {
    acc += hist[t] * 3;
    suffix[t] = acc;
  }
  for (const t of ACTIVITY_THRESHOLDS) {
    if (suffix[t] >= needSamples) return t;
  }
  return 0;
}

function makeV4BodyPicker(totalSamples, key, activity, threshold, excluded) {
  const occupied = new Uint8Array(Math.ceil(totalSamples / 8));
  const random = createRandomStream(key);
  const acceptedLimit = Math.floor(UINT32_RANGE / totalSamples) * totalSamples;
  return {
    async refill() {
      await random.refill();
    },
    nextSample() {
      for (;;) {
        const word = random.nextUint32();
        if (word === null) return null;
        if (word >= acceptedLimit) continue;
        const sample = word % totalSamples;
        if (excluded.has(sample)) continue;
        if (activity[(sample / 3) | 0] < threshold) continue;
        const mask = 1 << (sample & 7);
        const byteIndex = sample >> 3;
        if (occupied[byteIndex] & mask) continue;
        occupied[byteIndex] |= mask;
        return sample;
      }
    },
  };
}

async function drawSamples(picker, count) {
  const out = new Array(count);
  for (let i = 0; i < count; i++) {
    for (;;) {
      const sample = picker.nextSample();
      if (sample === null) {
        await picker.refill();
        continue;
      }
      out[i] = sample;
      break;
    }
  }
  return out;
}

function getBit(bytes, bitIndex) {
  return (bytes[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
}

function groupSyndrome(samples, data) {
  let syndrome = 0;
  for (let j = 0; j < MATRIX_GROUP; j++) {
    if (readBit(data, samples[j])) syndrome ^= j + 1;
  }
  return syndrome;
}

async function embedMatrixBody(data, body, picker) {
  const groups = Math.ceil((body.length * 8) / MATRIX_BITS);
  for (let g = 0; g < groups; g++) {
    const samples = await drawSamples(picker, MATRIX_GROUP);
    const syndrome = groupSyndrome(samples, data);
    const message =
      (getBit(body, g * MATRIX_BITS) << 2) |
      (getBit(body, g * MATRIX_BITS + 1) << 1) |
      getBit(body, g * MATRIX_BITS + 2);
    const target = syndrome ^ message;
    if (target !== 0) {
      const sample = samples[target - 1];
      writeBit(data, sample, readBit(data, sample) ^ 1);
    }
  }
}

async function extractMatrixBody(data, bodyBytes, picker) {
  const out = new Uint8Array(bodyBytes);
  const groups = Math.ceil((bodyBytes * 8) / MATRIX_BITS);
  const limit = bodyBytes * 8;
  for (let g = 0; g < groups; g++) {
    const samples = await drawSamples(picker, MATRIX_GROUP);
    const message = groupSyndrome(samples, data);
    for (let b = 0; b < MATRIX_BITS; b++) {
      const bitIndex = g * MATRIX_BITS + b;
      if (bitIndex >= limit) break;
      const bit = (message >> (MATRIX_BITS - 1 - b)) & 1;
      out[bitIndex >> 3] |= bit << (7 - (bitIndex & 7));
    }
  }
  return out;
}

function writeSequentialBytes(data, bytes, startByte = 0) {
  const startBit = startByte * 8;
  const endBit = startBit + bytes.length * 8;
  for (let i = startBit; i < endBit; i++) {
    const byteIndex = Math.floor(i / 8) - startByte;
    const bit = (bytes[byteIndex] >> (7 - (i & 7))) & 1;
    const sampleIndex = i;
    const pixelIndex = Math.floor(sampleIndex / 3);
    const channel = sampleIndex % 3;
    const offset = pixelIndex * 4 + channel;
    data[offset] = (data[offset] & 0xfe) | bit;
  }
}

function readSequentialBytes(data, count) {
  const out = new Uint8Array(count);
  const bitLength = count * 8;
  for (let i = 0; i < bitLength; i++) {
    const pixelIndex = Math.floor(i / 3);
    const channel = i % 3;
    const bit = data[pixelIndex * 4 + channel] & 1;
    out[i >> 3] = (out[i >> 3] << 1) | bit;
  }
  return out;
}

function writeBit(data, sampleIndex, bit) {
  const pixelIndex = Math.floor(sampleIndex / 3);
  const channel = sampleIndex % 3;
  const offset = pixelIndex * 4 + channel;
  data[offset] = (data[offset] & 0xfe) | bit;
}

function readBit(data, sampleIndex) {
  const pixelIndex = Math.floor(sampleIndex / 3);
  const channel = sampleIndex % 3;
  return data[pixelIndex * 4 + channel] & 1;
}

function incrementCounter(counter, blocks) {
  let carry = blocks;
  for (let i = counter.length - 1; i >= 0 && carry > 0; i--) {
    const sum = counter[i] + (carry % 256);
    counter[i] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum > 0xff ? 1 : 0);
  }
  if (carry > 0) throw new StegoError("CAPACITY", "Gambar terlalu besar untuk mode penyebaran V4.");
}

function createRandomStream(key) {
  const counter = new Uint8Array(16);
  let bytes = new Uint8Array(0);
  let offset = 0;

  return {
    nextUint32() {
      if (offset + 4 > bytes.length) return null;
      const value = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
      offset += 4;
      return value;
    },
    async refill() {
      const zeros = new Uint8Array(RANDOM_CHUNK_BYTES);
      bytes = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-CTR", counter, length: 128 },
        key,
        zeros
      ));
      incrementCounter(counter, bytes.length / 16);
      offset = 0;
    },
  };
}

function validateV4Payload(payload, imageData, hint = "") {
  if (payload.length < HEADER_FIXED) {
    throw new StegoError("CORRUPT", "Payload CryptoPic V4 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(5, false);
  const hintLen = view.getUint16(51, false);
  const prefixLength = HEADER_FIXED + hintLen;
  if (total !== payload.length || prefixLength + TAG_LEN > total) {
    throw new StegoError("CORRUPT", "Panjang payload CryptoPic V4 tidak konsisten.");
  }
  const totalSamples = imageData.width * imageData.height * 3;
  const groups = Math.ceil(((payload.length - prefixLength) * 8) / MATRIX_BITS);
  const usedSamples = BOOTSTRAP_SAMPLES + prefixLength * 8 + groups * MATRIX_GROUP;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO);
  if (totalSamples < BOOTSTRAP_SAMPLES + prefixLength * 8 || usedSamples > budget) {
    const maxBytes = maxMessageBytes(imageData.width, imageData.height, hint);
    throw new StegoError(
      "TOO_LARGE",
      `Pesan dan petunjuk melebihi kapasitas aman gambar (sekitar ${maxBytes} byte pesan). ` +
        "Gunakan gambar beresolusi lebih besar atau pesan lebih pendek."
    );
  }
  return { prefixLength, groups };
}

async function embedV4Payload(imageData, data, payload, stegoKey) {
  const width = imageData.width;
  const height = imageData.height;
  const totalSamples = width * height * 3;
  const { prefixLength } = validateV4Payload(payload, imageData);
  const nonce = payload.slice(15, 23);
  const prefix = payload.subarray(0, prefixLength);
  const body = payload.subarray(prefixLength);
  const groups = Math.ceil((body.length * 8) / MATRIX_BITS);
  const bodySamples = groups * MATRIX_GROUP;

  // Bootstrap: nonce 8 byte, ditulis berurutan (nilainya acak sehingga tidak
  // membocorkan struktur seperti header format lama).
  writeSequentialBytes(data, nonce);

  const seed = v4Seed(nonce, width, height);
  const bootstrap = bootstrapSet();
  const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
  const used = writeHeaderBytes(data, prefix, headerPicker);

  const excluded = new Set(used);
  for (let i = 0; i < BOOTSTRAP_SAMPLES; i++) excluded.add(i);

  const activity = computeActivity(imageData);
  const threshold = chooseActivityThreshold(activity, bodySamples + excluded.size);
  const picker = makeV4BodyPicker(totalSamples, stegoKey, activity, threshold, excluded);
  await picker.refill();
  await embedMatrixBody(data, body, picker);

  return new ImageData(data, width, height);
}

export async function embedPayload(imageData, payload, stegoKey = null) {
  if (!stegoKey) {
    throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload V4 memerlukan kunci posisi steganografi.");
  }
  const hasMagic =
    payload.length >= 5 &&
    payload[0] === MAGIC[0] &&
    payload[1] === MAGIC[1] &&
    payload[2] === MAGIC[2] &&
    payload[3] === MAGIC[3];
  if (!hasMagic || payload[4] !== VERSION) {
    throw new StegoError("BAD_VERSION", "Payload bukan format CryptoPic V4 yang didukung.");
  }

  const data = new Uint8ClampedArray(imageData.data);
  return embedV4Payload(imageData, data, payload, stegoKey);
}

function tryExtractV4(data, width, height) {
  const totalSamples = width * height * 3;
  if (totalSamples < BOOTSTRAP_SAMPLES + HEADER_FIXED * 8) return null;

  const nonce = readSequentialBytes(data, BOOTSTRAP_BYTES);
  const seed = v4Seed(nonce, width, height);
  const bootstrap = bootstrapSet();

  try {
    const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
    const { bytes: fixed } = readHeaderBytes(data, HEADER_FIXED, headerPicker);
    if (!(
      fixed[0] === MAGIC[0] &&
      fixed[1] === MAGIC[1] &&
      fixed[2] === MAGIC[2] &&
      fixed[3] === MAGIC[3] &&
      fixed[4] === VERSION
    )) {
      return null;
    }
    if (!nonceEqual(fixed.slice(15, 23), nonce)) return null;

    const view = new DataView(fixed.buffer, fixed.byteOffset, fixed.byteLength);
    const total = view.getUint32(5, false);
    const hintLen = view.getUint16(51, false);
    const prefixLength = HEADER_FIXED + hintLen;
    if (
      prefixLength + TAG_LEN > total ||
      total > totalSamples ||
      BOOTSTRAP_SAMPLES + prefixLength * 8 > totalSamples
    ) {
      return null;
    }

    let hintBytes = new Uint8Array(0);
    if (hintLen > 0) {
      hintBytes = readHeaderBytes(data, hintLen, headerPicker).bytes;
    }
    const prefix = new Uint8Array(prefixLength);
    prefix.set(fixed);
    prefix.set(hintBytes, HEADER_FIXED);
    return prefix;
  } catch {
    return null;
  }
}

export function extractPayload(imageData) {
  const data = imageData.data;
  const totalSamples = imageData.width * imageData.height * 3;
  if (Math.floor(totalSamples / 8) < HEADER_FIXED + TAG_LEN) {
    throw new StegoError("NOT_CRYPTOPIC", "Gambar terlalu kecil untuk berisi pesan CryptoPic.");
  }

  const v4 = tryExtractV4(data, imageData.width, imageData.height);
  if (v4) return v4;

  // Deteksi minimal format lama agar pesan errornya jelas. Jalur dekripsi lama
  // sudah dihapus; gambar lama memang tidak didukung lagi.
  const firstFive = readSequentialBytes(data, 5);
  const legacyMagic = firstFive[0] === MAGIC[0] && firstFive[1] === MAGIC[1] && firstFive[2] === MAGIC[2] && firstFive[3] === MAGIC[3];
  if (legacyMagic && firstFive[4] !== VERSION) {
    throw new StegoError(
      "LEGACY_FORMAT",
      `Gambar ini memakai format CryptoPic lama (v${firstFive[4]}) yang sudah tidak didukung. ` +
        "Minta pengirim membuat ulang gambar dengan versi terbaru."
    );
  }

  throw new StegoError(
    "NOT_CRYPTOPIC",
    "Gambar ini tidak berisi pesan CryptoPic V4, atau memakai format lama yang sudah tidak didukung."
  );
}

async function extractV4Body(imageData, parsed, stegoKey) {
  const width = imageData.width;
  const height = imageData.height;
  const totalSamples = width * height * 3;
  const bodyBytes = parsed.total - parsed.prefixLength;
  if (bodyBytes < TAG_LEN) {
    throw new StegoError("CORRUPT", "Payload V4 tidak lengkap.");
  }
  if (!parsed.nonce || parsed.nonce.length !== BOOTSTRAP_BYTES) {
    throw new StegoError("CORRUPT", "Nonce V4 pada gambar tidak valid.");
  }

  // Hitung ulang posisi header agar bisa dikecualikan dari pemilihan body.
  const seed = v4Seed(parsed.nonce, width, height);
  const bootstrap = bootstrapSet();
  const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
  const { used } = readHeaderBytes(imageData.data, parsed.prefixLength, headerPicker);

  const excluded = new Set(used);
  for (let i = 0; i < BOOTSTRAP_SAMPLES; i++) excluded.add(i);

  const groups = Math.ceil((bodyBytes * 8) / MATRIX_BITS);
  const bodySamples = groups * MATRIX_GROUP;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO);
  if (BOOTSTRAP_SAMPLES + parsed.prefixLength * 8 + bodySamples > budget) {
    throw new StegoError("CORRUPT", "Payload V4 tidak muat pada gambar atau pikselnya telah berubah.");
  }

  const activity = computeActivity(imageData);
  const threshold = chooseActivityThreshold(activity, bodySamples + excluded.size);
  const picker = makeV4BodyPicker(totalSamples, stegoKey, activity, threshold, excluded);
  await picker.refill();
  return extractMatrixBody(imageData.data, bodyBytes, picker);
}

export async function extractProtectedBody(imageData, parsed, stegoKey) {
  if (!stegoKey) {
    throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload V4 memerlukan kunci posisi steganografi.");
  }
  if (!parsed || parsed.version !== VERSION) {
    throw new StegoError("LEGACY_FORMAT", "Format gambar lama tidak didukung.");
  }
  return extractV4Body(imageData, parsed, stegoKey);
}

export function imageDataToPngBlob(imageData) {
  const canvas = document.createElement("canvas");
  canvas.width = imageData.width;
  canvas.height = imageData.height;
  const ctx = canvas.getContext("2d");
  ctx.putImageData(imageData, 0, 0);
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) resolve(blob);
      else reject(new StegoError("ENCODE_FAILED", "Gagal membuat file PNG."));
    }, "image/png");
  });
}

/* ---------------- Pembersihan gambar untuk dipakai ulang ---------------- */

const RANDOM_CHUNK_WORDS = 16384; // 65.536 byte per panggilan getRandomValues

function fillRandomWords(words) {
  for (let offset = 0; offset < words.length; offset += RANDOM_CHUNK_WORDS) {
    const end = Math.min(offset + RANDOM_CHUNK_WORDS, words.length);
    crypto.getRandomValues(words.subarray(offset, end));
  }
}

/**
 * Hancurkan payload lama dengan menimpa seluruh LSB R/G/B memakai bit acak.
 * Selisih visual maksimal 1 per channel dan alpha dipaksa 255 (putih).
 */
export function sanitizeImageData(imageData) {
  const width = imageData.width;
  const height = imageData.height;
  const data = new Uint8ClampedArray(imageData.data);
  const pixels = width * height;
  const words = new Uint32Array(Math.ceil((pixels * 3) / 32));
  fillRandomWords(words);

  let bitIndex = 0;
  for (let p = 0; p < pixels; p++) {
    const base = p * 4;
    for (let c = 0; c < 3; c++) {
      const bit = (words[bitIndex >>> 5] >>> (bitIndex & 31)) & 1;
      data[base + c] = (data[base + c] & 0xfe) | bit;
      bitIndex++;
    }
    data[base + 3] = 255;
  }
  return new ImageData(data, width, height);
}

/**
 * Sanitasi + encode + verifikasi. Payload lama harus benar-benar tidak terbaca
 * sebelum blob dikembalikan. Diulang maksimal 3 kali.
 */
export async function sanitizeToPngBlob(imageData) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const clean = sanitizeImageData(imageData);
    const blob = await imageDataToPngBlob(clean);

    let leaked = false;
    try {
      const img = await loadImageFromFile(blob);
      const reloaded = imageToImageData(img).imageData;
      extractPayload(reloaded);
      leaked = true;
    } catch {
      leaked = false;
    }
    if (!leaked) return blob;
  }
  throw new StegoError(
    "CLEAN_FAILED",
    "Gambar gagal dibersihkan sepenuhnya. Coba unggah ulang gambar aslinya."
  );
}
