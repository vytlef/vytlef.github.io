const V1_HEADER_FIXED = 40;
const V2_HEADER_FIXED = 34;
const V3_HEADER_FIXED = 53;
const V3_BOOTSTRAP_BYTES = 8;
const V3_BOOTSTRAP_SAMPLES = V3_BOOTSTRAP_BYTES * 8;
const MATRIX_GROUP = 7;
const MATRIX_BITS = 3;
const ACTIVITY_MASK = 0xfc;
const ACTIVITY_THRESHOLDS = [48, 32, 24, 16, 8, 4, 0];
const TAG_LEN = 16;
const HAMMING_BITS_PER_BYTE = 14;
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
 * Memvalidasi struktur PNG pada tingkat byte: menolak PNG dengan kedalaman
 * selain 8-bit (canvas akan memotong 16-bit dan merusak LSB) dan PNG dengan
 * profil warna ICC (canvas akan mengonversi warna dan mengubah piksel).
 * Mengembalikan info IHDR bila valid.
 */
export function validatePNGStructure(arrayBuffer) {
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
  if (ihdr.bitDepth !== 8) {
    throw new StegoError(
      "BAD_PNG",
      `PNG menggunakan kedalaman ${ihdr.bitDepth}-bit. CryptoPic membutuhkan PNG 8-bit agar piksel tidak berubah. ` +
        "Simpan ulang PNG sebagai 8-bit lalu coba lagi."
    );
  }
  if (![0, 2, 3, 6].includes(ihdr.colorType)) {
    throw new StegoError("BAD_PNG", "PNG menggunakan tipe warna yang tidak didukung.");
  }
  return ihdr;
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
  // Deteksi transparansi sebelum diratakan ke putih, agar UI bisa memberi tahu pengguna.
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  let hasTransparency = false;
  for (let i = 3; i < imageData.data.length; i += 4) {
    if (imageData.data[i] !== 255) {
      hasTransparency = true;
      break;
    }
  }
  for (let i = 3; i < imageData.data.length; i += 4) {
    imageData.data[i] = 255;
  }
  return { imageData, canvas, hasTransparency };
}

export function capacityBytes(width, height) {
  return Math.floor((width * height * 3) / 8);
}

export function maxMessageBytes(width, height, hint = "") {
  const prefixLength = V2_HEADER_FIXED + encoder.encode(hint).length;
  const totalSamples = width * height * 3;
  const bodySlots = totalSamples - prefixLength * 8;
  if (bodySlots <= 0) return 0;
  const maxCodedBits = Math.floor(bodySlots * MAX_EMBEDDED_SAMPLE_RATIO);
  const maxBodyBytes = Math.floor(maxCodedBits / HAMMING_BITS_PER_BYTE);
  return Math.max(0, maxBodyBytes - TAG_LEN);
}

/**
 * Estimasi kapasitas format V3 (matrix embedding 3 bit / 7 sampel).
 * Header + bootstrap ikut dihitung dalam anggaran rasio modifikasi.
 */
export function maxMessageBytesV3(width, height, hint = "") {
  const totalSamples = width * height * 3;
  const prefixLength = V3_HEADER_FIXED + encoder.encode(hint).length;
  const headerSamples = prefixLength * 8;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO) - V3_BOOTSTRAP_SAMPLES - headerSamples;
  if (budget <= 0) return 0;
  const groups = Math.floor(budget / MATRIX_GROUP);
  const bodyBytes = Math.floor((groups * MATRIX_BITS) / 8);
  return Math.max(0, bodyBytes - TAG_LEN);
}

/* ---------------- V3: header tersebar + adaptive matrix embedding ---------------- */

function fnv1a32(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function v3Seed(nonce, width, height) {
  let label = `${width}x${height}|`;
  for (let i = 0; i < nonce.length; i++) {
    label += nonce[i].toString(16).padStart(2, "0");
  }
  return fnv1a32(label) || 0x9e3779b9;
}

function bootstrapSet() {
  const set = new Set();
  for (let i = 0; i < V3_BOOTSTRAP_SAMPLES; i++) set.add(i);
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
          throw new StegoError("CAPACITY", "Ruang posisi header V3 tidak cukup.");
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

function makeV3BodyPicker(totalSamples, key, activity, threshold, excluded) {
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

function encodeHamming74(bytes) {
  const encoded = new Uint8Array(bytes.length * HAMMING_BITS_PER_BYTE);
  let out = 0;
  for (const byte of bytes) {
    for (const shift of [4, 0]) {
      const nibble = (byte >> shift) & 0x0f;
      const d1 = (nibble >> 3) & 1;
      const d2 = (nibble >> 2) & 1;
      const d3 = (nibble >> 1) & 1;
      const d4 = nibble & 1;
      encoded[out++] = d1 ^ d2 ^ d4;
      encoded[out++] = d1 ^ d3 ^ d4;
      encoded[out++] = d1;
      encoded[out++] = d2 ^ d3 ^ d4;
      encoded[out++] = d2;
      encoded[out++] = d3;
      encoded[out++] = d4;
    }
  }
  return encoded;
}

function decodeHamming74(bits) {
  if (bits.length % 14 !== 0) {
    throw new StegoError("CORRUPT", "Panjang data koreksi kesalahan pada gambar tidak valid.");
  }
  const decoded = new Uint8Array(bits.length / 14);
  let out = 0;
  for (let byteIndex = 0; byteIndex < decoded.length; byteIndex++) {
    let byte = 0;
    for (let half = 0; half < 2; half++) {
      const start = byteIndex * 14 + half * 7;
      const code = bits.slice(start, start + 7);
      const syndrome = (code[0] ^ code[2] ^ code[4] ^ code[6]) |
        ((code[1] ^ code[2] ^ code[5] ^ code[6]) << 1) |
        ((code[3] ^ code[4] ^ code[5] ^ code[6]) << 2);
      if (syndrome > 0) code[syndrome - 1] ^= 1;
      const nibble = (code[2] << 3) | (code[4] << 2) | (code[5] << 1) | code[6];
      byte |= nibble << (half === 0 ? 4 : 0);
    }
    decoded[out++] = byte;
  }
  return decoded;
}

function incrementCounter(counter, blocks) {
  let carry = blocks;
  for (let i = counter.length - 1; i >= 0 && carry > 0; i--) {
    const sum = counter[i] + (carry % 256);
    counter[i] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum > 0xff ? 1 : 0);
  }
  if (carry > 0) throw new StegoError("CAPACITY", "Gambar terlalu besar untuk mode penyebaran V2.");
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

function makeUniqueSamplePicker(slotCount, key) {
  if (!Number.isSafeInteger(slotCount) || slotCount < 1 || slotCount > UINT32_RANGE) {
    throw new StegoError("CAPACITY", "Jumlah piksel gambar berada di luar batas V2.");
  }
  const occupied = new Uint8Array(Math.ceil(slotCount / 8));
  const random = createRandomStream(key);
  const acceptedLimit = Math.floor(UINT32_RANGE / slotCount) * slotCount;

  return {
    async refill() {
      await random.refill();
    },
    nextSample() {
      while (true) {
        const word = random.nextUint32();
        if (word === null) return null;
        if (word >= acceptedLimit) continue;
        const sample = word % slotCount;
        const mask = 1 << (sample & 7);
        const byteIndex = sample >> 3;
        if (occupied[byteIndex] & mask) continue;
        occupied[byteIndex] |= mask;
        return sample;
      }
    },
  };
}

function validateV2Payload(payload, imageData) {
  if (payload.length < V2_HEADER_FIXED) {
    throw new StegoError("CORRUPT", "Payload CryptoPic V2 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(0, false);
  const prefixLength = V2_HEADER_FIXED + view.getUint16(32, false);
  if (total !== payload.length || prefixLength + TAG_LEN > total) {
    throw new StegoError("CORRUPT", "Panjang payload CryptoPic V2 tidak konsisten.");
  }
  const availableSlots = imageData.width * imageData.height * 3 - prefixLength * 8;
  const codedBits = (payload.length - prefixLength) * HAMMING_BITS_PER_BYTE;
  if (availableSlots <= 0 || codedBits > availableSlots * MAX_EMBEDDED_SAMPLE_RATIO) {
    const maxBytes = maxMessageBytes(imageData.width, imageData.height, "");
    throw new StegoError(
      "TOO_LARGE",
      `Pesan dan petunjuk melebihi kapasitas aman gambar (sekitar ${maxBytes} byte pesan). Gunakan gambar beresolusi lebih besar atau pesan lebih pendek.`
    );
  }
  return { prefixLength, availableSlots, codedBits };
}

async function embedV3Payload(imageData, data, payload, stegoKey) {
  const width = imageData.width;
  const height = imageData.height;
  const totalSamples = width * height * 3;
  if (payload.length < V3_HEADER_FIXED) {
    throw new StegoError("CORRUPT", "Payload CryptoPic V3 tidak lengkap.");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const total = view.getUint32(5, false);
  const hintLen = view.getUint16(51, false);
  const prefixLength = V3_HEADER_FIXED + hintLen;
  if (total !== payload.length || prefixLength + TAG_LEN > total) {
    throw new StegoError("CORRUPT", "Panjang payload CryptoPic V3 tidak konsisten.");
  }
  const nonce = payload.slice(15, 23);
  const prefix = payload.subarray(0, prefixLength);
  const body = payload.subarray(prefixLength);
  const headerSamples = prefixLength * 8;
  const groups = Math.ceil((body.length * 8) / MATRIX_BITS);
  const bodySamples = groups * MATRIX_GROUP;
  const usedSamples = V3_BOOTSTRAP_SAMPLES + headerSamples + bodySamples;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO);

  if (totalSamples < V3_BOOTSTRAP_SAMPLES + headerSamples || usedSamples > budget) {
    const maxBytes = maxMessageBytesV3(width, height, "");
    throw new StegoError(
      "TOO_LARGE",
      `Pesan dan petunjuk melebihi kapasitas aman gambar (sekitar ${maxBytes} byte pesan). ` +
        "Gunakan gambar beresolusi lebih besar atau pesan lebih pendek."
    );
  }

  // Bootstrap: nonce 8 byte, ditulis berurutan (nilainya acak sehingga tidak
  // membocorkan struktur seperti header V1/V2).
  writeSequentialBytes(data, nonce);

  const seed = v3Seed(nonce, width, height);
  const bootstrap = bootstrapSet();
  const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
  const used = writeHeaderBytes(data, prefix, headerPicker);

  const excluded = new Set(used);
  for (let i = 0; i < V3_BOOTSTRAP_SAMPLES; i++) excluded.add(i);

  const activity = computeActivity(imageData);
  const threshold = chooseActivityThreshold(activity, bodySamples + excluded.size);
  const picker = makeV3BodyPicker(totalSamples, stegoKey, activity, threshold, excluded);
  await picker.refill();
  await embedMatrixBody(data, body, picker);

  return new ImageData(data, width, height);
}

export async function embedPayload(imageData, payload, stegoKey = null) {
  const totalSamples = imageData.width * imageData.height * 3;
  const data = new Uint8ClampedArray(imageData.data);
  const hasMagic =
    payload.length >= 5 &&
    payload[0] === 0x43 &&
    payload[1] === 0x50 &&
    payload[2] === 0x49 &&
    payload[3] === 0x43;

  if (hasMagic && payload[4] === 1) {
    if (payload.length > Math.floor(totalSamples / 8)) {
      throw new StegoError("TOO_LARGE", "Pesan + petunjuk melebihi kapasitas PNG.");
    }
    writeSequentialBytes(data, payload);
    return new ImageData(data, imageData.width, imageData.height);
  }
  if (hasMagic && payload[4] === 3) {
    if (!stegoKey) {
      throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload V3 memerlukan kunci posisi steganografi.");
    }
    return embedV3Payload(imageData, data, payload, stegoKey);
  }
  if (hasMagic || !stegoKey) {
    throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload V2 memerlukan kunci posisi steganografi.");
  }

  const { prefixLength, availableSlots, codedBits } = validateV2Payload(payload, imageData);
  const prefix = payload.subarray(0, prefixLength);
  writeSequentialBytes(data, prefix);
  const encodedBody = encodeHamming74(payload.subarray(prefixLength));
  const picker = makeUniqueSamplePicker(availableSlots, stegoKey);
  const firstBodySample = prefixLength * 8;
  for (let i = 0; i < codedBits; i++) {
    let sample = picker.nextSample();
    if (sample === null) {
      await picker.refill();
      i--;
      continue;
    }
    writeBit(data, firstBodySample + sample, encodedBody[i]);
  }
  return new ImageData(data, imageData.width, imageData.height);
}

function tryExtractV3(data, width, height) {
  const totalSamples = width * height * 3;
  if (totalSamples < V3_BOOTSTRAP_SAMPLES + V3_HEADER_FIXED * 8) return null;

  const nonce = readSequentialBytes(data, V3_BOOTSTRAP_BYTES);
  const seed = v3Seed(nonce, width, height);
  const bootstrap = bootstrapSet();

  try {
    const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
    const { bytes: fixed } = readHeaderBytes(data, V3_HEADER_FIXED, headerPicker);
    if (!(fixed[0] === 0x43 && fixed[1] === 0x50 && fixed[2] === 0x49 && fixed[3] === 0x43 && fixed[4] === 3)) {
      return null;
    }
    if (!nonceEqual(fixed.slice(15, 23), nonce)) return null;

    const view = new DataView(fixed.buffer, fixed.byteOffset, fixed.byteLength);
    const total = view.getUint32(5, false);
    const hintLen = view.getUint16(51, false);
    const prefixLength = V3_HEADER_FIXED + hintLen;
    if (
      prefixLength + TAG_LEN > total ||
      total > totalSamples ||
      V3_BOOTSTRAP_SAMPLES + prefixLength * 8 > totalSamples
    ) {
      return null;
    }

    let hintBytes = new Uint8Array(0);
    if (hintLen > 0) {
      hintBytes = readHeaderBytes(data, hintLen, headerPicker).bytes;
    }
    const prefix = new Uint8Array(prefixLength);
    prefix.set(fixed);
    prefix.set(hintBytes, V3_HEADER_FIXED);
    return prefix;
  } catch {
    return null;
  }
}

export function extractPayload(imageData) {
  const data = imageData.data;
  const totalSamples = imageData.width * imageData.height * 3;
  if (Math.floor(totalSamples / 8) < V1_HEADER_FIXED + TAG_LEN) {
    throw new StegoError("NOT_CRYPTOPIC", "Gambar terlalu kecil untuk berisi pesan CryptoPic.");
  }

  const v3 = tryExtractV3(data, imageData.width, imageData.height);
  if (v3) return v3;

  const firstFour = readSequentialBytes(data, 4);
  const isV1 = firstFour[0] === 0x43 && firstFour[1] === 0x50 && firstFour[2] === 0x49 && firstFour[3] === 0x43;
  let version = 2;
  if (isV1) {
    version = readSequentialBytes(data, 5)[4];
    if (version !== 1) {
      throw new StegoError("BAD_VERSION", `Versi payload bertanda tidak didukung (v${version}).`);
    }
  }

  const fixedLength = version === 1 ? V1_HEADER_FIXED : V2_HEADER_FIXED;
  const fixed = readSequentialBytes(data, fixedLength);
  const view = new DataView(fixed.buffer);
  const total = view.getUint32(version === 1 ? 6 : 0, false);
  const prefixLength = version === 1
    ? V1_HEADER_FIXED + view.getUint16(38, false)
    : V2_HEADER_FIXED + view.getUint16(32, false);
  if (total > Math.floor(totalSamples / 8) || prefixLength + TAG_LEN > total) {
    throw new StegoError("CORRUPT", "Piksel gambar tidak konsisten atau pesan telah rusak.");
  }
  if (version === 2) {
    const bodyLength = total - prefixLength;
    const remainingSamples = totalSamples - prefixLength * 8;
    if (prefixLength * 8 > totalSamples || bodyLength * HAMMING_BITS_PER_BYTE > remainingSamples * MAX_EMBEDDED_SAMPLE_RATIO) {
      throw new StegoError("CORRUPT", "Header CryptoPic V2 menunjukkan kapasitas gambar yang tidak valid.");
    }
  }
  return readSequentialBytes(data, version === 1 ? total : prefixLength);
}

async function extractV3Body(imageData, parsed, stegoKey) {
  const width = imageData.width;
  const height = imageData.height;
  const totalSamples = width * height * 3;
  const bodyBytes = parsed.total - parsed.prefixLength;
  if (bodyBytes < TAG_LEN) {
    throw new StegoError("CORRUPT", "Payload V3 tidak lengkap.");
  }
  if (!parsed.nonce || parsed.nonce.length !== V3_BOOTSTRAP_BYTES) {
    throw new StegoError("CORRUPT", "Nonce V3 pada gambar tidak valid.");
  }

  // Hitung ulang posisi header agar bisa dikecualikan dari pemilihan body.
  const seed = v3Seed(parsed.nonce, width, height);
  const bootstrap = bootstrapSet();
  const headerPicker = makeSeededPicker(seed, totalSamples, bootstrap);
  const { used } = readHeaderBytes(imageData.data, parsed.prefixLength, headerPicker);

  const excluded = new Set(used);
  for (let i = 0; i < V3_BOOTSTRAP_SAMPLES; i++) excluded.add(i);

  const groups = Math.ceil((bodyBytes * 8) / MATRIX_BITS);
  const bodySamples = groups * MATRIX_GROUP;
  const budget = Math.floor(totalSamples * MAX_EMBEDDED_SAMPLE_RATIO);
  if (V3_BOOTSTRAP_SAMPLES + parsed.prefixLength * 8 + bodySamples > budget) {
    throw new StegoError("CORRUPT", "Payload V3 tidak muat pada gambar atau pikselnya telah berubah.");
  }

  const activity = computeActivity(imageData);
  const threshold = chooseActivityThreshold(activity, bodySamples + excluded.size);
  const picker = makeV3BodyPicker(totalSamples, stegoKey, activity, threshold, excluded);
  await picker.refill();
  return extractMatrixBody(imageData.data, bodyBytes, picker);
}

export async function extractProtectedBody(imageData, parsed, stegoKey) {
  if (!stegoKey) {
    throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload terproteksi memerlukan kunci posisi steganografi.");
  }
  if (parsed.version === 3) {
    return extractV3Body(imageData, parsed, stegoKey);
  }
  if (parsed.version !== 2) {
    throw new StegoError("CRYPTO_KEY_REQUIRED", "Payload V2 memerlukan kunci posisi steganografi.");
  }
  const bodyLength = parsed.total - parsed.prefixLength;
  const codedBits = bodyLength * HAMMING_BITS_PER_BYTE;
  const totalSamples = imageData.width * imageData.height * 3;
  const availableSlots = totalSamples - parsed.prefixLength * 8;
  if (bodyLength < TAG_LEN || availableSlots <= 0 || codedBits > availableSlots * MAX_EMBEDDED_SAMPLE_RATIO) {
    throw new StegoError("CORRUPT", "Payload V2 tidak muat pada gambar atau pikselnya telah berubah.");
  }

  const coded = new Uint8Array(codedBits);
  const picker = makeUniqueSamplePicker(availableSlots, stegoKey);
  const firstBodySample = parsed.prefixLength * 8;
  for (let i = 0; i < codedBits; i++) {
    let sample = picker.nextSample();
    if (sample === null) {
      await picker.refill();
      i--;
      continue;
    }
    coded[i] = readBit(imageData.data, firstBodySample + sample);
  }
  return decodeHamming74(coded);
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
