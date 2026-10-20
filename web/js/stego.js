const V1_HEADER_FIXED = 40;
const V2_HEADER_FIXED = 34;
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
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  for (let i = 3; i < imageData.data.length; i += 4) {
    imageData.data[i] = 255;
  }
  return { imageData, canvas };
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

export async function embedPayload(imageData, payload, stegoKey = null) {
  const totalSamples = imageData.width * imageData.height * 3;
  const data = new Uint8ClampedArray(imageData.data);
  const isV1 = payload.length >= 5 && payload[0] === 0x43 && payload[1] === 0x50 && payload[2] === 0x49 && payload[3] === 0x43;
  if (isV1 && payload[4] === 1) {
    if (payload.length > Math.floor(totalSamples / 8)) {
      throw new StegoError("TOO_LARGE", "Pesan + petunjuk melebihi kapasitas PNG.");
    }
    writeSequentialBytes(data, payload);
    return new ImageData(data, imageData.width, imageData.height);
  }
  if (isV1 || !stegoKey) {
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

export function extractPayload(imageData) {
  const data = imageData.data;
  const totalSamples = imageData.width * imageData.height * 3;
  if (Math.floor(totalSamples / 8) < V1_HEADER_FIXED + TAG_LEN) {
    throw new StegoError("NOT_CRYPTOPIC", "Gambar terlalu kecil untuk berisi pesan CryptoPic.");
  }

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

export async function extractProtectedBody(imageData, parsed, stegoKey) {
  if (parsed.version !== 2 || !stegoKey) {
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
