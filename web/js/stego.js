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

export function embedPayload(imageData, payload) {
  const capacity = capacityBytes(imageData.width, imageData.height);
  if (payload.length > capacity) {
    throw new StegoError(
      "TOO_LARGE",
      `Pesan + petunjuk membutuhkan ${payload.length} byte, tetapi gambar hanya muat ${capacity} byte. Perpendek pesan atau pakai gambar PNG beresolusi lebih besar.`
    );
  }

  const data = new Uint8ClampedArray(imageData.data);
  const bitLength = payload.length * 8;
  for (let i = 0; i < bitLength; i++) {
    const bit = (payload[i >> 3] >> (7 - (i & 7))) & 1;
    const offset = Math.floor(i / 3) * 4 + (i % 3);
    data[offset] = (data[offset] & 0xfe) | bit;
  }
  return new ImageData(data, imageData.width, imageData.height);
}

export function extractPayload(imageData) {
  const data = imageData.data;
  const capacity = capacityBytes(imageData.width, imageData.height);
  if (capacity < 56) {
    throw new StegoError("NOT_CRYPTOPIC", "Gambar terlalu kecil untuk berisi pesan CryptoPic.");
  }

  function readBytes(count) {
    const out = new Uint8Array(count);
    const bitLength = count * 8;
    for (let i = 0; i < bitLength; i++) {
      const offset = Math.floor(i / 3) * 4 + (i % 3);
      const bit = data[offset] & 1;
      out[i >> 3] = (out[i >> 3] << 1) | bit;
    }
    return out;
  }

  const fixed = readBytes(40);
  const total = new DataView(fixed.buffer).getUint32(6, false);
  if (total > capacity) {
    throw new StegoError(
      "CORRUPT",
      "Piksel gambar tidak konsisten — kemungkinan telah dikompresi, diubah ukurannya, atau discreenshot."
    );
  }
  const payload = readBytes(total);
  return payload;
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
