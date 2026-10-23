import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { runInNewContext } from "node:vm";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });
globalThis.ImageData = class ImageData {
  constructor(data, width, height) {
    this.data = data;
    this.width = width;
    this.height = height;
  }
};

const require = createRequire(import.meta.url);
globalThis.hashwasm = require(fileURLToPath(new URL("../web/js/vendor/hash-wasm-argon2-4.12.0.min.js", import.meta.url)));

async function importSource(relativePath) {
  const source = await readFile(new URL(relativePath, import.meta.url));
  return import(`data:text/javascript;base64,${source.toString("base64")}`);
}

const cryptoPic = await importSource("../web/js/crypto.js");
const stego = await importSource("../web/js/stego.js");
let passed = 0;
const started = performance.now();

/*
 * Node 26 + hash-wasm 4.12.0 menumpuk memori WASM antar panggilan Argon2id
 * in-process (aplikasi browser tidak terkena karena selalu memakai worker baru
 * tiap panggilan). Untuk bisa menjalankan seluruh suite di Node, grup bisa
 * dipilih lewat variabel lingkungan, mis. CRYPTOPIC_TEST_RANGE=1-8.
 */
const rangeEnv = process.env.CRYPTOPIC_TEST_RANGE || "";
const [rangeFrom, rangeTo] = rangeEnv
  ? rangeEnv.split("-").map((value) => Number(value))
  : [1, Infinity];
let groupIndex = 0;

async function check(name, fn) {
  groupIndex += 1;
  const current = groupIndex;
  if (current < rangeFrom || current > (rangeTo || Infinity)) return;
  await fn();
  passed++;
  console.log(`PASS ${current}: ${name}`);
}

function makeCover(width = 256, height = 256) {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let pixel = 0; pixel < width * height; pixel++) {
    data[pixel * 4] = (pixel * 29 + 53) & 0xff;
    data[pixel * 4 + 1] = (pixel * 17 + 91) & 0xff;
    data[pixel * 4 + 2] = (pixel * 7 + 137) & 0xff;
    data[pixel * 4 + 3] = 255;
  }
  return { width, height, data };
}

async function makeImage(message, password, hint, cover = makeCover(), kdf = undefined) {
  const encrypted = await cryptoPic.encryptPayload(password, message, hint, kdf);
  const image = await stego.embedPayload(cover, encrypted.payload, encrypted.stegoKey);
  const prefix = stego.extractPayload(image);
  const parsed = cryptoPic.parsePayload(prefix);
  const keys = await cryptoPic.deriveKeys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, keys.stegoKey);
  return { image, parsed, keys, body, prefix, message, encrypted };
}

function readSequentialSampleBytes(image, count) {
  const out = new Uint8Array(count);
  for (let i = 0; i < count * 8; i++) {
    const sample = i;
    const offset = Math.floor(sample / 3) * 4 + (sample % 3);
    out[i >> 3] = (out[i >> 3] << 1) | (image.data[offset] & 1);
  }
  return out;
}

async function openImage(password, parsed, image, keys = null) {
  const activeKeys = keys || await cryptoPic.deriveKeys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, activeKeys.stegoKey);
  return cryptoPic.decryptPayload(password, parsed, body, activeKeys);
}

await check("16 round trips (4 passphrase/message cases repeated 4 times)", async () => {
  const cases = [
    { password: "Pohon Kuat-2026!", message: "Pesan rahasia dengan tanda baca.", hint: "nama tempat" },
    { password: "Sandi V4 Baru", message: "Satu format saja, tanpa percabangan versi.", hint: "" },
    { password: "cafe\u0301-unicode", typed: "café-unicode", message: "Unicode NFC dan emoji 🔐🌿", hint: "petunjuk ü" },
    { password: "empat kata acak 2026", message: "Baris pertama\nBaris kedua\nBaris ketiga.", hint: "uji multi-baris" },
  ];
  const salts = new Set();
  const nonces = new Set();
  for (let round = 0; round < 4; round++) {
    for (const item of cases) {
      const result = await makeImage(item.message, item.password, item.hint);
      assert.equal(result.parsed.version, 4);
      assert.equal(result.parsed.hint, item.hint);
      assert.ok(result.parsed.kdf.memorySize >= 8 && result.parsed.kdf.iterations >= 1);
      assert.equal(
        await cryptoPic.decryptPayload(item.typed || item.password, result.parsed, result.body, result.keys),
        item.message
      );
      salts.add(Buffer.from(result.parsed.salt).toString("hex"));
      nonces.add(Buffer.from(result.parsed.nonce).toString("hex"));
    }
  }
  assert.equal(salts.size, 16, "Each encryption should use a fresh random salt.");
  assert.equal(nonces.size, 16, "Each encryption must use a fresh nonce.");
});

await check("Password case is ignored: lowercase, uppercase and mixed case all open V4 images", async () => {
  const result = await makeImage("Kapitalisasi tidak lagi menyulitkan penerima.", "Rahasia Besar 2026", "uji sandi");
  for (const typed of ["Rahasia Besar 2026", "rahasia besar 2026", "RAHASIA BESAR 2026", "rAhAsIa bEsAr 2026"]) {
    assert.equal(await openImage(typed, result.parsed, result.image), result.message);
  }
});

await check("Password spaces are still significant (capitalisation is not the only trap)", async () => {
  const result = await makeImage("Spasi tetap penting.", "sandi kuat 2026", "");
  await assert.rejects(
    openImage("sandikuat2026", result.parsed, result.image),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
  await assert.rejects(
    openImage("sandi kuat 2026 ", result.parsed, result.image),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("Wrong V4 password is rejected with WRONG_PASSWORD", async () => {
  const result = await makeImage("Kata sandi salah.", "sandi benar 2026", "uji sandi");
  await assert.rejects(
    openImage("sandi lain 2026", result.parsed, result.image),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("Argon2id worker returns the same bytes as the vendored library", async () => {
  let posted;
  const workerContext = {
    self: {
      hashwasm: globalThis.hashwasm,
      postMessage(message) { posted = message; },
    },
    importScripts() {},
    Uint8Array,
  };
  const workerSource = await readFile(new URL("../web/js/argon2-worker.js", import.meta.url), "utf8");
  runInNewContext(workerSource, workerContext, {
    filename: "argon2-worker.js",
    import: "<worker importScripts stubbed with the pinned vendored package>",
  });
  const password = new Uint8Array([112, 97, 115, 115]);
  const salt = new Uint8Array(16).fill(2);
  const options = { password, salt, iterations: 2, parallelism: 1, memorySize: 32, hashLength: 32, outputType: "binary" };
  const expected = await globalThis.hashwasm.argon2id(options);
  await workerContext.self.onmessage({ data: { ...options, hashLength: undefined, outputType: undefined } });
  assert.ok(posted && posted.root instanceof ArrayBuffer);
  assert.deepEqual(new Uint8Array(posted.root), expected);
});

await check("Memo vault keeps the old PIN normalisation (NFC only) so existing vaults still unlock", async () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kdf = { memorySize: 8192, iterations: 1, parallelism: 1 };
  const pin = "Vault PIN 2026";

  // Jalur vault (deriveArgon2KeyBytes) harus menghasilkan byte Argon2id yang
  // identik dengan hashwasm untuk PIN bentuk NFC — inilah yang membuat vault
  // Argon2id lama tetap bisa dibuka setelah refactor.
  const vaultKey = await cryptoPic.deriveArgon2KeyBytes(pin, salt, kdf);
  const expected = await globalThis.hashwasm.argon2id({
    password: new TextEncoder().encode(pin.normalize("NFC")),
    salt,
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    memorySize: kdf.memorySize,
    hashLength: 32,
    outputType: "binary",
  });
  assert.deepEqual(new Uint8Array(vaultKey), new Uint8Array(expected));

  const upper = await cryptoPic.deriveArgon2KeyBytes("VAULT PIN 2026", salt, kdf);
  assert.notEqual(
    Buffer.from(upper).toString("hex"),
    Buffer.from(vaultKey).toString("hex"),
    "PIN vault harus tetap case-sensitive seperti sebelumnya."
  );
  // deriveArgon2KeyBytes bersifat async, jadi pelanggaran batas KDF muncul
  // sebagai promise yang ditolak — pakai assert.rejects, bukan assert.throws.
  await assert.rejects(
    cryptoPic.deriveArgon2KeyBytes("pin", salt, { memorySize: 8, iterations: 1, parallelism: 1 }),
    (error) => error && error.code === "KDF_INVALID",
    "Parameter KDF di luar batas harus ditolak."
  );
  assert.ok(!cryptoPic.isKdfAcceptable({ memorySize: 8, iterations: 1, parallelism: 1 }));
});

await check("V4 header is not a sequential plaintext block at the start of the image", async () => {
  const result = await makeImage("Header harus tersebar.", "Sandi header tersebar", "petunjuk rahasia");
  const firstFive = readSequentialSampleBytes(result.image, 5);
  // Bootstrap acak; sangat tidak mungkin kebetulan sama dengan magic+versi.
  assert.notDeepEqual(Array.from(firstFive), [0x43, 0x50, 0x49, 0x43, 4]);
  // Namun pembaca tetap menemukan header dan petunjuknya.
  assert.equal(result.parsed.hint, "petunjuk rahasia");
});

await check("V4 matrix embedding changes fewer samples than raw LSB for the same payload", async () => {
  const cover = makeCover(512, 512);
  const message = "x".repeat(1200);
  const encrypted = await cryptoPic.encryptPayload("Sandi matrix embedding 2026", message, "");
  const image = await stego.embedPayload(cover, encrypted.payload, encrypted.stegoKey);

  let changed = 0;
  for (let sample = 0; sample < cover.width * cover.height * 3; sample++) {
    const offset = Math.floor(sample / 3) * 4 + (sample % 3);
    if ((cover.data[offset] & 1) !== (image.data[offset] & 1)) changed++;
  }
  const bodyBits = (encrypted.payload.length - 53) * 8;
  assert.ok(changed < bodyBits * 0.7, `changed=${changed} bodyBits=${bodyBits}`);
});

await check("V4 survives a flat (texture-less) cover by lowering the adaptive threshold", async () => {
  const width = 240;
  const height = 240;
  const flat = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < flat.length; i += 4) {
    flat[i] = 128;
    flat[i + 1] = 128;
    flat[i + 2] = 128;
    flat[i + 3] = 255;
  }
  const cover = { width, height, data: flat };
  const result = await makeImage("Pesan pada gambar datar.", "Sandi gambar datar 2026", "", cover);
  assert.equal(await openImage("SANDI GAMBAR DATAR 2026", result.parsed, result.image), "Pesan pada gambar datar.");
});

await check("V4 rejects tampered bootstrap and body pixels", async () => {
  const password = "Sandi anti-ubah 2026";
  const result = await makeImage("Pesan yang akan dirusak.", password, "tamper");

  // Bootstrap (nonce) tamper: penerima yang membuka file rusak harus membaca
  // ulang headernya dari gambar, bukan memakai header lama yang masih bersih.
  const bootstrapDamaged = new ImageData(
    new Uint8ClampedArray(result.image.data),
    result.image.width,
    result.image.height
  );
  bootstrapDamaged.data[0] ^= 1;
  let damagedRejected = false;
  try {
    const damagedPrefix = stego.extractPayload(bootstrapDamaged);
    const damagedParsed = cryptoPic.parsePayload(damagedPrefix);
    await openImage(password, damagedParsed, bootstrapDamaged);
  } catch (error) {
    damagedRejected =
      error && (error.code === "WRONG_PASSWORD" || error.code === "CORRUPT" || error.code === "NOT_CRYPTOPIC" || error.code === "LEGACY_FORMAT");
  }
  assert.ok(damagedRejected, "Nonce/bootstrap yang diubah harus membuat gambar tidak terbaca.");

  // Body tamper: alter the extracted ciphertext (deterministic) and ensure GCM rejects it.
  const prefix = stego.extractPayload(result.image);
  const parsed = cryptoPic.parsePayload(prefix);
  const keys = await cryptoPic.deriveKeys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(result.image, parsed, keys.stegoKey);
  const tampered = new Uint8Array(body);
  tampered[0] ^= 1;
  await assert.rejects(cryptoPic.decryptPayload(password, parsed, tampered, keys), (error) => {
    return error && (error.code === "WRONG_PASSWORD" || error.code === "CORRUPT");
  });
});

await check("Visible hint is authenticated as AES-GCM associated data", async () => {
  const result = await makeImage("Metadata perlu tervalidasi.", "Sandi metadata kuat", "hint");
  const changed = new ImageData(new Uint8ClampedArray(result.image.data), result.image.width, result.image.height);

  // Header V4 tersebar, jadi kita cari sample yang benar-benar mengubah prefix
  // hasil ekstraksi dengan membalik LSB-nya satu per satu.
  const totalSamples = changed.width * changed.height * 3;
  let alteredPrefix = null;
  let alteredParsed = null;
  for (let sample = 0; sample < totalSamples && !alteredPrefix; sample++) {
    const offset = Math.floor(sample / 3) * 4 + (sample % 3);
    changed.data[offset] ^= 1;
    try {
      const candidate = stego.extractPayload(changed);
      const candidateParsed = cryptoPic.parsePayload(candidate);
      // Targetkan perubahan pada byte petunjuk itu sendiri, bukan header lain.
      if (candidateParsed.hint !== result.parsed.hint) {
        alteredPrefix = candidate;
        alteredParsed = candidateParsed;
      }
    } catch {
      // sample ini bukan bagian header yang bisa di-parse; coba berikutnya.
    }
    if (!alteredPrefix) changed.data[offset] ^= 1;
  }

  assert.ok(alteredPrefix && alteredParsed, "Harus ada sample petunjuk yang bisa diubah untuk uji AAD.");
  assert.notEqual(alteredParsed.hint, result.parsed.hint);
  await assert.rejects(
    openImage("Sandi metadata kuat", alteredParsed, changed, result.keys),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("V4 capacity estimator is respected at and beyond the limit", async () => {
  const width = 400;
  const height = 400;
  const capacity = stego.maxMessageBytes(width, height, "hint");
  assert.ok(capacity > 0);

  const atLimit = await cryptoPic.encryptPayload("Sandi kapasitas V4 2026", "a".repeat(capacity), "hint");
  const embedded = await stego.embedPayload(makeCover(width, height), atLimit.payload, atLimit.stegoKey);
  assert.ok(embedded.data.length > 0, "Estimated V4 maximum should fit.");

  const over = await cryptoPic.encryptPayload("Sandi kapasitas V4 2026", "a".repeat(capacity + 64), "hint");
  await assert.rejects(
    stego.embedPayload(makeCover(width, height), over.payload, over.stegoKey),
    (error) => error && error.code === "TOO_LARGE"
  );
});

await check("V4 stores custom KDF parameters in the header and honours them", async () => {
  const kdf = { memorySize: 8192, iterations: 1, parallelism: 1 };
  const result = await makeImage("Parameter KDF kustom.", "Sandi KDF kustom 2026", "kdf", makeCover(192, 192), kdf);
  assert.deepEqual(result.parsed.kdf, kdf);
  assert.equal(await openImage("sandi kdf kustom 2026", result.parsed, result.image), "Parameter KDF kustom.");
});

await check("V4 rejects unreasonable KDF parameters", async () => {
  const { payload } = await cryptoPic.encryptPayload("Sandi KDF 2026", "pesan", "kdf");
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

  const tooMuchMemory = new Uint8Array(payload);
  new DataView(tooMuchMemory.buffer).setUint32(9, 1024 * 1024, false); // 1 GiB
  assert.throws(
    () => cryptoPic.parsePayload(tooMuchMemory),
    (error) => error && error.code === "CORRUPT"
  );

  const tooMuchWork = new Uint8Array(payload);
  const workView = new DataView(tooMuchWork.buffer);
  workView.setUint32(9, 256 * 1024, false); // 256 MiB
  tooMuchWork[13] = 8; // 8 iterasi → 2 GiB·iter > batas 512 MiB·iter
  assert.throws(
    () => cryptoPic.parsePayload(tooMuchWork),
    (error) => error && error.code === "CORRUPT"
  );

  assert.equal(view.getUint32(9, false), cryptoPic.KDF.memorySize);
  assert.ok(cryptoPic.isKdfAcceptable(cryptoPic.KDF));
  assert.ok(!cryptoPic.isKdfAcceptable({ memorySize: 8, iterations: 1, parallelism: 1 }));
  assert.ok(!cryptoPic.isKdfAcceptable({ memorySize: 65536, iterations: 3, parallelism: 0 }));
  // encryptPayload bersifat async: pelanggaran batas KDF muncul sebagai promise
  // yang ditolak, bukan lemparan sinkron.
  await assert.rejects(
    cryptoPic.encryptPayload("Sandi KDF 2026", "pesan", "", { memorySize: 1024 * 1024, iterations: 1, parallelism: 1 }),
    (error) => error && error.code === "KDF_INVALID"
  );
});

await check("Legacy formats are refused with a clear message instead of decrypting", async () => {
  // Header V3 buatan tangan: magic + versi 3.
  const legacy = new Uint8Array(53 + 16);
  legacy.set([0x43, 0x50, 0x49, 0x43], 0);
  legacy[4] = 3;
  new DataView(legacy.buffer).setUint32(5, legacy.length, false);
  new DataView(legacy.buffer).setUint32(9, cryptoPic.KDF.memorySize, false);
  legacy[13] = cryptoPic.KDF.iterations;
  legacy[14] = cryptoPic.KDF.parallelism;
  assert.throws(
    () => cryptoPic.parsePayload(legacy),
    (error) => error && error.code === "LEGACY_FORMAT"
  );

  // Payload V2 (tanpa magic) harus ditolak sebagai bukan V4. Panjangnya harus
  // minimal HEADER_FIXED agar melewati pemeriksaan panjang dan sampai ke
  // pemeriksaan magic.
  const v2Like = new Uint8Array(60);
  new DataView(v2Like.buffer).setUint32(0, 60, false);
  assert.throws(
    () => cryptoPic.parsePayload(v2Like),
    (error) => error && error.code === "NOT_CRYPTOPIC"
  );
});

await check("Steganography refuses legacy payloads and missing keys", async () => {
  const { payload, stegoKey } = await cryptoPic.encryptPayload("Sandi tolak lama 2026", "pesan", "");
  await assert.rejects(
    stego.embedPayload(makeCover(), payload, null),
    (error) => error && error.code === "CRYPTO_KEY_REQUIRED"
  );

  const legacy = new Uint8Array(payload);
  legacy[4] = 3;
  await assert.rejects(
    stego.embedPayload(makeCover(), legacy, stegoKey),
    (error) => error && error.code === "BAD_VERSION"
  );

  // Gambar lama (V1/V2) menyimpan magic + versi berurutan di LSB awal. Buat
  // gambar seperti itu secara manual supaya jalur deteksi format lama teruji.
  const cover = makeCover(80, 80);
  const legacyImageData = { width: cover.width, height: cover.height, data: new Uint8ClampedArray(cover.data) };
  const legacyBytes = new Uint8Array([0x43, 0x50, 0x49, 0x43, 2]);
  for (let i = 0; i < legacyBytes.length * 8; i++) {
    const bit = (legacyBytes[i >> 3] >> (7 - (i & 7))) & 1;
    const offset = Math.floor(i / 3) * 4 + (i % 3);
    legacyImageData.data[offset] = (legacyImageData.data[offset] & 0xfe) | bit;
  }
  assert.throws(
    () => stego.extractPayload(legacyImageData),
    (error) => error && error.code === "LEGACY_FORMAT"
  );
});

await check("Sanitasi menghapus payload dan mempertahankan dimensi", async () => {
  const { image } = await makeImage("Pesan yang harus musnah.", "Sandi bersih 2026", "bersih");

  let clean = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const candidate = stego.sanitizeImageData(image);
    let readable = false;
    try {
      cryptoPic.parsePayload(stego.extractPayload(candidate));
      readable = true;
    } catch {
      readable = false;
    }
    if (!readable) {
      clean = candidate;
      break;
    }
  }

  assert.ok(clean, "Sanitasi harus menghapus payload lama.");
  assert.equal(clean.width, image.width);
  assert.equal(clean.height, image.height);
  assert.equal(
    stego.maxMessageBytes(clean.width, clean.height, "baru"),
    stego.maxMessageBytes(image.width, image.height, "baru")
  );

  let maxDelta = 0;
  for (let i = 0; i < image.data.length; i++) {
    if (i % 4 === 3) {
      assert.equal(clean.data[i], 255);
      continue;
    }
    maxDelta = Math.max(maxDelta, Math.abs(clean.data[i] - image.data[i]));
  }
  assert.ok(maxDelta <= 1, `Perubahan pixel harus maksimal 1, dapat ${maxDelta}.`);
});

await check("PNG bit-depth: 8-bit accepted, 16-bit rejected with BIT_DEPTH", async () => {
  // Bangun PNG minimal dengan IHDR + IDAT valid (zlib) untuk tiap kedalaman.
  const zlib = require("node:zlib");
  const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  })();
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0);
    out.write(type, 4, "ascii");
    data.copy(out, 8);
    out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, "ascii"), data])), 8 + data.length);
    return out;
  };
  const makePng = (bitDepth, colorType, bytesPerPixel) => {
    const width = 4;
    const height = 4;
    const raw = Buffer.alloc((width * bytesPerPixel + 1) * height);
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = bitDepth;
    ihdr[9] = colorType;
    return Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      chunk("IHDR", ihdr),
      chunk("IDAT", zlib.deflateSync(raw)),
      chunk("IEND", Buffer.alloc(0)),
    ]);
  };
  const toArrayBuffer = (buffer) => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);

  const eightBit = toArrayBuffer(makePng(8, 6, 4));
  const ihdr8 = stego.validatePNGStructure(eightBit);
  assert.equal(ihdr8.bitDepth, 8);
  assert.equal(stego.is16BitPng(eightBit), false);

  const sixteenBit = toArrayBuffer(makePng(16, 6, 8));
  assert.equal(stego.is16BitPng(sixteenBit), true);
  assert.throws(
    () => stego.validatePNGStructure(sixteenBit),
    (error) => error && error.code === "BIT_DEPTH" && /16-bit/.test(error.message)
  );

  // Kedalaman bukan-8 lain (4-bit palette) tetap ditolak dengan kode sama.
  const fourBit = toArrayBuffer(makePng(4, 3, 1));
  assert.throws(
    () => stego.validatePNGStructure(fourBit),
    (error) => error && error.code === "BIT_DEPTH"
  );
});

const rangeNote = rangeEnv ? ` (range ${rangeFrom}-${rangeTo})` : "";
console.log(`\n${passed} test groups passed${rangeNote} in ${((performance.now() - started) / 1000).toFixed(1)}s.`);
