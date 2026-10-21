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

async function check(name, fn) {
  await fn();
  passed++;
  console.log(`PASS ${passed}: ${name}`);
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

async function makeV2(message, password, hint, cover = makeCover()) {
  const encrypted = await cryptoPic.encryptPayload(password, message, hint);
  const image = await stego.embedPayload(cover, encrypted.payload, encrypted.stegoKey);
  const extractedPrefix = stego.extractPayload(image);
  const parsed = cryptoPic.parsePayload(extractedPrefix);
  const keys = await cryptoPic.deriveV2Keys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, keys.stegoKey);
  return { image, parsed, keys, body, message, encrypted };
}

async function makeV3(message, password, hint, cover = makeCover(), kdf = undefined) {
  const encrypted = await cryptoPic.encryptPayloadV3(password, message, hint, kdf);
  const image = await stego.embedPayload(cover, encrypted.payload, encrypted.stegoKey);
  const extractedPrefix = stego.extractPayload(image);
  const parsed = cryptoPic.parsePayload(extractedPrefix);
  const keys = await cryptoPic.deriveV2Keys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, keys.stegoKey);
  return { image, parsed, keys, body, message, encrypted, prefix: extractedPrefix };
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

async function decryptV2(password, parsed, image, keys = null) {
  const activeKeys = keys || await cryptoPic.deriveV2Keys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, activeKeys.stegoKey);
  return cryptoPic.decryptPayload(password, parsed, body, activeKeys);
}

await check("12 round trips (4 passphrase/message cases repeated 3 times)", async () => {
  const cases = [
    { password: "Pohon Kuat-2026!", typed: "Pohon Kuat-2026!", message: "Pesan rahasia dengan tanda baca.", hint: "nama tempat" },
    { password: "CaseSensitive-AA", typed: "CaseSensitive-AA", message: "Huruf besar dan kecil dipertahankan.", hint: "" },
    { password: "cafe\u0301-unicode", typed: "café-unicode", message: "Unicode NFC dan emoji 🔐🌿", hint: "petunjuk ü" },
    { password: "empat kata acak 2026", typed: "empat kata acak 2026", message: "Baris pertama\nBaris kedua\nBaris ketiga.", hint: "uji multi-baris" },
  ];
  const salts = new Set();
  for (let round = 0; round < 3; round++) {
    for (const item of cases) {
      const result = await makeV2(item.message, item.password, item.hint);
      assert.equal(result.parsed.version, 2);
      assert.equal(result.parsed.hint, item.hint);
      assert.equal(await cryptoPic.decryptPayload(item.typed, result.parsed, result.body, result.keys), item.message);
      salts.add(Buffer.from(result.parsed.salt).toString("hex"));
    }
  }
  assert.equal(salts.size, 12, "Each encryption should have a fresh random salt.");
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

await check("V1 images still open and keep their original case-insensitive password behavior", async () => {
  const password = "Legacy Case 123";
  const message = "Pesan terenkripsi dari format V1.";
  const hint = "hint lama";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password.toLowerCase()), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const hintBytes = new TextEncoder().encode(hint);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(message)));
  const total = 40 + hintBytes.length + ciphertext.length;
  const payload = new Uint8Array(total);
  const view = new DataView(payload.buffer);
  payload.set([0x43, 0x50, 0x49, 0x43], 0);
  payload[4] = 1;
  payload[5] = 1;
  view.setUint32(6, total, false);
  payload.set(salt, 10);
  payload.set(iv, 26);
  view.setUint16(38, hintBytes.length, false);
  payload.set(hintBytes, 40);
  payload.set(ciphertext, 40 + hintBytes.length);
  const embedded = await stego.embedPayload(makeCover(80, 80), payload);
  const extracted = stego.extractPayload(embedded);
  const parsed = cryptoPic.parsePayload(extracted);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.hint, hint);
  assert.equal(await cryptoPic.decryptPayload("LEGACY CASE 123", parsed), message);
});

await check("Hamming(7,4) recovers each of the seven possible single-bit body errors", async () => {
  const result = await makeV2("Satu bit rusak per codeword masih bisa dipulihkan.", "Rangkaian sandi kuat 2026", "uji koreksi");
  const totalSamples = result.image.width * result.image.height * 3;
  const firstBodySample = result.parsed.prefixLength * 8;
  const availableSlots = totalSamples - firstBodySample;
  const acceptedLimit = Math.floor(0x100000000 / availableSlots) * availableSlots;
  const zeroCounter = new Uint8Array(16);
  const randomWords = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: zeroCounter, length: 128 },
    result.keys.stegoKey,
    new Uint8Array(64 * 1024)
  ));
  const wordView = new DataView(randomWords.buffer);
  const samples = [];
  const seen = new Set();
  for (let i = 0; samples.length < 7; i += 4) {
    const word = wordView.getUint32(i, false);
    if (word >= acceptedLimit) continue;
    const slot = word % availableSlots;
    if (seen.has(slot)) continue;
    seen.add(slot);
    samples.push(slot);
  }
  for (const slot of samples) {
    const damaged = new ImageData(new Uint8ClampedArray(result.image.data), result.image.width, result.image.height);
    const sampleIndex = firstBodySample + slot;
    const offset = Math.floor(sampleIndex / 3) * 4 + (sampleIndex % 3);
    damaged.data[offset] ^= 1;
    assert.equal(await decryptV2("Rangkaian sandi kuat 2026", result.parsed, damaged, result.keys), result.message);
  }
});

await check("Two flipped bits in one Hamming codeword are rejected by the AES-GCM tag", async () => {
  const result = await makeV2("Pesan untuk uji dua bit rusak.", "Dua bit error sandi", "uji autentikasi");
  const totalSamples = result.image.width * result.image.height * 3;
  const firstBodySample = result.parsed.prefixLength * 8;
  const availableSlots = totalSamples - firstBodySample;
  const acceptedLimit = Math.floor(0x100000000 / availableSlots) * availableSlots;
  const randomWords = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: new Uint8Array(16), length: 128 }, result.keys.stegoKey, new Uint8Array(64 * 1024)
  ));
  const view = new DataView(randomWords.buffer);
  const slots = [];
  for (let i = 0; slots.length < 2; i += 4) {
    const word = view.getUint32(i, false);
    if (word < acceptedLimit) slots.push(word % availableSlots);
  }
  const damaged = new ImageData(new Uint8ClampedArray(result.image.data), result.image.width, result.image.height);
  for (const slot of slots) {
    const sampleIndex = firstBodySample + slot;
    damaged.data[Math.floor(sampleIndex / 3) * 4 + (sampleIndex % 3)] ^= 1;
  }
  await assert.rejects(
    decryptV2("Dua bit error sandi", result.parsed, damaged, result.keys),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("Visible hint is authenticated as AES-GCM associated data", async () => {
  const result = await makeV2("Metadata perlu tervalidasi.", "Sandi metadata kuat", "hint");
  const changed = new ImageData(new Uint8ClampedArray(result.image.data), result.image.width, result.image.height);
  const sampleIndex = (34 * 8) + 1;
  changed.data[Math.floor(sampleIndex / 3) * 4 + (sampleIndex % 3)] ^= 1;
  const alteredPrefix = stego.extractPayload(changed);
  const alteredParsed = cryptoPic.parsePayload(alteredPrefix);
  assert.notEqual(alteredParsed.hint, result.parsed.hint);
  await assert.rejects(
    decryptV2("Sandi metadata kuat", alteredParsed, changed, result.keys),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("Wrong V2 password and changed password case cannot open the message", async () => {
  const result = await makeV2("Kasus kata sandi.", "Peka Huruf Besar 2026", "uji sandi");
  await assert.rejects(
    decryptV2("peka huruf besar 2026", result.parsed, result.image),
    (error) => error && error.code === "WRONG_PASSWORD"
  );
});

await check("Capacity estimator accounts for V2 metadata, authentication tag and correction coding", async () => {
  assert.equal(stego.maxMessageBytes(16, 16), 1);
  const capacity = stego.maxMessageBytes(256, 256, "hint");
  assert.ok(capacity > 0 && capacity < stego.capacityBytes(256, 256));
  const encoded = await cryptoPic.encryptPayload("Capacity test password", "a".repeat(capacity), "hint");
  const atLimit = await stego.embedPayload(makeCover(256, 256), encoded.payload, encoded.stegoKey);
  assert.ok(atLimit.data.length > 0, "The estimated maximum should fit.");
  const overLimit = new Uint8Array(encoded.payload.length + 1);
  overLimit.set(encoded.payload);
  new DataView(overLimit.buffer).setUint32(0, overLimit.length, false);
  await assert.rejects(
    stego.embedPayload(makeCover(256, 256), overLimit, encoded.stegoKey),
    (error) => error && error.code === "TOO_LARGE"
  );
});

await check("V3 round trips repeated with header-stored KDF parameters", async () => {
  const cases = [
    { password: "Pohon Kuat-2026!", message: "Pesan rahasia V3 dengan tanda baca.", hint: "nama tempat" },
    { password: "CaseSensitive-AA", message: "Huruf besar dan kecil dipertahankan.", hint: "" },
    { password: "cafe\u0301-unicode", typed: "café-unicode", message: "Unicode NFC dan emoji 🔐🌿", hint: "petunjuk ü" },
    { password: "empat kata acak 2026", message: "Baris pertama\nBaris kedua\nBaris ketiga.", hint: "uji multi-baris" },
  ];
  const nonces = new Set();
  for (let round = 0; round < 4; round++) {
    for (const item of cases) {
      const result = await makeV3(item.message, item.password, item.hint);
      assert.equal(result.parsed.version, 3);
      assert.equal(result.parsed.hint, item.hint);
      assert.ok(result.parsed.kdf.memorySize >= 8 && result.parsed.kdf.iterations >= 1);
      assert.equal(
        await cryptoPic.decryptPayload(item.typed || item.password, result.parsed, result.body, result.keys),
        item.message
      );
      nonces.add(Buffer.from(result.parsed.nonce).toString("hex"));
    }
  }
  assert.equal(nonces.size, 16, "Each V3 encryption must use a fresh nonce.");
});

await check("V3 stores custom KDF parameters in the header and honours them", async () => {
  const kdf = { memorySize: 1024, iterations: 1, parallelism: 1 };
  const result = await makeV3("Parameter KDF kustom.", "Sandi KDF kustom 2026", "kdf", makeCover(192, 192), kdf);
  assert.deepEqual(result.parsed.kdf, kdf);
  assert.equal(await cryptoPic.decryptPayload("Sandi KDF kustom 2026", result.parsed, result.body, result.keys), "Parameter KDF kustom.");
});

await check("V3 header is not a sequential plaintext block at the start of the image", async () => {
  const result = await makeV3("Header harus tersebar.", "Sandi header tersebar", "petunjuk rahasia");
  const firstFive = readSequentialSampleBytes(result.image, 5);
  // Bootstrap acak; sangat tidak mungkin kebetulan sama dengan magic+versi.
  assert.notDeepEqual(Array.from(firstFive), [0x43, 0x50, 0x49, 0x43, 3]);
  // Namun pembaca tetap menemukan header dan petunjuknya.
  assert.equal(result.parsed.hint, "petunjuk rahasia");
});

await check("V3 matrix embedding changes fewer samples than raw LSB for the same payload", async () => {
  const cover = makeCover(512, 512);
  const message = "x".repeat(1200);
  const encrypted = await cryptoPic.encryptPayloadV3("Sandi matrix embedding 2026", message, "");
  const image = await stego.embedPayload(cover, encrypted.payload, encrypted.stegoKey);

  let changed = 0;
  for (let sample = 0; sample < cover.width * cover.height * 3; sample++) {
    const offset = Math.floor(sample / 3) * 4 + (sample % 3);
    if ((cover.data[offset] & 1) !== (image.data[offset] & 1)) changed++;
  }
  const bodyBits = (encrypted.payload.length - 53) * 8;
  assert.ok(changed < bodyBits * 0.7, `changed=${changed} bodyBits=${bodyBits}`);
});

await check("V3 survives a flat (texture-less) cover by lowering the adaptive threshold", async () => {
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
  const result = await makeV3("Pesan pada gambar datar.", "Sandi gambar datar 2026", "", cover);
  assert.equal(await cryptoPic.decryptPayload("Sandi gambar datar 2026", result.parsed, result.body, result.keys), "Pesan pada gambar datar.");
});

async function attemptV3Open(image, password) {
  const prefix = stego.extractPayload(image);
  const parsed = cryptoPic.parsePayload(prefix);
  const keys = await cryptoPic.deriveV2Keys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(image, parsed, keys.stegoKey);
  return cryptoPic.decryptPayload(password, parsed, body, keys);
}

await check("V3 rejects tampered bootstrap and body pixels", async () => {
  const password = "Sandi anti-ubah 2026";
  const result = await makeV3("Pesan yang akan dirusak.", password, "tamper");
  const totalSamples = result.image.width * result.image.height * 3;

  // Bootstrap (nonce) tamper.
  const bootstrapDamaged = new ImageData(
    new Uint8ClampedArray(result.image.data),
    result.image.width,
    result.image.height
  );
  bootstrapDamaged.data[0] ^= 1;
  await assert.rejects(attemptV3Open(bootstrapDamaged, password), (error) => {
    return error && (error.code === "WRONG_PASSWORD" || error.code === "CORRUPT" || error.code === "BAD_VERSION" || error.code === "NOT_CRYPTOPIC");
  });

  // Body tamper: alter the extracted ciphertext (deterministic) and ensure GCM rejects it.
  const prefix = stego.extractPayload(result.image);
  const parsed = cryptoPic.parsePayload(prefix);
  const keys = await cryptoPic.deriveV2Keys(password, parsed.salt, parsed.kdf);
  const body = await stego.extractProtectedBody(result.image, parsed, keys.stegoKey);
  const tampered = new Uint8Array(body);
  tampered[0] ^= 1;
  await assert.rejects(cryptoPic.decryptPayload(password, parsed, tampered, keys), (error) => {
    return error && (error.code === "WRONG_PASSWORD" || error.code === "CORRUPT");
  });
});

await check("V3 capacity estimator is respected at and beyond the limit", async () => {
  const width = 400;
  const height = 400;
  const capacity = stego.maxMessageBytesV3(width, height, "hint");
  assert.ok(capacity > 0);

  const atLimit = await cryptoPic.encryptPayloadV3("Sandi kapasitas V3 2026", "a".repeat(capacity), "hint");
  const embedded = await stego.embedPayload(makeCover(width, height), atLimit.payload, atLimit.stegoKey);
  assert.ok(embedded.data.length > 0, "Estimated V3 maximum should fit.");

  const over = await cryptoPic.encryptPayloadV3("Sandi kapasitas V3 2026", "a".repeat(capacity + 64), "hint");
  await assert.rejects(
    stego.embedPayload(makeCover(width, height), over.payload, over.stegoKey),
    (error) => error && error.code === "TOO_LARGE"
  );
});

console.log(`\n${passed} test groups passed in ${((performance.now() - started) / 1000).toFixed(1)}s.`);
