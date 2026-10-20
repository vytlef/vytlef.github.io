importScripts("./vendor/hash-wasm-argon2-4.12.0.min.js");

self.onmessage = async (event) => {
  const { password, salt, iterations, parallelism, memorySize } = event.data || {};
  try {
    const root = await self.hashwasm.argon2id({
      password,
      salt,
      iterations,
      parallelism,
      memorySize,
      hashLength: 32,
      outputType: "binary",
    });
    self.postMessage({ root: root.buffer }, [root.buffer]);
  } catch {
    self.postMessage({ error: "Argon2id gagal menghitung kunci. Periksa memori perangkat lalu coba lagi." });
  }
};
