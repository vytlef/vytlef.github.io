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
  } catch (error) {
    const detail = error && typeof error.message === "string" ? error.message : String(error);
    self.postMessage({ error: `Argon2id gagal menghitung kunci: ${detail}` });
  }
};
