const VERSION = "cryptopic-v4";
const SHELL = [
  "./",
  "./index.html",
  "./styles.css",
  "./js/theme-init.js",
  "./js/app.js",
  "./js/crypto.js",
  "./js/stego.js",
  "./js/memo.js",
  "./manifest.json",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(VERSION)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== VERSION).map((key) => caches.delete(key)))
      )
      .then(() => self.clients.claim())
  );
});

async function offlineIndex() {
  const cached =
    (await caches.match("./index.html")) || (await caches.match("./"));
  if (!cached) {
    return new Response("CryptoPic sedang offline dan belum tersimpan di cache.", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
  if (cached.redirected) {
    return new Response(await cached.text(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
  return cached;
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(VERSION).then((cache) => cache.put("./index.html", copy));
          return response;
        })
        .catch(() => offlineIndex())
    );
    return;
  }

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok && response.type === "basic") {
          const copy = response.clone();
          caches.open(VERSION).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request))
  );
});
