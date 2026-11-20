// secwatch: 画面はキャッシュ、データはネット優先（電波がないときは前回分を表示）
const CACHE = "secwatch-m-v2";
const SHELL = ["./", "./index.html", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith("secwatch-") && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  if (url.pathname.startsWith(new URL("fw/", self.registration.scope).pathname)) return;  // FW・EOLウォッチは別アプリ
  const isData = url.pathname.endsWith("/data/advisories.json");
  const key = isData ? new URL("data/advisories.json", self.registration.scope).href
            : req.mode === "navigate" ? new URL("./", self.registration.scope).href : req;

  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    try {
      const res = await fetch(req);
      if (res.ok) c.put(key, res.clone());
      return res;
    } catch (err) {
      const hit = await c.match(key);
      if (!hit) throw err;
      if (isData) {
        const h = new Headers(hit.headers); h.set("X-From-Cache", "1");
        return new Response(await hit.blob(), { status: 200, headers: h });
      }
      return hit;
    }
  })());
});
