// 以前の secwatch はこの階層全体を担当していましたが、アプリを sec/ と fw/ に分けたため役目を終えました。
// 古い仕組みが残っている端末では、これが読み込まれた時点で自分自身を解除し、古いキャッシュを消します。
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k === "secwatch-m-v1" || k === "secwatch-m-v2") await caches.delete(k);
    await self.registration.unregister();
    for (const c of await self.clients.matchAll({ type: "window" })) c.navigate(c.url);
  })());
});
