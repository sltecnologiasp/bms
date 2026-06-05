// SMART BMS - Service Worker PWA sem cache agressivo
// Mantém PWA instalável, mas evita cache fantasma.

const CACHE_NAME = 'smart-bms-assets-v3';

const STATIC_ASSETS = [
  '/manifest.json',
  '/1000229030.png'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .catch(() => null)
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(key => {
        if (key !== CACHE_NAME) return caches.delete(key);
      })))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  const accept = request.headers.get('accept') || '';

  const isApi = url.pathname.startsWith('/api/');
  const isHtml = request.mode === 'navigate' || accept.includes('text/html');
  const isJs = url.pathname.endsWith('.js');
  const isCss = url.pathname.endsWith('.css');

  // Nunca cachear API, HTML, páginas ou JavaScript.
  if (isApi || isHtml || isJs || isCss) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // Imagens e manifest: cache first com fallback rede.
  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached;
      return fetch(request).then(response => {
        const clone = response.clone();
        if (response.ok && request.method === 'GET') {
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      });
    })
  );
});
