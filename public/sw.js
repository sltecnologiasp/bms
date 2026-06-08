// SMART BMS - Service Worker PWA seguro
// Mantém o app instalável, evita cache fantasma e usa apenas assets existentes.

const CACHE_NAME = 'smart-bms-assets-v5';

const STATIC_ASSETS = [
  '/',
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
      .then(keys => Promise.all(
        keys.map(key => key !== CACHE_NAME ? caches.delete(key) : Promise.resolve())
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;

  if (request.method !== 'GET') {
    return;
  }

  const url = new URL(request.url);
  const accept = request.headers.get('accept') || '';

  const isSameOrigin = url.origin === self.location.origin;
  const isApi = isSameOrigin && url.pathname.startsWith('/api/');
  const isHtml = request.mode === 'navigate' || accept.includes('text/html');
  const isJs = url.pathname.endsWith('.js');
  const isCss = url.pathname.endsWith('.css');

  // API nunca usa cache.
  if (isApi) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // HTML: rede primeiro para receber versão nova; fallback cacheado para abrir offline.
  if (isHtml) {
    event.respondWith(
      fetch(request, { cache: 'no-store' })
        .then(response => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put('/', clone));
          return response;
        })
        .catch(() => caches.match('/') || caches.match(request))
    );
    return;
  }

  // JS/CSS: sempre rede para evitar código antigo.
  if (isJs || isCss) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // Assets do próprio domínio: cache first + atualização em segundo plano.
  event.respondWith(
    caches.match(request).then(cached => {
      const fetchPromise = fetch(request).then(response => {
        if (response && response.ok && isSameOrigin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      }).catch(() => cached);

      return cached || fetchPromise;
    })
  );
});
