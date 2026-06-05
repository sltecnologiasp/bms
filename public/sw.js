// SMART BMS - Service Worker sem cache agressivo
// Objetivo: evitar "cache fantasma" após deploy no GitHub/Cloudflare.
// Este app NÃO foi projetado para uso offline.

const CACHE_VERSION = 'smart-bms-no-html-cache-v2';

// Ativa imediatamente o novo Service Worker
self.addEventListener('install', event => {
  self.skipWaiting();
});

// Remove caches antigos e assume controle das abas abertas
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

// Estratégia:
// - HTML, JS, API e navegação: sempre rede
// - Sem cache persistente de páginas
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  // Nunca cachear chamadas da API
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // Nunca cachear HTML, navegação, admin, index, simulador ou scripts
  const accept = request.headers.get('accept') || '';
  const isNavigation = request.mode === 'navigate';
  const isHtml = accept.includes('text/html');
  const isScript = url.pathname.endsWith('.js');
  const isMainPage =
    url.pathname === '/' ||
    url.pathname.endsWith('/index.html') ||
    url.pathname.endsWith('/admin.html') ||
    url.pathname.endsWith('/simulador.html');

  if (isNavigation || isHtml || isScript || isMainPage) {
    event.respondWith(
      fetch(request, { cache: 'no-store' }).catch(() => {
        return new Response(
          '<h1>SMART BMS</h1><p>Sem conexão com a internet.</p>',
          { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
        );
      })
    );
    return;
  }

  // Demais arquivos: busca normal da rede.
  event.respondWith(fetch(request));
});
