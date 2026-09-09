const CACHE_NAME = "dalzon-wallet-v2.2";

const APP_SHELL = [
  "./",
  "./index.html",
  "./manifest.json"
];

// ===============================
// INSTALLATION
// ===============================

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// ===============================
// ACTIVATION
// ===============================

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

// ===============================
// REQUÊTES
// ===============================

self.addEventListener("fetch", (event) => {
  const request = event.request;

  // Seulement les requêtes GET
  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);

  // =============================
  // API DALZON WALLET
  // =============================
  // On ne met PAS l'API en cache.
  // Les soldes et transactions doivent
  // toujours venir du serveur.

  if (url.origin === "https://dalzonmoney.onrender.com") {
    return;
  }

  // =============================
  // STRATÉGIE CACHE FIRST
  // =============================

  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {

        if (cachedResponse) {
          return cachedResponse;
        }

        return fetch(request)
          .then((response) => {

            // Ne pas mettre en cache les réponses invalides
            if (
              !response ||
              response.status !== 200 ||
              response.type === "opaque"
            ) {
              return response;
            }

            const responseClone =
              response.clone();

            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(request, responseClone);
              });

            return response;
          })
          .catch(() => {

            // Si index.html est demandé hors connexion
            if (request.mode === "navigate") {
              return caches.match("./index.html");
            }

            return new Response(
              "DALZON Wallet est temporairement hors connexion.",
              {
                status: 503,
                headers: {
                  "Content-Type": "text/plain; charset=utf-8"
                }
              }
            );
          });
      })
  );
});