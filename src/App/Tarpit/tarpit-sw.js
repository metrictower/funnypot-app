// Tarpit client-side pacing helper (FP-0245d).
//
// The cost-amplification tarpit's "leaked export" downloads (/admin/export/*) are served by the server
// as fast as the socket drains and hard byte-capped — the server NEVER paces them, because a server-side
// slow-drip on synchronous php-fpm pins one of only ~16 workers per slow client (the DownloadRouter
// lesson, mirrored here). So the believable-slow "big export downloading" experience is produced HERE,
// in the attacker's own browser, on the attacker's own CPU: this worker fetches the real (fast, capped)
// response once and then re-delivers its bytes to the page in paced, breathing chunks. It costs the
// server nothing beyond the one capped response it already served.
//
// It only ever touches the tarpit export paths; every other request goes to the network untouched. It
// degrades to a plain passthrough on any error, and a browser without Service Worker support simply
// never registers it and downloads normally — the pacing is a nicety, never a correctness dependency.

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

// The tarpit "export" surface this worker paces. Prefix match so all four polluter artifacts are covered.
var EXPORT_PREFIX = '/admin/export/';

// Pacing base interval (ms per chunk) is handed in via the registration URL query (?i=...), so it is
// config-driven from AppConfig (FUNNYPOT_TARPIT_LATENCY_MS), never hardcoded here. Clamped to a sane band.
function baseIntervalMs() {
  var i = 100;
  try {
    var q = new URL(self.location.href).searchParams.get('i');
    if (q !== null && q !== '') { i = parseInt(q, 10) || 0; }
  } catch (e) { /* defaults */ }
  if (i < 20) { i = 20; }
  if (i > 2000) { i = 2000; }
  return i;
}

// Breathing per-chunk delay so throughput looks like a real, slightly variable transfer rather than a
// metronome. Same sine-eased shape as the download bait's service worker.
function pacedDelay(base, n) {
  var elapsedS = (n * base) / 1000;
  var period = 20;
  var factor = 1 + 0.5 * Math.sin(2 * Math.PI * (elapsedS / period));
  if (factor < 0.2) { factor = 0.2; }
  var delay = Math.round(base / factor);
  return Math.max(Math.round(base * 0.2), Math.min(Math.round(base * 5), delay));
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') { return; }
  var url;
  try { url = new URL(event.request.url); } catch (e) { return; }
  if (url.origin !== self.location.origin) { return; }
  if (url.pathname.lastIndexOf(EXPORT_PREFIX, 0) !== 0) { return; }
  event.respondWith(pacedResponse(event.request));
});

// Fetch the real (server-capped) export once, then re-stream its bytes to the page in paced chunks. If
// anything is unavailable (no ReadableStream, a fetch error), fall straight back to the network response.
async function pacedResponse(request) {
  var base = baseIntervalMs();
  var upstream;
  try {
    upstream = await fetch(request);
  } catch (e) {
    return fetch(request);
  }
  if (!upstream.body || typeof ReadableStream === 'undefined') {
    return upstream;
  }

  var reader = upstream.body.getReader();
  var n = 0;
  var stream = new ReadableStream({
    async pull(controller) {
      try {
        await sleep(pacedDelay(base, n));
        n++;
        var step = await reader.read();
        if (step.done) { controller.close(); return; }
        controller.enqueue(step.value);
      } catch (e) {
        try { controller.close(); } catch (e2) { /* already closed */ }
      }
    },
    cancel() {
      try { reader.cancel(); } catch (e) { /* best effort */ }
    }
  });

  var headers = new Headers(upstream.headers);
  return new Response(stream, { status: upstream.status, statusText: upstream.statusText, headers: headers });
}
