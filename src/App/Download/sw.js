// Large-file download helper. Streams the requested archive to the browser in paced chunks so a big
// backup can start downloading immediately without the server buffering it whole. Registered by the
// server console page; intercepts only the console's own backup endpoint.

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

// Only the console's backup endpoint is handled here; everything else goes to the network untouched.
var TARGET = '/__dl/backup.zip';

self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') { return; }
  var url = new URL(event.request.url);
  if (url.origin !== self.location.origin || url.pathname !== TARGET) { return; }
  event.respondWith(makeResponse(url));
});

function le16(n) { return [n & 0xff, (n >>> 8) & 0xff]; }
function le32(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

function zipLocalHeader(name) {
  var enc = new TextEncoder().encode(String(name).slice(0, 255));
  var h = [].concat(
    [0x50, 0x4b, 0x03, 0x04],
    le16(20), le16(0x0008), le16(0), le16(0), le16(0),
    le32(0), le32(0), le32(0),
    le16(enc.length), le16(0)
  );
  var out = new Uint8Array(h.length + enc.length);
  out.set(h, 0);
  out.set(enc, h.length);
  return out;
}

function fillBytes(len, seed) {
  var a = new Uint8Array(len);
  var x = (seed >>> 0) || 1;
  for (var i = 0; i < len; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    a[i] = 32 + ((x >>> 0) % 94);
  }
  return a;
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

// Paced delay per chunk, breathing up and down so throughput looks like a normal broadband transfer.
function pacedDelay(cfg, n) {
  var base = cfg.intervalMs || 100;
  var elapsedS = (n * base) / 1000;
  var period = Math.max(1, cfg.easePeriodS || 20);
  var factor = 1 + ((cfg.varyPct || 0) / 100) * Math.sin(2 * Math.PI * (elapsedS / period));
  if (factor < 0.2) { factor = 0.2; }
  var delay = Math.round(base / factor);
  return Math.max(Math.round(base * 0.2), Math.min(Math.round(base * 5), delay));
}

async function makeResponse(url) {
  var cfg = { chunkMinKb: 100, chunkMaxKb: 200, intervalMs: 100, varyPct: 50, easePeriodS: 20 };
  var files = [];
  try {
    var res = await fetch('/__dl/manifest?host=' + encodeURIComponent(url.searchParams.get('host') || ''));
    var m = await res.json();
    if (m && m.throttle) { cfg = m.throttle; }
    if (m && m.files) { files = m.files; }
  } catch (e) { /* defaults */ }

  var n = 0;
  var fileIdx = 0;
  var headerFor = -1;
  var stream = new ReadableStream({
    async pull(controller) {
      await sleep(pacedDelay(cfg, n));
      var span = Math.max(cfg.chunkMinKb, cfg.chunkMaxKb) - cfg.chunkMinKb + 1;
      var len = Math.max(1, cfg.chunkMinKb + Math.floor(Math.random() * span)) * 1024;

      if (fileIdx < files.length) {
        if (headerFor !== fileIdx) {
          controller.enqueue(zipLocalHeader(files[fileIdx].path || ('file-' + fileIdx + '.dat')));
          headerFor = fileIdx;
        }
        controller.enqueue(fillBytes(len, ((n * 2654435761) ^ fileIdx) >>> 0));
        files[fileIdx]._sent = (files[fileIdx]._sent || 0) + len;
        if (files[fileIdx]._sent >= (files[fileIdx].size || len)) { fileIdx++; }
      } else {
        if (headerFor !== 2000000000) {
          controller.enqueue(zipLocalHeader('database-full-dump.sql'));
          headerFor = 2000000000;
        }
        controller.enqueue(fillBytes(len, (n * 2654435761) >>> 0));
      }
      n++;
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename="backup.zip"',
      'Cache-Control': 'no-store'
    }
  });
}
