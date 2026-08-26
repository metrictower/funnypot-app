// funnypot — endless backup-download service worker (decoy bait).
//
// Intercepts /__dl/backup.zip and answers with a ReadableStream that fabricates an ENDLESS, THROTTLED,
// store-method zip entirely in the attacker's browser — near-zero server cost. It never writes a
// central directory, so it is intentionally not an extractable archive: the point is a believable,
// cancelable time/bandwidth sink, not a working backup and NOT a zip bomb. All speed/variability comes
// from the server manifest's throttle block, so the rate is centrally configured, never hardcoded here.

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);
  // Only the bait path. The bare /backup.zip is honeypot surface and must reach the server so the
  // scanner that asked for it is detected and reported.
  if (url.pathname !== '/__dl/backup.zip') { return; }
  event.respondWith(makeResponse(url));
});

function le16(n) { return [n & 0xff, (n >>> 8) & 0xff]; }
function le32(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

// ZIP local file header, store method, general-purpose bit 3 (sizes deferred to a data descriptor we
// never write). Mirrors DownloadRouter::localFileHeader on the PHP side.
function localHeader(name) {
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

// Deterministic printable-ASCII filler (xorshift) so a chunk looks like config/dump text.
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

// Inter-chunk delay under the sine-eased breathing rate — matches DownloadRouter::easedDelayMs.
function easedDelay(cfg, n) {
  var base = cfg.intervalMs || 100;
  var elapsedS = (n * base) / 1000;
  var period = Math.max(1, cfg.easePeriodS || 20);
  var factor = 1 + ((cfg.varyPct || 0) / 100) * Math.sin(2 * Math.PI * (elapsedS / period));
  if (factor < 0.2) { factor = 0.2; }
  var delay = Math.round(base / factor);
  return Math.max(Math.round(base * 0.2), Math.min(Math.round(base * 5), delay));
}

async function makeResponse(url) {
  var host = url.searchParams.get('host') || '';
  var cfg = { chunkMinKb: 100, chunkMaxKb: 200, intervalMs: 100, varyPct: 50, easePeriodS: 20 };
  var files = [];
  try {
    var res = await fetch('/__dl/manifest?host=' + encodeURIComponent(host));
    var m = await res.json();
    if (m && m.throttle) { cfg = m.throttle; }
    if (m && m.files) { files = m.files; }
  } catch (e) { /* fall back to defaults + an endless single entry */ }

  var n = 0;
  var fileIdx = 0;
  var headerFor = -1;

  var stream = new ReadableStream({
    async pull(controller) {
      await sleep(easedDelay(cfg, n));
      var span = Math.max(cfg.chunkMinKb, cfg.chunkMaxKb) - cfg.chunkMinKb + 1;
      var chunkKb = cfg.chunkMinKb + Math.floor(Math.random() * span);
      var len = Math.max(1, chunkKb) * 1024;

      if (fileIdx < files.length) {
        if (headerFor !== fileIdx) {
          controller.enqueue(localHeader(files[fileIdx].path || ('file-' + fileIdx + '.bak')));
          headerFor = fileIdx;
        }
        controller.enqueue(fillBytes(len, ((n * 2654435761) ^ fileIdx) >>> 0));
        files[fileIdx]._sent = (files[fileIdx]._sent || 0) + len;
        if (files[fileIdx]._sent >= (files[fileIdx].size || len)) { fileIdx++; }
      } else {
        // Endless final entry — no descriptor, no central directory, never ends.
        if (headerFor !== 2000000000) {
          controller.enqueue(localHeader('database-full-dump.sql'));
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
