// funnypot — endless decoy-download service worker (client-side bait).
//
// Registered on every admin-panel page. Intercepts ANY same-origin download whose path ends in a decoy
// archive/dump/cert extension (.zip/.tar.gz/.tgz/.gz/.sql/.pem/.cer/.csv/.json/.bak — every "download"
// lure in the panel keeps its real extension) and answers with a ReadableStream that fabricates an
// ENDLESS, throttled, format-matched byte stream entirely in the attacker's browser. Near-zero server
// cost; the transfer never completes until the attacker cancels. Not a valid extractable archive, not a
// decompression bomb — a believable time/bandwidth sink. Throttle knobs come from the server manifest.

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

// BULK download lures only (mirror of EndlessArchive::MAP). Longest suffix first so .tar.gz beats .gz.
// Small credential/inspect-me baits (wallet.json, .pem, .cer, real .tar) are intentionally NOT here —
// they download normally so the keystore/cert bait stays intact.
var TYPES = [
  ['.tar.gz', 'gzip', 'application/gzip'],
  ['.tgz', 'gzip', 'application/gzip'],
  ['.gz', 'gzip', 'application/gzip'],
  ['.zip', 'zip', 'application/zip'],
  ['.sql', 'sql', 'application/sql'],
  ['.csv', 'csv', 'text/csv'],
  ['.bak', 'binary', 'application/octet-stream']
];

function typeFor(pathname) {
  var p = pathname.toLowerCase();
  for (var i = 0; i < TYPES.length; i++) {
    var suf = TYPES[i][0];
    if (p.length >= suf.length && p.slice(-suf.length) === suf) {
      return { format: TYPES[i][1], ctype: TYPES[i][2] };
    }
  }
  return null;
}

self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') { return; }
  var url = new URL(event.request.url);
  if (url.origin !== self.location.origin) { return; }
  // Never intercept the SW's OWN plumbing (it fetches the manifest; sw.js is the worker itself). But
  // DO intercept /__dl/backup.zip — the fleet console's bait lives there (moved off the bare /backup.zip
  // so that path stays scanner-reporting honeypot surface), and it must still stream endlessly.
  if (url.pathname === '/__dl/sw.js' || url.pathname.indexOf('/__dl/manifest') === 0) { return; }
  var t = typeFor(url.pathname);
  if (t === null) { return; }
  event.respondWith(makeResponse(url, t));
});

function le16(n) { return [n & 0xff, (n >>> 8) & 0xff]; }
function le32(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

function nameFrom(pathname) {
  var parts = pathname.split('/');
  var n = parts[parts.length - 1] || 'backup.zip';
  return n.slice(0, 255);
}

function zipLocalHeader(name) {
  var enc = new TextEncoder().encode(name);
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

// Deterministic printable-ASCII filler (xorshift).
function fillBytes(len, seed) {
  var a = new Uint8Array(len);
  var x = (seed >>> 0) || 1;
  for (var i = 0; i < len; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    a[i] = 32 + ((x >>> 0) % 94);
  }
  return a;
}

function bytesOf(str) { return new TextEncoder().encode(str); }

// One never-final DEFLATE stored block: 0x00 + LEN(2 LE) + ~LEN(2) + LEN bytes. A valid gzip body prefix
// that never terminates — a client inflating it streams forever.
function gzipBlock(len, seed) {
  var payload = Math.min(Math.max(1, len - 5), 0xffff);
  var data = fillBytes(payload, seed);
  var nlen = (~payload) & 0xffff;
  var out = new Uint8Array(5 + payload);
  out[0] = 0x00;
  out[1] = payload & 0xff; out[2] = (payload >>> 8) & 0xff;
  out[3] = nlen & 0xff; out[4] = (nlen >>> 8) & 0xff;
  out.set(data, 5);
  return out;
}

function opening(format, name) {
  switch (format) {
    case 'zip': return zipLocalHeader(name);
    case 'gzip': return new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff]);
    case 'pem': return bytesOf('-----BEGIN CERTIFICATE-----\n');
    case 'sql': return bytesOf('-- MySQL dump\n-- Host: localhost    Database: production\n\n');
    case 'json': return bytesOf('{"version":3,"crypto":{"ciphertext":"');
    case 'csv': return bytesOf('id,created_at,name,email,value\n');
    default: return new Uint8Array(0);
  }
}

function bodyChunk(format, len, n) {
  var seed = (n * 2654435761) >>> 0;
  if (format === 'gzip') { return gzipBlock(len, seed); }
  if (format === 'sql') {
    var s = '';
    while (s.length < len) { var v = (seed + s.length) >>> 0; s += 'INSERT INTO `accounts` VALUES (' + v + ",'user" + (v % 100000) + "');\n"; }
    return bytesOf(s.slice(0, len));
  }
  if (format === 'csv') {
    var c = '';
    while (c.length < len) { var w = (seed + c.length) >>> 0; c += w + ',2026-08-26,name' + (w % 100000) + ',user' + (w % 100000) + '@example.com,' + (w % 1000) + '\n'; }
    return bytesOf(c.slice(0, len));
  }
  // zip / pem / json / binary: printable filler
  return fillBytes(len, seed);
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function easedDelay(cfg, n) {
  var base = cfg.intervalMs || 100;
  var elapsedS = (n * base) / 1000;
  var period = Math.max(1, cfg.easePeriodS || 20);
  var factor = 1 + ((cfg.varyPct || 0) / 100) * Math.sin(2 * Math.PI * (elapsedS / period));
  if (factor < 0.2) { factor = 0.2; }
  var delay = Math.round(base / factor);
  return Math.max(Math.round(base * 0.2), Math.min(Math.round(base * 5), delay));
}

async function makeResponse(url, t) {
  var cfg = { chunkMinKb: 100, chunkMaxKb: 200, intervalMs: 100, varyPct: 50, easePeriodS: 20 };
  try {
    var res = await fetch('/__dl/manifest?host=' + encodeURIComponent(url.searchParams.get('host') || ''));
    var m = await res.json();
    if (m && m.throttle) { cfg = m.throttle; }
  } catch (e) { /* defaults */ }

  var name = nameFrom(url.pathname);
  var n = 0;
  var headerSent = false;
  var stream = new ReadableStream({
    async pull(controller) {
      await sleep(easedDelay(cfg, n));
      if (!headerSent) {
        var head = opening(t.format, name);
        if (head.length) { controller.enqueue(head); }
        headerSent = true;
      }
      var span = Math.max(cfg.chunkMinKb, cfg.chunkMaxKb) - cfg.chunkMinKb + 1;
      var len = Math.max(1, cfg.chunkMinKb + Math.floor(Math.random() * span)) * 1024;
      controller.enqueue(bodyChunk(t.format, len, n));
      n++;
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': t.ctype,
      'Content-Disposition': 'attachment; filename="' + name.replace(/[^\w.\-]/g, '_') + '"',
      'Cache-Control': 'no-store'
    }
  });
}
