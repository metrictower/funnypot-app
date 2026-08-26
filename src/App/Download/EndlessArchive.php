<?php

declare(strict_types=1);

namespace Funnypot\App\Download;

/**
 * Procedural, format-matched decoy download bytes for the server (non-JS) side of the endless-download
 * bait. Every "downloadable" lure in the panel (backups, exports, statements, keystores, dumps, certs)
 * keeps its real extension; this turns the request into a large, believable, HARD-CAPPED stream whose
 * magic bytes + Content-Type match that extension — instead of a small static file. A browser gets the
 * truly endless version from the service worker; a curl/scanner gets this capped one (unbounded here
 * would pin a worker = self-DoS, so the cap is deliberate).
 *
 * Nothing is a valid extractable archive by design — the point is a time/bandwidth sink, not a real
 * backup, and never a decompression bomb. Pure + deterministic-ish (seeded filler), yields chunks so
 * callers stream without buffering and tests can drain without I/O.
 */
final class EndlessArchive
{
    /**
     * BULK download lures only — the ones worth turning into an endless time/bandwidth sink. Longest
     * suffix first so `.tar.gz` wins over `.gz`. suffix => [format, contentType].
     *
     * Deliberately EXCLUDED: small "inspect-me" credential baits — `wallet.json` (a valid keystore v3
     * carrying a real block-explorer-verifiable address), `.pem`/`.cer` (a huge cert is itself a tell),
     * and the real-magic `.tar`/`.tar.bz2` decoys. Those keep their small static file; endless would
     * destroy the bait.
     */
    private const MAP = [
        '.tar.gz' => ['gzip', 'application/gzip'],
        '.tgz' => ['gzip', 'application/gzip'],
        '.gz' => ['gzip', 'application/gzip'],
        '.zip' => ['zip', 'application/zip'],
        '.sql' => ['sql', 'application/sql'],
        '.csv' => ['csv', 'text/csv'],
        '.bak' => ['binary', 'application/octet-stream'],
    ];

    /** True if this path ends in a suffix we can turn into an endless download. */
    public static function handles(string $path): bool
    {
        return self::formatFor($path) !== null;
    }

    public static function contentTypeFor(string $path): string
    {
        $f = self::formatFor($path);

        return $f !== null ? $f[1] : 'application/octet-stream';
    }

    /** A safe attachment filename echoing what was asked for. */
    public static function downloadName(string $path): string
    {
        $name = basename($path);
        $name = (string) preg_replace('/[^\w.\-]/', '_', $name);

        return $name === '' || strpos($name, '.') === false ? 'backup.zip' : $name;
    }

    /**
     * Yield bytes of the format matching $path until $capBytes is reached. Format-correct opening bytes
     * (zip local header / gzip magic / PEM banner / …) then procedural filler. Never throws.
     *
     * @return \Generator<int,string>
     */
    public function chunks(string $path, int $capBytes, int $chunkBytes = 65536): \Generator
    {
        $f = self::formatFor($path);
        $format = $f !== null ? $f[0] : 'binary';
        $seed = crc32('endless|' . $path);
        $chunkBytes = max(1024, $chunkBytes);
        $sent = 0;

        // Format-specific opening bytes so the first packet looks right to a sniffing client.
        $head = $this->opening($format, $path);
        if ($head !== '') {
            yield $head;
            $sent += strlen($head);
        }

        $i = 0;
        while ($sent < $capBytes) {
            $take = (int) min($chunkBytes, $capBytes - $sent);
            $chunk = $this->body($format, $seed + $i, $take);
            if ($chunk === '') {
                break;
            }
            yield $chunk;
            $sent += strlen($chunk);
            $i++;
        }
    }

    /** @return array{0:string,1:string}|null [format, contentType] */
    private static function formatFor(string $path): ?array
    {
        $p = strtolower($path);
        foreach (self::MAP as $suffix => $spec) {
            if (substr($p, -strlen($suffix)) === $suffix) {
                return $spec;
            }
        }

        return null;
    }

    private function opening(string $format, string $path): string
    {
        switch ($format) {
            case 'zip':
                return $this->zipLocalHeader(self::downloadName($path));
            case 'gzip':
                // gzip member header: magic, deflate, no flags, mtime 0, no xfl, OS unknown (0xFF).
                return "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff";
            case 'pem':
                return "-----BEGIN CERTIFICATE-----\n";
            case 'sql':
                return "-- MySQL dump\n-- Host: localhost    Database: production\n\n";
            case 'json':
                return '{"version":3,"id":"' . substr(md5($path), 0, 8) . '","crypto":{"ciphertext":"';
            case 'csv':
                return "id,created_at,name,email,value\n";
            default:
                return '';
        }
    }

    private function body(string $format, int $seed, int $len): string
    {
        switch ($format) {
            case 'gzip':
                return $this->deflateStoredBlock($seed, $len);
            case 'pem':
            case 'json':
                // base64/hex-ish printable payload — plausible key/ciphertext material.
                return substr(str_repeat(base64_encode(hash('sha256', 'k' . $seed, true)), (int) ceil($len / 44) + 1), 0, $len);
            case 'sql':
                return $this->sqlLines($seed, $len);
            case 'csv':
                return $this->csvLines($seed, $len);
            case 'zip':
            default:
                return $this->fill($seed, $len);
        }
    }

    /** Deterministic printable filler (base64 of a hashed block, trimmed to length). */
    private function fill(int $seed, int $len): string
    {
        $block = base64_encode(hash('sha256', 'f' . $seed, true) . hash('sha256', 'g' . $seed, true));
        $out = str_repeat($block, (int) ceil($len / strlen($block)) + 1);

        return substr($out, 0, $len);
    }

    /** One DEFLATE "stored" (uncompressed) block, never the final block — a valid gzip prefix that
     *  never ends, so a client streaming/inflating it keeps going forever. */
    private function deflateStoredBlock(int $seed, int $len): string
    {
        // header (1 byte, BFINAL=0 BTYPE=00) + LEN (2, LE) + NLEN (2, ~LEN) + LEN data bytes.
        $payload = min(max(1, $len - 5), 0xffff);
        $data = $this->fill($seed, $payload);
        $nlen = (~$payload) & 0xffff;

        return "\x00" . pack('v', $payload) . pack('v', $nlen) . $data;
    }

    private function sqlLines(int $seed, int $len): string
    {
        $out = '';
        $n = $seed;
        while (strlen($out) < $len) {
            $n = ($n * 1103515245 + 12345) & 0x7fffffff;
            $out .= 'INSERT INTO `accounts` VALUES (' . $n . ",'user" . ($n % 100000) . "','"
                . substr(md5((string) $n), 0, 16) . "');\n";
        }

        return substr($out, 0, $len);
    }

    private function csvLines(int $seed, int $len): string
    {
        $out = '';
        $n = $seed;
        while (strlen($out) < $len) {
            $n = ($n * 1103515245 + 12345) & 0x7fffffff;
            $out .= $n . ',2026-08-26T00:00:00Z,name' . ($n % 100000) . ',user' . ($n % 100000)
                . '@example.com,' . ($n % 1000) . "\n";
        }

        return substr($out, 0, $len);
    }

    /** ZIP local file header, store method, data-descriptor bit set (sizes deferred, never written). */
    private function zipLocalHeader(string $name): string
    {
        $name = substr($name, 0, 255);

        return "PK\x03\x04" . pack('v', 20) . pack('v', 0x0008) . pack('v', 0)
            . pack('v', 0) . pack('v', 0) . pack('V', 0) . pack('V', 0) . pack('V', 0)
            . pack('v', strlen($name)) . pack('v', 0) . $name;
    }
}
