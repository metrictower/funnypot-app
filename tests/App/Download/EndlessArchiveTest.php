<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Download;

use Funnypot\App\Download\EndlessArchive;
use PHPUnit\Framework\TestCase;

/**
 * The server-side (non-JS fallback) endless-download generator: which suffixes it turns into a bulk
 * sink, that each format opens with the right magic bytes + Content-Type, that the stream stays under
 * the cap, and that small credential baits are deliberately excluded.
 */
final class EndlessArchiveTest extends TestCase
{
    public function test_bulk_suffixes_are_handled_credential_baits_are_not(): void
    {
        foreach (['/a.zip', '/x/cardholders.csv.zip', '/b.tar.gz', '/c.tgz', '/d.gz', '/e.sql', '/f.csv', '/g.bak'] as $p) {
            self::assertTrue(EndlessArchive::handles($p), "should handle {$p}");
        }
        // Small inspect-me / real-magic decoys must NOT be turned endless.
        foreach (['/wallet.json', '/server.pem', '/tls/server.cer', '/backup.tar', '/host.tar.bz2', '/index.php', '/robots.txt'] as $p) {
            self::assertFalse(EndlessArchive::handles($p), "should NOT handle {$p}");
        }
    }

    /** @return array<string,array{0:string,1:string,2:string}> path, expected content-type, hex magic */
    public static function formats(): array
    {
        return [
            'zip'        => ['/backups/db.zip', 'application/zip', '504b0304'],
            'csv.zip'    => ['/x/cardholders_2026-08.csv.zip', 'application/zip', '504b0304'],
            'tar.gz'     => ['/srv/site.tar.gz', 'application/gzip', '1f8b0800'],
            'tgz'        => ['/a.tgz', 'application/gzip', '1f8b0800'],
            'gz'         => ['/db.gz', 'application/gzip', '1f8b0800'],
        ];
    }

    /** @dataProvider formats */
    public function test_format_magic_and_content_type(string $path, string $ctype, string $magicHex): void
    {
        self::assertSame($ctype, EndlessArchive::contentTypeFor($path));
        $first = '';
        foreach ((new EndlessArchive())->chunks($path, 200_000) as $c) {
            $first = $c;
            break;
        }
        self::assertSame($magicHex, bin2hex(substr($first, 0, 4)), "wrong magic for {$path}");
    }

    public function test_text_formats_open_plausibly(): void
    {
        self::assertStringStartsWith('-- MySQL dump', $this->firstChunk('/dump.sql'));
        self::assertStringStartsWith('id,created_at,name', $this->firstChunk('/export.csv'));
    }

    public function test_stream_stays_under_cap(): void
    {
        foreach (['/a.zip', '/b.tar.gz', '/c.sql', '/d.csv', '/e.bak'] as $p) {
            $total = 0;
            foreach ((new EndlessArchive())->chunks($p, 500_000) as $c) {
                $total += strlen($c);
            }
            self::assertLessThanOrEqual(500_000, $total, "{$p} exceeded cap");
            self::assertGreaterThan(0, $total, "{$p} produced nothing");
        }
    }

    public function test_download_name_is_sanitised(): void
    {
        self::assertSame('db.zip', EndlessArchive::downloadName('/admin/backups/download/db.zip'));
        self::assertSame('a_b.tar.gz', EndlessArchive::downloadName('/x/a b.tar.gz'));
        self::assertSame('backup.zip', EndlessArchive::downloadName('/no-extension-here'));
    }

    public function test_never_throws_on_odd_input(): void
    {
        foreach (['', '/', '/.zip', '/' . str_repeat('a', 4096) . '.sql'] as $p) {
            $n = 0;
            foreach ((new EndlessArchive())->chunks($p, 4096) as $c) {
                $n += strlen($c);
            }
            self::assertLessThanOrEqual(4096, $n);
        }
    }

    private function firstChunk(string $path): string
    {
        foreach ((new EndlessArchive())->chunks($path, 100_000) as $c) {
            return $c;
        }

        return '';
    }
}
