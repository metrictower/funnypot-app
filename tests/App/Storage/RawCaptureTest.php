<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\RawCapture;
use Funnypot\Core\RequestContext;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Full-request capture for a vuln scan (FUNNYPOT_CAPTURE_RAW). Unlike the classified `hits` table (which
 * keeps only UA + Referer + a 300-char body slice), this stores the COMPLETE request — every header, the
 * full query string, and the full body up to a 64KB cap — so an operator can see exactly what a scanner
 * sent. Fail-open: capture must never break request handling.
 */
final class RawCaptureTest extends TestCase
{
    private function tmpDb(): string
    {
        return sys_get_temp_dir() . '/fp-raw-' . uniqid() . '.sqlite';
    }

    public function test_captures_every_header_the_full_query_and_body(): void
    {
        $db = $this->tmpDb();
        $ctx = new RequestContext(
            'POST',
            '/wp-login.php',
            'a=1&b=2&redirect=/etc/passwd',
            ['User-Agent' => 'sqlmap/1.7', 'X-Forwarded-For' => '1.2.3.4', 'Authorization' => 'Bearer xyz', 'Cookie' => 'sess=deadbeef'],
            "log=admin&pwd=' OR 1=1-- -",
            'victim.test',
            'https',
            '1.1'
        );
        (new RawCapture($db))->capture($ctx, '203.0.113.9');

        $pdo = new PDO('sqlite:' . $db);
        $row = $pdo->query('SELECT * FROM raw_requests')->fetch(PDO::FETCH_ASSOC);
        self::assertSame('POST', $row['method']);
        self::assertSame('/wp-login.php', $row['path']);
        self::assertSame('a=1&b=2&redirect=/etc/passwd', $row['query'], 'full GET query captured');
        self::assertSame('203.0.113.9', $row['ip']);
        // EVERY header, not just UA/Referer.
        self::assertStringContainsString('sqlmap', $row['headers']);
        self::assertStringContainsString('X-Forwarded-For', $row['headers']);
        self::assertStringContainsString('Authorization', $row['headers']);
        self::assertStringContainsString('Cookie', $row['headers']);
        // Full body, not a 300-char slice.
        self::assertStringContainsString("OR 1=1", $row['body']);
        self::assertSame('victim.test', $row['host']);
    }

    public function test_body_is_capped_at_64kb_but_the_true_size_is_recorded(): void
    {
        $db = $this->tmpDb();
        $big = str_repeat('A', 100000); // 100KB payload
        (new RawCapture($db))->capture(new RequestContext('POST', '/x', '', [], $big), '1.1.1.1');

        $pdo = new PDO('sqlite:' . $db);
        $row = $pdo->query('SELECT length(body) bl, body_bytes FROM raw_requests')->fetch(PDO::FETCH_ASSOC);
        self::assertSame(65536, (int) $row['bl'], 'body stored capped at 64KB');
        self::assertSame(100000, (int) $row['body_bytes'], 'true byte size recorded even when the stored body is capped');
    }

    public function test_capture_never_throws_even_on_an_unwritable_path(): void
    {
        // Fail-open: a broken capture must not break the honeypot.
        (new RawCapture('/no/such/dir/raw.sqlite'))->capture(new RequestContext('GET', '/'), '1.1.1.1');
        self::assertTrue(true);
    }
}
