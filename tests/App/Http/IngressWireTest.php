<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/acceptance/ingress/Wire.php';

/** Only pure decoding/closed-target guards. Never opens a socket or runs the acceptance job. */
final class IngressWireTest extends TestCase
{
    public function test_http_decoder_preserves_headers_and_checks_complete_framing(): void
    {
        self::assertSame(['status' => 0, 'headers' => [], 'body' => ''], \IngressWire::parseHttp(''));
        $response = \IngressWire::parseHttp("HTTP/1.1 414 URI Too Long\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc");
        self::assertSame(414, $response['status']);
        self::assertSame(['close'], $response['headers']['connection']);
        self::assertSame('abc', $response['body']);
        $response = \IngressWire::parseHttp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n");
        self::assertSame('abc', $response['body']);
    }

    public function test_incomplete_ambiguous_and_malformed_http_cannot_be_counted_as_passes(): void
    {
        foreach ([
            'garbage', "HTTP/1.1 200 OK\r\n\r\nshort", // valid close framing, tested separately below
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: bogus\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
        ] as $index => $raw) {
            if ($index === 1) {
                self::assertSame('short', \IngressWire::parseHttp($raw)['body']);
                continue;
            }
            try {
                \IngressWire::parseHttp($raw);
                self::fail('invalid HTTP was accepted');
            } catch (\RuntimeException $error) {
                self::assertNotSame('', $error->getMessage());
            }
        }
    }

    public function test_fastcgi_decoder_requires_clean_end_record_and_no_stderr(): void
    {
        $stdout = self::record(6, "Status: 414 URI Too Long\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\nfixed");
        $end = self::record(3, str_repeat("\0", 8));
        $response = \IngressWire::parseFastcgi($stdout . $end);
        self::assertSame(414, $response['status']);
        self::assertSame('fixed', $response['body']);
        foreach ([$stdout, $stdout . substr($end, 0, -1), $stdout . self::record(7, 'diagnostic') . $end,
            $stdout . self::record(3, "\0\0\0\1\0\0\0\0"), $stdout . $end . self::record(6, 'extra'),
            self::record(6, "Content-Type: text/html\r\n\r\nno-status") . $end] as $raw) {
            try {
                \IngressWire::parseFastcgi($raw);
                self::fail('invalid FastCGI was accepted');
            } catch (\RuntimeException $error) {
                self::assertNotSame('', $error->getMessage());
            }
        }
    }

    public function test_off_target_is_rejected_before_attempting_a_connection(): void
    {
        foreach ([[80, 'elsewhere.invalid'], [22, 'public.ingress.invalid']] as [$port, $host]) {
            try {
                (new \IngressWire())->partial($port, $host, '');
                self::fail('off-target connection accepted');
            } catch (\RuntimeException $error) {
                self::assertSame('off-target-connection', $error->getMessage());
            }
        }
    }

    private static function record(int $type, string $body): string
    {
        return pack('CCnnCC', 1, $type, 1, strlen($body), 0, 0) . $body;
    }
}
