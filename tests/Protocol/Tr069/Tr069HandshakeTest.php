<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Tr069;

use Funnypot\Protocol\Tr069\Tr069Config;
use Funnypot\Protocol\Tr069\Tr069Server;
use Funnypot\Protocol\Tr069\Tr069Session;
use PHPUnit\Framework\TestCase;

/**
 * Response-shape tests: the CPE persona answers each RPC with a plausible SOAP frame, challenges the
 * connection-request with Digest, serves a landing page on /, 400s malformed input, honours the low
 * mode SOAP Fault, and frames a split body correctly.
 */
final class Tr069HandshakeTest extends TestCase
{
    use Tr069TestFrames;

    private function drive(string $raw, ?Tr069Config $config = null): string
    {
        $server = new Tr069Server($config ?? new Tr069Config(), function (array $e): void {
        });
        $session = new Tr069Session('198.51.100.7', 40000, 1);
        $session->inbuf = $raw;
        $server->processInbound($session);

        return $session->outbuf;
    }

    public function test_setntpservers_returns_200_response(): void
    {
        $out = $this->drive(self::setNtpServersRequest('pool.ntp.org'));
        self::assertStringContainsString('HTTP/1.1 200 OK', $out);
        self::assertStringContainsString('SetNTPServersResponse', $out);
    }

    public function test_download_returns_in_progress_status(): void
    {
        $out = $this->drive(self::downloadRequest('http://good.example/fw.bin'));
        self::assertStringContainsString('DownloadResponse', $out);
        self::assertStringContainsString('<Status>1</Status>', $out);
    }

    public function test_getparametervalues_returns_persona_set(): void
    {
        $out = $this->drive(self::getParameterValuesRequest());
        self::assertStringContainsString('GetParameterValuesResponse', $out);
        self::assertStringContainsString('VMG3312-B10A', $out);       // persona model
        self::assertStringContainsString('SerialNumber', $out);
    }

    public function test_get_connection_request_returns_401_digest(): void
    {
        $out = $this->drive("GET /cwmp HTTP/1.1\r\nHost: x:7547\r\n\r\n");
        self::assertStringContainsString('HTTP/1.1 401 Unauthorized', $out);
        self::assertStringContainsString('WWW-Authenticate: Digest realm="RomPager"', $out);
    }

    public function test_get_root_returns_landing_page(): void
    {
        $out = $this->drive("GET / HTTP/1.1\r\nHost: x:7547\r\n\r\n");
        self::assertStringContainsString('HTTP/1.1 200 OK', $out);
        self::assertStringContainsString('text/html', $out);
    }

    public function test_malformed_request_returns_400(): void
    {
        $out = $this->drive("GARBAGE-NO-VERSION\r\n\r\n");
        self::assertStringContainsString('HTTP/1.1 400 Bad Request', $out);
    }

    public function test_low_mode_returns_soap_fault(): void
    {
        $out = $this->drive(self::setNtpServersRequest('pool.ntp.org'), new Tr069Config(mode: Tr069Config::MODE_LOW));
        self::assertStringContainsString('HTTP/1.1 500', $out);
        self::assertStringContainsString('SOAP-ENV:Fault', $out);
    }

    public function test_every_response_carries_the_server_banner(): void
    {
        foreach ([
            self::setNtpServersRequest('pool.ntp.org'),
            self::getParameterValuesRequest(),
            "GET /cwmp HTTP/1.1\r\nHost: x\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        ] as $raw) {
            self::assertStringContainsString('Server: RomPager/4.07', $this->drive($raw));
        }
    }

    public function test_split_body_waits_for_full_content_length(): void
    {
        $full = self::setNtpServersRequest('pool.ntp.org');
        $server = new Tr069Server(new Tr069Config(), function (array $e): void {
        });
        $session = new Tr069Session('1.2.3.4', 1, 1);

        $session->inbuf = substr($full, 0, strlen($full) - 25);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf, 'no response until the body is complete');

        $session->inbuf .= substr($full, strlen($full) - 25);
        $server->processInbound($session);
        self::assertStringContainsString('SetNTPServersResponse', $session->outbuf);
    }

    public function test_soap_response_content_type_is_xml(): void
    {
        $out = $this->drive(self::setNtpServersRequest('pool.ntp.org'));
        self::assertStringContainsString('Content-Type: text/xml', $out);
    }
}
