<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Coap;

use Funnypot\Protocol\Coap\CoapConfig;
use Funnypot\Protocol\Coap\CoapServer;
use Funnypot\Protocol\Coap\CoapSession;
use PHPUnit\Framework\TestCase;

final class CoapHandshakeTest extends TestCase
{
    use CoapTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:CoapServer,1:CoapSession}
     */
    private function serverSession(?CoapConfig $config = null): array
    {
        $this->events = [];
        $server = new CoapServer($config ?? new CoapConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new CoapSession('192.0.2.50', 5683, 1);

        return [$server, $session];
    }

    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }

    public function test_get_well_known_core_returns_the_link_format_list(): void
    {
        [$server, $session] = $this->serverSession();

        // A GET big enough (padded) to hold the full resource list under the anti-amplification cap.
        $req = self::getMessage(self::T_CON, 0xBEEF, "\x01\x02\x03\x04", '/.well-known/core', [self::padOption(400)]);
        $session->inbuf = $req;
        $server->processInbound($session);

        $get = $this->eventOfType('coap_get');
        self::assertNotNull($get);
        self::assertStringContainsString('GET /.well-known/core', $get['path']);
        self::assertSame('/.well-known/core', $session->path);

        self::assertNotSame('', $session->outbuf);
        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(2, $resp['type'], 'a CON request draws a piggybacked ACK');
        self::assertSame(0x45, $resp['code'], '2.05 Content');
        self::assertSame(0xBEEF, $resp['messageId'], 'message id echoed');
        self::assertSame("\x01\x02\x03\x04", $resp['token'], 'token echoed');
        self::assertSame(40, $resp['contentFormat'], 'application/link-format');
        self::assertStringContainsString('</.well-known/core>', $resp['payload']);
        self::assertStringContainsString('rt="temperature"', $resp['payload']);
    }

    public function test_get_advertised_resource_returns_its_value(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::getMessage(self::T_CON, 0x0101, 'tok', '/sensors/temp');
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertSame('/sensors/temp', $session->path);

        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(0x45, $resp['code'], '2.05 Content');
        self::assertSame(0, $resp['contentFormat'], 'text/plain');
        self::assertSame('21.4', $resp['payload']);
    }

    public function test_get_unknown_resource_returns_not_found(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::getMessage(self::T_CON, 0x2222, 'z', '/admin/secret');
        $session->inbuf = $req;
        $server->processInbound($session);

        $get = $this->eventOfType('coap_get');
        self::assertNotNull($get);
        self::assertStringContainsString('/admin/secret', $get['path']);

        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(0x84, $resp['code'], '4.04 Not Found');
        self::assertSame('', $resp['payload'], 'a 4.04 carries no body');
        self::assertSame(0x2222, $resp['messageId']);
    }

    public function test_non_request_draws_a_non_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A non-confirmable GET is answered with a non-confirmable reply (not an ACK).
        $req = self::getMessage(self::T_NON, 0x3333, 'nn', '/sensors/humidity');
        $session->inbuf = $req;
        $server->processInbound($session);

        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(1, $resp['type'], 'NON request -> NON reply');
        self::assertSame(0x45, $resp['code']);
        self::assertSame('46', $resp['payload']);
    }

    public function test_confirmable_ping_is_answered_with_reset(): void
    {
        [$server, $session] = $this->serverSession();

        // An empty CON message (code 0.00, no token) is a CoAP ping — a real endpoint answers RST.
        $session->inbuf = self::coapMessage(self::T_CON, 0x00, 0x4444, '', []);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('coap_unknown'));
        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(3, $resp['type'], 'RST');
        self::assertSame(0, $resp['code'], 'empty message');
        self::assertSame(0x4444, $resp['messageId'], 'message id echoed');
    }

    public function test_encode_parse_roundtrip(): void
    {
        $msg = CoapServer::encodeMessage(0, 0x01, 0x1234, "\xAA\xBB", [[11, 'a'], [11, 'bb'], [15, 'x=1']], 'hello');
        $parsed = CoapServer::parseMessage($msg);

        self::assertNotNull($parsed);
        self::assertSame(1, $parsed['version']);
        self::assertSame(0x1234, $parsed['messageId']);
        self::assertSame("\xAA\xBB", $parsed['token']);
        self::assertSame('/a/bb', $parsed['uriPath'], 'Uri-Path segments reassembled in order');
        self::assertSame('x=1', $parsed['uriQuery']);
        self::assertSame('hello', $parsed['payload']);
    }

    public function test_large_option_delta_and_length_roundtrip(): void
    {
        // Option number 300 (delta needs the 2-byte extended form) with a 20-byte value (length needs
        // the 1-byte extended form) — exercises both nibble-extension paths.
        $value = str_repeat('v', 20);
        $msg = CoapServer::encodeMessage(1, 0x02, 0x0001, '', [[300, $value]], '');
        $parsed = CoapServer::parseMessage($msg);

        self::assertNotNull($parsed);
        self::assertCount(1, $parsed['options']);
        self::assertSame(300, $parsed['options'][0]['number']);
        self::assertSame($value, $parsed['options'][0]['value']);
    }
}
