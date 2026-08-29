<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Stun;

use Funnypot\Protocol\Stun\StunConfig;
use Funnypot\Protocol\Stun\StunServer;
use Funnypot\Protocol\Stun\StunSession;
use PHPUnit\Framework\TestCase;

final class StunHandshakeTest extends TestCase
{
    use StunTestFrames;

    private const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    private const ATTR_SOFTWARE = 0x8022;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:StunServer,1:StunSession}
     */
    private function serverSession(string $ip = '192.0.2.10', int $port = 44444, ?StunConfig $config = null): array
    {
        $this->events = [];
        $server = new StunServer($config ?? new StunConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new StunSession($ip, $port, 1);

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

    public function test_binding_request_is_parsed_and_transaction_id_captured(): void
    {
        $txid = self::txid();
        $msg = self::bindingRequest($txid);

        $parsed = StunServer::parseMessage($msg);
        self::assertNotNull($parsed);
        self::assertSame(0x0001, $parsed['messageType']);
        self::assertSame($txid, $parsed['transactionId']);
        self::assertNull($parsed['software']);
    }

    public function test_build_binding_response_echoes_txid_and_decodes_to_source(): void
    {
        $txid = self::txid();

        $resp = StunServer::buildBindingResponse($txid, '203.0.113.55', 51515, '');
        $parsed = StunServer::parseMessage($resp);

        self::assertNotNull($parsed);
        self::assertSame(0x0101, $parsed['messageType'], 'Binding Success Response type');
        self::assertSame($txid, $parsed['transactionId'], 'transaction id echoed');

        self::assertArrayHasKey(self::ATTR_XOR_MAPPED_ADDRESS, $parsed['attributes']);
        $decoded = StunServer::decodeXorMappedAddress($parsed['attributes'][self::ATTR_XOR_MAPPED_ADDRESS], $txid);
        self::assertNotNull($decoded);
        self::assertSame('203.0.113.55', $decoded['ip']);
        self::assertSame(51515, $decoded['port']);
    }

    public function test_xor_mapped_address_actually_xors_with_the_magic_cookie(): void
    {
        // The stored X-Address/X-Port must NOT be the plaintext address — that is the whole point of
        // XOR-MAPPED-ADDRESS. Decoding reverses the XOR; the raw attribute bytes differ from raw addr.
        $txid = self::txid();
        $resp = StunServer::buildBindingResponse($txid, '198.51.100.7', 0x1234, '');
        $parsed = StunServer::parseMessage($resp);
        self::assertNotNull($parsed);

        $value = $parsed['attributes'][self::ATTR_XOR_MAPPED_ADDRESS];
        // Bytes 2..3 are X-Port; raw port XOR 0x2112 => must differ from the plaintext port bytes.
        self::assertNotSame(pack('n', 0x1234), substr($value, 2, 2), 'port is XORed, not plaintext');
        self::assertNotSame(inet_pton('198.51.100.7'), substr($value, 4, 4), 'address is XORed, not plaintext');

        $decoded = StunServer::decodeXorMappedAddress($value, $txid);
        self::assertSame('198.51.100.7', $decoded['ip']);
        self::assertSame(0x1234, $decoded['port']);
    }

    public function test_software_attribute_is_included_when_configured(): void
    {
        $txid = self::txid();
        $resp = StunServer::buildBindingResponse($txid, '192.0.2.1', 3478, 'coturn-4.5.2');
        $parsed = StunServer::parseMessage($resp);

        self::assertNotNull($parsed);
        self::assertArrayHasKey(self::ATTR_SOFTWARE, $parsed['attributes']);
        self::assertSame('coturn-4.5.2', $parsed['attributes'][self::ATTR_SOFTWARE]);
        self::assertSame('coturn-4.5.2', $parsed['software']);
    }

    public function test_client_supplied_software_attribute_is_parsed(): void
    {
        $msg = self::bindingRequest(self::txid(), self::softwareAttr('Nimbus STUN Client 1.0'));

        $parsed = StunServer::parseMessage($msg);
        self::assertNotNull($parsed);
        self::assertSame('Nimbus STUN Client 1.0', $parsed['software']);
    }

    public function test_bad_magic_cookie_is_rejected(): void
    {
        // Right length, right type, wrong magic cookie => not STUN.
        $bogus = pack('n', 0x0001) . pack('n', 0) . "\xDE\xAD\xBE\xEF" . self::txid();
        self::assertNull(StunServer::parseMessage($bogus));
    }

    public function test_short_and_high_bit_messages_are_rejected(): void
    {
        self::assertNull(StunServer::parseMessage('too-short'), 'under 20 bytes is not a STUN message');

        // A leading byte with the top two bits set is not a STUN message (e.g. a TLS record 0x16... no,
        // 0x16 has clear high bits; use 0xC0 which sets them).
        $highBits = "\xC0\x00" . pack('n', 0) . self::MAGIC . self::txid();
        self::assertNull(StunServer::parseMessage($highBits));
    }

    public function test_processing_a_binding_request_reflects_the_socket_source(): void
    {
        // The mapped address comes from the session (the observed socket source), not from anything in
        // the request body — a padded request keeps the reply within the anti-amplification cap.
        [$server, $session] = $this->serverSession('192.0.2.10', 44444);
        $session->inbuf = self::bindingRequest(self::txid(), self::softwareAttr('probe-tool/2'));
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf);
        $parsed = StunServer::parseMessage($session->outbuf);
        self::assertNotNull($parsed);
        self::assertSame(0x0101, $parsed['messageType']);
        self::assertSame(self::txid(), $parsed['transactionId']);

        $decoded = StunServer::decodeXorMappedAddress(
            $parsed['attributes'][self::ATTR_XOR_MAPPED_ADDRESS],
            self::txid()
        );
        self::assertSame('192.0.2.10', $decoded['ip']);
        self::assertSame(44444, $decoded['port']);
    }
}
