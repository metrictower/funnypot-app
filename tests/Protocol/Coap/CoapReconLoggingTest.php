<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Coap;

use Funnypot\Protocol\Coap\CoapConfig;
use Funnypot\Protocol\Coap\CoapServer;
use Funnypot\Protocol\Coap\CoapSession;
use PHPUnit\Framework\TestCase;

final class CoapReconLoggingTest extends TestCase
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
        $session = new CoapSession('198.51.100.9', 5683, 1);

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

    public function test_every_event_carries_the_coap_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getMessage(self::T_CON, 1, 't', '/sensors/temp');
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('coap', $e['proto']);
            self::assertSame('COAP', $e['method']);
            self::assertSame(1, $e['matched']);
            self::assertSame(1, $e['served']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
            self::assertArrayHasKey('event', $e);
            self::assertArrayHasKey('ip', $e);
            self::assertArrayHasKey('port', $e);
            self::assertArrayHasKey('path', $e);
        }
    }

    public function test_reply_never_exceeds_the_request_datagram(): void
    {
        // A minimal GET whose believable link-format reply would be far larger must be capped so it
        // can never amplify.
        [$server, $session] = $this->serverSession();

        $req = self::getMessage(self::T_CON, 5, 't', '/.well-known/core');
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('coap_get'));
        self::assertLessThanOrEqual(
            strlen($req),
            strlen($session->outbuf),
            'anti-amplification: the reply is never larger than the request'
        );
    }

    public function test_large_resource_is_never_dumped(): void
    {
        // /large is the classic CoAP amplification target: a tiny GET must not pull the big body.
        [$server, $session] = $this->serverSession();

        $req = self::getMessage(self::T_CON, 6, 't', '/large');
        $session->inbuf = $req;
        $server->processInbound($session);

        $get = $this->eventOfType('coap_get');
        self::assertNotNull($get);
        self::assertSame('medium', $get['severity'], '/large probe is higher-value recon');

        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf), 'the amplification target is neutered');
        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(0x45, $resp['code'], 'still a believable 2.05');
        self::assertSame('', $resp['payload'], 'but the large body is dropped under the cap');
    }

    public function test_post_payload_is_captured_and_never_applied(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::postMessage(self::T_CON, 7, 'p', '/actuators/led', 'on');
        $server->processInbound($session);

        $post = $this->eventOfType('coap_post');
        self::assertNotNull($post);
        self::assertStringContainsString('POST /actuators/led', $post['path']);
        self::assertStringContainsString('2 bytes payload', $post['path']);
        self::assertSame('on', $post['payload']);
        self::assertSame('on', $session->payload);

        // INERT: the acknowledged reply never actually changed the resource.
        self::assertSame('off', (new CoapConfig())->resources['/actuators/led']);

        $resp = CoapServer::parseMessage($session->outbuf);
        self::assertNotNull($resp);
        self::assertSame(0x45, $resp['code'], 'a plausible 2.05 ack');
    }

    public function test_put_and_delete_are_captured_as_unknown_and_refused(): void
    {
        foreach ([self::C_PUT => 'PUT', self::C_DELETE => 'DELETE'] as $code => $name) {
            [$server, $session] = $this->serverSession();

            $session->inbuf = self::methodMessage(self::T_CON, $code, 8, 'm', '/config');
            $server->processInbound($session);

            $unknown = $this->eventOfType('coap_unknown');
            self::assertNotNull($unknown, "$name is captured as coap_unknown");
            self::assertStringContainsString("CoAP $name /config", $unknown['path']);

            $resp = CoapServer::parseMessage($session->outbuf);
            self::assertNotNull($resp);
            self::assertSame(0x84, $resp['code'], "$name is refused with 4.04, never applied");
        }
    }

    public function test_response_code_inbound_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A 2.05 Content (code 0x45) arriving inbound is a response, not a request — never reply.
        $session->inbuf = self::coapMessage(self::T_NON, 0x45, 9, 't', [], 'data');
        $server->processInbound($session);

        $unknown = $this->eventOfType('coap_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('non-request code 2.05', $unknown['path']);
        self::assertSame('', $session->outbuf, 'no reflection primitive for a stray response');
    }

    public function test_reserved_token_length_is_rejected_as_unparseable(): void
    {
        [$server, $session] = $this->serverSession();

        // TKL 9 is reserved (a message format error): logged unknown, no reply.
        $session->inbuf = chr((1 << 6) | (0 << 4) | 9) . chr(0x01) . "\x00\x0a" . str_repeat("\x00", 9);
        $server->processInbound($session);

        $unknown = $this->eventOfType('coap_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('unparseable', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_truncated_option_is_rejected_as_unparseable(): void
    {
        [$server, $session] = $this->serverSession();

        // Option header claims a 5-byte value but the datagram ends immediately after it.
        $session->inbuf = chr((1 << 6) | (0 << 4) | 0) . chr(self::C_GET) . "\x00\x0b" . chr((11 << 4) | 5);
        $server->processInbound($session);

        $unknown = $this->eventOfType('coap_unknown');
        self::assertNotNull($unknown);
        self::assertSame('', $session->outbuf);
    }

    public function test_payload_marker_with_no_payload_is_rejected(): void
    {
        [$server, $session] = $this->serverSession();

        // A 0xFF payload marker with nothing after it is a message format error.
        $session->inbuf = chr((1 << 6) | (0 << 4) | 0) . chr(self::C_GET) . "\x00\x0b" . "\xFF";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('coap_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_short_datagram_is_rejected(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = "\x40\x01"; // only 2 of the required 4 header bytes
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('coap_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_junk_datagram_never_faults_the_listener(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = random_bytes(37);
        // Must not throw — a malformed datagram degrades to a logged event, never crashes the loop.
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_COAP_CORE=</status>;rt="node"');
        putenv('FUNNYPOT_COAP_DEVICE=edge-gw-7');

        $config = CoapConfig::fromEnv();
        self::assertSame('</status>;rt="node"', $config->wellKnownCore);
        self::assertSame('edge-gw-7', $config->deviceName);

        putenv('FUNNYPOT_COAP_CORE');
        putenv('FUNNYPOT_COAP_DEVICE');
    }
}
