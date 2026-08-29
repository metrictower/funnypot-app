<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dnp3;

use Funnypot\Protocol\Dnp3\Dnp3Config;
use Funnypot\Protocol\Dnp3\Dnp3Server;
use Funnypot\Protocol\Dnp3\Dnp3Session;
use PHPUnit\Framework\TestCase;

final class Dnp3ReconLoggingTest extends TestCase
{
    use Dnp3TestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:Dnp3Server,1:Dnp3Session}
     */
    private function serverSession(?Dnp3Config $config = null): array
    {
        $this->events = [];
        $server = new Dnp3Server($config ?? new Dnp3Config(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new Dnp3Session('198.51.100.20', 33000, 1);

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

    /** Decodes the IIN2 octet of an application response reply. */
    private static function responseIin2(string $frame): int
    {
        $ud = Dnp3Server::stripBlockCrcs($frame, ord($frame[2]) - 5);
        $app = Dnp3Server::parseApplication($ud);
        self::assertSame(0x81, $app['function'], 'reply is an application RESPONSE');

        return ord($app['objects'][1]); // AC + func consumed; objects = IIN1, IIN2, ...
    }

    public function test_every_event_carries_the_dnp3_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::readClass0();
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('dnp3', $e['proto']);
            self::assertSame('DNP3', $e['method']);
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

    public function test_read_of_analog_inputs_is_captured(): void
    {
        [$server, $session] = $this->serverSession();

        // READ of group 30 (Analog Input) variation 1, points 0..9.
        $session->inbuf .= self::readRange(30, 1, 0, 9);
        $server->processInbound($session);

        $read = $this->eventOfType('dnp3_read');
        self::assertNotNull($read);
        self::assertStringContainsString('g30v1', $read['path']);
        self::assertStringContainsString('g30v1', $read['objects']);
        self::assertSame(30, $session->readObjects[0]['group']);
        self::assertSame(1, $session->readObjects[0]['variation']);
    }

    public function test_class_objects_map_to_class_labels(): void
    {
        [$server, $session] = $this->serverSession();

        // READ of group 60 variation 2 = Class 1 event data.
        $session->inbuf .= self::appFunc(0x01, self::objAll(60, 2));
        $server->processInbound($session);

        $read = $this->eventOfType('dnp3_read');
        self::assertNotNull($read);
        self::assertStringContainsString('class1', $read['path']);
    }

    public function test_read_captures_multiple_object_groups(): void
    {
        [$server, $session] = $this->serverSession();

        // A single READ enumerating class 0 and class 1 in one request.
        $objects = self::objAll(60, 1) . self::objAll(60, 2);
        $session->inbuf .= self::appFunc(0x01, $objects);
        $server->processInbound($session);

        self::assertCount(2, $session->readObjects);
        $read = $this->eventOfType('dnp3_read');
        self::assertNotNull($read);
        self::assertStringContainsString('class0', $read['path']);
        self::assertStringContainsString('class1', $read['path']);
    }

    public function test_operate_is_captured_critical_and_refused_inert(): void
    {
        [$server, $session] = $this->serverSession();

        // OPERATE (0x04) — a control command. Captured, flagged, and refused; never actuated.
        $session->inbuf .= self::appFunc(0x04, self::objRange8(12, 1, 0, 0));
        $server->processInbound($session);

        $event = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($event);
        self::assertSame('OPERATE', $event['app_function']);
        self::assertSame('critical', $event['severity']);
        self::assertStringContainsString('inert, not actuated', $event['path']);

        // The reply refuses the command: IIN2.0 (function not implemented) is set.
        self::assertNotSame('', $session->outbuf);
        self::assertSame(0x01, self::responseIin2($session->outbuf) & 0x01);
    }

    public function test_write_is_captured_and_refused(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::appFunc(0x02, self::objRange8(40, 1, 0, 0)); // WRITE
        $server->processInbound($session);

        $event = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($event);
        self::assertSame('WRITE', $event['app_function']);
        self::assertSame('critical', $event['severity']);
        self::assertSame(0x01, self::responseIin2($session->outbuf) & 0x01);
    }

    public function test_cold_restart_is_captured_critical(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::appFunc(0x0D); // COLD_RESTART, no objects
        $server->processInbound($session);

        $event = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($event);
        self::assertSame('COLD_RESTART', $event['app_function']);
        self::assertSame('critical', $event['severity']);
    }

    public function test_confirm_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A master CONFIRM acknowledges our own response; there is nothing to answer.
        $session->inbuf .= self::appFunc(0x00);
        $server->processInbound($session);

        $event = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($event);
        self::assertSame('CONFIRM', $event['app_function']);
        self::assertSame('', $session->outbuf, 'a CONFIRM draws no reply');
        self::assertFalse($session->close);
    }

    public function test_secondary_frame_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A secondary (PRM=0) frame inbound is a response, not a request: record, never reply.
        $session->inbuf .= Dnp3Server::assembleFrame(0x0B, 1024, 5, ''); // PRM=0, LINK_STATUS shape
        $server->processInbound($session);

        $link = $this->eventOfType('dnp3_link');
        self::assertNotNull($link);
        self::assertSame('', $session->outbuf);
    }

    public function test_unsupported_link_function_is_recorded_without_closing(): void
    {
        [$server, $session] = $this->serverSession();

        // Primary link function 0x7 is unmodelled: record it but keep serving later frames.
        $session->inbuf .= self::linkRequest(0x7);
        $server->processInbound($session);

        $unknown = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('unsupported link function', $unknown['path']);
        self::assertFalse($session->close);
        self::assertSame('', $session->outbuf);
    }

    public function test_bad_crc_is_noted_but_still_captured(): void
    {
        [$server, $session] = $this->serverSession();

        // A REQUEST_LINK_STATUS frame with a corrupted header CRC is still captured as intel.
        $frame = self::linkRequest(0x9);
        $frame[8] = chr((ord($frame[8]) + 1) & 0xFF); // flip the low CRC octet

        $session->inbuf .= $frame;
        $server->processInbound($session);

        $link = $this->eventOfType('dnp3_link');
        self::assertNotNull($link);
        self::assertStringContainsString('crc=bad', $link['path']);
    }

    public function test_read_response_never_exposes_real_point_data(): void
    {
        // Every fabricated point octet is the ONLINE flag with state 0 — synthetic, never real data.
        $config = new Dnp3Config(outstationAddress: 1024, indicateRestart: true, staticBinaryPoints: 6);
        [$server, $session] = $this->serverSession($config);

        $session->inbuf .= self::readClass0();
        $server->processInbound($session);

        $ud = Dnp3Server::stripBlockCrcs($session->outbuf, ord($session->outbuf[2]) - 5);
        $app = Dnp3Server::parseApplication($ud);
        $objectData = substr($app['objects'], 2); // past IIN1, IIN2
        $points = substr($objectData, 5); // past group/var/qual/start/stop
        self::assertSame(6, strlen($points));
        self::assertSame(str_repeat("\x01", 6), $points);
    }

    public function test_crc_check_value_matches_the_standard(): void
    {
        // CRC-16/DNP has an authoritative check value of 0xEA82 for the ASCII string "123456789".
        self::assertSame(0xEA82, Dnp3Server::dnp3Crc('123456789'));
    }

    public function test_object_header_walker_stops_on_unknown_qualifier(): void
    {
        // group 1 var 2 with a free-format qualifier (0x0B) cannot be sized, so the walk stops there.
        $objects = self::objAll(30, 1) . chr(1) . chr(2) . chr(0x0B) . "\xff\xff";
        $parsed = Dnp3Server::parseObjectHeaders($objects, true);

        self::assertCount(2, $parsed);
        self::assertSame(30, $parsed[0]['group']);
        self::assertSame(1, $parsed[1]['group']);
        self::assertSame(0x0B, $parsed[1]['qualifier']);
    }
}
