<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dnp3;

use Funnypot\Protocol\Dnp3\Dnp3Config;
use Funnypot\Protocol\Dnp3\Dnp3Server;
use Funnypot\Protocol\Dnp3\Dnp3Session;
use PHPUnit\Framework\TestCase;

final class Dnp3HandshakeTest extends TestCase
{
    use Dnp3TestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?Dnp3Config $config = null): Dnp3Server
    {
        $this->events = [];

        return new Dnp3Server($config ?? new Dnp3Config(), function (array $e): void {
            $this->events[] = $e;
        });
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

    /**
     * Decodes a reply frame into its link header and (when present) application layer for assertions.
     *
     * @return array{link:array<string,mixed>,func:?int,iin1:?int,iin2:?int,objectData:string}
     */
    private static function decode(string $frame): array
    {
        $link = Dnp3Server::parseLinkHeader($frame);
        self::assertNotNull($link, 'reply is a parseable DNP3 frame');
        $ud = Dnp3Server::stripBlockCrcs($frame, ord($frame[2]) - 5);
        if ($ud === null || strlen($ud) < 3) {
            return ['link' => $link, 'func' => null, 'iin1' => null, 'iin2' => null, 'objectData' => ''];
        }
        $app = Dnp3Server::parseApplication($ud);
        $objects = $app['objects'];

        return [
            'link' => $link,
            'func' => $app['function'],
            'iin1' => strlen($objects) >= 1 ? ord($objects[0]) : null,
            'iin2' => strlen($objects) >= 2 ? ord($objects[1]) : null,
            'objectData' => strlen($objects) > 2 ? substr($objects, 2) : '',
        ];
    }

    public function test_request_link_status_returns_link_status(): void
    {
        $server = $this->newServer(); // default outstation address 1024
        $session = new Dnp3Session('203.0.113.5', 50000, 1);

        $session->inbuf .= self::linkRequest(0x9, dest: 1024, source: 5); // REQUEST_LINK_STATUS
        $server->processInbound($session);

        self::assertSame(5, $session->sourceAddress);
        self::assertSame(1024, $session->destAddress);

        $link = $this->eventOfType('dnp3_link');
        self::assertNotNull($link);
        self::assertSame('REQUEST_LINK_STATUS', $link['link_function']);
        self::assertSame(5, $link['src_addr']);
        self::assertSame(1024, $link['dest_addr']);

        // Reply: a secondary LINK_STATUS frame (PRM=0, function 0x0B) addressed back to the master.
        $d = self::decode($session->outbuf);
        self::assertSame(0, $d['link']['prm'], 'reply is a secondary frame');
        self::assertSame(0x0B, $d['link']['function'], 'reply is LINK_STATUS');
        self::assertSame(1024, $d['link']['source'], 'reply source is the outstation address');
        self::assertSame(5, $d['link']['dest'], 'reply is addressed to the master');
        self::assertTrue($d['link']['crcValid'], 'reply carries a valid header CRC');
    }

    public function test_reset_link_states_returns_ack(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('203.0.113.5', 50000, 1);

        $session->inbuf .= self::linkRequest(0x0, dest: 1024, source: 7); // RESET_LINK_STATES
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('dnp3_link'));

        $d = self::decode($session->outbuf);
        self::assertSame(0, $d['link']['prm']);
        self::assertSame(0x00, $d['link']['function'], 'reply is a link ACK');
        self::assertSame(7, $d['link']['dest']);
        self::assertSame(1024, $d['link']['source']);
    }

    public function test_read_class0_captures_and_responds_with_binary_inputs(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('198.51.100.7', 44818, 1);

        $session->inbuf .= self::readClass0();
        $server->processInbound($session);

        $read = $this->eventOfType('dnp3_read');
        self::assertNotNull($read);
        self::assertSame('READ', $read['app_function']);
        self::assertStringContainsString('class0', $read['path']);
        self::assertSame([['group' => 60, 'variation' => 1, 'qualifier' => 0x06]], $session->readObjects);

        // Reply: an application RESPONSE(0x81) carrying a Group 1 Var 2 block.
        $d = self::decode($session->outbuf);
        self::assertSame(1, $d['link']['prm'], 'app response rides in a primary user-data frame');
        self::assertSame(0x81, $d['func'], 'application function is RESPONSE');
        self::assertSame(0x80, $d['iin1'] & 0x80, 'first response advertises device restart (IIN1.7)');

        // The object block is Group 1 (Binary Input) Var 2, 4 fabricated points, each ONLINE + off.
        $obj = $d['objectData'];
        self::assertSame(0x01, ord($obj[0]), 'object group 1');
        self::assertSame(0x02, ord($obj[1]), 'variation 2 (with flags)');
        self::assertSame(0x00, ord($obj[2]), 'qualifier 8-bit start/stop');
        self::assertSame(0x00, ord($obj[3]), 'start index 0');
        self::assertSame(0x03, ord($obj[4]), 'stop index 3 (4 points)');
        // INERT: every point octet is 0x01 = ONLINE flag with state 0. Never a real point value.
        self::assertSame(str_repeat("\x01", 4), substr($obj, 5, 4));
    }

    public function test_device_restart_indication_only_on_first_response(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('198.51.100.7', 44818, 1);

        $session->inbuf .= self::readClass0();
        $server->processInbound($session);
        $first = self::decode($session->outbuf);
        self::assertSame(0x80, $first['iin1'] & 0x80, 'restart set on the first response');
        $session->outbuf = '';

        $session->inbuf .= self::readClass0(seq: 1);
        $server->processInbound($session);
        $second = self::decode($session->outbuf);
        self::assertSame(0x00, $second['iin1'] & 0x80, 'restart cleared on subsequent responses');
    }

    public function test_response_sequence_number_echoes_the_request(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('198.51.100.7', 44818, 1);

        $session->inbuf .= self::readClass0(seq: 5);
        $server->processInbound($session);

        $ud = Dnp3Server::stripBlockCrcs($session->outbuf, ord($session->outbuf[2]) - 5);
        $app = Dnp3Server::parseApplication($ud);
        self::assertSame(5, $app['seq'], 'the application response echoes the request sequence');
    }

    public function test_partial_frame_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('192.0.2.2', 5001, 1);

        $frame = self::readClass0();
        // Feed the header block plus a fragment: nothing should parse yet.
        $session->inbuf .= substr($frame, 0, 10);
        $server->processInbound($session);
        self::assertNull($this->eventOfType('dnp3_read'));
        self::assertSame('', $session->outbuf);

        // Deliver the remainder: the request now parses and is answered.
        $session->inbuf .= substr($frame, 10);
        $server->processInbound($session);
        self::assertNotNull($this->eventOfType('dnp3_read'));
        self::assertNotSame('', $session->outbuf);
    }

    public function test_two_pipelined_frames_are_both_processed(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('192.0.2.2', 5001, 1);

        $session->inbuf .= self::linkRequest(0x9) . self::readClass0();
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('dnp3_link'));
        self::assertNotNull($this->eventOfType('dnp3_read'));
    }

    public function test_non_dnp3_start_bytes_close_cleanly(): void
    {
        // A TLS ClientHello (0x16) or other junk lacks the 0x05 0x64 start: record and drop.
        $server = $this->newServer();
        $session = new Dnp3Session('192.0.2.1', 5000, 1);

        $session->inbuf .= "\x16\x03\x01\x00\x50" . str_repeat("\x00", 80);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('dnp3_unknown'));
    }

    public function test_malformed_application_fragment_never_escapes(): void
    {
        // A user-data frame whose fragment is too short to hold an application header must degrade.
        $server = $this->newServer();
        $session = new Dnp3Session('192.0.2.3', 5002, 1);

        // appPayload of a single byte -> user data (transport + 1) is too short for AC + function.
        $session->inbuf .= self::appFrame("\x00");
        $server->processInbound($session);

        $unknown = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('malformed application fragment', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_bad_link_length_closes_cleanly(): void
    {
        $server = $this->newServer();
        $session = new Dnp3Session('192.0.2.4', 5003, 1);

        // Valid start bytes but a length below the 5-octet minimum.
        $session->inbuf .= "\x05\x64\x02\x44\x00\x04\x00\x04" . "\x00\x00";
        $server->processInbound($session);

        self::assertTrue($session->close);
        $unknown = $this->eventOfType('dnp3_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('bad link length', $unknown['path']);
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_DNP3_ADDRESS=100');
        putenv('FUNNYPOT_DNP3_POINTS=8');
        putenv('FUNNYPOT_DNP3_RESTART=0');

        $config = Dnp3Config::fromEnv();
        self::assertSame(100, $config->outstationAddress);
        self::assertSame(8, $config->staticBinaryPoints);
        self::assertFalse($config->indicateRestart);

        putenv('FUNNYPOT_DNP3_ADDRESS');
        putenv('FUNNYPOT_DNP3_POINTS');
        putenv('FUNNYPOT_DNP3_RESTART');

        // Defaults when unset.
        $config = Dnp3Config::fromEnv();
        self::assertSame(1024, $config->outstationAddress);
        self::assertTrue($config->indicateRestart);
    }
}
