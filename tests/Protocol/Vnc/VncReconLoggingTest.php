<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Vnc;

use Funnypot\Protocol\Vnc\VncConfig;
use Funnypot\Protocol\Vnc\VncServer;
use Funnypot\Protocol\Vnc\VncSession;
use PHPUnit\Framework\TestCase;

final class VncReconLoggingTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function activeSession(): array
    {
        $this->events = [];
        $logger = function (array $e): void {
            $this->events[] = $e;
        };
        $config = new VncConfig(style: 'realistic', width: 400, height: 300);
        $server = new VncServer($config, $logger);
        $session = new VncSession('198.51.100.7', 5900, 1);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // security None
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // ClientInit
        $server->processInbound($session);

        return [$server, $session];
    }

    public function test_encoding_name_mapping(): void
    {
        self::assertSame('Raw', VncServer::encodingName(0));
        self::assertSame('Tight', VncServer::encodingName(7));
        self::assertSame('ZRLE', VncServer::encodingName(16));
        self::assertSame('Cursor', VncServer::encodingName(-239));
        self::assertSame('ExtDesktopSize', VncServer::encodingName(-308));
        self::assertSame('TightJPEGQuality', VncServer::encodingName(-25));
        self::assertSame('enc(12345)', VncServer::encodingName(12345));
    }

    public function test_version_and_security_type_are_logged(): void
    {
        $this->activeSession();

        $version = $this->eventOfType('version');
        self::assertNotNull($version);
        self::assertStringContainsString('RFB 003.008', $version['path']);

        $auth = $this->eventOfType('auth_select');
        self::assertNotNull($auth);
        self::assertStringContainsString('None', $auth['path']);
        self::assertStringContainsString('RFB 003.008', $auth['path']);
    }

    public function test_setencodings_is_logged_with_client_fingerprint(): void
    {
        [$server, $session] = $this->activeSession();

        // Raw(0), Tight(7), ZRLE(16), Cursor(-239), DesktopSize(-223)
        $session->inbuf .= "\x02\x00" . pack('n', 5) . pack('NNNNN', 0, 7, 16, -239, -223);
        $server->processInbound($session);

        $enc = $this->eventOfType('encodings');
        self::assertNotNull($enc);
        self::assertStringContainsString('[5]', $enc['path']);
        self::assertStringContainsString('Raw(0)', $enc['path']);
        self::assertStringContainsString('Tight(7)', $enc['path']);
        self::assertStringContainsString('ZRLE(16)', $enc['path']);
        self::assertStringContainsString('Cursor(-239)', $enc['path']);
    }

    public function test_first_framebuffer_request_logged_once(): void
    {
        [$server, $session] = $this->activeSession();

        $req = "\x03\x00" . pack('nnnn', 0, 0, 400, 300);
        $session->inbuf .= $req;
        $server->processInbound($session);
        $session->inbuf .= $req; // a second request must NOT log again
        $server->processInbound($session);

        $seen = array_filter($this->events, static fn ($e) => ($e['event'] ?? '') === 'screen_viewed');
        self::assertCount(1, $seen);
        $first = array_values($seen)[0];
        self::assertStringContainsString('saw the screen', $first['path']);
        self::assertStringContainsString('400x300', $first['path']);
    }

    public function test_client_clipboard_has_readable_path(): void
    {
        [$server, $session] = $this->activeSession();

        $text = 'stolen-secret-123';
        $session->inbuf .= "\x06\x00\x00\x00" . pack('N', strlen($text)) . $text;
        $server->processInbound($session);

        $clip = $this->eventOfType('client_clipboard');
        self::assertNotNull($clip);
        self::assertSame($text, $clip['body']);
        self::assertStringContainsString($text, $clip['path']);
    }

    public function test_unknown_message_is_logged_as_extension_probe(): void
    {
        [$server, $session] = $this->activeSession();

        // 82 = 'R' — a bot injecting an UltraVNC/extension message or a stray banner.
        $session->inbuf .= "\x52\x00\x00\x00";
        $server->processInbound($session);

        $unknown = $this->eventOfType('unknown_msg');
        self::assertNotNull($unknown);
        self::assertStringContainsString('82', $unknown['path']);
        self::assertTrue($session->close);
    }

    public function test_accept_captures_real_peer_from_accept_not_a_collapsed_source(): void
    {
        $this->events = [];
        $config = new VncConfig(style: 'realistic', width: 400, height: 300);
        $server = new VncServer($config, function (array $e): void {
            $this->events[] = $e;
        });

        $listen = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($listen, "listen: {$errstr} ({$errno})");
        $listenAddr = (string) stream_socket_get_name($listen, false);
        $client = @stream_socket_client('tcp://' . $listenAddr, $errno, $errstr, 1);
        self::assertIsResource($client, "client: {$errstr} ({$errno})");

        $clientAddr = (string) stream_socket_get_name($client, false);
        $clientPort = (int) substr($clientAddr, strrpos($clientAddr, ':') + 1);

        $accept = new \ReflectionMethod($server, 'accept');
        $accept->setAccessible(true);

        // Drive the accept until the connection lands (loopback connect is prompt, but retry to be safe).
        $conns = [];
        $perIp = [];
        for ($i = 0; $i < 100 && $this->eventOfType('connect') === null; $i++) {
            $args = [$listen, &$conns, &$perIp, 5900, time()];
            $accept->invokeArgs($server, $args);
            if ($this->eventOfType('connect') === null) {
                usleep(1000);
            }
        }

        $connect = $this->eventOfType('connect');
        self::assertNotNull($connect, 'accept must log a connect event');
        self::assertSame('127.0.0.1', $connect['ip']);
        // The accept-time peer carries the real ephemeral client port — not a collapsed 0/placeholder.
        self::assertGreaterThan(0, $clientPort);
        self::assertStringContainsString("127.0.0.1:{$clientPort}", $connect['path']);
        // Every VNC event carries a UTC ISO-8601 timestamp for the dashboard.
        self::assertArrayHasKey('ts', $connect);

        foreach ($conns as $c) {
            @fclose($c['sock']);
        }
        @fclose($client);
        @fclose($listen);
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
