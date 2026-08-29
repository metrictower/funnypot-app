<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Rtsp;

use Funnypot\Protocol\Rtsp\RtspConfig;
use Funnypot\Protocol\Rtsp\RtspServer;
use Funnypot\Protocol\Rtsp\RtspSession;
use PHPUnit\Framework\TestCase;

final class RtspReconLoggingTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private static function request(string $method, string $uri, array $headers = []): string
    {
        $lines = ["{$method} {$uri} RTSP/1.0"];
        foreach ($headers as $k => $v) {
            $lines[] = "{$k}: {$v}";
        }

        return implode("\r\n", $lines) . "\r\n\r\n";
    }

    /**
     * @return array{0:RtspServer,1:RtspSession}
     */
    private function driven(string $raw, ?RtspConfig $config = null): array
    {
        $this->events = [];
        $server = new RtspServer($config ?? new RtspConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new RtspSession('198.51.100.20', 554, 1);
        $session->inbuf .= $raw;
        $server->processInbound($session);

        return [$server, $session];
    }

    public function test_every_event_carries_the_rtsp_envelope(): void
    {
        $this->driven(self::request('OPTIONS', 'rtsp://10.0.0.1/', ['CSeq' => '1']));

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('rtsp', $e['proto']);
            self::assertSame('RTSP', $e['method']);
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

    public function test_describe_captures_stream_path_and_user_agent(): void
    {
        [, $session] = $this->driven(self::request('DESCRIBE', 'rtsp://cam.local:554/onvif1', [
            'CSeq' => '2',
            'User-Agent' => 'Nmap NSE',
        ]));

        $describe = $this->eventOfType('rtsp_describe');
        self::assertNotNull($describe);
        self::assertSame('/onvif1', $describe['stream_path']);
        self::assertSame('Nmap NSE', $describe['user_agent']);
        self::assertSame('/onvif1', $session->streamPath);
        self::assertSame('Nmap NSE', $session->userAgent);
    }

    public function test_credential_capture_is_critical_severity(): void
    {
        $this->driven(self::request('DESCRIBE', 'rtsp://10.0.0.1/h264', [
            'CSeq' => '3',
            'Authorization' => 'Basic ' . base64_encode('operator:secret-pass'),
        ]));

        $auth = $this->eventOfType('rtsp_auth');
        self::assertNotNull($auth);
        self::assertSame('critical', $auth['severity']);
        self::assertSame('operator', $auth['username']);
        self::assertSame('secret-pass', $auth['password']);
    }

    public function test_control_bytes_in_captured_fields_are_sanitised(): void
    {
        // Attacker-supplied bytes must be neutralised before they reach the log.
        $raw = "DESCRIBE rtsp://10.0.0.1/a\x00\x1bb RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: e\x07vil\r\n\r\n";
        $this->driven($raw);

        $describe = $this->eventOfType('rtsp_describe');
        self::assertNotNull($describe);
        self::assertStringNotContainsString("\x00", (string) $describe['stream_path']);
        self::assertStringNotContainsString("\x1b", (string) $describe['stream_path']);
        self::assertStringNotContainsString("\x07", (string) $describe['user_agent']);
    }

    public function test_parse_request_extracts_method_uri_and_headers(): void
    {
        $req = RtspServer::parseRequest(self::request('SETUP', 'rtsp://h/x/trackID=1', [
            'CSeq' => '7',
            'Transport' => 'RTP/AVP;unicast;client_port=9000-9001',
        ]));

        self::assertNotNull($req);
        self::assertSame('SETUP', $req['method']);
        self::assertSame('rtsp://h/x/trackID=1', $req['uri']);
        self::assertSame('/x/trackID=1', $req['path']);
        self::assertSame(7, $req['cseq']);
        self::assertSame('RTP/AVP;unicast;client_port=9000-9001', $req['headers']['transport']);
    }

    public function test_parse_request_rejects_non_rtsp(): void
    {
        self::assertNull(RtspServer::parseRequest("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        self::assertNull(RtspServer::parseRequest("garbage\r\n\r\n"));
        self::assertNull(RtspServer::parseRequest(''));
    }

    public function test_path_from_uri_variants(): void
    {
        self::assertSame('/Streaming/Channels/101', RtspServer::pathFromUri('rtsp://10.0.0.1:554/Streaming/Channels/101'));
        self::assertSame('/', RtspServer::pathFromUri('rtsp://10.0.0.1'));
        self::assertSame('*', RtspServer::pathFromUri('*'));
        self::assertSame('/cam?x=1', RtspServer::pathFromUri('rtsps://host/cam?x=1'));
        self::assertSame('/relative/path', RtspServer::pathFromUri('/relative/path'));
    }

    public function test_parse_authorization_basic_and_digest(): void
    {
        $basic = RtspServer::parseAuthorization('Basic ' . base64_encode('admin:admin'));
        self::assertSame('basic', $basic['scheme']);
        self::assertSame('admin', $basic['username']);
        self::assertSame('admin', $basic['password']);

        $digest = RtspServer::parseAuthorization('Digest username="svc", realm="IP Camera", nonce="n", response="rrr"');
        self::assertSame('digest', $digest['scheme']);
        self::assertSame('svc', $digest['username']);
        self::assertSame('n', $digest['nonce']);
        self::assertSame('rrr', $digest['response']);
    }

    public function test_parse_authorization_handles_password_with_colon(): void
    {
        $basic = RtspServer::parseAuthorization('Basic ' . base64_encode('user:pa:ss:word'));
        self::assertSame('user', $basic['username']);
        self::assertSame('pa:ss:word', $basic['password']);
    }

    public function test_config_from_env_reads_knobs(): void
    {
        putenv('FUNNYPOT_RTSP_SERVER=H264DVR');
        putenv('FUNNYPOT_RTSP_REALM=Test Realm');
        putenv('FUNNYPOT_RTSP_AUTH=both');
        putenv('FUNNYPOT_RTSP_REQUIRE_AUTH=0');

        $config = RtspConfig::fromEnv();
        self::assertSame('H264DVR', $config->serverName);
        self::assertSame('Test Realm', $config->realm);
        self::assertSame(RtspConfig::AUTH_BOTH, $config->authScheme);
        self::assertFalse($config->requireAuth);

        putenv('FUNNYPOT_RTSP_SERVER');
        putenv('FUNNYPOT_RTSP_REALM');
        putenv('FUNNYPOT_RTSP_AUTH');
        putenv('FUNNYPOT_RTSP_REQUIRE_AUTH');

        $default = RtspConfig::fromEnv();
        self::assertSame('Rtsp Server', $default->serverName);
        self::assertSame(RtspConfig::AUTH_DIGEST, $default->authScheme);
        self::assertTrue($default->requireAuth);
    }

    public function test_both_scheme_challenge_offers_basic_and_digest(): void
    {
        [, $session] = $this->driven(
            self::request('DESCRIBE', 'rtsp://10.0.0.1/h264', ['CSeq' => '2']),
            new RtspConfig(authScheme: RtspConfig::AUTH_BOTH)
        );

        self::assertStringContainsString('WWW-Authenticate: Basic realm="IP Camera"', $session->outbuf);
        self::assertStringContainsString('WWW-Authenticate: Digest realm="IP Camera"', $session->outbuf);
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
