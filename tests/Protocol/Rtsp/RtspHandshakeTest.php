<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Rtsp;

use Funnypot\Protocol\Rtsp\RtspConfig;
use Funnypot\Protocol\Rtsp\RtspServer;
use Funnypot\Protocol\Rtsp\RtspSession;
use PHPUnit\Framework\TestCase;

final class RtspHandshakeTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?RtspConfig $config = null): RtspServer
    {
        $this->events = [];

        return new RtspServer($config ?? new RtspConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    /** Builds a CRLF-framed RTSP request with a trailing blank line. */
    private static function request(string $method, string $uri, array $headers = [], string $body = ''): string
    {
        $lines = ["{$method} {$uri} RTSP/1.0"];
        foreach ($headers as $k => $v) {
            $lines[] = "{$k}: {$v}";
        }
        if ($body !== '') {
            $lines[] = 'Content-Length: ' . strlen($body);
        }

        return implode("\r\n", $lines) . "\r\n\r\n" . $body;
    }

    public function test_options_replies_200_with_public_methods(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('OPTIONS', 'rtsp://10.0.0.1:554/', [
            'CSeq' => '1',
            'User-Agent' => 'LibVLC/3.0.0',
        ]);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertStringContainsString('CSeq: 1', $session->outbuf);
        self::assertStringContainsString('Public: OPTIONS, DESCRIBE, SETUP, PLAY', $session->outbuf);
        self::assertNotNull($this->eventOfType('rtsp_options'));
    }

    public function test_describe_without_auth_challenges_401(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('DESCRIBE', 'rtsp://10.0.0.1/Streaming/Channels/101', [
            'CSeq' => '2',
            'Accept' => 'application/sdp',
        ]);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 401 Unauthorized', $session->outbuf);
        self::assertStringContainsString('WWW-Authenticate: Digest realm="IP Camera"', $session->outbuf);
        self::assertStringContainsString('nonce=', $session->outbuf);

        // The requested stream path (the camera-model fingerprint) is captured on the challenge.
        $describe = $this->eventOfType('rtsp_describe');
        self::assertNotNull($describe);
        self::assertSame('/Streaming/Channels/101', $describe['stream_path']);
    }

    public function test_describe_with_basic_auth_captures_credential_and_returns_sdp(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('DESCRIBE', 'rtsp://10.0.0.1/cam/realmonitor?channel=1', [
            'CSeq' => '3',
            'Authorization' => 'Basic ' . base64_encode('admin:12345'),
            'User-Agent' => 'Mozilla/5.0',
        ]);
        $server->processInbound($session);

        // The authed retry gets a believable SDP describing an H.264 track — but no media is streamed.
        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertStringContainsString('Content-Type: application/sdp', $session->outbuf);
        self::assertStringContainsString('m=video 0 RTP/AVP 96', $session->outbuf);
        self::assertStringContainsString('a=rtpmap:96 H264/90000', $session->outbuf);

        $auth = $this->eventOfType('rtsp_auth');
        self::assertNotNull($auth);
        self::assertSame('critical', $auth['severity']);
        self::assertSame('admin', $auth['username']);
        self::assertSame('12345', $auth['password']);
        self::assertStringContainsString('scheme=basic', $auth['body']);
        self::assertSame('/cam/realmonitor?channel=1', $auth['stream_path']);
    }

    public function test_describe_with_digest_auth_captures_response_material(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('198.51.100.9', 44444, 1);
        $digest = 'Digest username="root", realm="IP Camera", '
            . 'nonce="abc123", uri="rtsp://10.0.0.1/h264", response="deadbeefcafef00ddeadbeefcafef00d"';
        $session->inbuf .= self::request('DESCRIBE', 'rtsp://10.0.0.1/h264', [
            'CSeq' => '4',
            'Authorization' => $digest,
        ]);
        $server->processInbound($session);

        $auth = $this->eventOfType('rtsp_auth');
        self::assertNotNull($auth);
        self::assertSame('root', $auth['username']);
        self::assertStringContainsString('scheme=digest', $auth['body']);
        self::assertStringContainsString('response=deadbeefcafef00ddeadbeefcafef00d', $auth['body']);
        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
    }

    public function test_describe_returns_sdp_directly_when_auth_disabled(): void
    {
        $server = $this->newServer(new RtspConfig(requireAuth: false));
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('DESCRIBE', 'rtsp://10.0.0.1/live.sdp', ['CSeq' => '2']);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertStringContainsString('application/sdp', $session->outbuf);
    }

    public function test_setup_and_play_reply_plausibly_and_stream_nothing(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);

        $session->inbuf .= self::request('SETUP', 'rtsp://10.0.0.1/h264/trackID=1', [
            'CSeq' => '5',
            'Transport' => 'RTP/AVP;unicast;client_port=8000-8001',
        ]);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertStringContainsString('Session: ', $session->outbuf);
        self::assertStringContainsString('client_port=8000-8001', $session->outbuf);
        self::assertStringContainsString('server_port=', $session->outbuf);
        self::assertNotNull($session->rtspSessionId);

        $session->outbuf = '';
        $session->inbuf .= self::request('PLAY', 'rtsp://10.0.0.1/h264', [
            'CSeq' => '6',
            'Session' => $session->rtspSessionId,
            'Range' => 'npt=0.000-',
        ]);
        $server->processInbound($session);

        // A plausible PLAY response, but the honeypot never emits an RTP packet on any transport.
        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertStringContainsString('RTP-Info: ', $session->outbuf);
    }

    public function test_teardown_replies_then_marks_close(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('TEARDOWN', 'rtsp://10.0.0.1/h264', ['CSeq' => '9']);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertTrue($session->close);
    }

    public function test_unknown_method_replies_501_and_logs_unknown(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::request('FROBNICATE', 'rtsp://10.0.0.1/', ['CSeq' => '1']);
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 501 Not Implemented', $session->outbuf);
        self::assertNotNull($this->eventOfType('rtsp_unknown'));
    }

    public function test_malformed_request_line_closes_cleanly(): void
    {
        // Not an RTSP request line (e.g. an HTTP probe) — log, answer 400, close, never crash.
        $server = $this->newServer();
        $session = new RtspSession('192.0.2.1', 5000, 1);
        $session->inbuf .= "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        $server->processInbound($session);

        self::assertStringStartsWith('RTSP/1.0 400 Bad Request', $session->outbuf);
        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('rtsp_unknown'));
    }

    public function test_interleaved_binary_frame_is_dropped(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('192.0.2.2', 5001, 1);
        $session->inbuf .= "\x24\x00\x00\x10" . str_repeat("\xAB", 16);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('rtsp_unknown'));
    }

    public function test_partial_request_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('192.0.2.3', 5002, 1);

        $full = self::request('OPTIONS', 'rtsp://10.0.0.1/', ['CSeq' => '1']);
        // Feed everything except the final blank line: nothing parsed yet.
        $session->inbuf .= substr($full, 0, -2);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);
        self::assertSame([], $this->eventsOfType('rtsp_options'));

        // Deliver the remainder: the request now completes.
        $session->inbuf .= substr($full, -2);
        $server->processInbound($session);
        self::assertStringStartsWith('RTSP/1.0 200 OK', $session->outbuf);
        self::assertNotNull($this->eventOfType('rtsp_options'));
    }

    public function test_pipelined_requests_are_all_processed(): void
    {
        $server = $this->newServer();
        $session = new RtspSession('192.0.2.4', 5003, 1);
        $session->inbuf .= self::request('OPTIONS', 'rtsp://10.0.0.1/', ['CSeq' => '1'])
            . self::request('DESCRIBE', 'rtsp://10.0.0.1/live', ['CSeq' => '2']);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('rtsp_options'));
        self::assertNotNull($this->eventOfType('rtsp_describe'));
        // Two responses queued back to back.
        self::assertSame(2, substr_count($session->outbuf, 'RTSP/1.0 '));
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

    /**
     * @return array<int,array<string,mixed>>
     */
    private function eventsOfType(string $type): array
    {
        return array_values(array_filter($this->events, static fn ($e) => ($e['event'] ?? '') === $type));
    }
}
