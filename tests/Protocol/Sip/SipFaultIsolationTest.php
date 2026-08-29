<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\RtpStreamer;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Sip\SipSession;
use PHPUnit\Framework\TestCase;

/**
 * The SIP listener runs unsupervised, so a fault handling one message/session must degrade — logged
 * and skipped — never escape the run loop and kill the process (the invariant: degrade, never crash).
 */
final class SipFaultIsolationTest extends TestCase
{
    public function test_runonce_survives_a_throwing_component_and_logs_it(): void
    {
        $logged = [];
        $throwingRtp = new class () extends RtpStreamer {
            public function getSocket()
            {
                throw new \RuntimeException('select boom');
            }
        };
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        }, $throwingRtp);

        // Must NOT throw — the loop has to survive a component blowing up.
        $server->runOnce();

        $errors = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'error'));
        $this->assertNotEmpty($errors, 'the fault must be logged, not silently swallowed');
        $this->assertStringContainsString('select boom', $errors[0]['path']);
    }

    public function test_a_throwing_rtp_send_evicts_the_session_instead_of_looping(): void
    {
        $logged = [];
        $throwingRtp = new class () extends RtpStreamer {
            public function sendPacket(SipSession $s, string $audioPayload): bool
            {
                throw new \RuntimeException('rtp boom');
            }
        };
        $server = new SipServer(new SipConfig(recordCalls: true, rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        }, $throwingRtp);

        // INVITE + valid ACK (echoing our To-tag) -> streaming session.
        $inv = SipMessage::parse(
            "INVITE sip:100@t SIP/2.0\r\nCall-ID: boom-1\r\nCSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\nContent-Length: 30\r\n\r\nv=0\r\nm=audio 4000 RTP/AVP 0\r\n"
        );
        $server->dispatchMessage($inv, '9.9.9.9', 5060, 'udp');
        $tag = $server->dialogToTag('boom-1', '9.9.9.9');
        $ack = SipMessage::parse("ACK sip:100@t SIP/2.0\r\nCall-ID: boom-1\r\nTo: <sip:100@t>;tag={$tag}\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($ack, '9.9.9.9', 5060, 'udp');
        $this->assertSame(1, $server->getActiveSessionCount());

        // Let 20ms elapse so the tick tries to send — where sendPacket throws.
        usleep(25000);
        $server->tickRtpStreams(); // must not throw

        $this->assertSame(0, $server->getActiveSessionCount(), 'a session whose RTP send faults must be evicted, not retried');
        $errors = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'error'));
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('rtp boom', end($errors)['path']);
    }
}
