<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Sip\SipSession;
use PHPUnit\Framework\TestCase;

/**
 * FP-0248 §2b — the SIP cumulative UDP egress byte-budget invariant: bytes_out <= udpEgressRatio *
 * bytes_in per apparent source (k=3 by default), colocated with the F4 packet-rate bucket. This is
 * SIP's answer to "never emit a response that enables reflection DDoS" — a strict per-packet amp<=1
 * (the other 6 UDP listeners) is impossible for SIP, since a real PBX's 400/401/200 is legitimately
 * larger than a tiny request.
 */
final class SipEgressBudgetTest extends TestCase
{
    private const RATIO = 3.0;

    // ---- helpers --------------------------------------------------------------------------------

    private function boundServer(?SipConfig $config = null): SipServer
    {
        $server = new SipServer($config ?? new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
        $server->bind();

        return $server;
    }

    private function creditOf(SipServer $server, string $ip): float
    {
        $buckets = new \ReflectionProperty($server, 'udpResponseBuckets');
        $buckets->setAccessible(true);
        $map = $buckets->getValue($server);

        return (float) ($map[$ip]['credit'] ?? 0.0);
    }

    private function tokensOf(SipServer $server, string $ip): ?float
    {
        $buckets = new \ReflectionProperty($server, 'udpResponseBuckets');
        $buckets->setAccessible(true);
        $map = $buckets->getValue($server);

        return isset($map[$ip]['tokens']) ? (float) $map[$ip]['tokens'] : null;
    }

    /** Fully replenishes $ip's F4 packet-rate bucket so a test can isolate the byte-budget guard. */
    private function primeF4Full(SipServer $server, string $ip): void
    {
        $ensure = new \ReflectionMethod($server, 'udpResponseBucketEnsure');
        $ensure->setAccessible(true);
        $ensure->invoke($server, $ip, microtime(true));

        $buckets = new \ReflectionProperty($server, 'udpResponseBuckets');
        $buckets->setAccessible(true);
        $map = $buckets->getValue($server);
        $map[$ip]['tokens'] = 20.0; // UDP_RESP_BURST
        $map[$ip]['last'] = microtime(true);
        $buckets->setValue($server, $map);
    }

    /** Backdates $ip's F4 bucket 'last' timestamp by $seconds, simulating elapsed real time for refill —
     *  the same technique SipEnumerationTest uses on $s->answerAt, applied to the bucket map instead. */
    private function ageF4(SipServer $server, string $ip, float $seconds): void
    {
        $buckets = new \ReflectionProperty($server, 'udpResponseBuckets');
        $buckets->setAccessible(true);
        $map = $buckets->getValue($server);
        if (isset($map[$ip])) {
            $map[$ip]['last'] -= $seconds;
            $buckets->setValue($server, $map);
        }
    }

    private function invokeSendResponse(SipServer $server, string $raw, string $ip, int $port = 5060, string $transport = 'udp', $tcpSock = null): void
    {
        $m = new \ReflectionMethod($server, 'sendResponse');
        $m->setAccessible(true);
        $m->invoke($server, $raw, $ip, $port, $transport, $tcpSock);
    }

    private function invokeCreditIngress(SipServer $server, string $ip, int $len): void
    {
        $m = new \ReflectionMethod($server, 'creditUdpIngress');
        $m->setAccessible(true);
        $m->invoke($server, $ip, $len);
    }

    /**
     * Sends one raw UDP datagram to $server's bound socket and drives handleInboundUdp() to process
     * it, returning whatever (if anything) $client received back — the genuine on-the-wire response,
     * including addViaReceived() growth. A short bounded poll absorbs loopback scheduling jitter (the
     * same pattern SipEnumerationTest::roundTrip() uses for its real select-loop round trip).
     */
    private function udpRoundTrip(SipServer $server, $client, string $raw): string
    {
        fwrite($client, $raw);

        $handle = new \ReflectionMethod($server, 'handleInboundUdp');
        $handle->setAccessible(true);

        $resp = '';
        for ($i = 0; $i < 50; $i++) {
            $handle->invoke($server);
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp = $got;
                break;
            }
            usleep(500);
        }

        return $resp;
    }

    private function loopbackClientFor(SipServer $server)
    {
        $ref = new \ReflectionProperty($server, 'udpSocket');
        $ref->setAccessible(true);
        $sock = $ref->getValue($server);
        $addr = stream_socket_get_name($sock, false);

        $client = stream_socket_client('udp://' . $addr, $errno, $errstr, 1);
        $this->assertIsResource($client, "client socket: {$errstr} ({$errno})");
        stream_set_blocking($client, false);

        return $client;
    }

    private function realisticInviteWithSdp(string $callId, string $fromIp, int $fromPort = 5060): string
    {
        $sdp = "v=0\r\no=- 1 1 IN IP4 {$fromIp}\r\ns=-\r\nc=IN IP4 {$fromIp}\r\nt=0 0\r\n"
            . "m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n";

        return "INVITE sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP {$fromIp}:{$fromPort};branch=z9hG4bK-{$callId}\r\n"
            . "Max-Forwards: 70\r\n"
            . "From: <sip:caller@{$fromIp}>;tag=from-{$callId}\r\n"
            . "To: <sip:100@target>\r\n"
            . "Call-ID: {$callId}\r\n"
            . "CSeq: 1 INVITE\r\n"
            . "Contact: <sip:caller@{$fromIp}:{$fromPort}>\r\n"
            . "User-Agent: Grandstream GXP2170\r\n"
            . "Content-Type: application/sdp\r\n"
            . "Content-Length: " . strlen($sdp) . "\r\n\r\n"
            . $sdp;
    }

    // ---- §4b: the cumulative ratio invariant ----------------------------------------------------

    /**
     * Drives the REAL sendResponse()/creditUdpIngress() code path (not a reimplementation) through many
     * ingress/egress cycles of varying size — including deliberately oversized responses that must be
     * refused — from one apparent source, asserting sum(bytes_out) <= RATIO * sum(bytes_in) holds after
     * EVERY step, never just at the end. The F4 packet-rate bucket is kept fully primed each iteration
     * so this isolates the byte-budget guard specifically (F4 itself is covered by
     * UdpReflectionInvariantTest::test_lru_cycling_cannot_restore_burst).
     */
    public function test_cumulative_udp_egress_never_exceeds_ratio(): void
    {
        $server = $this->boundServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0, udpEgressRatio: self::RATIO));
        $ip = '198.51.100.44';

        $sumIn = 0;
        $sumOut = 0;

        for ($i = 0; $i < 60; $i++) {
            $reqLen = 80 + ($i % 5) * 20; // 80..160 bytes, varying like real OPTIONS/REGISTER traffic
            $sumIn += $reqLen;
            $this->invokeCreditIngress($server, $ip, $reqLen);
            $this->primeF4Full($server, $ip);

            // Every third response is deliberately oversized (must be refused); the rest are modest.
            $bodyPad = ($i % 3 === 0) ? 1200 : 100;
            $raw = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP {$ip}:5060;branch=z9hG4bK-{$i}\r\nCall-ID: c{$i}\r\n"
                . "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n" . str_repeat('X', $bodyPad) . "\r\n\r\n";

            $before = $this->creditOf($server, $ip);
            $this->invokeSendResponse($server, $raw, $ip);
            $after = $this->creditOf($server, $ip);

            // A granted send debits exactly strlen($raw) (no ;rport in this Via, so addViaReceived is a
            // no-op and the debited amount equals the raw byte count); a refusal changes nothing.
            $sent = max(0.0, $before - $after);
            $sumOut += $sent;

            self::assertLessThanOrEqual(
                self::RATIO * $sumIn + 1e-6,
                $sumOut,
                "cumulative egress ratio invariant violated at step {$i} (sumIn={$sumIn}, sumOut={$sumOut})"
            );
        }

        // The invariant held throughout AND real traffic actually flowed (not every send refused).
        self::assertGreaterThan(0.0, $sumOut, 'at least some legitimate replies must have been sent');
    }

    /**
     * The malformed-400 path (handleInboundUdp() -> SipMessage::build400()), driven end-to-end through
     * the real bound socket: minimal garbage with Via/Call-ID/CSeq repeated from one source cannot
     * extract more than RATIO x its cumulative bytes, using the UNMODIFIED code path (both F4 and F4b
     * compounding exactly as in production).
     */
    public function test_malformed_400_is_metered(): void
    {
        $server = $this->boundServer();
        $client = $this->loopbackClientFor($server);

        $sumIn = 0;
        $sumOut = 0;

        for ($i = 0; $i < 8; $i++) {
            $garbage = "NOT A SIP REQUEST\r\nVia: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-g{$i}\r\n"
                . "Call-ID: garbage-{$i}\r\nCSeq: 1 OPTIONS\r\n\r\n";
            $sumIn += strlen($garbage);

            $resp = $this->udpRoundTrip($server, $client, $garbage);
            $sumOut += strlen($resp);

            self::assertLessThanOrEqual(
                self::RATIO * $sumIn + 1e-6,
                $sumOut,
                "malformed-400 cumulative amplification exceeded the ratio at repeat {$i}"
            );
        }

        fclose($client);
        $server->closeSockets();
    }

    // ---- §4b: legit dialog is not starved ---------------------------------------------------------

    /**
     * An un-ACKed INVITE dialog's total UDP egress (100 Trying + 180 Ringing immediately, then the
     * ONE-SHOT delayed 200 OK once deliverPendingAnswers() fires) stays within budget for a realistic
     * SDP-bearing INVITE. The ring delay is simulated the same way SipEnumerationTest does (backdating
     * answerAt) plus backdating the F4 bucket by the same amount, matching how much real refill time
     * would actually have passed by then.
     */
    public function test_unacked_invite_dialog_within_budget(): void
    {
        $server = $this->boundServer();
        $client = $this->loopbackClientFor($server);
        $ip = '203.0.113.20';

        $invite = $this->realisticInviteWithSdp('dlg-1', $ip);
        $reqLen = strlen($invite);

        $resp1 = $this->udpRoundTrip($server, $client, $invite);
        self::assertStringContainsString('100 Trying', $resp1, 'first immediate response must be 100 Trying');
        $sumOut = strlen($resp1);

        // The second immediate response (180 Ringing) is already queued behind the first; drain it.
        $resp2 = '';
        for ($i = 0; $i < 50; $i++) {
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp2 = $got;
                break;
            }
            usleep(500);
        }
        self::assertStringContainsString('180 Ringing', $resp2, 'the second immediate response must be 180 Ringing (seed=2.0)');
        $sumOut += strlen($resp2);

        self::assertLessThanOrEqual(self::RATIO * $reqLen, $sumOut, '100+180 alone must already fit the budget');

        // Force the ring to have elapsed (SipEnumerationTest's answerAt-nudge pattern) and age the F4
        // bucket by the same amount, so the one-shot delayed 200 OK is checked under realistic refill.
        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);
        $sessions = array_values($sessProp->getValue($server));
        self::assertCount(1, $sessions);
        $s = $sessions[0];
        $s->answerAt = microtime(true) - 0.01;
        // Age the bucket keyed by the REAL loopback socket peer ($s->peerIp), not the Via-header IP —
        // the bucket is always keyed by the actual UDP source address, spoofed Via content is irrelevant.
        $this->ageF4($server, $s->peerIp, 8.0);

        $deliver = new \ReflectionMethod($server, 'deliverPendingAnswers');
        $deliver->setAccessible(true);
        $deliver->invoke($server);

        $resp3 = '';
        for ($i = 0; $i < 50; $i++) {
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp3 = $got;
                break;
            }
            usleep(500);
        }
        self::assertStringContainsString('200 OK', $resp3, 'the one-shot delayed 200 OK must be delivered within budget');
        $sumOut += strlen($resp3);

        self::assertLessThanOrEqual(
            self::RATIO * $reqLen,
            $sumOut,
            'full dialog egress (100+180+200) must stay within k * ingress bytes'
        );

        fclose($client);
        $server->closeSockets();
    }

    /**
     * The named §5 risk, pinned green with a REALISTIC first-contact caller (SDP INVITE, plausible
     * headers — not a stripped-down synthetic frame): 100 Trying AND 180 Ringing both arrive immediately
     * (proving the seed=2.0 fix — a seed of 1.0 would silently drop the 180), the 200 OK arrives after
     * the ring window, and a follow-up BYE still gets its 200 (the dialog is not starved end-to-end).
     */
    public function test_legit_invite_dialog_not_starved(): void
    {
        $server = $this->boundServer();
        $client = $this->loopbackClientFor($server);
        $ip = '203.0.113.21';

        $invite = $this->realisticInviteWithSdp('dlg-2', $ip);
        $resp1 = $this->udpRoundTrip($server, $client, $invite);
        self::assertStringContainsString('100 Trying', $resp1);

        $resp2 = '';
        for ($i = 0; $i < 50; $i++) {
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp2 = $got;
                break;
            }
            usleep(500);
        }
        self::assertStringContainsString('180 Ringing', $resp2, 'seed=2.0 must not starve the second immediate response');

        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);
        $sessions = array_values($sessProp->getValue($server));
        $s = $sessions[0];
        $callId = $s->callId;
        $toTag = $s->toTag;
        $s->answerAt = microtime(true) - 0.01;
        // Age the bucket keyed by the REAL loopback socket peer ($s->peerIp), not the Via-header IP.
        $this->ageF4($server, $s->peerIp, 8.0);

        $deliver = new \ReflectionMethod($server, 'deliverPendingAnswers');
        $deliver->setAccessible(true);
        $deliver->invoke($server);

        $resp3 = '';
        for ($i = 0; $i < 50; $i++) {
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp3 = $got;
                break;
            }
            usleep(500);
        }
        self::assertStringContainsString('200 OK', $resp3, 'the call must be answered, not starved');
        self::assertSame(SipSession::STATE_CONNECTED, $s->state);

        // Follow-up BYE from the same caller still gets its 200 (more ingress bytes bank more credit).
        $this->ageF4($server, $s->peerIp, 2.0);
        $bye = "BYE sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP {$ip}:5060;branch=z9hG4bK-bye\r\n"
            . "Max-Forwards: 70\r\n"
            . "From: <sip:caller@{$ip}>;tag=from-dlg-2\r\n"
            . "To: <sip:100@target>;tag={$toTag}\r\n"
            . "Call-ID: {$callId}\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
        $resp4 = $this->udpRoundTrip($server, $client, $bye);
        self::assertStringContainsString('200 OK', $resp4, 'BYE must still be answered — the dialog is not starved end-to-end');

        fclose($client);
        $server->closeSockets();
    }

    // ---- §4b: credit cap bounds banking ------------------------------------------------------------

    public function test_credit_cap_bounds_banking(): void
    {
        $cap = 1000;
        $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0, udpEgressCreditCap: $cap), null);
        $ip = '198.51.100.55';

        // A drip of small datagrams that would earn far more than the cap if unbounded.
        for ($i = 0; $i < 50; $i++) {
            $this->invokeCreditIngress($server, $ip, 100); // 100 * 3.0 = 300 credit per call
        }

        self::assertSame((float) $cap, $this->creditOf($server, $ip), 'banked credit must stop growing at the configured cap');
    }

    // ---- §2b: check-then-debit ordering burns neither guard on a refusal --------------------------

    public function test_refused_send_burns_neither_guard(): void
    {
        $server = $this->boundServer();

        // (a) Byte budget exhausted, F4 fully primed: a refusal must leave the F4 rate bucket untouched
        // (the byte check runs FIRST and is pure — F4 is never even consulted).
        $ipA = '198.51.100.61';
        $this->invokeCreditIngress($server, $ipA, 10); // credit = 30
        $this->primeF4Full($server, $ipA);
        $tokensBefore = $this->tokensOf($server, $ipA);

        $oversized = "SIP/2.0 400 Bad Request\r\nVia: x\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n"
            . str_repeat('X', 500) . "\r\n\r\n"; // far more than the 30-byte credit
        $this->invokeSendResponse($server, $oversized, $ipA);

        self::assertSame(30.0, $this->creditOf($server, $ipA), 'a byte-budget refusal must not itself change credit');
        self::assertSame($tokensBefore, $this->tokensOf($server, $ipA), 'a byte-budget refusal must leave the F4 token bucket untouched (F4 never consulted)');

        // (b) F4 exhausted, byte budget effectively unlimited: a refusal must leave the byte credit
        // untouched (the byte credit is debited only once BOTH guards have granted, per sendResponse()).
        $ipB = '198.51.100.62';
        $this->invokeCreditIngress($server, $ipB, 1_000_000); // enormous credit — never the limiting factor
        $small = "SIP/2.0 200 OK\r\nVia: x\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

        // First two sends consume the depleted (seed=2.0) F4 bucket; the third must be refused by F4.
        $this->invokeSendResponse($server, $small, $ipB);
        $this->invokeSendResponse($server, $small, $ipB);
        $creditBeforeThird = $this->creditOf($server, $ipB);
        $this->invokeSendResponse($server, $small, $ipB);
        $creditAfterThird = $this->creditOf($server, $ipB);

        self::assertSame($creditBeforeThird, $creditAfterThird, 'an F4-refused send must leave the byte credit untouched');
    }

    // ---- TCP stays unmetered ------------------------------------------------------------------------

    public function test_tcp_responses_unmetered(): void
    {
        $server = new SipServer(new SipConfig(rtpPort: 0), null);

        [$client, $sock] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
        stream_set_blocking($client, false);
        stream_set_blocking($sock, false);

        $id = (int) $sock;
        foreach (['tcpClients' => null, 'tcpBuffers' => '', 'tcpLastActivity' => microtime(true), 'tcpPeers' => '203.0.113.30:41000'] as $prop => $val) {
            $ref = new \ReflectionProperty($server, $prop);
            $ref->setAccessible(true);
            $map = $ref->getValue($server);
            $map[$id] = $val;
            $ref->setValue($server, $map);
        }

        $handle = new \ReflectionMethod($server, 'handleInboundTcp');
        $handle->setAccessible(true);

        // No creditUdpIngress() is ever called for TCP (only handleInboundUdp() calls it), so this
        // source has ZERO UDP egress credit banked — yet a normal-sized TCP OPTIONS reply must still
        // flow every time, proving TCP bypasses the UDP-only F4b guard entirely (structural: sendResponse()
        // returns from the TCP branch before either guard is consulted).
        for ($i = 0; $i < 5; $i++) {
            $raw = "OPTIONS sip:target SIP/2.0\r\n"
                . "Via: SIP/2.0/TCP 203.0.113.30:41000;branch=z9hG4bK-t{$i}\r\n"
                . "Call-ID: tcp-{$i}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
            fwrite($client, $raw);
            $handle->invoke($server, $sock);

            $resp = @fread($client, 65535);
            self::assertNotFalse($resp);
            self::assertStringContainsString('SIP/2.0 200 OK', $resp, "TCP reply {$i} must not be withheld by the UDP-only egress guard");
        }

        self::assertSame(0.0, $this->creditOf($server, '203.0.113.30'), 'TCP traffic must never bank or need UDP egress credit');
    }
}
