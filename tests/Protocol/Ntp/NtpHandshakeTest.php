<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ntp;

use Funnypot\Protocol\Ntp\NtpConfig;
use Funnypot\Protocol\Ntp\NtpServer;
use Funnypot\Protocol\Ntp\NtpSession;
use PHPUnit\Framework\TestCase;

final class NtpHandshakeTest extends TestCase
{
    use NtpTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:NtpServer,1:NtpSession}
     */
    private function serverSession(?NtpConfig $config = null): array
    {
        $this->events = [];
        $server = new NtpServer($config ?? new NtpConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new NtpSession('192.0.2.10', 43210, 1);

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

    public function test_client_request_gets_a_mode4_server_response(): void
    {
        [$server, $session] = $this->serverSession(new NtpConfig(stratum: 2, refid: '17.253.66.253'));

        $session->inbuf = self::clientRequest(4, 0xE4000000, 0x80000000, 6);
        $server->processInbound($session);

        self::assertSame(3, $session->mode, 'client mode captured');
        self::assertSame(4, $session->version);

        $resp = $session->outbuf;
        self::assertSame(NtpServer::NTP_PACKET_SIZE, strlen($resp), 'a full 48-byte reply');

        // Leading byte: LI=0, VN echoed (4), Mode=4 (server).
        $b0 = ord($resp[0]);
        self::assertSame(0, ($b0 >> 6) & 0x03, 'leap indicator 0');
        self::assertSame(4, ($b0 >> 3) & 0x07, 'version echoed');
        self::assertSame(4, $b0 & 0x07, 'mode 4 server');

        // Stratum 2, and the refid encodes the configured upstream IPv4.
        self::assertSame(2, ord($resp[1]), 'stratum from config');
        self::assertSame(inet_pton('17.253.66.253'), substr($resp, 12, 4), 'refid is the upstream IPv4');
    }

    public function test_originate_echoes_the_client_transmit_timestamp(): void
    {
        [$server, $session] = $this->serverSession();

        $txSecs = 0xE4123456;
        $txFrac = 0xABCD0000;
        $session->inbuf = self::clientRequest(4, $txSecs, $txFrac);
        $server->processInbound($session);

        $resp = $session->outbuf;
        // Originate timestamp (t1) sits at bytes 24-31 and must equal the client's transmit (t3).
        self::assertSame($txSecs, self::be32At($resp, 24), 'originate seconds echo client transmit');
        self::assertSame($txFrac, self::be32At($resp, 28), 'originate fraction echo client transmit');
    }

    public function test_receive_and_transmit_trail_originate(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::clientRequest(4, 0xE4000000, 0x00000000);
        $server->processInbound($session);
        $resp = $session->outbuf;

        $origSecs = self::be32At($resp, 24);
        $rxFrac = self::be32At($resp, 36);
        $txFrac = self::be32At($resp, 44);

        // With a zero originate fraction, receive and transmit advance by fixed positive deltas and
        // stay within the same second — a believable tiny service delay.
        self::assertSame($origSecs, self::be32At($resp, 32), 'receive same second');
        self::assertSame($origSecs, self::be32At($resp, 40), 'transmit same second');
        self::assertGreaterThan(0, $rxFrac, 'receive fraction advanced past originate');
        self::assertGreaterThan($rxFrac, $txFrac, 'transmit fraction advanced past receive');
    }

    public function test_reference_timestamp_precedes_originate(): void
    {
        [$server, $session] = $this->serverSession(new NtpConfig(referenceAgeSeconds: 1024));

        $txSecs = 0xE4000000;
        $session->inbuf = self::clientRequest(4, $txSecs, 0);
        $server->processInbound($session);
        $resp = $session->outbuf;

        // Reference timestamp (bytes 16-23) is a plausible interval before originate.
        self::assertSame($txSecs - 1024, self::be32At($resp, 16), 'reference is one poll interval earlier');
    }

    public function test_response_is_deterministic_no_wallclock(): void
    {
        // The same request must always produce identical bytes — proof the builder reads no clock.
        $req = self::clientRequest(4, 0xE4555555, 0x12340000, 8);

        [$serverA, $sessA] = $this->serverSession();
        $sessA->inbuf = $req;
        $serverA->processInbound($sessA);

        [$serverB, $sessB] = $this->serverSession();
        $sessB->inbuf = $req;
        $serverB->processInbound($sessB);

        self::assertSame(bin2hex($sessA->outbuf), bin2hex($sessB->outbuf), 'byte-identical across runs');
        self::assertNotSame('', $sessA->outbuf);
    }

    public function test_zero_transmit_timestamp_falls_back_to_seeded_base(): void
    {
        $config = new NtpConfig(baseNtpSeconds: 3997000000);
        [$server, $session] = $this->serverSession($config);

        $session->inbuf = self::clientRequest(4, 0, 0);
        $server->processInbound($session);
        $resp = $session->outbuf;

        self::assertSame(NtpServer::NTP_PACKET_SIZE, strlen($resp));
        // With no client time, originate uses the fixed seeded base, not zero and not a live clock.
        self::assertSame(3997000000, self::be32At($resp, 24), 'originate falls back to the seeded base');
    }

    public function test_stratum_and_ascii_refid_for_low_stratum(): void
    {
        // Stratum 1 uses an ASCII clock-source code in the refid, not an IPv4 address.
        $config = new NtpConfig(stratum: 1, refid: 'GPS');
        [$server, $session] = $this->serverSession($config);

        $session->inbuf = self::clientRequest(4, 0xE4000000, 0);
        $server->processInbound($session);
        $resp = $session->outbuf;

        self::assertSame(1, ord($resp[1]), 'stratum 1');
        self::assertSame("GPS\x00", substr($resp, 12, 4), 'ASCII refid null-padded to 4 bytes');
    }

    public function test_reply_never_exceeds_request_no_amplification(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::clientRequest(4, 0xE4000000, 0);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'a valid client request is still answered');
        self::assertLessThanOrEqual(
            strlen($req),
            strlen($session->outbuf),
            'anti-amplification: the reply is never larger than the request'
        );
    }

    public function test_encode_refid_variants(): void
    {
        self::assertSame(inet_pton('129.6.15.28'), NtpServer::encodeRefid('129.6.15.28', 2));
        self::assertSame("PPS\x00", NtpServer::encodeRefid('PPS', 1));
        // Not an IPv4 at stratum 2: treated as ASCII, truncated to 4 bytes.
        self::assertSame('LOCL', NtpServer::encodeRefid('LOCL', 2));
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_NTP_STRATUM=3');
        putenv('FUNNYPOT_NTP_REFID=129.6.15.28');
        putenv('FUNNYPOT_NTP_POLL=7');

        $config = NtpConfig::fromEnv();
        self::assertSame(3, $config->stratum);
        self::assertSame('129.6.15.28', $config->refid);
        self::assertSame(7, $config->poll);

        putenv('FUNNYPOT_NTP_STRATUM');
        putenv('FUNNYPOT_NTP_REFID');
        putenv('FUNNYPOT_NTP_POLL');
    }
}
