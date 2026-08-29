<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Kerberos;

use Funnypot\Protocol\Kerberos\KerberosConfig;
use Funnypot\Protocol\Kerberos\KerberosServer;
use Funnypot\Protocol\Kerberos\KerberosSession;
use PHPUnit\Framework\TestCase;

final class KerberosReconLoggingTest extends TestCase
{
    use KerberosTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:KerberosServer,1:KerberosSession}
     */
    private function serverSession(?KerberosConfig $config = null): array
    {
        $this->events = [];
        $server = new KerberosServer($config ?? new KerberosConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new KerberosSession('198.51.100.7', 88, 1);

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

    public function test_every_event_carries_the_kerberos_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('kerberos', $e['proto']);
            self::assertSame('KERBEROS', $e['method']);
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

    public function test_known_principal_is_captured_at_high_severity(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $asreq = $this->eventOfType('krb_asreq');
        self::assertNotNull($asreq);
        self::assertSame('high', $asreq['severity']);
    }

    public function test_unknown_principal_is_medium_severity(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['nobody-here'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $asreq = $this->eventOfType('krb_asreq');
        self::assertNotNull($asreq);
        self::assertSame('medium', $asreq['severity']);
    }

    public function test_non_as_req_message_logs_unknown_and_closes(): void
    {
        // A TGS-REQ ([APPLICATION 12] = 0x6C) is not modelled here: record the probe and close.
        [$server, $session] = $this->serverSession();

        $tgsReq = "\x6c\x03\x02\x01\x05"; // application 12 wrapping something small
        $session->inbuf = self::framed($tgsReq);
        $server->processInbound($session);

        $unknown = $this->eventOfType('krb_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('application tag 0x6C', $unknown['path']);
        self::assertTrue($session->close);
        self::assertSame('', $session->outbuf, 'no reply to a non-AS-REQ message');
    }

    public function test_unparseable_as_req_logs_unknown_and_closes(): void
    {
        [$server, $session] = $this->serverSession();

        // Correct application tag but garbage body.
        $session->inbuf = self::framed("\x6a\x05not-der");
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('krb_unknown'));
        self::assertTrue($session->close);
    }

    public function test_partial_message_is_buffered_until_complete(): void
    {
        [$server, $session] = $this->serverSession();

        $full = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));

        // Deliver the length prefix and a fragment first: nothing should be parsed yet.
        $session->inbuf = substr($full, 0, 8);
        $server->processInbound($session);
        self::assertNull($session->cname);
        self::assertNull($this->eventOfType('krb_asreq'));

        // Deliver the remainder: the request now parses.
        $session->inbuf .= substr($full, 8);
        $server->processInbound($session);
        self::assertSame('administrator', $session->cname);
    }

    public function test_two_pipelined_requests_are_both_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']))
            . self::framed(self::asReq('CORP.LOCAL', ['guest'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $asreqs = array_filter($this->events, static fn (array $e): bool => ($e['event'] ?? '') === 'krb_asreq');
        self::assertCount(2, $asreqs, 'both pipelined AS-REQs are captured');
        // The session reflects the last request; two framed KRB-ERRORs are queued.
        self::assertSame('guest', $session->cname);
    }

    public function test_oversize_length_prefix_is_rejected(): void
    {
        [$server, $session] = $this->serverSession();

        // A length prefix beyond the modelled cap (and with the reserved top bit set) is refused.
        $session->inbuf = "\xFF\xFF\xFF\xFF" . str_repeat("\x00", 16);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('krb_unknown'));
        self::assertTrue($session->close);
        self::assertSame('', $session->outbuf);
    }

    public function test_config_from_env_reads_realm_and_known_principals(): void
    {
        putenv('FUNNYPOT_KERBEROS_REALM=HONEYNET.LAN');
        putenv('FUNNYPOT_KERBEROS_KNOWN_PRINCIPALS=svc-web, dbadmin ,Root');

        $config = KerberosConfig::fromEnv();
        self::assertSame('HONEYNET.LAN', $config->realm);
        self::assertTrue($config->isKnownPrincipal('svc-web'));
        self::assertTrue($config->isKnownPrincipal('dbadmin'), 'whitespace around names is trimmed');
        self::assertTrue($config->isKnownPrincipal('root'), 'membership is case-insensitive');
        self::assertFalse($config->isKnownPrincipal('administrator'), 'the default set is replaced');

        putenv('FUNNYPOT_KERBEROS_REALM');
        putenv('FUNNYPOT_KERBEROS_KNOWN_PRINCIPALS');
    }

    public function test_default_config_models_common_accounts(): void
    {
        $config = new KerberosConfig();
        self::assertSame('CORP.LOCAL', $config->realm);
        self::assertTrue($config->isKnownPrincipal('Administrator'));
        self::assertTrue($config->isKnownPrincipal('krbtgt'));
        self::assertFalse($config->isKnownPrincipal('random-scan-name'));
    }
}
