<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Kerberos;

use Funnypot\Protocol\Kerberos\KerberosConfig;
use Funnypot\Protocol\Kerberos\KerberosServer;
use Funnypot\Protocol\Kerberos\KerberosSession;
use PHPUnit\Framework\TestCase;

final class KerberosHandshakeTest extends TestCase
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
        $session = new KerberosSession('203.0.113.9', 51000, 1);

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

    public function test_as_req_captures_cname_realm_and_sname(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        self::assertSame('administrator', $session->cname);
        self::assertSame('CORP.LOCAL', $session->realm);
        self::assertSame('krbtgt/CORP.LOCAL', $session->sname);

        $asreq = $this->eventOfType('krb_asreq');
        self::assertNotNull($asreq);
        self::assertStringContainsString('cname=administrator@CORP.LOCAL', $asreq['path']);
        self::assertStringContainsString('krbtgt/CORP.LOCAL', $asreq['path']);
    }

    public function test_parse_as_req_static_extracts_all_fields(): void
    {
        $parsed = KerberosServer::parseAsReq(self::asReq('EXAMPLE.COM', ['jdoe'], ['krbtgt', 'EXAMPLE.COM'], 1, 2));

        self::assertNotNull($parsed);
        self::assertSame(10, $parsed['msgType']);
        self::assertSame('jdoe', $parsed['cname']);
        self::assertSame(['jdoe'], $parsed['cnameParts']);
        self::assertSame(1, $parsed['cnameType']);
        self::assertSame('EXAMPLE.COM', $parsed['realm']);
        self::assertSame('krbtgt/EXAMPLE.COM', $parsed['sname']);
        self::assertSame(['krbtgt', 'EXAMPLE.COM'], $parsed['snameParts']);
        self::assertSame(2, $parsed['snameType']);
    }

    public function test_known_principal_gets_preauth_required(): void
    {
        // "administrator" is a modelled account, so the KDC pretends it exists (preauth-required),
        // baiting the attacker into spraying / roasting it.
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $err = KerberosServer::parseKrbError(substr($session->outbuf, 4));
        self::assertNotNull($err);
        self::assertSame(30, $err['msgType'], 'response is a KRB-ERROR');
        self::assertSame(25, $err['errorCode'], 'KDC_ERR_PREAUTH_REQUIRED for a known account');
    }

    public function test_unknown_principal_gets_principal_unknown(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['zzz-not-a-real-user'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $err = KerberosServer::parseKrbError(substr($session->outbuf, 4));
        self::assertNotNull($err);
        self::assertSame(6, $err['errorCode'], 'KDC_ERR_C_PRINCIPAL_UNKNOWN for an unmodelled account');
    }

    public function test_response_is_a_krb_error_never_a_ticket(): void
    {
        // The reply must be a KRB-ERROR ([APPLICATION 30] = 0x7E) and never an AS-REP
        // ([APPLICATION 11] = 0x6B): a real ticket is never issued.
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('CORP.LOCAL', ['administrator'], ['krbtgt', 'CORP.LOCAL']));
        $server->processInbound($session);

        $msg = substr($session->outbuf, 4);
        self::assertSame(0x7E, ord($msg[0]), 'top tag is [APPLICATION 30] KRB-ERROR');
        self::assertNotSame(0x6B, ord($msg[0]), 'never an AS-REP');

        // The framed length prefix matches the message length.
        $prefix = unpack('N', substr($session->outbuf, 0, 4))[1];
        self::assertSame(strlen($msg), $prefix);
    }

    public function test_response_echoes_realm_and_requested_service(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::framed(self::asReq('EXAMPLE.COM', ['bob'], ['krbtgt', 'EXAMPLE.COM']));
        $server->processInbound($session);

        $err = KerberosServer::parseKrbError(substr($session->outbuf, 4));
        self::assertNotNull($err);
        self::assertSame('EXAMPLE.COM', $err['realm']);
        self::assertSame('krbtgt/EXAMPLE.COM', $err['sname']);
    }

    public function test_multi_component_service_name_is_joined_with_slash(): void
    {
        $parsed = KerberosServer::parseAsReq(
            self::asReq('CORP.LOCAL', ['svc_sql'], ['MSSQLSvc', 'db01.corp.local:1433'])
        );

        self::assertNotNull($parsed);
        self::assertSame('MSSQLSvc/db01.corp.local:1433', $parsed['sname']);
    }

    public function test_request_without_realm_falls_back_to_persona_realm(): void
    {
        // A malformed request that omits its realm is still answered; the persona realm fills in.
        $config = new KerberosConfig(realm: 'HONEY.LAN');
        [$server, $session] = $this->serverSession($config);

        // Build an AS-REQ then strip its realm field would be fiddly; instead craft a body with only
        // cname + sname by reusing the builder and confirming the response realm when the request
        // carries an empty realm string.
        $session->inbuf = self::framed(self::asReq('', ['administrator'], ['krbtgt', 'HONEY.LAN']));
        $server->processInbound($session);

        $err = KerberosServer::parseKrbError(substr($session->outbuf, 4));
        self::assertNotNull($err);
        self::assertSame('HONEY.LAN', $err['realm'], 'empty request realm falls back to the persona realm');
    }
}
