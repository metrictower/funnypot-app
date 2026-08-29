<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ldap;

use Funnypot\Protocol\Ldap\LdapConfig;
use Funnypot\Protocol\Ldap\LdapServer;
use Funnypot\Protocol\Ldap\LdapSession;
use PHPUnit\Framework\TestCase;

final class LdapReconLoggingTest extends TestCase
{
    use LdapTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:LdapServer,1:LdapSession}
     */
    private function serverSession(?LdapConfig $config = null): array
    {
        $this->events = [];
        $server = new LdapServer($config ?? new LdapConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new LdapSession('198.51.100.20', 389, 1);

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

    public function test_every_event_carries_the_ldap_envelope(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::simpleBind(1, 'cn=admin', 'pw')
            . self::searchRequest(2, 'dc=x', self::presentFilter('cn'));
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('ldap', $e['proto']);
            self::assertSame('LDAP', $e['method']);
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

    public function test_bind_event_shape(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::simpleBind(1, 'cn=svc,dc=corp', 'hunter2', 3);
        $server->processInbound($session);

        $bind = $this->eventOfType('ldap_bind');
        self::assertNotNull($bind);
        self::assertSame('ldap_bind', $bind['event']);
        self::assertSame('cn=svc,dc=corp', $bind['dn']);
        self::assertSame('hunter2', $bind['password']);
        self::assertSame('simple', $bind['auth']);
        self::assertSame(3, $bind['version']);
    }

    public function test_search_event_shape(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::searchRequest(1, 'ou=admins,dc=corp', self::equalityFilter('cn', 'root'));
        $server->processInbound($session);

        $search = $this->eventOfType('ldap_search');
        self::assertNotNull($search);
        self::assertSame('ou=admins,dc=corp', $search['base']);
        self::assertSame('(cn=root)', $search['filter']);
    }

    public function test_password_with_control_bytes_is_sanitised_in_log(): void
    {
        [$server, $session] = $this->serverSession();
        // A password with embedded NUL / control bytes must not leak raw into the log path.
        $session->inbuf .= self::simpleBind(1, 'cn=x', "a\x00b\x1fc");
        $server->processInbound($session);

        $bind = $this->eventOfType('ldap_bind');
        self::assertNotNull($bind);
        self::assertSame('a.b.c', $bind['password']);
        // The raw bytes are still captured verbatim on the session for offline analysis.
        self::assertSame("a\x00b\x1fc", $session->bindPassword);
    }

    public function test_filter_value_specials_are_escaped(): void
    {
        [$server, $session] = $this->serverSession();
        // A value containing '(' ')' '*' '\' must render escaped in RFC 4515 form.
        $session->inbuf .= self::searchRequest(1, 'dc=x', self::equalityFilter('cn', 'a(b)*c\\d'));
        $server->processInbound($session);

        self::assertSame('(cn=a\\28b\\29\\2ac\\5cd)', $session->searchFilter);
    }

    public function test_or_filter_renders(): void
    {
        [$server, $session] = $this->serverSession();
        $filter = self::orFilter(
            self::equalityFilter('uid', 'a'),
            self::presentFilter('mail')
        );
        $session->inbuf .= self::searchRequest(1, 'dc=x', $filter);
        $server->processInbound($session);

        self::assertSame('(|(uid=a)(mail=*))', $session->searchFilter);
    }

    public function test_connect_event_is_not_emitted_by_process_inbound(): void
    {
        // connect is logged in accept(); driving the parser directly should only yield protocol events.
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::unbindRequest(1);
        $server->processInbound($session);

        self::assertNull($this->eventOfType('connect'));
    }

    public function test_unmodelled_op_logs_unknown_and_closes(): void
    {
        [$server, $session] = $this->serverSession();
        // A modifyRequest [APPLICATION 6] (0x66) is not modelled.
        $op = self::tlv(0x66, self::octet('cn=x'));
        $session->inbuf .= self::ldapMessage(1, $op);
        $server->processInbound($session);

        $unknown = $this->eventOfType('ldap_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('0x66', $unknown['path']);
        self::assertTrue($session->close);
    }

    public function test_config_from_env_accept_flag(): void
    {
        putenv('FUNNYPOT_LDAP_ACCEPT=1');
        self::assertTrue(LdapConfig::fromEnv()->acceptBinds);

        putenv('FUNNYPOT_LDAP_ACCEPT=0');
        self::assertFalse(LdapConfig::fromEnv()->acceptBinds);

        putenv('FUNNYPOT_LDAP_ACCEPT');
        self::assertFalse(LdapConfig::fromEnv()->acceptBinds);
    }

    public function test_response_bytes_are_well_formed_ldap_messages(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::simpleBind(42, 'cn=a', 'p');
        $server->processInbound($session);

        // The whole outbuf must be exactly one self-delimiting LDAPMessage (no trailing bytes).
        $tlv = LdapServer::readTlv($session->outbuf, 0);
        self::assertNotNull($tlv);
        self::assertSame(0x30, $tlv['tag']);
        self::assertSame(strlen($session->outbuf), $tlv['next'], 'response is one complete message');
    }
}
