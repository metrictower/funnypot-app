<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ldap;

use Funnypot\Protocol\Ldap\LdapConfig;
use Funnypot\Protocol\Ldap\LdapServer;
use Funnypot\Protocol\Ldap\LdapSession;
use PHPUnit\Framework\TestCase;

final class LdapHandshakeTest extends TestCase
{
    use LdapTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?LdapConfig $config = null): LdapServer
    {
        $this->events = [];

        return new LdapServer($config ?? new LdapConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    /**
     * Reads the top-level protocolOp of a response LDAPMessage: returns its tag, the messageID it
     * echoes, and the resultCode from the leading ENUMERATED of its LDAPResult.
     *
     * @return array{op:int,messageId:int,resultCode:int}
     */
    private static function parseResponse(string $msg): array
    {
        $seq = LdapServer::readTlv($msg, 0);
        self::assertNotNull($seq, 'response is a SEQUENCE');
        $idTlv = LdapServer::readTlv($msg, $seq['valueOff']);
        $messageId = ord($msg[$idTlv['valueOff'] + $idTlv['len'] - 1]);
        $op = LdapServer::readTlv($msg, $idTlv['next']);
        $resTlv = LdapServer::readTlv($msg, $op['valueOff']); // resultCode ENUMERATED
        $resultCode = ord($msg[$resTlv['valueOff'] + $resTlv['len'] - 1]);

        return ['op' => $op['tag'], 'messageId' => $messageId, 'resultCode' => $resultCode];
    }

    public function test_simple_bind_captures_dn_and_password_and_denies(): void
    {
        $server = $this->newServer(); // default: deny
        $session = new LdapSession('203.0.113.5', 40000, 1);
        $session->inbuf .= self::simpleBind(1, 'cn=admin,dc=corp,dc=local', 'S3cr3t!', 3);
        $server->processInbound($session);

        // --- intel captured on the session ---
        self::assertSame('cn=admin,dc=corp,dc=local', $session->bindDn);
        self::assertSame('S3cr3t!', $session->bindPassword);
        self::assertSame(3, $session->version);

        // --- ldap_bind event carries DN + password in the path ---
        $bind = $this->eventOfType('ldap_bind');
        self::assertNotNull($bind);
        self::assertStringContainsString('dn=cn=admin,dc=corp,dc=local', $bind['path']);
        self::assertStringContainsString('password=S3cr3t!', $bind['path']);
        self::assertSame('high', $bind['severity']);

        // --- bindResponse denies with invalidCredentials (49), echoing the messageID ---
        $resp = self::parseResponse($session->outbuf);
        self::assertSame(0x61, $resp['op'], 'protocolOp is bindResponse [APPLICATION 1]');
        self::assertSame(1, $resp['messageId']);
        self::assertSame(49, $resp['resultCode'], 'default deny -> invalidCredentials');

        // The connection stays open so the brute-forcer can keep trying.
        self::assertFalse($session->close);
    }

    public function test_accept_mode_binds_return_success_but_grant_nothing(): void
    {
        $server = $this->newServer(new LdapConfig(acceptBinds: true));
        $session = new LdapSession('203.0.113.6', 40001, 1);
        $session->inbuf .= self::simpleBind(7, 'cn=root', 'letmein');
        $server->processInbound($session);

        $resp = self::parseResponse($session->outbuf);
        self::assertSame(0x61, $resp['op']);
        self::assertSame(7, $resp['messageId']);
        self::assertSame(0, $resp['resultCode'], 'accept mode -> success');

        // Even accepted, the password is still captured and no real session exists.
        self::assertSame('letmein', $session->bindPassword);
        self::assertNotNull($this->eventOfType('ldap_bind'));
    }

    public function test_anonymous_bind_is_captured(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('198.51.100.7', 40002, 1);
        $session->inbuf .= self::simpleBind(1, '', '');
        $server->processInbound($session);

        $bind = $this->eventOfType('ldap_bind');
        self::assertNotNull($bind);
        self::assertSame('', $session->bindDn);
        self::assertSame('', $session->bindPassword);
        self::assertSame('medium', $bind['severity'], 'no credential -> medium');
    }

    public function test_sasl_bind_captures_mechanism(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('198.51.100.8', 40003, 1);
        $session->inbuf .= self::saslBind(1, 'cn=x', 'DIGEST-MD5');
        $server->processInbound($session);

        $bind = $this->eventOfType('ldap_bind');
        self::assertNotNull($bind);
        self::assertSame('DIGEST-MD5', $session->saslMechanism);
        self::assertStringContainsString('sasl=DIGEST-MD5', $bind['path']);
    }

    public function test_search_captures_base_and_filter_returns_done_no_entries(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.9', 40004, 1);

        // Bind first, then search — the usual scanner flow on one connection.
        $session->inbuf .= self::simpleBind(1, 'cn=reader,dc=corp,dc=local', 'pw');
        $server->processInbound($session);
        $session->outbuf = '';

        $filter = self::equalityFilter('uid', 'admin');
        $session->inbuf .= self::searchRequest(2, 'ou=people,dc=corp,dc=local', $filter);
        $server->processInbound($session);

        // --- intel captured ---
        self::assertSame('ou=people,dc=corp,dc=local', $session->searchBase);
        self::assertSame('(uid=admin)', $session->searchFilter);

        $search = $this->eventOfType('ldap_search');
        self::assertNotNull($search);
        self::assertStringContainsString('base="ou=people,dc=corp,dc=local"', $search['path']);
        self::assertStringContainsString('filter=(uid=admin)', $search['path']);

        // --- searchResultDone(success), and NOT a single searchResultEntry ---
        $resp = self::parseResponse($session->outbuf);
        self::assertSame(0x65, $resp['op'], 'protocolOp is searchResDone [APPLICATION 5]');
        self::assertSame(2, $resp['messageId']);
        self::assertSame(0, $resp['resultCode']);
        self::assertStringNotContainsString("\x64", $session->outbuf, 'no searchResultEntry emitted');
        self::assertFalse($session->close);
    }

    public function test_present_filter_renders_objectclass_star(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.10', 40005, 1);
        $session->inbuf .= self::searchRequest(5, '', self::presentFilter('objectClass'));
        $server->processInbound($session);

        self::assertSame('(objectClass=*)', $session->searchFilter);
    }

    public function test_compound_and_filter_renders(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.11', 40006, 1);
        $filter = self::andFilter(
            self::equalityFilter('objectClass', 'person'),
            self::equalityFilter('uid', 'root')
        );
        $session->inbuf .= self::searchRequest(9, 'dc=x', $filter);
        $server->processInbound($session);

        self::assertSame('(&(objectClass=person)(uid=root))', $session->searchFilter);
    }

    public function test_substring_filter_renders(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.12', 40007, 1);
        $filter = self::substringFilter('cn', 'ad', ['mi'], 'n');
        $session->inbuf .= self::searchRequest(3, 'dc=x', $filter);
        $server->processInbound($session);

        self::assertSame('(cn=ad*mi*n)', $session->searchFilter);
    }

    public function test_unbind_closes_the_connection(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.13', 40008, 1);
        $session->inbuf .= self::unbindRequest(4);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertSame('', $session->outbuf, 'unbind has no response');
    }

    public function test_partial_message_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.14', 40009, 1);

        $msg = self::simpleBind(1, 'cn=partial', 'pw');
        // Feed all but the last 4 bytes: nothing parses yet.
        $session->inbuf .= substr($msg, 0, -4);
        $server->processInbound($session);
        self::assertSame('', $session->bindDn);
        self::assertNull($this->eventOfType('ldap_bind'));

        // Deliver the remainder: the bind now parses.
        $session->inbuf .= substr($msg, -4);
        $server->processInbound($session);
        self::assertSame('cn=partial', $session->bindDn);
    }

    public function test_two_messages_in_one_buffer_are_both_handled(): void
    {
        $server = $this->newServer();
        $session = new LdapSession('203.0.113.15', 40010, 1);
        $session->inbuf .= self::simpleBind(1, 'cn=a', 'p')
            . self::searchRequest(2, 'dc=x', self::presentFilter('cn'));
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('ldap_bind'));
        self::assertNotNull($this->eventOfType('ldap_search'));
    }

    public function test_non_ldap_leading_byte_closes_cleanly(): void
    {
        // A TLS ClientHello (0x16) for an LDAPS client is unmodelled: log and drop, never crash.
        $server = $this->newServer();
        $session = new LdapSession('192.0.2.1', 5000, 1);
        $session->inbuf .= "\x16\x03\x01\x00\x50" . str_repeat("\x00", 80);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('ldap_unknown'));
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
