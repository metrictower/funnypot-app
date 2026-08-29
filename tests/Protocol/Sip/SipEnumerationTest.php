<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\App\Render\Fake\Org;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use PHPUnit\Framework\TestCase;

/**
 * Extension-enumeration shaping: a plausible, bounded set of extensions 401-challenges (a real PBX
 * with real AORs — a juicy target that lures svwar into a password spray), while clearly-random junk
 * gets a 404 like a real dial plan. Every probe is still logged as intel — we never lose the probe
 * just because we answered 404.
 */
final class SipEnumerationTest extends TestCase
{
    // --- SipConfig valid/invalid policy ---

    public function test_default_policy_accepts_numbers_and_allowlisted_names(): void
    {
        $cfg = new SipConfig(rtpPort: 0);

        // Numeric extensions and plausible dialed numbers (short internal + long toll-fraud target).
        $this->assertTrue($cfg->isValidExtension('100'));
        $this->assertTrue($cfg->isValidExtension('200'));
        $this->assertTrue($cfg->isValidExtension('4515215'));
        $this->assertTrue($cfg->isValidExtension('0014155550199'));
        $this->assertTrue($cfg->isValidExtension('+14155550199'));

        // A small allowlist of by-name accounts scanners target, case-insensitively.
        $this->assertTrue($cfg->isValidExtension('root'));
        $this->assertTrue($cfg->isValidExtension('admin'));
        $this->assertTrue($cfg->isValidExtension('ADMIN'));
        $this->assertTrue($cfg->isValidExtension('operator'));
    }

    public function test_default_policy_rejects_random_junk(): void
    {
        $cfg = new SipConfig(rtpPort: 0);

        $this->assertFalse($cfg->isValidExtension('asdf9zqxwer'));
        $this->assertFalse($cfg->isValidExtension('xyzzy'));
        $this->assertFalse($cfg->isValidExtension('100abc'));
        $this->assertFalse($cfg->isValidExtension(''));
    }

    public function test_env_override_changes_the_valid_set(): void
    {
        // re:7\d{2} stays a literal backslash-d in this single-quoted string.
        putenv('FUNNYPOT_SIP_VALID_EXTENSIONS=1001,20*,re:7\d{2}');
        try {
            $cfg = SipConfig::fromEnv();

            // The override defines the valid set: explicit, glob, and regex forms all match.
            $this->assertTrue($cfg->isValidExtension('1001'));
            $this->assertTrue($cfg->isValidExtension('2005'));
            $this->assertTrue($cfg->isValidExtension('750'));

            // The override REPLACES the default, so numbers/names valid by default are now rejected.
            $this->assertFalse($cfg->isValidExtension('100'));
            $this->assertFalse($cfg->isValidExtension('admin'));
            $this->assertFalse($cfg->isValidExtension('asdf9zqxwer'));
        } finally {
            putenv('FUNNYPOT_SIP_VALID_EXTENSIONS');
        }
    }

    // --- REGISTER shaping (end-to-end over the wire) ---

    public function test_valid_numeric_ext_register_gets_401_challenge(): void
    {
        $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
        $raw = $this->register('100', 'enum-valid-num');
        $resp = $this->roundTrip($server, $raw);

        $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $resp);
        $this->assertStringContainsString('WWW-Authenticate', $resp);
    }

    public function test_allowlisted_name_root_gets_401_challenge(): void
    {
        $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
        $raw = $this->register('root', 'enum-valid-root');
        $resp = $this->roundTrip($server, $raw);

        $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $resp);
    }

    public function test_invalid_junk_ext_register_returns_404_and_logs_probe(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = $this->register('asdf9zqxwer', 'enum-junk');
        $resp = $this->roundTrip($server, $raw);

        // Wire response is a 404, never the 401 challenge that would imply an infinite-ext PBX.
        $this->assertStringContainsString('SIP/2.0 404 Not Found', $resp);
        $this->assertStringNotContainsString('401 Unauthorized', $resp);

        // Intel is preserved: the probe is still logged, tagged as an enumeration attempt.
        $probes = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'probe'));
        $this->assertNotEmpty($probes);
        $ev = end($probes);
        $this->assertStringContainsString('asdf9zqxwer', $ev['path']);
        $this->assertStringContainsString('404', $ev['path']);
        $this->assertStringContainsString('enumeration probe', $ev['path']);

        // A 404 never issues a nonce (no challenge was sent).
        $ref = new \ReflectionProperty($server, 'activeNonces');
        $ref->setAccessible(true);
        $this->assertEmpty($ref->getValue($server));
    }

    // --- OPTIONS shaping ---

    public function test_options_to_invalid_ext_returns_404_and_logs_probe(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "OPTIONS sip:asdf9zqxwer@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-o\r\n"
            . "Call-ID: opt-junk\r\nCSeq: 1 OPTIONS\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertSame('probe', $ev['event']);
        $this->assertStringContainsString('404', $ev['path']);
        $this->assertStringContainsString('enumeration probe', $ev['path']);
    }

    public function test_server_directed_options_keeps_normal_200_probe(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // No user part in the Request-URI -> server-directed keep-alive, not enumeration.
        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-o2\r\n"
            . "Call-ID: opt-server\r\nCSeq: 1 OPTIONS\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertSame('probe', $ev['event']);
        $this->assertStringContainsString('OPTIONS probe', $ev['path']);
        $this->assertStringNotContainsString('404', $ev['path']);
    }

    // --- INVITE shaping ---

    public function test_invite_always_answers_even_for_an_off_directory_target(): void
    {
        // An INVITE must ALWAYS connect — never 404 on the dialed target. Callers dial external
        // numbers / arbitrary targets (toll-fraud, or an operator test call) that are not PBX
        // extensions; the honeypot answers, connects and streams a persona to capture them. The
        // enumeration 404-gate applies only to REGISTER/OPTIONS, never to a call.
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "INVITE sip:3333666@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-i\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:3333666@target>\r\n"
            . "Call-ID: inv-offdir\r\nCSeq: 1 INVITE\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        // The call is set up (answered), and the dialed number is captured on the call event.
        $this->assertSame(1, $server->getActiveSessionCount());
        $ev = end($logged);
        $this->assertSame('call', $ev['event']);
        $this->assertStringContainsString('3333666', $ev['path']);
    }

    public function test_invite_to_valid_number_still_connects(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // A plausible toll-fraud target number must keep the normal call flow.
        $raw = "INVITE sip:0014155550199@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-i2\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:0014155550199@target>\r\n"
            . "Call-ID: inv-valid\r\nCSeq: 1 INVITE\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $this->assertSame(1, $server->getActiveSessionCount());
        $this->assertSame('call', end($logged)['event']);
    }

    // --- 'org' mode: extension directory coherent with the seeded company roster (FP-0180) ---

    public function test_org_mode_valid_set_equals_org_roster_and_derives_seed_like_panels(): void
    {
        // Coherence via fromEnv: the SIP directory resolves the SAME seed+domain the office panels do
        // (PersonaIdentity::seedFromMaterial + the persona domain), so the two describe one company.
        putenv('FUNNYPOT_PERSONA_SEED=fp0180-coherence');
        putenv('FUNNYPOT_SIP_EXTENSION_MODE=org');
        try {
            $cfg = SipConfig::fromEnv();

            $seed = PersonaIdentity::seedFromMaterial('fp0180-coherence');
            $domain = VisualPersona::fromSeed($seed)->domain();
            $org = Org::fromSeed($seed, $domain);
            $roster = array_map(static fn (array $p): string => $p['ext'], $org->people($org->headcount()));
            sort($roster);

            // The SIP-valid extension directory EQUALS the Org roster's extension set for this seed.
            $this->assertNotEmpty($roster);
            $this->assertSame($roster, $cfg->orgExtensions());

            // Every roster extension is valid; a number outside the bounded roster is not.
            foreach ($roster as $ext) {
                $this->assertTrue($cfg->isValidExtension($ext), "roster ext {$ext} should be valid");
            }
            $this->assertFalse($cfg->isValidExtension('9999'));
        } finally {
            putenv('FUNNYPOT_PERSONA_SEED');
            putenv('FUNNYPOT_SIP_EXTENSION_MODE');
        }
    }

    public function test_org_mode_roster_extension_register_gets_401_challenge(): void
    {
        [$cfg, $roster] = $this->orgConfig('fp0180-a');
        $ext = $roster[0]; // a real roster extension (computed from the same seed the config uses)
        $this->assertTrue($cfg->isValidExtension($ext));

        $server = new SipServer($cfg, null);
        $resp = $this->roundTrip($server, $this->register($ext, 'org-valid'));

        // A real directory extension keeps the 401 challenge → weak-auth latch, the juicy target.
        $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $resp);
        $this->assertStringContainsString('WWW-Authenticate', $resp);
    }

    public function test_org_mode_off_roster_number_returns_404_and_logs_probe(): void
    {
        [$cfg, $roster] = $this->orgConfig('fp0180-b');
        $this->assertNotContains('9999', $roster); // sanity: the junk number really is off-roster

        $logged = [];
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $resp = $this->roundTrip($server, $this->register('9999', 'org-junk'));

        // Off-roster numbers 404 in 'org' mode — the bounded directory, not the FP-0178 "any number".
        $this->assertStringContainsString('SIP/2.0 404 Not Found', $resp);
        $this->assertStringNotContainsString('401 Unauthorized', $resp);

        // Intel is preserved: the probe is still logged as an enumeration attempt.
        $probes = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'probe'));
        $this->assertNotEmpty($probes);
        $ev = end($probes);
        $this->assertStringContainsString('9999', $ev['path']);
        $this->assertStringContainsString('enumeration probe', $ev['path']);
    }

    public function test_org_mode_allowlisted_name_still_gets_401_challenge(): void
    {
        [$cfg] = $this->orgConfig('fp0180-allow');

        // The by-name allowlist stays valid in 'org' mode so common-name probes are still captured.
        $this->assertTrue($cfg->isValidExtension('admin'));

        $server = new SipServer($cfg, null);
        $resp = $this->roundTrip($server, $this->register('root', 'org-name'));
        $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $resp);
    }

    public function test_pattern_mode_still_accepts_any_number_off_roster(): void
    {
        // Same seed/domain, contrasting modes: 'pattern' keeps the FP-0178 behavior (any E.164-ish
        // number is valid, roster or not) while 'org' bounds it to the roster.
        $seed = PersonaIdentity::seedFromMaterial('fp0180-d');
        $domain = VisualPersona::fromSeed($seed)->domain();
        $pattern = new SipConfig(rtpPort: 0, extensionMode: 'pattern', personaSeed: $seed, personaDomain: $domain);
        $org = new SipConfig(rtpPort: 0, extensionMode: 'org', personaSeed: $seed, personaDomain: $domain);

        $this->assertTrue($pattern->isValidExtension('9999'));   // pattern: any number valid (FP-0178)
        $this->assertFalse($org->isValidExtension('9999'));      // org: bounded to the roster

        // The directory is only exposed (server-side) in 'org' mode.
        $this->assertSame([], $pattern->orgExtensions());
        $this->assertNotEmpty($org->orgExtensions());

        // Pattern mode's operator-rule override and default allowlist are untouched by the new mode.
        $this->assertTrue($pattern->isValidExtension('admin'));
        $this->assertFalse($pattern->isValidExtension('asdf9zqxwer'));
    }

    // --- helpers ---

    /**
     * An 'org'-mode SipConfig plus its sorted roster extension list, both derived from the same seed
     * material so a test can pick a guaranteed real (or off-) roster extension.
     *
     * @return array{0: SipConfig, 1: list<string>}
     */
    private function orgConfig(string $material, string $bind = '127.0.0.1:0'): array
    {
        $seed = PersonaIdentity::seedFromMaterial($material);
        $domain = VisualPersona::fromSeed($seed)->domain();
        $cfg = new SipConfig(bind: $bind, rtpPort: 0, extensionMode: 'org', personaSeed: $seed, personaDomain: $domain);

        $org = Org::fromSeed($seed, $domain);
        $roster = array_map(static fn (array $p): string => $p['ext'], $org->people($org->headcount()));
        sort($roster);

        return [$cfg, $roster];
    }

    private function register(string $ext, string $callId): string
    {
        return "REGISTER sip:pbx.example.com SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-{$callId}\r\n"
            . "From: <sip:{$ext}@pbx.example.com>;tag=t\r\n"
            . "To: <sip:{$ext}@pbx.example.com>\r\n"
            . "Call-ID: {$callId}\r\n"
            . "CSeq: 1 REGISTER\r\n\r\n";
    }

    /**
     * Bind the server on an ephemeral loopback UDP port, send one datagram from a client socket, run
     * the server loop until it replies, and return the raw response — proving the on-the-wire code.
     */
    private function roundTrip(SipServer $server, string $raw): string
    {
        $server->bind();

        $ref = new \ReflectionProperty($server, 'udpSocket');
        $ref->setAccessible(true);
        $sock = $ref->getValue($server);
        $addr = stream_socket_get_name($sock, false);

        $client = stream_socket_client('udp://' . $addr, $errno, $errstr, 1);
        $this->assertIsResource($client, "client socket: {$errstr} ({$errno})");
        stream_set_blocking($client, false);
        fwrite($client, $raw);

        $resp = '';
        for ($i = 0; $i < 100; $i++) {
            $server->runOnce();
            $got = @stream_socket_recvfrom($client, 65535);
            if ($got !== false && $got !== '') {
                $resp = $got;
                break;
            }
            usleep(1000);
        }

        fclose($client);
        $server->closeSockets();

        return $resp;
    }
}
