<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\App\Render\Fake\Org;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Sip\SipSession;
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
            $cfg = SipConfig::fromEnv(\Funnypot\App\Identity\SipIdentity::fromPersonaMaterial('sip-env-override-test'));

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

    public function test_permissive_org_shapes_enumeration_offroster_404_onroster_challenged(): void
    {
        // FP-0223: even under permissive (easy-connect) + an org roster, an off-roster extension is 404'd
        // so a scan (sipexten/svwar) does not see EVERY extension answer — the clearest honeypot tell.
        // A roster/allowlist extension still 401-challenges (permissive then accepts), preserving the
        // brute-force lure on the extensions that actually exist.
        $cfg = new SipConfig(bind: '127.0.0.1:0', rtpPort: 0, authMode: 'permissive', extensionMode: 'org', personaSeed: 12345);
        self::assertTrue($cfg->shapesExtensionEnumeration(), 'org mode shapes enumeration regardless of auth mode');
        $server = new SipServer($cfg, null);

        $resp404 = $this->roundTrip($server, $this->register('zzq9x7wv3n', 'perm-org-junk'));
        self::assertStringContainsString('SIP/2.0 404 Not Found', $resp404, 'off-roster extension must 404 even under permissive');
        self::assertStringNotContainsString('401 Unauthorized', $resp404);

        $resp401 = $this->roundTrip($server, $this->register('root', 'perm-org-root'));
        self::assertStringContainsString('SIP/2.0 401 Unauthorized', $resp401, 'an existing (allowlisted) account still challenges + lures');
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

    // --- randomized ring before answer (a constant answer time is a tell) ---

    public function test_invite_rings_before_answering_and_holds_the_200_ok(): void
    {
        // The call must not be answered inline: it rings (180 sent, 200 held) for a randomized
        // interval within the ring window, so the caller's phone is heard ringing a random count.
        $server = new SipServer(new SipConfig(rtpPort: 0), null);

        $raw = "INVITE sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-r\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:100@target>\r\n"
            . "Call-ID: inv-ring\r\nCSeq: 1 INVITE\r\n\r\n";
        $before = microtime(true);
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);
        $sessions = array_values($sessProp->getValue($server));
        $this->assertCount(1, $sessions);
        $s = $sessions[0];

        $this->assertSame(SipSession::STATE_RINGING, $s->state);
        $this->assertNotSame('', $s->pendingOk, 'the 200 OK is held during the ring');
        $this->assertGreaterThanOrEqual($before + 4.0, $s->answerAt, 'answer deferred by at least the min ring');
        $this->assertLessThanOrEqual($before + 12.0 + 0.5, $s->answerAt, 'answer within the ring window');
    }

    public function test_pending_answer_is_delivered_once_the_ring_elapses(): void
    {
        $server = new SipServer(new SipConfig(rtpPort: 0), null);

        $raw = "INVITE sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-r2\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:100@target>\r\n"
            . "Call-ID: inv-ring2\r\nCSeq: 1 INVITE\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);
        $s = array_values($sessProp->getValue($server))[0];
        // Force the ring to have elapsed.
        $s->answerAt = microtime(true) - 0.01;

        $deliver = new \ReflectionMethod($server, 'deliverPendingAnswers');
        $deliver->setAccessible(true);
        $deliver->invoke($server);

        $this->assertSame(SipSession::STATE_CONNECTED, $s->state);
        $this->assertSame('', $s->pendingOk);
        $this->assertSame(0.0, $s->answerAt);
    }

    // --- enumeration shaping is only for the credential-guarding modes ---

    public function test_permissive_mode_engages_off_roster_register_instead_of_404(): void
    {
        // permissive/open exist to be trivially easy to reach, so an off-roster/junk AOR must be
        // challenged (engaged), not 404-shaped away — the 404 map is a weak/strict-mode behaviour.
        $logged = [];
        $cfg = new SipConfig(rtpPort: 0, authMode: 'permissive');
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "REGISTER sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-p\r\n"
            . "From: <sip:asdf9zqxwer@target>;tag=f\r\nTo: <sip:asdf9zqxwer@target>\r\n"
            . "Call-ID: reg-perm\r\nCSeq: 1 REGISTER\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertStringNotContainsString('enumeration probe', $ev['path']);
        $this->assertStringNotContainsString('404', $ev['path']);
        $this->assertStringContainsString('challenge sent', $ev['path']);
    }

    public function test_unacked_invite_session_is_evicted_at_setup_timeout(): void
    {
        // A scan INVITE that never ACKs must not hold a call slot until the max-duration cap — a
        // handful would fill maxActiveCalls and 486-Busy every later caller (and the test call).
        $server = new SipServer(new SipConfig(rtpPort: 0), null);

        $raw = "INVITE sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-nb\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:100@target>\r\n"
            . "Call-ID: inv-noack\r\nCSeq: 1 INVITE\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');
        $this->assertSame(1, $server->getActiveSessionCount());

        // Age the never-ACKed (non-streaming) session past the RFC 3261 setup timeout.
        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);
        foreach ($sessProp->getValue($server) as $s) {
            $s->startTime = microtime(true) - 40.0;
        }

        $cleanup = new \ReflectionMethod($server, 'cleanupExpiredSessions');
        $cleanup->setAccessible(true);
        $cleanup->invoke($server);

        $this->assertSame(0, $server->getActiveSessionCount(), 'stalled no-ACK INVITE must be evicted');
    }

    public function test_streaming_call_with_no_caller_audio_is_dropped_on_the_short_clock(): void
    {
        // A scanner that ACKs but never sends RTP would otherwise stream our persona to no one until the
        // full idle cap. With callNoAudioTimeout set, a zero-inbound-audio streaming call must be reaped
        // on the shorter clock (idle 12s > 10s no-audio cap, but < the 30s normal idle cap).
        $server = new SipServer(new SipConfig(rtpPort: 0, callNoAudioTimeout: 10, callIdleTimeout: 30), null);
        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);

        $s = new SipSession("k", "9.9.9.9", 5060);
        $s->state = SipSession::STATE_STREAMING;
        $s->remoteRtpPort = 10000;
        $s->startTime = microtime(true) - 12.0;
        $s->lastInboundTime = microtime(true) - 12.0; // caller went silent right after ACK
        $s->recordedInbound = '';                     // never sent a single RTP packet
        $sessProp->setValue($server, ['k' => $s]);

        $cleanup = new \ReflectionMethod($server, 'cleanupExpiredSessions');
        $cleanup->setAccessible(true);
        $cleanup->invoke($server);

        $this->assertSame(0, $server->getActiveSessionCount(), 'silent streaming bot must be dropped fast');
    }

    public function test_streaming_call_that_sent_audio_keeps_the_normal_idle_cap(): void
    {
        // A real caller who spoke then paused must NOT be cut on the short no-audio clock — once any
        // inbound audio exists, the call falls back to the (longer) normal idle timeout.
        $server = new SipServer(new SipConfig(rtpPort: 0, callNoAudioTimeout: 10, callIdleTimeout: 30), null);
        $sessProp = new \ReflectionProperty($server, 'sessions');
        $sessProp->setAccessible(true);

        $s = new SipSession("k", "9.9.9.9", 5060);
        $s->state = SipSession::STATE_STREAMING;
        $s->remoteRtpPort = 10000;
        $s->startTime = microtime(true) - 12.0;
        $s->lastInboundTime = microtime(true) - 12.0;
        $s->recordedInbound = str_repeat("\x7f", 800); // caller sent audio, then went quiet
        $sessProp->setValue($server, ['k' => $s]);

        $cleanup = new \ReflectionMethod($server, 'cleanupExpiredSessions');
        $cleanup->setAccessible(true);
        $cleanup->invoke($server);

        $this->assertSame(1, $server->getActiveSessionCount(), 'a call that spoke must keep the normal idle cap');
    }

    // --- 'org' mode: extension directory coherent with the seeded company roster (FP-0180) ---

    public function test_org_mode_valid_set_equals_org_roster_and_derives_seed_like_panels(): void
    {
        // Coherence via fromEnv: the SIP directory resolves the SAME seed+domain the office panels do
        // (PersonaIdentity::seedFromMaterial + the persona domain) from the INJECTED install identity —
        // a persona variable in the environment is ignored, so the two describe one company.
        putenv('FUNNYPOT_PERSONA_SEED=must-be-ignored-by-sip');
        putenv('FUNNYPOT_SIP_EXTENSION_MODE=org');
        try {
            $cfg = SipConfig::fromEnv(\Funnypot\App\Identity\SipIdentity::fromPersonaMaterial('fp0180-coherence'));

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

    // --- per-method response fidelity (FP-0224): match a real Asterisk, not a bare 200 to everything ---

    public function test_subscribe_and_publish_are_challenged_401_like_real_asterisk(): void
    {
        foreach (['SUBSCRIBE', 'PUBLISH', 'REFER'] as $method) {
            $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
            $raw = "{$method} sip:target SIP/2.0\r\nVia: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-m\r\n"
                . "From: <sip:x@t>;tag=a\r\nTo: <sip:x@t>\r\nCall-ID: m-{$method}\r\nCSeq: 1 {$method}\r\nEvent: message-summary\r\n\r\n";
            $resp = $this->roundTrip($server, $raw);
            $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $resp, "{$method} should be challenged, not 200'd");
            $this->assertStringContainsString('realm="asterisk"', $resp);
        }
    }

    public function test_out_of_dialog_notify_gets_481(): void
    {
        $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
        $raw = "NOTIFY sip:target SIP/2.0\r\nVia: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-n\r\n"
            . "From: <sip:x@t>;tag=a\r\nTo: <sip:x@t>\r\nCall-ID: n-1\r\nCSeq: 1 NOTIFY\r\n\r\n";
        $resp = $this->roundTrip($server, $raw);
        $this->assertStringContainsString('SIP/2.0 481', $resp, 'an out-of-dialog NOTIFY should be 481, not 200');
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
