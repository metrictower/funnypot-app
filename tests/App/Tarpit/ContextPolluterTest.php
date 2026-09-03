<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\HostileFormat;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\App\Tarpit\ShadowBait;
use PHPUnit\Framework\TestCase;

/**
 * FP-0245c — the front-loaded context-polluters' own invariants (plan §"Verification — 0245c"):
 * deep-key-survives-sampling (A4), token-hostile-≠-byte-heavy (A3), the inert/legal sweep (fingerprint
 * gate + no real credential/host/ARN), byte caps, and flat/bounded memory. The HTTP wiring (budget gate,
 * off-by-default, fail-safe, Range) is proven in {@see PolluterControllerTest}.
 */
final class ContextPolluterTest extends TestCase
{
    private const SEED = 4242;
    private const CAP = 8 * 1024 * 1024;

    // --- helpers -----------------------------------------------------------------------------------

    private function configBody(int $cap = self::CAP, int $seed = self::SEED): string
    {
        $out = '';
        foreach ((new ConfigDump($seed))->chunks($cap) as $c) {
            $out .= $c;
        }

        return $out;
    }

    private function logBody(int $cap = self::CAP, int $seed = self::SEED): string
    {
        $out = '';
        foreach ((new LogRabbitHole($seed))->chunks($cap) as $c) {
            $out .= $c;
        }

        return $out;
    }

    /** @return array{literals:list<string>,patterns:list<string>,own_vocabulary:list<string>} the app fingerprint denylist */
    private static function denylist(): array
    {
        $d = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';

        return [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
            'own_vocabulary' => array_values((array) ($d['own_vocabulary'] ?? [])),
        ];
    }

    /** Assert $text carries no denylisted upstream-detector signature (leak-IN) AND no own_vocabulary
     *  self-identifying term (leak-OUT, FP-0112 review #3 — these polluters are a real served surface,
     *  see PolluterControllerTest, so both directions of the gate apply here too). */
    private static function assertFingerprintClean(string $text, string $where): void
    {
        $d = self::denylist();
        foreach ($d['literals'] as $needle) {
            if ($needle !== '') {
                self::assertFalse(stripos($text, $needle) !== false, "fingerprint literal '{$needle}' leaked in {$where}");
            }
        }
        foreach ($d['patterns'] as $pattern) {
            self::assertSame(0, @preg_match('~' . $pattern . '~i', $text), "fingerprint pattern /{$pattern}/ leaked in {$where}");
        }
        $ownVocabularyPattern = '/(?<![a-zA-Z0-9])(' . implode('|', $d['own_vocabulary']) . ')(?![a-zA-Z0-9])/i';
        self::assertSame(0, preg_match($ownVocabularyPattern, $text), "own_vocabulary term leaked in {$where}");
    }

    /** Assert $text names no real third-party host / ARN / live-key — only inert synthetic identities. */
    private static function assertNoRealThirdParty(string $text, string $where): void
    {
        foreach (['amazonaws.com', 'arn:aws:', 'sk_live_', 'AKIA' . 'IOSFODNN7EXAMPLE', 'googleapis.com',
            '.stripe.com', 'windows.net', 'digitaloceanspaces.com', 'herokuapp.com', 'firebaseio.com', ] as $needle) {
            self::assertFalse(stripos($text, $needle) !== false, "real third-party token '{$needle}' in {$where}");
        }
    }

    // --- A1 config dump ----------------------------------------------------------------------------

    public function test_config_dump_is_byte_capped_and_deterministic(): void
    {
        self::assertSame(1024, strlen($this->configBody(1024)), 'config dump honours a tight byte cap exactly');
        self::assertSame(self::CAP, strlen($this->configBody(self::CAP)), 'config dump fills to the cap');
        self::assertSame($this->configBody(4096), $this->configBody(4096), 'same seed ⇒ byte-identical');
        self::assertNotSame($this->configBody(4096, 1), $this->configBody(4096, 2), 'a different seed diverges');
    }

    public function test_config_dump_scatters_inert_credential_and_flag_tokens(): void
    {
        $body = $this->configBody(256 * 1024);
        self::assertMatchesRegularExpression('/AKIA[A-Z0-9]{16}/', $body, 'an AWS-shaped (inert) key');
        self::assertMatchesRegularExpression('/sk_test_[A-Za-z0-9]{24}/', $body, 'a Stripe TEST-shaped (inert) key');
        self::assertMatchesRegularExpression('/FLAG\{[0-9a-f]{32}\}/', $body, 'a dead FLAG honeytoken');
        self::assertStringNotContainsString('sk_live_', $body, 'never a live-key shape');
    }

    // --- A4 log rabbit-hole: deep-key survives head/tail sampling -----------------------------------

    public function test_deep_key_is_absent_from_head_and_tail_but_present_at_its_offset(): void
    {
        $log = new LogRabbitHole(self::SEED);
        $size = $log->size();
        $head = $log->bytesAt(0, 65536);
        $tail = $log->bytesAt($size - 65536, 65536);

        $juicy = $log->juicyLineIndices();
        self::assertNotEmpty($juicy, 'the log injects at least one deep credential line');

        foreach ($juicy as $line) {
            $secret = $log->secretForLine($line);
            self::assertNotSame('', $secret);
            $offset = $line * LogRabbitHole::LINE_WIDTH;

            // Present at its true offset (a Range around it returns it)...
            $window = $log->bytesAt($offset, LogRabbitHole::LINE_WIDTH);
            self::assertStringContainsString($secret, $window, "juicy token must sit at its own offset (line {$line})");

            // ...but ABSENT from the head and tail an agent would sample (defeats head/tail scanning).
            self::assertStringNotContainsString($secret, $head, "juicy token must NOT be in the 64 KiB head (line {$line})");
            self::assertStringNotContainsString($secret, $tail, "juicy token must NOT be in the 64 KiB tail (line {$line})");
        }
    }

    public function test_log_is_offset_addressable_and_range_consistent(): void
    {
        $log = new LogRabbitHole(self::SEED);
        // A narrow window equals the matching slice of a wider window that contains it (Range = whole).
        $narrow = $log->bytesAt(2_000_000, 300);
        $wide = $log->bytesAt(1_999_700, 900);
        self::assertSame($narrow, substr($wide, 2_000_000 - 1_999_700, 300));
        // Every line is fixed width and newline-terminated (the property that makes it offset-addressable).
        $line0 = $log->bytesAt(0, LogRabbitHole::LINE_WIDTH);
        self::assertSame(LogRabbitHole::LINE_WIDTH, strlen($line0));
        self::assertSame("\n", substr($line0, -1));
        self::assertStringNotContainsString("\r", $log->bytesAt(0, 10000), 'CRLF-safe');
    }

    public function test_log_body_honours_the_byte_cap(): void
    {
        // A cap below the logical size trims exactly; a cap above it stops at the logical size.
        self::assertSame(4096, strlen($this->logBody(4096)));
        $full = $this->logBody(PHP_INT_MAX);
        self::assertSame((new LogRabbitHole(self::SEED))->size(), strlen($full), 'never exceeds the logical size');
    }

    // --- A3 token-hostile ≠ byte-heavy -------------------------------------------------------------

    public function test_hostile_format_is_token_heavy_but_byte_light(): void
    {
        $hf = new HostileFormat(self::SEED);
        $hostile = $hf->json(self::CAP);
        self::assertLessThanOrEqual(self::CAP, strlen($hostile), 'bytes stay under the cap (not a huge file)');

        // A friendly JSON of comparable byte size costs materially FEWER tokens: the tax is on their
        // tokeniser, our bytes stay small (spec §7 / backfire register 5).
        $friendly = $hf->friendlyEquivalent(strlen($hostile));
        $hTokens = HostileFormat::tokenEstimate($hostile);
        $fTokens = HostileFormat::tokenEstimate($friendly);

        self::assertGreaterThan(
            $fTokens * 1.5,
            $hTokens,
            "token-hostile output must cost materially more tokens than an equivalent friendly JSON "
            . "(hostile={$hTokens}, friendly={$fTokens} at ~equal bytes)"
        );
        // ...for roughly the same byte budget.
        self::assertLessThan(0.15, abs(strlen($hostile) - strlen($friendly)) / max(1, strlen($hostile)),
            'the comparison is at comparable byte size');
    }

    public function test_hostile_format_is_deterministic(): void
    {
        self::assertSame((new HostileFormat(self::SEED))->json(4096), (new HostileFormat(self::SEED))->json(4096));
        self::assertNotSame((new HostileFormat(1))->json(4096), (new HostileFormat(2))->json(4096));
    }

    // --- C4 /etc/shadow bcrypt bait: verifies against NOTHING --------------------------------------

    public function test_shadow_hashes_are_bcrypt_shaped_and_authenticate_to_nothing(): void
    {
        $shadow = new ShadowBait(self::SEED);
        $guesses = ['anything', 'password', '123456', 'admin', 'root', 'toor', '', 'letmein', 'changeme'];

        foreach ($shadow->hashedAccounts() as $user) {
            $hash = $shadow->hashFor($user);
            self::assertMatchesRegularExpression('/^\$2y\$\d{2}\$[A-Za-z0-9]{53}$/', $hash, "bcrypt shape for {$user}");
            self::assertSame('bcrypt', password_get_info($hash)['algoName'] ?? '', "recognised as bcrypt for {$user}");

            // The whole point of the bait: it is NOT derived from any password, so it verifies against
            // NONE — even feeding the account name or the hash itself back.
            foreach (array_merge($guesses, [$user, $hash]) as $guess) {
                self::assertFalse(password_verify($guess, $hash), "hash for {$user} must NOT verify '{$guess}'");
            }
        }
    }

    public function test_shadow_file_has_shadow_layout_and_locked_system_accounts(): void
    {
        $body = (new ShadowBait(self::SEED))->render();
        self::assertStringContainsString("root:\$2y\$", $body, 'root carries a bcrypt hash');
        self::assertMatchesRegularExpression('/^daemon:\*:/m', $body, 'a locked system account uses *');
        self::assertMatchesRegularExpression('/^bin:!:/m', $body, 'a locked system account uses !');
        foreach (explode("\n", trim($body)) as $line) {
            self::assertSame(8, substr_count($line, ':'), "9-field shadow layout: {$line}");
        }
        self::assertLessThan(4096, strlen($body), 'the shadow bait is a bounded, small static file');
    }

    // --- inert / legal sweep across every polluter -------------------------------------------------

    /**
     * The strengthened fingerprint sweep (FP-0245c review). The original scanned ONE seed at a REDUCED
     * cap and so MISSED that the STRUCTURAL filler identifiers (config slugs, log hex filler) were not
     * gated — an all-digit slug like `943936` reads as a bare CRS-rule id, and a raw sha256 filler prefix
     * can carry a retired hex bait literal. This sweeps MANY seeds — including the reviewer-found
     * offenders — at the FULL 8 MiB cap for the config, and the FULL log body (juicy offsets included).
     * It FAILS without the systemic clean-gate on slug()/hexToken() and PASSES with it.
     *
     * @dataProvider fingerprintSeeds
     */
    public function test_every_polluter_body_passes_the_fingerprint_gate_at_full_cap(int $seed): void
    {
        // Config at the FULL BYTES_PER_RESP_MB cap (8 MiB) — where the ungated slugs surfaced (~28-38%).
        $config = $this->configBody(self::CAP, $seed);
        self::assertSame(self::CAP, strlen($config), 'config was scanned at the full response cap');
        self::assertFingerprintClean($config, "config (seed {$seed}, 8 MiB)");
        self::assertNoRealThirdParty($config, "config (seed {$seed})");

        // The FULL log body, juicy credential offsets included (the ungated hex filler surfaced ~6%).
        $log = $this->logBody(PHP_INT_MAX, $seed);
        self::assertSame((new LogRabbitHole($seed))->size(), strlen($log), 'log was scanned in full');
        self::assertFingerprintClean($log, "log (seed {$seed}, full body)");
        self::assertNoRealThirdParty($log, "log (seed {$seed})");

        $hostile = (new HostileFormat($seed))->json(self::CAP);
        self::assertFingerprintClean($hostile, "hostile (seed {$seed})");
        self::assertNoRealThirdParty($hostile, "hostile (seed {$seed})");

        $shadow = (new ShadowBait($seed))->render();
        self::assertFingerprintClean($shadow, "shadow (seed {$seed})");
        self::assertNoRealThirdParty($shadow, "shadow (seed {$seed})");
    }

    /**
     * Seeds to sweep: the reviewer-found offenders (99991, 957659, 992929, 935109 + 4242) plus a broad
     * contiguous range, so a regression in ANY generated identifier's gating is caught, not just one seed.
     *
     * @return array<string,array{0:int}>
     */
    public static function fingerprintSeeds(): array
    {
        $seeds = [99991, 957659, 992929, 935109, 4242];
        for ($s = 1; $s <= 20; $s++) {
            $seeds[] = $s;
        }
        $out = [];
        foreach (array_values(array_unique($seeds)) as $s) {
            $out['seed ' . $s] = [$s];
        }

        return $out;
    }

    // --- flat / bounded memory (SHOULD-FIX 1: non-vacuous, memory_reset_peak_usage) -----------------

    public function test_config_stream_peak_memory_is_flat_while_output_grows(): void
    {
        if (!function_exists('memory_reset_peak_usage')) {
            self::markTestSkipped('flat-memory assertion needs PHP 8.2+ memory_reset_peak_usage()');
        }
        $drain = function (int $cap): int {
            $n = 0;
            foreach ((new ConfigDump(self::SEED))->chunks($cap) as $c) {
                $n += strlen($c); // SUM + DISCARD — never accumulate the body
            }

            return $n;
        };
        $drain(4096); // warm up class/opcodes/interned strings

        memory_reset_peak_usage();
        $small = $drain(1024);
        $peakSmall = memory_get_peak_usage();

        memory_reset_peak_usage();
        $large = $drain(8 * 1024 * 1024);
        $peakLarge = memory_get_peak_usage();

        self::assertSame(1024, $small);
        self::assertSame(8 * 1024 * 1024, $large);
        self::assertLessThan(
            1024 * 1024,
            $peakLarge - $peakSmall,
            'config-dump peak grew with output — the blob is being materialised (self-DoS defect)'
        );
    }

    public function test_log_range_peak_memory_is_independent_of_offset(): void
    {
        if (!function_exists('memory_reset_peak_usage')) {
            self::markTestSkipped('needs PHP 8.2+ memory_reset_peak_usage()');
        }
        $log = new LogRabbitHole(self::SEED);
        $size = $log->size();
        $win = 65536;
        $log->bytesAt(0, $win); // warm up

        memory_reset_peak_usage();
        $log->bytesAt(0, $win);
        $peakStart = memory_get_peak_usage();

        memory_reset_peak_usage();
        $log->bytesAt($size - $win, $win); // a Range at the very end of a ~6 MiB log
        $peakEnd = memory_get_peak_usage();

        // A Range near the end costs no more peak than one at the start: O(window), never O(offset). If
        // the log were materialised to reach the deep offset, this delta would track the offset (MiBs).
        self::assertLessThan(
            512 * 1024,
            abs($peakEnd - $peakStart),
            'a deep Range cost more memory than a head Range — the log is not offset-addressable (O(1) Range broken)'
        );
    }
}
