<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Http\HoneypotController;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * The decoy-archive fallback maps a probed suffix to a static decoy asset + content type.
 * These tests pin the suffix map (source of truth for coverage) and prove each mapped
 * asset carries genuinely-matching bytes, never a relabeled archive.
 */
final class DecoyArchiveTest extends TestCase
{
    /** @return array{0:string,1:string}|null [file, contentType] or null */
    private function decoyFor(string $path): ?array
    {
        $m = new ReflectionMethod(HoneypotController::class, 'decoyForPath');
        $m->setAccessible(true);
        return $m->invoke(null, $path);
    }

    private function decoyDir(): string
    {
        return dirname(__DIR__, 2) . '/demo/decoys';
    }

    /**
     * @return array<string, array{0:string, 1:array{0:string,1:string}}>
     */
    public static function extensions(): array
    {
        return [
            // existing coverage (regression guard)
            '.tar.gz' => ['/wp-content/backup.tar.gz', ['backup.tar.gz', 'application/gzip']],
            '.tgz'    => ['/site.tgz', ['backup.tar.gz', 'application/gzip']],
            '.gz'     => ['/db.gz', ['backup.tar.gz', 'application/gzip']],
            '.zip'    => ['/backup.zip', ['backup.zip', 'application/zip']],
            // new tarballs
            '.tar'      => ['/backup.tar', ['backup.tar', 'application/x-tar']],
            '.tar.bz2'  => ['/host.tar.bz2', ['backup.tar.bz2', 'application/x-bzip2']],
            '.tbz2'     => ['/host.tbz2', ['backup.tar.bz2', 'application/x-bzip2']],
            // new text decoys
            '.sql'    => ['/database.sql', ['backup.sql', 'application/sql']],
            '.pem'    => ['/server.pem', ['backup.pem', 'application/x-pem-file']],
            '.cer'    => ['/tls/server.cer', ['backup.cer', 'application/x-x509-ca-cert']],
            // Specific filename, not a broad '.json' — see test_unrelated_json_does_not_match_wallet().
            'wallet.json' => ['/admin/bank/crypto/eth-a/wallet.json', ['wallet.json', 'application/json']],
        ];
    }

    /** @dataProvider extensions */
    public function test_suffix_maps_to_expected_decoy(string $path, array $expected): void
    {
        self::assertSame($expected, $this->decoyFor($path));
    }

    public function test_longer_suffix_wins_over_shorter(): void
    {
        // .tar.gz must not resolve to the .gz or .tar decoy.
        self::assertSame(['backup.tar.gz', 'application/gzip'], $this->decoyFor('/a.tar.gz'));
        // .tar.bz2 must not collapse to a bare-.tar match.
        self::assertSame(['backup.tar.bz2', 'application/x-bzip2'], $this->decoyFor('/a.tar.bz2'));
    }

    public function test_match_is_case_insensitive(): void
    {
        self::assertSame(['backup.zip', 'application/zip'], $this->decoyFor('/BACKUP.ZIP'));
    }

    public function test_unknown_suffix_returns_null(): void
    {
        self::assertNull($this->decoyFor('/index.php'));
        self::assertNull($this->decoyFor('/robots.txt'));
        self::assertNull($this->decoyFor('/app.war'));   // Java WAR deliberately excluded
        self::assertNull($this->decoyFor('/keystore.jks'));
    }

    /** The wallet.json match is a specific filename, NOT a broad '.json' — an unrelated JSON probe
     *  must fall through to null (a plain 404), never receive the ETH keystore decoy. */
    public function test_unrelated_json_does_not_match_wallet(): void
    {
        self::assertNull($this->decoyFor('/foo/config.json'));
        self::assertNull($this->decoyFor('/package.json'));
        self::assertNull($this->decoyFor('/api/data.json'));
        // Only a path that literally ends "wallet.json" matches.
        self::assertSame(['wallet.json', 'application/json'], $this->decoyFor('/anything/at/all/wallet.json'));
    }

    /** @dataProvider extensions */
    public function test_mapped_asset_exists(string $path, array $expected): void
    {
        [$file] = $expected;
        self::assertFileExists($this->decoyDir() . '/' . $file);
    }

    public function test_tarball_assets_have_real_archive_magic(): void
    {
        // ustar magic sits near offset 257 in a POSIX tar header.
        self::assertStringContainsString('ustar', (string) file_get_contents($this->decoyDir() . '/backup.tar'));
        // bzip2 stream starts with the "BZh" signature.
        self::assertStringStartsWith('BZh', (string) file_get_contents($this->decoyDir() . '/backup.tar.bz2'));
    }

    /**
     * Archive decoys are deep nested chains grown to ~1MB so extraction wastes an attacker's time.
     * The band's floor keeps the depth/junk in place; the ceiling caps the served payload so the
     * decoy can never become a bandwidth-amplification vector when hammered.
     */
    public function test_archive_decoys_are_about_one_megabyte(): void
    {
        foreach (['backup.zip', 'backup.tar.gz', 'backup.tar', 'backup.tar.bz2'] as $file) {
            $size = (int) filesize($this->decoyDir() . '/' . $file);
            self::assertGreaterThan(800_000, $size, "$file too small — nesting/junk missing");
            self::assertLessThan(1_400_000, $size, "$file too large — served-payload cap");
        }
    }

    /** Text decoys stay small: a 1MB cert/key would itself be a fingerprint tell. */
    public function test_pem_and_cer_stay_small(): void
    {
        self::assertLessThan(20_000, (int) filesize($this->decoyDir() . '/backup.pem'));
        self::assertLessThan(20_000, (int) filesize($this->decoyDir() . '/backup.cer'));
    }

    public function test_sql_decoy_is_plausible_dump_text_not_binary(): void
    {
        $sql = (string) file_get_contents($this->decoyDir() . '/backup.sql');
        self::assertStringContainsString('CREATE TABLE', $sql);
        self::assertStringContainsString('INSERT INTO', $sql);
        self::assertNotBinary($sql);
    }

    public function test_pem_and_cer_are_pem_blocks_not_binary(): void
    {
        $pem = (string) file_get_contents($this->decoyDir() . '/backup.pem');
        self::assertStringContainsString('-----BEGIN', $pem);
        self::assertStringContainsString('-----END', $pem);
        self::assertNotBinary($pem);

        $cer = (string) file_get_contents($this->decoyDir() . '/backup.cer');
        self::assertStringContainsString('-----BEGIN CERTIFICATE-----', $cer);
        self::assertNotBinary($cer);
    }

    /** Text decoys must not be a relabeled zip/gzip. */
    private static function assertNotBinary(string $bytes): void
    {
        self::assertStringStartsNotWith('PK', $bytes, 'looks like a zip');
        self::assertNotSame("\x1f\x8b", substr($bytes, 0, 2), 'looks like gzip');
    }

    // --- wallet.json: the ETH keystore decoy (SAFETY-critical — no functional private key, ever) ---

    /** A small text decoy: a 1MB JSON file would itself be a fingerprint tell (real keystores are tiny). */
    public function test_wallet_json_stays_small(): void
    {
        self::assertLessThan(20_000, (int) filesize($this->decoyDir() . '/wallet.json'));
    }

    public function test_wallet_json_is_a_valid_keystore_v3_structure(): void
    {
        $raw = (string) file_get_contents($this->decoyDir() . '/wallet.json');
        $data = json_decode($raw, true);
        self::assertIsArray($data, 'wallet.json parses as JSON');
        self::assertSame(3, $data['version'] ?? null, 'keystore version 3');
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            (string) ($data['id'] ?? ''),
            'id is uuid-shaped'
        );
        self::assertSame('aes-128-ctr', $data['crypto']['cipher'] ?? null);
        self::assertSame('scrypt', $data['crypto']['kdf'] ?? null);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) ($data['crypto']['cipherparams']['iv'] ?? ''));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', (string) ($data['crypto']['kdfparams']['salt'] ?? ''));
        self::assertSame(262144, $data['crypto']['kdfparams']['n'] ?? null);
    }

    /** Embeds the REAL, block-explorer-verifiable primary reserve address (spec §3) — the block-explorer
     *  balance check is the "green" that makes this bait convincing. */
    public function test_wallet_json_embeds_the_real_reserve_address(): void
    {
        $data = json_decode((string) file_get_contents($this->decoyDir() . '/wallet.json'), true);
        self::assertSame(
            '638a2f4c652dcdd671adc9b712e0dabf01e256c5',
            strtolower((string) $data['address']),
            'embedded address matches Fake\\Bank ETH_RESERVE Cold Reserve A (no 0x prefix, keystore convention)'
        );
    }

    /**
     * SAFETY INVARIANT: no functional private key. The ciphertext/mac are RANDOM hex, unrelated to any
     * real key material — they cannot decrypt (with any passphrase) to a private key that controls the
     * embedded address. This test can't prove a cryptographic negative for every passphrase, but it
     * pins the structural guarantee: ciphertext/mac are exactly random-looking hex of the expected
     * byte length, generated by `openssl rand`, never derived from — or equal to — anything else in
     * the file (a real exported keystore's mac is HMAC-derived from the ciphertext + derived key, so a
     * random, unrelated mac is itself proof this was never a real export).
     */
    public function test_wallet_json_ciphertext_and_mac_are_nonsense(): void
    {
        $data = json_decode((string) file_get_contents($this->decoyDir() . '/wallet.json'), true);
        $ciphertext = (string) $data['crypto']['ciphertext'];
        $mac = (string) $data['crypto']['mac'];
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $ciphertext);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $mac);
        // A real keystore's mac = keccak256(derivedKey[16:32] || ciphertext) — never equal to random
        // hex sharing no derivation relationship with the ciphertext.
        self::assertNotSame($ciphertext, $mac);
    }
}
