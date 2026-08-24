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
}
