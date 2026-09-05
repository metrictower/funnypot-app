<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityKeyDeriver;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * Static source boundary over src/, demo/ and bin/ (scripts/ holds dev benches and is out of scope):
 * no production reader of a persona/legacy secret variable outside IdentityInputs, no HostSecret,
 * no fleet-literal persona fallback, no second HKDF caller, no derive-by-label, and no post-exploit
 * key reader in ordinary web/dashboard/reporting code.
 */
final class IdentitySourceBoundaryTest extends TestCase
{
    /** @return list<string> */
    private static function productionFiles(): array
    {
        $root = dirname(__DIR__, 3);
        $out = [];
        foreach (['src', 'demo', 'bin'] as $dir) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . $dir, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                $p = (string) $f;
                if (str_ends_with($p, '.php') || str_ends_with($p, '/funnypot') || str_ends_with($p, '.sh')) {
                    if (str_contains($p, '/demo/storage/') || str_contains($p, '/demo/assets/') || str_contains($p, '/demo/decoys/')) {
                        continue;
                    }
                    $out[] = $p;
                }
            }
        }
        sort($out);
        self::assertNotEmpty($out);

        return $out;
    }

    private static function rel(string $p): string
    {
        return substr($p, strlen(dirname(__DIR__, 3)) + 1);
    }

    public function test_no_production_persona_or_legacy_secret_env_reader_outside_identity_inputs(): void
    {
        foreach (self::productionFiles() as $f) {
            $rel = self::rel($f);
            if ($rel === 'src/App/Identity/IdentityInputs.php' || $rel === 'demo/entrypoint.sh') {
                continue; // the ONE reader, and the shell that unsets them
            }
            $src = (string) file_get_contents($f);
            foreach (['FUNNYPOT_PERSONA_SEED', 'FUNNYPOT_PERSONA_SECRET', 'FUNNYPOT_FS_SECRET', 'FUNNYPOT_INSTALL_SECRET'] as $var) {
                self::assertDoesNotMatchRegularExpression(
                    '/getenv\(\s*[\'"]' . preg_quote($var, '/') . '/',
                    $src,
                    "{$rel} reads {$var} directly; identity inputs are read once by IdentityInputs"
                );
                self::assertDoesNotMatchRegularExpression('/\$_ENV\[\s*[\'"]' . preg_quote($var, '/') . '/', $src, "{$rel} reads {$var} via \$_ENV");
                self::assertDoesNotMatchRegularExpression('/\$_SERVER\[\s*[\'"]' . preg_quote($var, '/') . '/', $src, "{$rel} reads {$var} via \$_SERVER");
            }
        }
    }

    public function test_no_host_secret_reader_and_no_fleet_literal_persona_fallback(): void
    {
        foreach (self::productionFiles() as $f) {
            $rel = self::rel($f);
            if (str_starts_with($rel, 'src/Protocol/Ssh/')) {
                continue; // frozen tree; a comment there mentions the retired class by name only
            }
            $src = (string) file_get_contents($f);
            self::assertStringNotContainsString('HostSecret', $src, "{$rel} still references the retired HostSecret");
            if ($rel !== 'src/App/Identity/IdentityPreparer.php') { // the preparer only lstat()s it to raise the migration warning
                self::assertStringNotContainsString('fs_secret', $src, "{$rel} still references the legacy fs_secret file");
            }
            self::assertDoesNotMatchRegularExpression("/\\?:\\s*'funnypot'/", $src, "{$rel} falls back to the fleet literal persona");
            self::assertDoesNotMatchRegularExpression("/FUNNYPOT_PERSONA_SE(?:ED|CRET)'\\s*,\\s*'funnypot'/", $src, "{$rel} falls back to the fleet literal persona");
            self::assertDoesNotMatchRegularExpression('/seedFromMaterial\(\s*[\'"]/', $src, "{$rel} seeds the persona from a literal");
        }
        self::assertFileDoesNotExist(dirname(__DIR__, 3) . '/src/Shell/Fs/HostSecret.php');
    }

    public function test_hkdf_is_called_only_by_the_deriver_and_has_no_public_label_method(): void
    {
        foreach (self::productionFiles() as $f) {
            $rel = self::rel($f);
            $src = (string) file_get_contents($f);
            if ($rel !== 'src/App/Identity/IdentityKeyDeriver.php') {
                self::assertStringNotContainsString('hash_hkdf(', $src, "{$rel} derives identity keys outside IdentityKeyDeriver");
            }
        }
        $rc = new ReflectionClass(IdentityKeyDeriver::class);
        foreach ($rc->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
            if (!$m->isStatic()) {
                self::assertSame(0, $m->getNumberOfParameters(), "IdentityKeyDeriver::{$m->getName()} accepts a caller-chosen label");
            }
        }
    }

    public function test_ordinary_web_dashboard_and_reporting_code_has_no_post_exploit_or_master_reader(): void
    {
        $root = dirname(__DIR__, 3);
        $ordinary = array_merge(
            glob($root . '/src/App/Http/*.php') ?: [],
            glob($root . '/src/App/Admin/*.php') ?: [],
            glob($root . '/src/App/ThreatIntel/*.php') ?: [],
            glob($root . '/src/App/Storage/*.php') ?: [],
            glob($root . '/src/App/Engagement/*.php') ?: [],
            [$root . '/demo/index.php', $root . '/demo/retention.php', $root . '/demo/rollup.php', $root . '/demo/abuse-drain.php', $root . '/demo/threatintel-drain.php'],
        );
        foreach ($ordinary as $f) {
            $src = (string) file_get_contents($f);
            $rel = self::rel($f);
            self::assertStringNotContainsString('PostExploitIdentity', $src, "{$rel} must not read the post-exploit key");
            self::assertStringNotContainsString('RedisIdentity', $src, "{$rel} must not read the Redis telemetry key");
            self::assertStringNotContainsString('ShellIdentity', $src, "{$rel} must not read the root-only shell bundle");
            self::assertStringNotContainsString('InstallSecretStore', $src, "{$rel} must not touch the master store");
            self::assertStringNotContainsString('IdentityKeyDeriver', $src, "{$rel} must not hold a derivation service");
            self::assertStringNotContainsString('install.secret', $src, "{$rel} names the master file");
        }
    }

    public function test_listener_and_web_composition_roots_read_only_their_scoped_views(): void
    {
        $root = dirname(__DIR__, 3);
        $index = (string) file_get_contents($root . '/demo/index.php');
        self::assertStringContainsString('HttpIdentity::load(', $index);
        foreach (['manifestPath', 'manifest.json', 'readManifest', 'InstallSecretStore', 'IdentityPreparer'] as $forbidden) {
            self::assertStringNotContainsString($forbidden, $index, "the web tier never touches the persistent manifest/master ({$forbidden})");
        }
        $listen = (string) file_get_contents($root . '/demo/listen.php');
        self::assertStringContainsString('ShellIdentity::class', $listen);
        self::assertStringContainsString('SipIdentity::class', $listen);
        self::assertStringNotContainsString('HttpIdentity', $listen, 'a listener never opens the web bundle');
        self::assertStringNotContainsString('PostExploitIdentity', $listen, 'no current child loads the post-exploit source');
        self::assertStringNotContainsString('personaSeed', (string) file_get_contents($root . '/src/App/Config/AppConfig.php'));
    }

    public function test_cli_accepts_no_secret_option(): void
    {
        $cli = (string) file_get_contents(dirname(__DIR__, 3) . '/bin/funnypot');
        self::assertStringContainsString("if (\$argvv !== []) {", $cli, 'identity commands reject every option');
        self::assertDoesNotMatchRegularExpression('/--(secret|master|install-secret)=/', $cli, 'no argv secret option exists');
    }
}
