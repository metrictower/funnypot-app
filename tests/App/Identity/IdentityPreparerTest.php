<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\HttpIdentity;
use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityKeyDeriver;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\IdentityPreparationResult;
use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Identity\InstallSecretStore;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Identity\ReservedPrincipals;
use Funnypot\App\Identity\ShellIdentity;
use Funnypot\App\Tls\DecoyCertificateManager;
use PHPUnit\Framework\TestCase;

/**
 * The preparation transaction: source resolution and its fail-closed transitions, persona override
 * semantics, migration warnings, the nine typed source handles, reserved principals, and status.
 */
final class IdentityPreparerTest extends TestCase
{
    private string $base = '';

    protected function setUp(): void
    {
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_prep_' . bin2hex(random_bytes(5));
        mkdir($this->base, 0755);
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->base) . ' && rm -rf ' . escapeshellarg($this->base));
        }
    }

    private function root(string $name = 'r1'): string
    {
        $s = $this->base . '/' . $name;
        if (!is_dir($s)) {
            mkdir($s, 0777);
            mkdir($s . '/no-legacy', 0700);
            mkdir($s . '/no-le', 0700);
        }

        return $s;
    }

    private function preparer(IdentityInputs $inputs, string $name = 'r1', ?IdentityFileOps $ops = null): IdentityPreparer
    {
        $s = $this->root($name);
        $paths = IdentityPaths::forStorage($s, $this->base . '/' . $name . '-runtime');
        $ops ??= new IdentityFileOps();

        return new IdentityPreparer($paths, $inputs, $ops, new DecoyCertificateManager($paths, $ops, $inputs, $s . '/no-legacy', $s . '/no-le'));
    }

    private function expectCode(string $code, callable $fn): void
    {
        try {
            $fn();
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());
            self::assertStringNotContainsString($this->base, $e->getMessage());

            return;
        }
        self::fail("expected {$code}");
    }

    public function test_generated_then_persisted_with_seven_open_sources_and_matching_attestations(): void
    {
        $r1 = $this->preparer(new IdentityInputs())->prepare();
        self::assertSame(IdentityPreparationResult::SOURCE_GENERATED, $r1->sourceClass);
        self::assertSame(IdentityPreparationResult::PERSONA_DERIVED, $r1->personaSource);
        self::assertStringStartsWith('fpph1_', $r1->publicPersonaHash);
        self::assertStringStartsWith('fpkc1_', $r1->keysetCommitment);
        self::assertContains(IdentityPreparer::WARN_PERSONA_FIRST_DERIVED, $r1->warnings);
        self::assertFalse($r1->httpGroupApplied, 'non-root: the www-data group cannot be applied');
        self::assertContains(IdentityPreparer::WARN_HTTP_GROUP_NOT_APPLIED, $r1->warnings);

        $sources = $r1->sources();
        self::assertSame([
            PreparedIdentitySource::HTTP, PreparedIdentitySource::SHELL, PreparedIdentitySource::SIP, PreparedIdentitySource::REDIS,
            PreparedIdentitySource::TLS_CERTIFICATE, PreparedIdentitySource::TLS_PRIVATE_KEY, PreparedIdentitySource::POST_EXPLOIT,
        ], array_keys($sources), 'the seven always-present sources (admin pair absent without Let\'s Encrypt)');
        self::assertNull($r1->adminTlsCertificate);
        foreach ($sources as $class => $src) {
            self::assertIsResource($src->handle, "{$class} handle is open");
            self::assertTrue($src->attestation->isRegularFile());
            self::assertSame(1, $src->attestation->nlink);
            self::assertTrue($src->attestation->matches((array) fstat($src->handle)), "{$class}: fstat of the retained handle reproduces the attestation");
            rewind($src->handle);
            self::assertSame($src->sha256, hash('sha256', (string) stream_get_contents($src->handle)), "{$class}: sha256 is over the handle's bytes");
        }
        foreach ([PreparedIdentitySource::HTTP, PreparedIdentitySource::SHELL, PreparedIdentitySource::SIP, PreparedIdentitySource::REDIS, PreparedIdentitySource::POST_EXPLOIT] as $c) {
            self::assertSame($r1->publicPersonaHash, $sources[$c]->envelope['public_persona_hash']);
            self::assertSame($r1->keysetCommitment, $sources[$c]->envelope['keyset_commitment']);
        }
        self::assertSame($r1->tls->fingerprintSha256, $sources[PreparedIdentitySource::TLS_CERTIFICATE]->envelope['fingerprint_sha256']);
        $r1->close();

        $r2 = $this->preparer(new IdentityInputs())->prepare();
        self::assertSame(IdentityPreparationResult::SOURCE_PERSISTED, $r2->sourceClass);
        self::assertSame($r1->publicPersonaHash, $r2->publicPersonaHash);
        self::assertSame($r1->keysetCommitment, $r2->keysetCommitment);
        self::assertSame($r1->tls->fingerprintSha256, $r2->tls->fingerprintSha256);
        self::assertNotContains(IdentityPreparer::WARN_PERSONA_FIRST_DERIVED, $r2->warnings);
        $r2->close();
    }

    public function test_fresh_roots_vary_and_explicit_over_generated_conflicts(): void
    {
        $a = $this->preparer(new IdentityInputs(), 'a')->prepare();
        $b = $this->preparer(new IdentityInputs(), 'b')->prepare();
        self::assertNotSame($a->publicPersonaHash, $b->publicPersonaHash);
        self::assertNotSame($a->keysetCommitment, $b->keysetCommitment);
        self::assertNotSame($a->tls->fingerprintSha256, $b->tls->fingerprintSha256);
        $a->close();
        $b->close();
        $this->expectCode('identity-source-conflict', fn () => $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('x')), 'a')->prepare());
    }

    public function test_explicit_file_source_restart_change_and_loss(): void
    {
        $file = $this->base . '/master.secret';
        file_put_contents($file, IdentityTestSupport::canonicalMaster('f'));
        chmod($file, 0600);
        $r = $this->preparer(new IdentityInputs(secretFile: $file))->prepare();
        self::assertSame(IdentityPreparationResult::SOURCE_EXPLICIT_FILE, $r->sourceClass);
        self::assertSame(IdentityTestSupport::deriver('f')->keysetCommitment(), $r->keysetCommitment);
        self::assertFileDoesNotExist(IdentityPaths::forStorage($this->root(), '/x')->masterPath(), 'an explicit source is never copied to the persisted file');
        $r->close();

        $again = $this->preparer(new IdentityInputs(secretFile: $file))->prepare();
        self::assertSame($r->keysetCommitment, $again->keysetCommitment);
        $again->close();

        file_put_contents($file, IdentityTestSupport::canonicalMaster('g'));
        $this->expectCode('explicit-source-changed', fn () => $this->preparer(new IdentityInputs(secretFile: $file))->prepare());
        $this->expectCode('explicit-source-missing', fn () => $this->preparer(new IdentityInputs())->prepare());
        $this->expectCode('explicit-source-missing', fn () => $this->preparer(new IdentityInputs(personaSeed: 'httptest'))->prepare());

        file_put_contents($file, IdentityTestSupport::canonicalMaster('f'));
        chmod($file, 0644);
        $this->expectCode('install-secret-file-unsafe', fn () => $this->preparer(new IdentityInputs(secretFile: $file))->prepare());
        chmod($file, 0600);
        symlink($file, $this->base . '/master-link.secret');
        $this->expectCode('install-secret-file-path', fn () => $this->preparer(new IdentityInputs(secretFile: $this->base . '/master-link.secret'))->prepare());
        file_put_contents($file, 'garbage');
        $this->expectCode('install-secret-file-malformed', fn () => $this->preparer(new IdentityInputs(secretFile: $file))->prepare());
    }

    public function test_explicit_env_source_validation(): void
    {
        $this->expectCode('install-secret-env-malformed', fn () => $this->preparer(new IdentityInputs(secretEnv: 'not-a-master'), 'e1')->prepare());
        $this->expectCode('install-secret-env-all-zero', fn () => $this->preparer(new IdentityInputs(secretEnv: InstallSecretStore::serialize(str_repeat("\0", 32))), 'e2')->prepare());
        $this->expectCode('install-secret-env-malformed', fn () => $this->preparer(new IdentityInputs(secretEnv: rtrim(IdentityTestSupport::canonicalMaster(), "\n")), 'e3')->prepare());
        $r = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('z')), 'e4')->prepare();
        self::assertSame(IdentityPreparationResult::SOURCE_EXPLICIT_ENV, $r->sourceClass);
        self::assertSame(IdentityTestSupport::deriver('z')->keysetCommitment(), $r->keysetCommitment);
        $r->close();
    }

    public function test_persona_override_is_verbatim_cosmetic_and_warns_when_weak(): void
    {
        $r = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('a'), personaSeed: 'httptest'), 'p1')->prepare();
        self::assertSame(IdentityPreparationResult::PERSONA_OVERRIDE, $r->personaSource);
        self::assertSame(IdentityKeyDeriver::publicPersonaHash('httptest'), $r->publicPersonaHash);
        self::assertContains(IdentityPreparer::WARN_PERSONA_WEAK, $r->warnings, 'shorter than 16 chars is weak (a warning, not a rejection)');
        $http = HttpIdentity::load(IdentityPaths::forStorage($this->root('p1'), $this->base . '/p1-runtime'));
        self::assertSame('httptest', $http->personaMaterial(), 'the override is used VERBATIM');
        self::assertSame(1137404178250321592, $http->personaSeed(), 'today\'s seedFromMaterial integer is preserved');
        $r->close();

        // Same override, another master: identical visible identity, every private thing differs.
        $r2 = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('b'), personaSeed: 'httptest'), 'p2')->prepare();
        $http2 = HttpIdentity::load(IdentityPaths::forStorage($this->root('p2'), $this->base . '/p2-runtime'));
        self::assertSame($r->publicPersonaHash, $r2->publicPersonaHash);
        self::assertSame($http->personaSeed(), $http2->personaSeed());
        self::assertNotSame($r->keysetCommitment, $r2->keysetCommitment);
        self::assertNotSame($http->coreRenderSalt(), $http2->coreRenderSalt());
        self::assertNotSame($http->filesystemKey(), $http2->filesystemKey());
        self::assertNotSame($http->sessionMacKey(), $http2->sessionMacKey());
        self::assertNotSame($http->dockerRegistryTokenKey(), $http2->dockerRegistryTokenKey());
        self::assertNotSame(ShellIdentity::load(IdentityPaths::forStorage($this->root('p1'), $this->base . '/p1-runtime'))->filesystemKey(), ShellIdentity::load(IdentityPaths::forStorage($this->root('p2'), $this->base . '/p2-runtime'))->filesystemKey());
        $r2->close();

        // Legacy variable: honoured second, flagged; SEED wins over SECRET; strong value has no weak warning.
        $r3 = $this->preparer(new IdentityInputs(personaSecret: 'a-sufficiently-long-legacy-persona-value'), 'p3')->prepare();
        self::assertSame(IdentityKeyDeriver::publicPersonaHash('a-sufficiently-long-legacy-persona-value'), $r3->publicPersonaHash);
        self::assertContains(IdentityPreparer::WARN_PERSONA_LEGACY_VAR, $r3->warnings);
        self::assertNotContains(IdentityPreparer::WARN_PERSONA_WEAK, $r3->warnings);
        $r3->close();
        $r4 = $this->preparer(new IdentityInputs(personaSeed: 'seed-wins-over-secret-value', personaSecret: 'legacy-loses'), 'p4')->prepare();
        self::assertSame(IdentityKeyDeriver::publicPersonaHash('seed-wins-over-secret-value'), $r4->publicPersonaHash);
        $r4->close();

        foreach (['funnypot', 'CHANGEME', ' change-me ', 'default', 'test', 'example', 'fifteen-chars--'] as $weak) {
            self::assertTrue(IdentityPreparer::isWeakOverride($weak), "'{$weak}' is weak");
        }
        self::assertFalse(IdentityPreparer::isWeakOverride('sixteen-chars-ok'));
        $this->expectCode('persona-override-invalid', fn () => $this->preparer(new IdentityInputs(personaSeed: "bad\x01value-with-control"), 'p5')->prepare());
        $this->expectCode('persona-override-invalid', fn () => $this->preparer(new IdentityInputs(personaSeed: str_repeat('x', 513)), 'p6')->prepare());
    }

    public function test_legacy_fs_secret_is_ignored_not_imported_and_reported(): void
    {
        $s = $this->root('l1');
        file_put_contents($s . '/fs_secret', 'legacy-bytes');
        $r = $this->preparer(new IdentityInputs(legacyFsSecretEnvSet: true), 'l1')->prepare();
        self::assertContains(IdentityPreparer::WARN_LEGACY_FS_SECRET_FILE, $r->warnings);
        self::assertContains(IdentityPreparer::WARN_LEGACY_FS_SECRET_ENV, $r->warnings);
        self::assertSame('legacy-bytes', file_get_contents($s . '/fs_secret'), 'left untouched');
        $shell = ShellIdentity::load(IdentityPaths::forStorage($s, $this->base . '/l1-runtime'));
        self::assertNotSame('legacy-bytes', $shell->filesystemKey(), 'never imported as the filesystem key');
        $r->close();
    }

    public function test_reserved_principals_absent_ok_exact_ok_partial_or_conflict_fails(): void
    {
        $exact = ['name' => 'funnypot-state', 'uid' => 10005, 'gid' => 10005, 'dir' => '/nonexistent', 'shell' => '/usr/sbin/nologin'];
        $mk = static fn (?array $pw, ?array $gr) => new class ($pw, $gr) extends IdentityFileOps {
            public function __construct(private ?array $pw, private ?array $gr)
            {
            }

            public function passwdByName(string $name): ?array
            {
                return $name === 'funnypot-state' ? $this->pw : null;
            }

            public function passwdByUid(int $uid): ?array
            {
                return $uid === 10005 ? $this->pw : null;
            }

            public function groupByName(string $name): ?array
            {
                return $name === 'funnypot-state' ? $this->gr : null;
            }

            public function groupByGid(int $gid): ?array
            {
                return $gid === 10005 ? $this->gr : null;
            }
        };
        (new ReservedPrincipals($mk(null, null)))->verify();
        (new ReservedPrincipals($mk($exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []])))->verify();
        $this->expectCode('reserved-principal-partial', static fn () => (new ReservedPrincipals($mk(null, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []])))->verify());
        $this->expectCode('reserved-principal-conflict', static fn () => (new ReservedPrincipals($mk(['shell' => '/bin/sh'] + $exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []])))->verify());
        $this->expectCode('reserved-principal-conflict', static fn () => (new ReservedPrincipals($mk(['dir' => '/home/x'] + $exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []])))->verify());
        $this->expectCode('reserved-principal-conflict', static fn () => (new ReservedPrincipals($mk($exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => ['www-data']])))->verify());
        $this->expectCode('reserved-principal-conflict', static fn () => (new ReservedPrincipals($mk(['gid' => 10010] + $exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []])))->verify());
        // and the preparer runs the check before publishing anything
        $this->expectCode('reserved-principal-conflict', fn () => $this->preparer(new IdentityInputs(), 'rp', $mk(['shell' => '/bin/sh'] + $exact, ['name' => 'funnypot-state', 'gid' => 10005, 'members' => []]))->prepare());
        self::assertFileDoesNotExist(IdentityPaths::forStorage($this->root('rp'), '/x')->manifestPath());
    }

    public function test_manifest_is_secret_free_and_status_reports_without_secrets(): void
    {
        $master = IdentityTestSupport::master('m');
        $r = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('m'), personaSeed: 'my-override-persona-value'), 'm1')->prepare();
        $paths = IdentityPaths::forStorage($this->root('m1'), $this->base . '/m1-runtime');
        $manifest = (string) file_get_contents($paths->manifestPath());
        self::assertStringNotContainsString(IdentityKeyDeriver::encodeKey($master), $manifest);
        self::assertStringNotContainsString(bin2hex($master), $manifest);
        self::assertStringNotContainsString('my-override-persona-value', $manifest, 'the raw override is never persisted');
        self::assertStringNotContainsString($this->base, $manifest, 'no path');
        foreach (['coreRenderSalt', 'shellFilesystemKey', 'consoleSessionMacKey', 'postExploitStateKey', 'redisTelemetryFingerprintKey'] as $m) {
            self::assertStringNotContainsString(IdentityKeyDeriver::encodeKey(IdentityTestSupport::deriver('m')->{$m}()), $manifest, "{$m} must not be in the manifest");
        }
        $doc = json_decode($manifest, true);
        self::assertSame(IdentityPreparer::MANIFEST_SCHEMA, $doc['schema']);
        self::assertSame('explicit-env', $doc['source']);
        self::assertSame($r->keysetCommitment, $doc['keyset_commitment']);
        self::assertSame(0600, (int) lstat($paths->manifestPath())['mode'] & 0777);

        $status = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('m'), personaSeed: 'my-override-persona-value'), 'm1')->status();
        self::assertTrue($status['ready']);
        self::assertSame($r->publicPersonaHash, $status['public_identity']);
        self::assertArrayNotHasKey('keyset_commitment', $status);
        self::assertStringNotContainsString($r->keysetCommitment, json_encode($status));
        self::assertStringNotContainsString('my-override-persona-value', json_encode($status));
        self::assertStringNotContainsString($this->base, json_encode($status));
        $r->close();

        // A tampered bundle envelope is visible to status and rejected by the child reader.
        $bundle = (string) file_get_contents($paths->shellBundlePath());
        file_put_contents($paths->shellBundlePath(), str_replace('fpkc1_', 'fpkc1_0', $bundle));
        $status = $this->preparer(new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster('m'), personaSeed: 'my-override-persona-value'), 'm1')->status();
        self::assertFalse($status['ready']);
        self::assertSame('envelope-mismatch', $status['checks']['shell']);
        self::assertSame('ok', $status['checks']['http']);
    }

    public function test_bundles_and_runtime_are_regenerated_idempotently_without_rotating_the_master(): void
    {
        $r = $this->preparer(new IdentityInputs(), 'i1')->prepare();
        $r->close();
        $paths = IdentityPaths::forStorage($this->root('i1'), $this->base . '/i1-runtime');
        $ino = lstat($paths->masterPath())['ino'];
        exec('rm -rf ' . escapeshellarg($paths->runtimeRoot()));
        unlink($paths->manifestPath());
        $r2 = $this->preparer(new IdentityInputs(), 'i1')->prepare();
        self::assertSame($r->publicPersonaHash, $r2->publicPersonaHash);
        self::assertSame($r->keysetCommitment, $r2->keysetCommitment);
        self::assertSame($r->tls->fingerprintSha256, $r2->tls->fingerprintSha256, 'the persisted TLS pair survives runtime loss');
        clearstatcache();
        self::assertSame($ino, lstat($paths->masterPath())['ino'], 'the master is never rotated');
        self::assertFileExists($paths->httpBundlePath());
        $r2->close();
    }

    public function test_a_bundle_that_does_not_verify_fails_before_success(): void
    {
        // Fault injection: the bytes that reach the http bundle carry a different public hash than the
        // manifest (same length, so the write itself succeeds) — the root-read/compare pass must catch it.
        $ops = new class () extends IdentityFileOps {
            public function write($h, string $bytes)
            {
                $meta = stream_get_meta_data($h);
                if (str_contains((string) ($meta['uri'] ?? ''), 'http.json')) {
                    $bytes = str_replace('fpph1_', 'fpph2_', $bytes);
                }

                return parent::write($h, $bytes);
            }
        };
        $this->expectCode('bundle-verify-failed', fn () => $this->preparer(new IdentityInputs(), 'v1', $ops)->prepare());
    }
}
