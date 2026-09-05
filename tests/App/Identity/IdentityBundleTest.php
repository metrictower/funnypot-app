<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\HttpIdentity;
use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityBundleReader;
use Funnypot\App\Identity\IdentityKeyDeriver;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\PostExploitIdentity;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Identity\RedisIdentity;
use Funnypot\App\Identity\ShellIdentity;
use Funnypot\App\Identity\SipIdentity;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * The scoped runtime bundles: exact payload contracts per consumer (Redis and post-exploit are
 * downstream tickets' contracts), key isolation between bundles, modes, child-reader rejections of
 * every tamper shape, and the handle/attestation chain a downstream projector relies on.
 */
final class IdentityBundleTest extends TestCase
{
    private string $data = '';
    private string $runtime = '';
    private IdentityPaths $paths;

    protected function setUp(): void
    {
        $this->data = (string) realpath(sys_get_temp_dir()) . '/fp_bundle_' . bin2hex(random_bytes(5));
        mkdir($this->data, 0777);
        $prepared = PreparedIdentityFixture::prepare($this->data, 'bundle-test-persona-value');
        $prepared['result']->close();
        $this->runtime = $prepared['runtimeDir'];
        $this->paths = IdentityPaths::forStorage($this->data, $this->runtime);
    }

    protected function tearDown(): void
    {
        if ($this->data !== '' && is_dir($this->data)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->data) . ' && rm -rf ' . escapeshellarg($this->data));
        }
    }

    private function expectCode(string $code, callable $fn): void
    {
        try {
            $fn();
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());

            return;
        }
        self::fail("expected {$code}");
    }

    public function test_payload_contracts_are_exact(): void
    {
        $d = IdentityTestSupport::deriver();
        $http = json_decode((string) file_get_contents($this->paths->httpBundlePath()), true);
        $shell = json_decode((string) file_get_contents($this->paths->shellBundlePath()), true);
        $sip = json_decode((string) file_get_contents($this->paths->sipBundlePath()), true);
        $redis = json_decode((string) file_get_contents($this->paths->redisBundlePath()), true);
        $post = json_decode((string) file_get_contents($this->paths->postExploitBundlePath()), true);

        self::assertSame(['console_session_mac_key', 'core_render_salt', 'docker_registry_token_key', 'engagement_analytics_key', 'persona_material', 'shell_filesystem_key'], array_keys($http['payload']));
        self::assertSame(['persona_material', 'shell_filesystem_key'], array_keys($shell['payload']));
        self::assertSame(['persona_material'], array_keys($sip['payload']));
        self::assertSame(['persona_material', 'redis_telemetry_fingerprint_key'], array_keys($redis['payload']), 'RedisIdentity: exactly persona + redis-telemetry/v1');
        self::assertSame(['persona_material', 'post_exploit_state_key'], array_keys($post['payload']), 'PostExploitIdentity: exactly persona + post-exploit-state/v1');
        foreach ([$http, $shell, $sip, $redis, $post] as $b) {
            self::assertSame(['bundle', 'keyset_commitment', 'public_persona_hash', 'schema', 'source'], array_keys($b['envelope']));
            self::assertSame(IdentityBundleReader::SCHEMA, $b['envelope']['schema']);
            self::assertSame('bundle-test-persona-value', $b['payload']['persona_material']);
        }
        self::assertSame(IdentityKeyDeriver::encodeKey($d->redisTelemetryFingerprintKey()), $redis['payload']['redis_telemetry_fingerprint_key']);
        self::assertSame(IdentityKeyDeriver::encodeKey($d->postExploitStateKey()), $post['payload']['post_exploit_state_key']);
        self::assertSame($http['payload']['shell_filesystem_key'], $shell['payload']['shell_filesystem_key'], 'web console and shell share ONE filesystem key');
        self::assertNotSame($http['payload']['shell_filesystem_key'], $http['payload']['console_session_mac_key'], 'filesystem and session-MAC keys differ');

        // No child bundle carries another tier's private key.
        $postKey = IdentityKeyDeriver::encodeKey($d->postExploitStateKey());
        $redisKey = IdentityKeyDeriver::encodeKey($d->redisTelemetryFingerprintKey());
        foreach ([$this->paths->httpBundlePath(), $this->paths->shellBundlePath(), $this->paths->sipBundlePath()] as $p) {
            $raw = (string) file_get_contents($p);
            self::assertStringNotContainsString($postKey, $raw, basename($p) . ' must not carry the post-exploit key');
            self::assertStringNotContainsString($redisKey, $raw, basename($p) . ' must not carry the redis key');
        }
        self::assertStringNotContainsString($postKey, (string) file_get_contents($this->paths->redisBundlePath()));
        self::assertStringNotContainsString(IdentityKeyDeriver::encodeKey(IdentityTestSupport::master()), implode('', array_map('file_get_contents', [$this->paths->httpBundlePath(), $this->paths->shellBundlePath(), $this->paths->sipBundlePath(), $this->paths->redisBundlePath(), $this->paths->postExploitBundlePath(), $this->paths->manifestPath()])), 'the master is in no artifact');
    }

    public function test_dto_surfaces_are_closed(): void
    {
        $methods = static fn (string $class): array => array_values(array_map(
            static fn (ReflectionMethod $m): string => $m->getName(),
            array_filter((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC), static fn (ReflectionMethod $m): bool => !$m->isStatic())
        ));
        self::assertSame(['toPayload', 'personaMaterial', 'personaSeed', 'redisTelemetryFingerprintKey'], $methods(RedisIdentity::class));
        self::assertSame(['toPayload', 'personaMaterial', 'personaSeed', 'postExploitStateKey'], $methods(PostExploitIdentity::class));
        self::assertSame(['toPayload', 'personaMaterial', 'personaSeed', 'filesystemKey'], $methods(ShellIdentity::class));
        self::assertSame(['toPayload', 'personaMaterial', 'personaSeed', 'personaDomain'], $methods(SipIdentity::class));
        foreach ($methods(HttpIdentity::class) as $m) {
            self::assertNotContains($m, ['postExploitStateKey', 'redisTelemetryFingerprintKey'], 'HttpIdentity exposes no other tier\'s key');
        }
        foreach ([HttpIdentity::class, ShellIdentity::class, SipIdentity::class, RedisIdentity::class, PostExploitIdentity::class] as $c) {
            self::assertFalse((new ReflectionClass($c))->isInstantiable(), "{$c} is immutable: no public constructor");
            self::assertFalse((new ReflectionClass($c))->hasMethod('derive'), "{$c} offers no derivation");
        }
        // The RedisIdentity typed view loads from its own bundle only.
        $r = RedisIdentity::load($this->paths);
        self::assertSame(32, strlen($r->redisTelemetryFingerprintKey()));
        self::assertSame('bundle-test-persona-value', $r->personaMaterial());
        $p = PostExploitIdentity::load($this->paths);
        self::assertSame(32, strlen($p->postExploitStateKey()));
        self::assertNotSame($r->redisTelemetryFingerprintKey(), $p->postExploitStateKey());
    }

    public function test_modes_follow_the_scoped_layout(): void
    {
        clearstatcache();
        self::assertSame(0700, (int) lstat($this->paths->privateRuntimeDir())['mode'] & 0777);
        self::assertSame(0, (int) lstat($this->paths->httpRuntimeDir())['mode'] & 0022, 'the web parent is never group/other writable');
        foreach ([$this->paths->shellBundlePath(), $this->paths->sipBundlePath(), $this->paths->redisBundlePath(), $this->paths->postExploitBundlePath()] as $p) {
            self::assertSame(0600, (int) lstat($p)['mode'] & 0777, basename($p) . ' is root-only');
        }
        self::assertSame(0640, (int) lstat($this->paths->httpBundlePath())['mode'] & 0777, 'the web bundle is owner rw + group r (www-data when root)');
        self::assertSame(0600, (int) lstat($this->paths->manifestPath())['mode'] & 0777);
        self::assertSame(0700, (int) lstat($this->paths->persistentRoot())['mode'] & 0777);
    }

    public function test_child_reader_rejects_every_tamper_shape(): void
    {
        $p = $this->paths->httpBundlePath();
        $good = (string) file_get_contents($p);

        file_put_contents($p, str_replace(IdentityBundleReader::SCHEMA, 'funnypot-identity-bundle/v0', $good));
        $this->expectCode('bundle-schema', fn () => HttpIdentity::load($this->paths));

        file_put_contents($p, str_replace('"bundle": "http"', '"bundle": "shell"', $good));
        $this->expectCode('bundle-name', fn () => HttpIdentity::load($this->paths));

        file_put_contents($p, '{"envelope":{}}');
        $this->expectCode('bundle-malformed', fn () => HttpIdentity::load($this->paths));

        file_put_contents($p, str_replace('"engagement_analytics_key"', '"extra_key"', $good));
        $this->expectCode('bundle-payload-malformed', fn () => HttpIdentity::load($this->paths));

        file_put_contents($p, $good);
        chmod($p, 0666);
        $this->expectCode('bundle-unsafe', fn () => HttpIdentity::load($this->paths));
        chmod($p, 0640);
        HttpIdentity::load($this->paths); // sane again

        unlink($p);
        symlink($this->paths->shellBundlePath(), $p);
        $this->expectCode('bundle-unsafe', fn () => HttpIdentity::load($this->paths));
        unlink($p);
        $this->expectCode('bundle-missing', fn () => HttpIdentity::load($this->paths));

        chmod($this->paths->httpRuntimeDir(), 0777);
        $this->expectCode('bundle-component-unsafe', fn () => HttpIdentity::load($this->paths));
        chmod($this->paths->httpRuntimeDir(), 0700);

        $this->expectCode('bundle-unknown', fn () => (new IdentityBundleReader($this->paths))->read('manifest'));
    }

    public function test_reader_never_touches_the_manifest_or_the_master(): void
    {
        // Delete the persistent state entirely: a child with only its runtime bundle still loads.
        exec('rm -rf ' . escapeshellarg($this->paths->privateRoot()));
        $h = HttpIdentity::load($this->paths);
        self::assertSame('bundle-test-persona-value', $h->personaMaterial());
        ShellIdentity::load($this->paths);
        SipIdentity::load($this->paths);
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Identity/IdentityBundleReader.php');
        foreach (['manifestPath', 'manifest.json', 'readManifest', 'masterPath', 'install.secret', 'InstallSecretStore', 'IdentityKeyDeriver::fromMaster'] as $forbidden) {
            self::assertStringNotContainsString($forbidden, $src, "the child reader must not reach the manifest/master ({$forbidden})");
        }
    }

    public function test_retained_handle_detects_a_swapped_source(): void
    {
        $prepared = PreparedIdentityFixture::prepare($this->data, 'bundle-test-persona-value');
        $src = $prepared['result']->sources()[PreparedIdentitySource::HTTP];
        self::assertTrue($src->attestation->matches((array) fstat($src->handle)));
        // Rename-over (what a tamperer or a stale writer would do): the retained handle now points at
        // an unlinked inode, so nlink drops and the attestation no longer matches.
        $tmp = $this->paths->httpBundlePath() . '.swap';
        file_put_contents($tmp, (string) file_get_contents($this->paths->httpBundlePath()));
        rename($tmp, $this->paths->httpBundlePath());
        self::assertFalse($src->attestation->matches((array) fstat($src->handle)), 'a consumer that COMPARES catches the swap');
        $prepared['result']->close();
    }
}
