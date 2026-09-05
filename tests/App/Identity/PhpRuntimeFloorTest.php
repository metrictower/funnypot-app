<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use PHPUnit\Framework\TestCase;

/**
 * The PHP 8.2 floor is one decision expressed in five places — Composer metadata, the lock, CI, the
 * image and the docs — and the crash-safe store must never silently downgrade its durability on a
 * runtime that lacks native fsync(). This pins all of them together.
 */
final class PhpRuntimeFloorTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    public function test_composer_json_declares_the_floor_and_posix(): void
    {
        $j = json_decode((string) file_get_contents(self::root() . '/composer.json'), true);
        self::assertSame('>=8.2', $j['require']['php']);
        self::assertArrayHasKey('ext-posix', $j['require']);
        self::assertArrayHasKey('ext-sodium', $j['require']);
        self::assertArrayHasKey('ext-openssl', $j['require']);
    }

    public function test_composer_lock_is_fresh_and_carries_the_platform_floor(): void
    {
        $j = json_decode((string) file_get_contents(self::root() . '/composer.json'), true);
        $lock = json_decode((string) file_get_contents(self::root() . '/composer.lock'), true);
        self::assertSame('>=8.2', $lock['platform']['php']);
        self::assertArrayHasKey('ext-posix', $lock['platform']);
        self::assertSame('v0.6.3', self::lockedVersion($lock, 'metrictower/funnypot-core'), 'the installed core stays at the compatible v0.6.3 — no core bump rides this change');

        // Composer's content-hash: md5 of the relevant composer.json keys, ksorted.
        $keys = ['name', 'version', 'require', 'require-dev', 'conflict', 'replace', 'provide', 'minimum-stability', 'prefer-stable', 'repositories', 'extra'];
        $rel = [];
        foreach ($keys as $k) {
            if (isset($j[$k])) {
                $rel[$k] = $j[$k];
            }
        }
        if (isset($j['config']['platform'])) {
            $rel['config']['platform'] = $j['config']['platform'];
        }
        ksort($rel);
        self::assertSame(md5((string) json_encode($rel)), $lock['content-hash'], 'composer.lock content-hash is stale for composer.json');
    }

    public function test_ci_matrix_container_and_docs_agree(): void
    {
        $yml = (string) file_get_contents(self::root() . '/.github/workflows/tests.yml');
        self::assertMatchesRegularExpression("/php:\s*\['8\.2',\s*'8\.3',\s*'8\.4'\]/", $yml);
        self::assertStringNotContainsString("'8.0'", $yml);
        self::assertStringNotContainsString("'8.1'", $yml);

        $dockerfile = (string) file_get_contents(self::root() . '/demo/Dockerfile');
        self::assertMatchesRegularExpression('/^FROM php:8\.[2-9]-fpm-alpine/m', $dockerfile);
        self::assertStringContainsString('COPY bin ./bin', $dockerfile, 'the identity CLI must be in the runtime image');

        $readme = (string) file_get_contents(self::root() . '/README.md');
        self::assertStringContainsString('php-%3E%3D8.2', $readme, 'README badge');
        self::assertStringContainsString('PHP 8.2+', $readme);
        self::assertStringNotContainsString('%3E%3D8.0', $readme);
    }

    public function test_native_fsync_is_present_and_never_polyfilled(): void
    {
        self::assertTrue(function_exists('fsync'), 'PHP >= 8.1 provides fsync(); the floor is 8.2');
        self::assertGreaterThanOrEqual(80200, PHP_VERSION_ID, 'the suite itself runs on the declared floor');
        foreach (glob(self::root() . '/src/App/Identity/*.php') ?: [] as $file) {
            $src = (string) file_get_contents($file);
            // A global `function fsync(` (a polyfill) is forbidden; the seam's `public function fsync($h)` method is the real call.
            self::assertDoesNotMatchRegularExpression('/^\s*function\s+fsync\s*\(/m', $src, basename($file) . ' must not define a fsync() polyfill');
            self::assertDoesNotMatchRegularExpression('/if\s*\(\s*!\s*function_exists\(\s*[\'"]fsync/', $src, basename($file) . ' must not soft-fallback around fsync');
            self::assertStringNotContainsString("function_exists('fsync') ?", $src, basename($file) . ' must not soft-fallback around fsync');
        }
    }

    /** @param array<string,mixed> $lock */
    private static function lockedVersion(array $lock, string $package): ?string
    {
        foreach ((array) ($lock['packages'] ?? []) as $p) {
            if (($p['name'] ?? null) === $package) {
                return (string) $p['version'];
            }
        }

        return null;
    }
}
