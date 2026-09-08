<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\EarlyIngressGuard;
use PHPUnit\Framework\TestCase;

final class EarlyIngressGuardTest extends TestCase
{
    public function test_admission_counts_whole_raw_bytes_without_normalization(): void
    {
        foreach ([0, 1, 4095, 4096, 4097, 65536] as $bytes) {
            foreach (['a', '%', "\xff", "\0", '/', '?'] as $unit) {
                self::assertSame($bytes <= 4096, EarlyIngressGuard::accepts(str_repeat($unit, $bytes)));
            }
        }
        foreach (['/.env?', 'http://example.invalid/.env?', '/x?%2541=%00&', '/a//../?&&', '/x?é='] as $prefix) {
            foreach ([4095, 4096, 4097] as $bytes) {
                $target = $prefix . str_repeat('q', $bytes - strlen($prefix));
                self::assertSame($bytes <= 4096, EarlyIngressGuard::accepts($target));
                self::assertSame($bytes, strlen($target), 'admission must not shorten the identity');
            }
        }
        self::assertFalse(EarlyIngressGuard::accepts(str_repeat('é', 2049)), 'bytes, not characters');
    }

    public function test_missing_and_non_string_targets_keep_the_existing_slash_fallback(): void
    {
        foreach ([null, false, true, 4097, [], new \stdClass()] as $value) {
            self::assertTrue(EarlyIngressGuard::accepts($value));
        }
    }
}
