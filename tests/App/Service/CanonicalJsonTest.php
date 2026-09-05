<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\CanonicalJson;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Golden-byte tests for the one canonical JSON writer. The literals here are authored by hand (not a
 * json_encode round-trip), so a drift in the writer's bytes fails the assertion rather than moving
 * the expectation with it.
 */
final class CanonicalJsonTest extends TestCase
{
    public function testKeysAreSortedByByteOrderAndOutputEndsInOneLf(): void
    {
        self::assertSame('{"a":2,"b":1}' . "\n", CanonicalJson::encode(['b' => 1, 'a' => 2]));
    }

    public function testNestedObjectsSortRecursivelyAndArraysKeepOrder(): void
    {
        $in = ['z' => ['y' => true, 'x' => null], 'a' => [3, 1, 2]];
        self::assertSame('{"a":[3,1,2],"z":{"x":null,"y":true}}' . "\n", CanonicalJson::encode($in));
    }

    public function testEmptyArrayEncodesAsJsonArray(): void
    {
        self::assertSame("[]\n", CanonicalJson::encode([]));
    }

    public function testMinimalEscapingLeavesSlashesAndUnicodeButEscapesRequiredChars(): void
    {
        $in = ['s' => "a/b\"c\\d\ne\u{1F600}"];
        self::assertSame('{"s":"a/b\"c\\\\d\ne' . "\u{1F600}" . '"}' . "\n", CanonicalJson::encode($in));
    }

    public function testFloatIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CanonicalJson::encode(['n' => 1.5]);
    }

    public function testNegativeIntegerIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CanonicalJson::encode(['n' => -1]);
    }

    public function testInvalidUtf8IsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CanonicalJson::encode(['s' => "\xff\xfe"]);
    }

    public function testNonAsciiKeyIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CanonicalJson::encode(["k\u{00e9}" => 1]);
    }

    public function testDigestMatchesIndependentlyComputedSha256(): void
    {
        $payload = ['b' => 1, 'a' => ['d' => 2, 'c' => [1, 2]]];
        $domain = 'funnypot/effective-service-exposure/v1';
        $bytes = CanonicalJson::encode($payload);
        $expected = hash('sha256', $domain . "\0" . $bytes);
        self::assertSame($expected, CanonicalJson::digest($domain, $payload));
        self::assertSame(64, strlen(CanonicalJson::digest($domain, $payload)));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', CanonicalJson::digest($domain, $payload));
    }

    public function testKeyOrderDoesNotChangeDigestButValueDoes(): void
    {
        $domain = 'd';
        $a = CanonicalJson::digest($domain, ['x' => 1, 'y' => 2]);
        $b = CanonicalJson::digest($domain, ['y' => 2, 'x' => 1]);
        self::assertSame($a, $b);
        $c = CanonicalJson::digest($domain, ['x' => 1, 'y' => 3]);
        self::assertNotSame($a, $c);
    }

    public function testDomainSeparationChangesTheDigest(): void
    {
        self::assertNotSame(
            CanonicalJson::digest('domain-a', ['x' => 1]),
            CanonicalJson::digest('domain-b', ['x' => 1]),
        );
    }
}
