<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\InertSecret;
use Funnypot\App\Tarpit\InertSecretExhausted;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

final class InertSecretTest extends TestCase
{
    public function test_first_clean_candidate_returns_without_an_extra_generator_call(): void
    {
        $keys = [];
        $result = InertSecret::derive('primary', static function (string $key) use (&$keys): string {
            $keys[] = $key;

            return 'ordinary-value';
        });
        self::assertSame('ordinary-value', $result);
        self::assertSame(['primary'], $keys);
    }

    public function test_last_primary_candidate_preserves_the_exact_key_schedule(): void
    {
        $keys = [];
        $result = InertSecret::derive('primary', static function (string $key) use (&$keys): string {
            $keys[] = $key;

            return count($keys) === 64 ? 'ordinary-value' : 'ModSecurity';
        });
        self::assertSame('ordinary-value', $result);
        self::assertSame(array_merge(['primary'], array_map(
            static fn (int $i): string => 'primary|v' . $i,
            range(1, 63)
        )), $keys);
    }

    public function test_primary_exhaustion_returns_only_a_checked_key_separated_emergency_token(): void
    {
        $results = [];
        foreach (['emergency-a', 'emergency-a', 'emergency-b'] as $key) {
            $calls = 0;
            $results[] = $result = InertSecret::derive($key, static function () use (&$calls): string {
                $calls++;

                return 'ModSecurity';
            });
            self::assertSame(64, $calls, 'the generator is never called a 65th time');
            self::assertTrue(InertSecret::isClean('"' . $result . '"'));
            self::assertMatchesRegularExpression('/\A[qvxzjkw]{24}\z/', $result);
            self::assertNotSame('ModSecurity', $result);
        }
        // Computed independently using unpack(C*) and a 24-byte array slice before implementation.
        self::assertSame(['qwqkqzzvkwkqxwvjzxwqwvzv', 'qwqkqzzvkwkqxwvjzxwqwvzv',
            'jzvjkqzjqxwxwzwjxqvkqjxx'], $results);
    }

    public function test_emergency_candidates_are_checked_and_rerolled_in_decimal_index_order(): void
    {
        $reject = ['dirty-primary'];
        // This fixture independently enumerates the rejected candidates; fixed index-63 golden below
        // pins decimal encoding and byte order rather than merely reusing the implementation's output.
        for ($i = 0; $i < 63; $i++) {
            $bytes = array_slice(unpack('C*', hash('sha256',
                "funnypot/inert-secret-emergency/v1\0emergency-a\0" . $i, true)), 0, 24);
            $reject[] = implode('', array_map(static fn (int $b): string => 'qvxzjkw'[$b % 7], $bytes));
        }
        $this->withDenylist(['literals' => $reject, 'patterns' => [], 'ownVocabularyPattern' => ''],
            static function (): void {
                $calls = 0;
                $result = InertSecret::derive('emergency-a', static function () use (&$calls): string {
                    $calls++;

                    return 'dirty-primary';
                });
                self::assertSame('jwzjkxzqwjxvzvzjxqvqzjkv', $result);
                self::assertSame(64, $calls);
                self::assertTrue(InertSecret::isClean('"' . $result . '"'));
            });
    }

    public function test_total_exhaustion_throws_only_the_fixed_message_and_numeric_code(): void
    {
        $this->withDenylist(['literals' => ['dirty-primary'], 'patterns' => ['[qvxzjkw]'],
            'ownVocabularyPattern' => ''], static function (): void {
                $calls = 0;
                try {
                    InertSecret::derive('private-key-sentinel', static function () use (&$calls): string {
                        $calls++;

                        return 'dirty-primary';
                    });
                    self::fail('rejecting both candidate families must never return a dirty value');
                } catch (InertSecretExhausted $error) {
                    self::assertSame(64, $calls);
                    self::assertSame('inert-secret-clean-exhausted', $error->getMessage());
                    self::assertSame(0, $error->getCode());
                    self::assertNull($error->getPrevious());
                    self::assertSame(0, (new \ReflectionMethod($error, '__construct'))->getNumberOfParameters());
                }
            });
        self::assertSame('ordinary-value', InertSecret::derive('after-restore', static fn (): string => 'ordinary-value'));
    }

    public function test_representative_common_path_output_hashes_do_not_change(): void
    {
        // Hashes of pre-change public helper output: preserve exact bytes without secret-shaped literals.
        $goldens = [
            0 => ['53ef131aa19868c76adfdcd1050d71be3ef9c7fc1f22a755bc15359a2827fc9a',
                '48f10627d8ea395b3d483746df1e518ca42fdb14e5d6c4550a089f5a6105cab4',
                'aa2fbf5217a17e0a910fd26d339217137b4407816edd9a8d664136e9c0ef649c',
                '021ee1acdafbe06ee41ce63ed70313e7070bfab06a30974b873d88a7289c54fe',
                '49e36efac16e629317e95df06155de76377fc0cae22704916fb053e8e027881b'],
            4242 => ['5461fa4a5f79b4657655cde9b780631622e7cd9b96c1cdb9b3c130f198a7bdfa',
                'da9349bc192b6491e1d6f49fe52f3f74536eecbfe74b51eae74b26563122fc33',
                'f095c39e1ebf88b46cb2045510c16decb0b9f6615406bddb912a21d0a0ee4692',
                'cb5599e5eac00fb163f1728275a8f3c4b2c23ec9a628c205692f65677b5fee9b',
                '777b5cb2b469b2a9735dc2852b4aba4d0a805dd6c09aa9cceffe6ee9ec76269b'],
            2147483647 => ['897f72a58db3f2dfe88b176807c44599613c452218f995c1f9492d53a085e369',
                '472be217df853877023a58fb49c18f4f2768f37f44025cb67949685940fe2f84',
                '5497ffc56a89b76ba511eec4a6d17ae15710fbb49d5f0febb8e5a8fa64b9b6e5',
                '0c7db828cb2e1ac04c3ff6f5950208bc442cb7cee16869d75529e66ae594cce2',
                'ac7553f6fc63a6e79325bdd14676eea895a941b0135faed85e22faa8bb6855aa'],
        ];
        foreach ($goldens as $seed => $hashes) {
            foreach (['apiKey', 'stripeKey', 'resetToken', 'bcryptHash', 'flag'] as $i => $method) {
                $value = InertSecret::$method($seed, 'golden/primary');
                self::assertSame($hashes[$i], hash('sha256', $value), $seed . ':' . $method);
                self::assertTrue(InertSecret::isClean('"' . $value . '"'));
            }
        }
    }

    private function withDenylist(array $denylist, callable $check): void
    {
        $property = new ReflectionProperty(InertSecret::class, 'denylist');
        $property->setAccessible(true);
        $before = $property->getValue();
        try {
            $property->setValue(null, $denylist);
            $check();
        } finally {
            $property->setValue(null, $before);
        }
    }
}
