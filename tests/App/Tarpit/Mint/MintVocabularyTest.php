<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintVocabulary;
use LogicException;
use PHPUnit\Framework\TestCase;

final class MintVocabularyTest extends TestCase
{
    public function test_every_message_renders_with_no_unfilled_placeholder(): void
    {
        $fill = ['company' => 'Palvora', 'wait' => '2 minutes', 'scope' => 'orders:read', 'app' => 'ci-bot'];
        foreach (array_keys(MintVocabulary::MESSAGES) as $key) {
            $vars = array_intersect_key($fill, array_flip(MintVocabulary::placeholders($key)));
            self::assertCount(count(MintVocabulary::placeholders($key)), $vars, "{$key} takes only known fillers");
            $text = MintVocabulary::text($key, $vars);
            self::assertDoesNotMatchRegularExpression('/\{[a-z_]+\}/', $text, $key);
            self::assertNotSame('', $text);
        }
    }

    public function test_a_missing_filler_throws_instead_of_reaching_a_client(): void
    {
        $this->expectException(LogicException::class);
        MintVocabulary::text('expiration_none');
    }

    public function test_the_throttle_counts_requests_not_tokens(): void
    {
        $t = MintVocabulary::text('throttled', ['wait' => MintVocabulary::wait(61)]);
        self::assertSame("You've made too many requests. Try again in 2 minutes.", $t);
        self::assertStringNotContainsString('token', $t);
        self::assertSame('1 minute', MintVocabulary::wait(1));
        self::assertSame('5 minutes', MintVocabulary::wait(300));
    }
}
