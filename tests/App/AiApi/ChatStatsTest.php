<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatStats;
use PHPUnit\Framework\TestCase;

/**
 * Deterministic $now + $rand injection lets these assert exact shapes (regex / equality) instead of
 * depending on wall-clock time or real randomness.
 */
final class ChatStatsTest extends TestCase
{
    private ChatStats $stats;

    protected function setUp(): void
    {
        $i = 0;
        $rand = function (int $min, int $max) use (&$i): int {
            $i++;
            $span = $max - $min + 1;

            return $min + ($i * 7) % max(1, $span);
        };
        $this->stats = new ChatStats(1769904000, $rand);
    }

    public function test_openai_id_shape(): void
    {
        self::assertMatchesRegularExpression('/^chatcmpl-[A-Za-z0-9]{24}$/', $this->stats->openAiId());
    }

    public function test_anthropic_id_shape(): void
    {
        self::assertMatchesRegularExpression('/^msg_[A-Za-z0-9]{24}$/', $this->stats->anthropicId());
    }

    public function test_system_fingerprint_shape(): void
    {
        self::assertMatchesRegularExpression('/^fp_[0-9a-f]{8}$/', $this->stats->systemFingerprint());
    }

    public function test_openai_created_echoes_injected_now(): void
    {
        self::assertSame(1769904000, $this->stats->openAiCreated());
    }

    public function test_ollama_created_at_is_rfc3339_with_fractional_seconds(): void
    {
        self::assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/',
            $this->stats->ollamaCreatedAt()
        );
    }

    public function test_now_rfc3339_shape(): void
    {
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $this->stats->nowRfc3339());
    }

    public function test_eval_count_is_positive_and_scales_with_pieces(): void
    {
        self::assertGreaterThan(0, $this->stats->evalCount(5));
        self::assertGreaterThanOrEqual($this->stats->evalCount(1), $this->stats->evalCount(20));
    }

    public function test_durations_ns_returns_four_positive_ints(): void
    {
        $d = $this->stats->durationsNs(5);
        self::assertCount(4, $d);
        foreach ($d as $v) {
            self::assertIsInt($v);
            self::assertGreaterThan(0, $v);
        }
    }

    public function test_context_ints_non_empty(): void
    {
        $ctx = $this->stats->contextInts();
        self::assertNotEmpty($ctx);
        foreach ($ctx as $v) {
            self::assertIsInt($v);
        }
    }
}
