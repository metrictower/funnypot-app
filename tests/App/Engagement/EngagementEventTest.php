<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/** The typed event refuses anything outside the closed vocabularies, negative costs and unknown-as-zero LLM usage. */
final class EngagementEventTest extends TestCase
{
    public function test_a_well_formed_event_constructs_and_estimates_context_from_bytes(): void
    {
        $e = new EngagementEvent(Stage::COLLECT, EventKind::LURE_FOLLOWED, 4097, 12, LureId::POLLUTER_LOG, null, true, 0, 0);

        self::assertSame(1025, $e->estimatedContextTokens(), 'ceil(bytes/4) — a deterministic estimate, not a measurement');
        self::assertSame(0, (new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 0, 0))->estimatedContextTokens());
    }

    /** @dataProvider rejected */
    public function test_rejected(callable $make): void
    {
        $this->expectException(InvalidArgumentException::class);
        $make();
    }

    /** @return array<string,array{0:callable}> */
    public static function rejected(): array
    {
        return [
            'unknown stage' => [static fn () => new EngagementEvent('root', EventKind::LURE_FOLLOWED, 1, 1)],
            'unknown kind' => [static fn () => new EngagementEvent(Stage::DISCOVER, 'clicked', 1, 1)],
            'attacker-chosen lure id' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, '/etc/passwd')],
            'artifact id that is a handle, not a stored id' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::ARTIFACT_FETCHED, 1, 1, null, '1.1.2.abc.def')],
            'oversized artifact id' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::ARTIFACT_FETCHED, 1, 1, null, str_repeat('a', 65))],
            'negative bytes' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, -1, 1)],
            'negative wall' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, -1)],
            'negative request units' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, false, null, null, -1)],
            'negative tool turns' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::TOOL_TURN, 1, 1, null, null, false, null, null, 1, -1)],
            'unknown LLM usage recorded as zero' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, false, 0, 0)],
            'unknown LLM usage with tokens only' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, false, null, 5)],
            'available LLM usage with null calls' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, true, null, 0)],
            'available LLM usage with negative tokens' => [static fn () => new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, true, 1, -1)],
        ];
    }

    public function test_observed_zero_and_unknown_are_distinct(): void
    {
        $zero = new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, true, 0, 0);
        $unknown = new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1, null, null, false, null, null);

        self::assertTrue($zero->serverLlmUsageAvailable);
        self::assertSame(0, $zero->serverLlmCalls);
        self::assertFalse($unknown->serverLlmUsageAvailable);
        self::assertNull($unknown->serverLlmCalls);
        self::assertNull($unknown->serverLlmTokens);
    }

    public function test_vocabularies_are_closed_and_stage_ranks_are_ordered(): void
    {
        self::assertCount(9, Stage::all());
        self::assertSame(1, Stage::rank(Stage::DISCOVER));
        self::assertSame(9, Stage::rank(Stage::EXIT));
        self::assertGreaterThan(Stage::rank(Stage::ENUMERATE), Stage::rank(Stage::COLLECT));
        self::assertSame(0, Stage::rank('nope'));
        self::assertSame(Stage::COLLECT, Stage::fromRank(5));
        self::assertNull(Stage::fromRank(42));
        self::assertCount(8, EventKind::all());
        self::assertFalse(LureId::isValid('anything-else'));
        self::assertSame(LureId::POLLUTER_SHADOW, LureId::forPolluterPath('/admin/export/shadow'));
        self::assertNull(LureId::forPolluterPath('/admin/export/other'));
    }
}
