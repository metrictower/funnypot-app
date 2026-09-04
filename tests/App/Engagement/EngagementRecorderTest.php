<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/** The observer never throws and never sleeps: a store fault is a returned status, timed from outside. */
final class EngagementRecorderTest extends TestCase
{
    private function recorder(EngagementStore $store): EngagementRecorder
    {
        $key = AnalyticsKey::fromRaw(str_repeat('k', 32));

        return new EngagementRecorder($store, new EpisodeResolver($key, new SignedHandle($key)), static fn (): int => 1_700_000_000);
    }

    public function test_a_throwing_store_is_absorbed_into_a_fault_status(): void
    {
        $r = $this->recorder(new class implements EngagementStore {
            public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
            {
                throw new \RuntimeException('disk on fire');
            }
        });

        $status = $r->record('203.0.113.9', 'curl/8', new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1));
        self::assertSame(EngagementStore::FAULT, $status);
        self::assertGreaterThan(0.0, $r->lastCallMs());
        self::assertLessThan(100.0, $r->lastCallMs(), 'no retry, no sleep');
    }

    public function test_status_passes_through_and_the_key_reaches_the_store(): void
    {
        $seen = null;
        $store = new class($seen) implements EngagementStore {
            public function __construct(private &$seen)
            {
            }

            public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
            {
                $this->seen = $key;

                return self::SHED;
            }
        };
        $r = $this->recorder($store);
        self::assertSame(EngagementStore::SHED, $r->record('203.0.113.9', 'curl/8', new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 1, 1)));
        self::assertInstanceOf(EpisodeKey::class, $seen);
        self::assertStringNotContainsString('203.0.113.9', $seen->digest);
    }

    public function test_user_agent_is_read_case_insensitively(): void
    {
        self::assertSame('curl/8', EngagementRecorder::userAgentOf(new RequestContext('GET', '/', '', ['user-agent' => 'curl/8'])));
        self::assertSame('curl/8', EngagementRecorder::userAgentOf(new RequestContext('GET', '/', '', ['User-Agent' => 'curl/8'])));
        self::assertSame('', EngagementRecorder::userAgentOf(new RequestContext('GET', '/', '', [])));
    }
}
