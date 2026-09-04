<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigRegistry;
use Funnypot\App\Engagement\EngagementCaps;
use PHPUnit\Framework\TestCase;

/** The engagement knobs: opt-in, clamped both ways, key env-only, retention capped by hit retention and 30 days. */
final class EngagementConfigTest extends TestCase
{
    private const ENV = [
        'FUNNYPOT_ENGAGEMENT', 'FUNNYPOT_ANALYTICS_KEY', 'FUNNYPOT_ENGAGEMENT_IDLE_GAP_S', 'FUNNYPOT_ENGAGEMENT_LIFETIME_S',
        'FUNNYPOT_ENGAGEMENT_MAX_EVENTS', 'FUNNYPOT_ENGAGEMENT_MAX_ARTIFACTS', 'FUNNYPOT_ENGAGEMENT_BYTES_PER_EP_MB',
        'FUNNYPOT_ENGAGEMENT_GLOBAL_ROWS', 'FUNNYPOT_ENGAGEMENT_GLOBAL_BYTES_MB', 'FUNNYPOT_ENGAGEMENT_RETAIN_DAYS', 'FUNNYPOT_RETAIN_DAYS',
    ];

    protected function tearDown(): void
    {
        foreach (self::ENV as $k) {
            putenv($k);
        }
    }

    public function test_defaults_are_off_with_the_documented_caps(): void
    {
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertFalse($c->engagementEnabled);
        self::assertSame('', $c->analyticsKey);
        self::assertSame(600, $c->engagementIdleGapS);
        self::assertSame(7200, $c->engagementLifetimeS);
        self::assertSame(2000, $c->engagementMaxEvents);
        self::assertSame(256, $c->engagementMaxArtifacts);
        self::assertSame(2, $c->engagementBytesPerEpMb);
        self::assertSame(250000, $c->engagementGlobalRows);
        self::assertSame(256, $c->engagementGlobalBytesMb);
        self::assertSame(30, $c->engagementRetainDays);
    }

    public function test_knobs_are_clamped_floor_and_ceiling(): void
    {
        putenv('FUNNYPOT_ENGAGEMENT=1');
        putenv('FUNNYPOT_ENGAGEMENT_IDLE_GAP_S=5');
        putenv('FUNNYPOT_ENGAGEMENT_LIFETIME_S=999999');
        putenv('FUNNYPOT_ENGAGEMENT_MAX_EVENTS=0');
        putenv('FUNNYPOT_ENGAGEMENT_RETAIN_DAYS=90');
        putenv('FUNNYPOT_ENGAGEMENT_GLOBAL_BYTES_MB=-1');
        $c = AppConfig::fromEnv(sys_get_temp_dir());

        self::assertTrue($c->engagementEnabled);
        self::assertSame(60, $c->engagementIdleGapS);
        self::assertSame(21600, $c->engagementLifetimeS);
        self::assertSame(1, $c->engagementMaxEvents);
        self::assertSame(30, $c->engagementRetainDays);
        self::assertSame(1, $c->engagementGlobalBytesMb);

        $caps = EngagementCaps::fromConfig($c);
        self::assertSame(60, $caps->idleGapS);
        self::assertSame(1024 * 1024, $caps->globalMaxBytes);
    }

    public function test_retention_ceiling_never_exceeds_source_hits_or_30_days(): void
    {
        self::assertSame(30, EngagementCaps::retainCeiling(30, 0), 'unbounded hits ⇒ the 30-day cap alone');
        self::assertSame(7, EngagementCaps::retainCeiling(30, 7), 'never longer than the hit retention');
        self::assertSame(3, EngagementCaps::retainCeiling(3, 7));
        self::assertSame(30, EngagementCaps::retainCeiling(30, 90));
        self::assertSame(1, EngagementCaps::retainCeiling(0, 0), 'never 0 (unbounded)');

        putenv('FUNNYPOT_RETAIN_DAYS=5');
        self::assertSame(5, EngagementCaps::fromConfig(AppConfig::fromEnv(sys_get_temp_dir()))->retainDays);
    }

    public function test_analytics_key_is_env_only_and_the_caps_are_a_registry_group(): void
    {
        $reg = new ConfigRegistry();
        self::assertNull($reg->keyForEnv('FUNNYPOT_ANALYTICS_KEY'), 'secrets are never registry knobs');
        self::assertSame('engagement.enabled', $reg->keyForEnv('FUNNYPOT_ENGAGEMENT'));
        self::assertSame([true, '1800'], $reg->validate('engagement.idle_gap_s', '99999'));
        self::assertSame([true, '30'], $reg->validate('engagement.retain_days', '365'));
        foreach ($reg->entries() as $key => $e) {
            if (str_starts_with($key, 'engagement.')) {
                self::assertSame('Engagement', $e['group']);
                self::assertFalse($e['live'], 'store + caps are built at bootstrap');
            }
        }
    }
}
