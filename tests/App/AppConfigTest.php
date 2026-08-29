<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Config\AppConfig;
use PHPUnit\Framework\TestCase;

/**
 * AppConfig::fromEnv resolves every FUNNYPOT_* var once, with sane defaults and path bases.
 */
final class AppConfigTest extends TestCase
{
    /** @var string[] */
    private array $keys = [
        'FUNNYPOT_MODE', 'FUNNYPOT_STYLE', 'FUNNYPOT_DB', 'FUNNYPOT_LOG', 'FUNNYPOT_ATTACK',
        'FUNNYPOT_DECOY_ARCHIVE', 'FUNNYPOT_PROTOCOLS', 'FUNNYPOT_RETAIN_DAYS', 'FUNNYPOT_RETAIN_GB',
        'FUNNYPOT_DASHBOARD_PATH', 'FUNNYPOT_CEILING', 'FUNNYPOT_JITTER_MS',
        'FUNNYPOT_ENDLESS_DOWNLOAD', 'FUNNYPOT_DL_CHUNK_MIN_KB', 'FUNNYPOT_DL_CHUNK_MAX_KB',
        'FUNNYPOT_DL_INTERVAL_MS', 'FUNNYPOT_DL_VARY_PCT', 'FUNNYPOT_DL_EASE_PERIOD_S',
        'FUNNYPOT_DL_FALLBACK_CAP_MB', 'FUNNYPOT_APP_PATH', 'FUNNYPOT_HIDE_MAIN', 'FUNNYPOT_CAPTURE_RAW',
    ];

    protected function setUp(): void
    {
        foreach ($this->keys as $k) {
            putenv($k);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->keys as $k) {
            putenv($k);
        }
    }

    public function test_funnypot_page_path_defaults_to_funnypot_and_is_shown(): void
    {
        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('/funnypot', $c->funnypotPath);
        self::assertFalse($c->hideMainPage);
    }

    public function test_funnypot_page_path_and_hide_are_configurable(): void
    {
        putenv('FUNNYPOT_APP_PATH=/ops-console/');
        putenv('FUNNYPOT_HIDE_MAIN=1');
        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('/ops-console', $c->funnypotPath);
        self::assertTrue($c->hideMainPage);
    }

    public function test_raw_capture_is_off_by_default_and_opt_in(): void
    {
        self::assertFalse(AppConfig::fromEnv('/app/demo')->captureRaw);

        putenv('FUNNYPOT_CAPTURE_RAW=1');
        self::assertTrue(AppConfig::fromEnv('/app/demo')->captureRaw);
    }

    public function test_defaults(): void
    {
        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('public', $c->mode);
        self::assertSame('realistic', $c->style);
        self::assertSame('/app/demo/storage/funnypot.sqlite', $c->dbPath);
        self::assertSame('/app/demo/storage/hits.log', $c->logPath);
        self::assertSame('critical', $c->severityCeiling);
        self::assertSame(40, $c->jitterMs);
        self::assertTrue($c->attackEmulation);
        self::assertTrue($c->decoyArchive);
        self::assertTrue($c->protocolsEnabled);
        self::assertSame(0, $c->retainDays);
        self::assertSame('/__fp/', $c->dashboardPath);
    }

    public function test_style_and_http_style_fallback(): void
    {
        putenv('FUNNYPOT_STYLE=malformed');
        $c = AppConfig::fromEnv('/app/demo');
        self::assertSame('malformed', $c->style);      // protocol tier sees the real value
        self::assertTrue($c->isMalformed());
        self::assertSame('realistic', $c->httpStyle()); // HTTP/core tier falls back (core supports realistic|taunt)

        putenv('FUNNYPOT_STYLE=taunt');
        self::assertSame('taunt', AppConfig::fromEnv('/app/demo')->httpStyle());

        putenv('FUNNYPOT_STYLE=nonsense');
        $c2 = AppConfig::fromEnv('/app/demo');
        self::assertSame('realistic', $c2->httpStyle()); // any invalid style -> realistic for HTTP
        self::assertFalse($c2->isMalformed());
    }

    public function test_endless_download_defaults(): void
    {
        $c = AppConfig::fromEnv('/app/demo');

        self::assertTrue($c->endlessDownload);        // on by default
        self::assertSame(100, $c->dlChunkMinKb);
        self::assertSame(200, $c->dlChunkMaxKb);
        self::assertSame(100, $c->dlIntervalMs);
        self::assertSame(50, $c->dlVaryPct);
        self::assertSame(20, $c->dlEasePeriodS);
        self::assertSame(50, $c->dlFallbackCapMb);
    }

    public function test_endless_download_off_and_clamped(): void
    {
        putenv('FUNNYPOT_ENDLESS_DOWNLOAD=0');
        putenv('FUNNYPOT_DL_CHUNK_MIN_KB=0');        // -> clamped up to 1
        putenv('FUNNYPOT_DL_CHUNK_MAX_KB=99999');    // -> clamped down to 1024
        putenv('FUNNYPOT_DL_INTERVAL_MS=1');         // -> clamped up to 10
        putenv('FUNNYPOT_DL_VARY_PCT=250');          // -> clamped down to 95
        putenv('FUNNYPOT_DL_EASE_PERIOD_S=0');       // -> clamped up to 1
        putenv('FUNNYPOT_DL_FALLBACK_CAP_MB=100000'); // -> clamped down to 500
        $c = AppConfig::fromEnv('/app/demo');

        self::assertFalse($c->endlessDownload);
        self::assertSame(1, $c->dlChunkMinKb);
        self::assertSame(1024, $c->dlChunkMaxKb);
        self::assertSame(10, $c->dlIntervalMs);
        self::assertSame(95, $c->dlVaryPct);
        self::assertSame(1, $c->dlEasePeriodS);
        self::assertSame(500, $c->dlFallbackCapMb);
    }

    public function test_env_overrides(): void
    {
        putenv('FUNNYPOT_MODE=stealth');
        putenv('FUNNYPOT_STYLE=taunt');
        putenv('FUNNYPOT_ATTACK=0');
        putenv('FUNNYPOT_PROTOCOLS=0');
        putenv('FUNNYPOT_RETAIN_DAYS=30');
        putenv('FUNNYPOT_RETAIN_GB=2.5');
        putenv('FUNNYPOT_DASHBOARD_PATH=secretconsole');
        putenv('FUNNYPOT_DB=off');

        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('stealth', $c->mode);
        self::assertSame('taunt', $c->style);
        self::assertFalse($c->attackEmulation);
        self::assertFalse($c->protocolsEnabled);
        self::assertSame(30, $c->retainDays);
        self::assertSame(2.5, $c->retainGb);
        self::assertSame('/secretconsole/', $c->dashboardPath);   // normalised with slashes
        self::assertSame('/app/demo/storage/funnypot.sqlite', $c->dbPath); // 'off' no longer disables
    }

    public function test_unknown_mode_falls_back_to_public(): void
    {
        putenv('FUNNYPOT_MODE=banana');
        self::assertSame('public', AppConfig::fromEnv('/app/demo')->mode);
    }

    public function test_threatintel_defaults_off_and_env_overrides(): void
    {
        foreach (['FUNNYPOT_THREATINTEL_REPORT', 'FUNNYPOT_THREATINTEL_URL', 'FUNNYPOT_THREATINTEL_KEY'] as $k) {
            putenv($k);
        }
        $d = AppConfig::fromEnv('/app/demo');
        self::assertFalse($d->threatIntelReport);                                   // off by default
        self::assertSame('https://threatintel.metrictower.com', $d->threatIntelUrl);
        self::assertSame('', $d->threatIntelKey);
        self::assertSame(1000, $d->threatIntelDailyCap);
        self::assertSame(24, $d->threatIntelDedupHours);

        putenv('FUNNYPOT_THREATINTEL_REPORT=on');
        putenv('FUNNYPOT_THREATINTEL_URL=https://ti.example');
        putenv('FUNNYPOT_THREATINTEL_KEY=mnk_sensor_abc');
        $c = AppConfig::fromEnv('/app/demo');
        self::assertTrue($c->threatIntelReport);
        self::assertSame('https://ti.example', $c->threatIntelUrl);
        self::assertSame('mnk_sensor_abc', $c->threatIntelKey);

        foreach (['FUNNYPOT_THREATINTEL_REPORT', 'FUNNYPOT_THREATINTEL_URL', 'FUNNYPOT_THREATINTEL_KEY'] as $k) {
            putenv($k);
        }
    }

    public function test_persona_seed_is_stable_and_derived(): void
    {
        putenv('FUNNYPOT_PERSONA_SEED=my-host');
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($this->expectedPersonaSeed('my-host'), $c->personaSeed);
        putenv('FUNNYPOT_PERSONA_SEED');
    }

    public function test_persona_seed_default_ignores_public_le_domain(): void
    {
        putenv('FUNNYPOT_LE_DOMAIN=example-honeypot.com');
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($this->expectedPersonaSeed('funnypot'), $c->personaSeed); // public cert CN must never seed identity
        putenv('FUNNYPOT_LE_DOMAIN');
    }

    public function test_persona_seed_uses_private_secret_and_seed_takes_precedence(): void
    {
        putenv('FUNNYPOT_PERSONA_SECRET=super-private-value');
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($this->expectedPersonaSeed('super-private-value'), $c->personaSeed);
        self::assertNotSame($this->expectedPersonaSeed('funnypot'), $c->personaSeed);

        putenv('FUNNYPOT_PERSONA_SEED=explicit-override');
        $c2 = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($this->expectedPersonaSeed('explicit-override'), $c2->personaSeed);

        putenv('FUNNYPOT_PERSONA_SECRET');
        putenv('FUNNYPOT_PERSONA_SEED');
    }

    private function expectedPersonaSeed(string $src): int
    {
        return (int) hexdec(substr(hash('sha256', 'funnypot-persona|' . $src), 0, 15));
    }
}
