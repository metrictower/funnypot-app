<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Storage\Sqlite;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0242b — dashboard.public_view enforcement (spec §6.4, §7.8, plan T-PV-1/2). An UNAUTHENTICATED
 * visitor sees only what the knob allows; an authenticated operator ALWAYS sees the full view. The
 * enforcement fails toward LESS exposure: the registry/AppConfig baseline is 'none', a config-read
 * fault resolves to that baseline, and any unknown value clamps to 'none'.
 *
 * FP-0250 2.8: a 'none' 404 is no longer an empty body — it is the honeypot's own believable 404
 * (HoneypotController::serveBelievable404()), closing the bare-GET oracle where the one zero-byte 404
 * on the box precisely spotted the hidden dashboard path on a plain GET sweep. Asserted here via
 * {@see believable404Body()} against the SAME bytes any other probed path gets.
 */
final class DashboardPublicViewTest extends TestCase
{
    private const PASS = 'operator-secret-pw';

    /** @var string[] */
    private array $tmp = [];

    /** @var string[] recording fixture files written into the real recordings dir, cleaned up after */
    private array $recFixtures = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        putenv('FUNNYPOT_PUBLIC_VIEW');
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
            @rmdir($f); // breakStore() may have left a directory at the db path
            @unlink(dirname($f) . '/config.gen');
        }
        foreach ($this->recFixtures as $f) {
            @unlink($f);
        }
        $this->tmp = [];
        $this->recFixtures = [];
        putenv('FUNNYPOT_PUBLIC_VIEW');
        unset($_GET, $_POST, $_SERVER['HTTP_RANGE'], $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    /**
     * Write a minimal .ulaw recording into the (hardcoded) recordings dir recording() reads, and return
     * its id. The dir is the real demo/storage/recordings; the file is a random id, removed in tearDown.
     */
    private function recordingFixture(): string
    {
        $id = 'pvtest_' . bin2hex(random_bytes(6));
        $dir = dirname(__DIR__, 3) . '/demo/storage/recordings';
        @mkdir($dir, 0777, true);
        $file = $dir . '/' . $id . '.ulaw';
        file_put_contents($file, str_repeat("\x7f", 160)); // 20ms of mu-law silence
        $this->recFixtures[] = $file;

        return $id;
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function configFor(string $view): AppConfig
    {
        putenv('FUNNYPOT_PUBLIC_VIEW=' . $view);
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        putenv('FUNNYPOT_PUBLIC_VIEW');

        return $c;
    }

    private function controller(AppConfig $config, ?AdminAuth $auth): DashboardController
    {
        $hit = new SqliteHitStore($this->path('hit'));

        return new DashboardController(
            $hit,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            $config,
            sys_get_temp_dir(),
            null,
            null,
            $hit,
            $auth,
            null,
        );
    }

    private function authedAuth(): AdminAuth
    {
        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', self::PASS);
        $auth->login('admin', self::PASS, '203.0.113.5');

        return $auth;
    }

    private function body(callable $fn): string
    {
        ob_start();
        @$fn();

        return (string) ob_get_clean();
    }

    /** The exact believable-404 body (FP-0250 2.8) — captured through the SAME public helper so a
     *  future edit to the shared constant is picked up here automatically, never hand-duplicated. */
    private function believable404Body(): string
    {
        return $this->body(static fn () => HoneypotController::serveBelievable404());
    }

    // --- T-PV-1: none ⇒ unauth sees nothing, authed sees full ---

    public function test_none_unauthenticated_shell_and_feed_emit_nothing(): void
    {
        $config = $this->configFor('none');
        self::assertSame('none', $config->dashboardPublicView);
        $c = $this->controller($config, $this->auth_noSession());
        $decoy = $this->believable404Body();

        self::assertSame($decoy, $this->body(fn () => $c->shell('/__fp/')), 'a 404 decoy emits no dashboard HTML — the honeypot 404, not empty (FP-0250 2.8)');
        self::assertSame($decoy, $this->body(fn () => $c->feed()), 'the feed emits the honeypot 404 to an unauth visitor under none, not empty bytes');
    }

    public function test_none_authenticated_operator_sees_the_full_view(): void
    {
        $config = $this->configFor('none');
        $c = $this->controller($config, $this->authedAuth());

        $shell = $this->body(fn () => $c->shell('/__fp/'));
        self::assertStringContainsString('id=rows', $shell, 'the operator gets the full live table');
        self::assertStringContainsString('window.FP_AUTHED=true', $shell, 'the shell marks the operator authenticated');

        $feed = json_decode($this->body(fn () => $c->feed()), true);
        self::assertIsArray($feed);
        self::assertArrayHasKey('stats', $feed, 'the operator gets the full feed payload');
    }

    // --- minimal ⇒ chrome only, no rows/controls; authed still full ---

    public function test_minimal_unauthenticated_is_chrome_only_with_an_empty_feed(): void
    {
        $config = $this->configFor('minimal');
        $c = $this->controller($config, $this->auth_noSession());

        $shell = $this->body(fn () => $c->shell('/__fp/'));
        self::assertNotSame('', $shell, 'minimal renders a page');
        self::assertStringContainsString('honeypot', $shell, 'the chrome (lead) is present');
        self::assertStringNotContainsString('id=rows', $shell, 'no live event table in minimal');
        self::assertStringNotContainsString('id=analytics', $shell, 'no admin controls in minimal');

        $feed = json_decode($this->body(fn () => $c->feed()), true);
        self::assertIsArray($feed);
        self::assertSame([], $feed['rows'], 'minimal feed returns no event rows');
    }

    public function test_full_unauthenticated_sees_todays_public_feed(): void
    {
        $config = $this->configFor('full');
        $c = $this->controller($config, $this->auth_noSession());

        $shell = $this->body(fn () => $c->shell('/__fp/'));
        self::assertStringContainsString('id=rows', $shell, 'full keeps the live table');
        self::assertStringContainsString('window.FP_AUTHED=false', $shell, 'but the visitor is not authenticated');

        $feed = json_decode($this->body(fn () => $c->feed()), true);
        self::assertArrayHasKey('stats', $feed, 'full feed carries the stats payload');
    }

    // --- recording() obeys the same public-visibility gate (captured audio is sensitive) ---

    public function test_none_hides_recordings_from_an_unauthenticated_visitor(): void
    {
        $id = $this->recordingFixture();
        $config = $this->configFor('none');
        $c = $this->controller($config, $this->auth_noSession());

        // Even though the recording FILE exists, an unauthenticated visitor under 'none' gets the
        // honeypot's believable 404 with NO audio bytes (FP-0250 2.8 — not an empty body).
        self::assertSame($this->believable404Body(), $this->body(fn () => $c->recording($id)), 'no audio may leak to an unauth visitor under none');
    }

    public function test_authenticated_operator_is_served_the_recording_under_none(): void
    {
        $id = $this->recordingFixture();
        $config = $this->configFor('none');
        $c = $this->controller($config, $this->authedAuth());

        $body = $this->body(fn () => $c->recording($id));
        self::assertStringStartsWith('RIFF', $body, 'the operator is served the WAV audio regardless of public_view');
    }

    public function test_full_serves_recordings_to_the_public(): void
    {
        $id = $this->recordingFixture();
        $config = $this->configFor('full');
        $c = $this->controller($config, $this->auth_noSession());

        // Under explicit full, the public recording behaviour is unchanged (served).
        self::assertStringStartsWith('RIFF', $this->body(fn () => $c->recording($id)));
    }

    // --- T-PV-2: fail-safe direction ---

    public function test_unknown_value_clamps_to_none(): void
    {
        $config = $this->configFor('garbage');
        self::assertSame('none', $config->dashboardPublicView, 'an unknown value clamps to the least-exposed level');
        $c = $this->controller($config, $this->auth_noSession());
        self::assertSame($this->believable404Body(), $this->body(fn () => $c->shell('/__fp/')), 'and an unknown value 404s the unauth visitor with the honeypot 404');
    }

    public function test_config_read_fault_resolves_to_the_baseline_none(): void
    {
        // A stored 'full' row that becomes UNREADABLE (corrupt db) must not leave 'full' resolved: the
        // store fails safe to the baseline, and the baseline is the least-exposed 'none'. Planted via a
        // raw SQL row (not ConfigStore::set(), which FP-0250 2.3 now rejects outright when it would
        // loosen exposure below the CURRENT env ceiling) while env FUNNYPOT_PUBLIC_VIEW=full so the row
        // is a legitimate, non-clamped override right up until the fault — isolating THIS test's fault
        // path (overrides() itself throwing, an orthogonal fail-safe mechanism to 2.3's protected-knob
        // clamp) from 2.3's own read-time clamp, which ConfigStoreProtectedTest covers directly.
        $dbPath = $this->path('cfg');
        $raw = Sqlite::open($dbPath);
        $raw->exec('CREATE TABLE IF NOT EXISTS config (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT ""
        )');
        $raw->exec('CREATE TABLE IF NOT EXISTS config_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)');
        $raw->exec("INSERT INTO config (key, value, updated_at, updated_by) VALUES ('dashboard.public_view', 'full', '2026-01-01T00:00:00Z', 'legacy')");
        $raw->exec("INSERT INTO config_meta (k, v) VALUES ('generation', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1");
        @file_put_contents(dirname($dbPath) . '/config.gen', '1');
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $planted = new ConfigStore($dbPath);
        self::assertSame('full', $planted->get('dashboard.public_view', 'FUNNYPOT_PUBLIC_VIEW', 'none'), 'sanity: the planted row resolves (env=full is its own ceiling) before the fault');
        putenv('FUNNYPOT_PUBLIC_VIEW'); // unset again — the fault below must resolve to the DEFAULT baseline 'none', not env

        // Make the store UNREADABLE: drop the db + its WAL sidecars and put a DIRECTORY at the path so
        // any open/query throws (a plain corrupt-header file is silently recovered from the intact -wal,
        // which would not exercise the fault path). The sentinel still says "there is a generation", so
        // overrides() attempts the read and hits the fail-safe branch → the env/default baseline.
        $this->breakStore($dbPath);
        $faulted = new ConfigStore($dbPath);
        $config = AppConfig::fromStore($faulted, sys_get_temp_dir());

        self::assertSame('none', $config->dashboardPublicView, 'a config-read fault resolves to the baseline none, never full');

        $c = $this->controller($config, $this->auth_noSession());
        self::assertSame($this->believable404Body(), $this->body(fn () => $c->shell('/__fp/')), 'and the unauth visitor then 404s with the honeypot 404');
    }

    public function test_documented_edge_a_store_fault_falls_back_to_env_not_the_stored_override(): void
    {
        // Reviewer SHOULD-FIX #2 (documented, accepted edge): fromStore falls back to getenv on a store
        // fault. So if an operator sets env FUNNYPOT_PUBLIC_VIEW=full AND stores a tighter 'none', a
        // store read fault resolves to the ENV 'full' — MORE exposure than the stored level. This test
        // PINS that direction so it is understood: leave the env unset (or at the least-exposed level
        // ever wanted) and a store fault can never loosen a stored override.
        $dbPath = $this->path('cfg');
        $store = new ConfigStore($dbPath);
        $store->set('dashboard.public_view', 'none', 'admin', '203.0.113.5');
        $this->breakStore($dbPath); // force the read fault (see the note in the fault test above)

        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $config = AppConfig::fromStore(new ConfigStore($dbPath), sys_get_temp_dir());
        putenv('FUNNYPOT_PUBLIC_VIEW');

        self::assertSame('full', $config->dashboardPublicView, 'a store fault falls back to the env value — the documented edge');
    }

    /**
     * Render the config store at $dbPath permanently unreadable: remove the db + its WAL sidecars and
     * put a directory in their place so every subsequent open/query throws (exercising the store's
     * fail-safe read branch). The sentinel file is left intact so currentGen() still reports a
     * generation and overrides() actually attempts the doomed read.
     */
    private function breakStore(string $dbPath): void
    {
        foreach (['', '-wal', '-shm'] as $suf) {
            @unlink($dbPath . $suf);
        }
        @mkdir($dbPath);
    }

    /** A wired AdminAuth with a user but NO active session for this request. */
    private function auth_noSession(): AdminAuth
    {
        unset($_COOKIE[AdminAuth::COOKIE]);
        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', self::PASS);

        return $auth;
    }
}
