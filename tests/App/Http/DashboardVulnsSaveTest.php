<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0250 §2.7/§4.5 — the emulation-catalog write (`?admin=vulns-save`) is atomic (tmp+rename, so a
 * concurrent reader — EmulationPolicy::fromPackage(), read on every honeypot request — never sees a torn
 * file) and not world-writable (0644, was an implicit direct write under a 0777 dir).
 */
final class DashboardVulnsSaveTest extends TestCase
{
    private const PASS = 'operator-secret-pw-3';

    /** @var string[] */
    private array $tmp = [];
    private ?string $vulnsPath = null;

    private int $origUmask = 0;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        // A permissive umask (0) so the explicit chmod(0644) calls are the ONLY thing that can produce
        // 0644 — under this repo's actual sandbox umask (022), file_put_contents()'s own default mode
        // (0666) is ALREADY masked down to 0644 with no explicit chmod at all, which would let a dropped
        // chmod() call pass this test by environmental coincidence.
        $this->origUmask = umask(0);
        $dir = sys_get_temp_dir() . '/fp_vulns_' . bin2hex(random_bytes(6));
        $this->vulnsPath = $dir . '/nested/funnypot-vulns.json'; // nested so @mkdir(...,true) is exercised
        putenv('FUNNYPOT_VULNS=' . $this->vulnsPath);
    }

    protected function tearDown(): void
    {
        umask($this->origUmask);
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
        if ($this->vulnsPath !== null) {
            $dir = dirname($this->vulnsPath);
            @unlink($this->vulnsPath);
            @unlink($this->vulnsPath . '.tmp');
            @rmdir($dir);
            @rmdir(dirname($dir));
        }
        putenv('FUNNYPOT_VULNS');
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_vulnstest_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:DashboardController,1:AdminAuth} an authed controller + its AdminAuth, CSRF-ready */
    private function authedController(): array
    {
        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', self::PASS);
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        self::assertTrue($res['ok']);

        $hit = new SqliteHitStore($this->path('hit'));
        $c = new DashboardController(
            $hit,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            AppConfig::fromEnv(sys_get_temp_dir()),
            sys_get_temp_dir(),
            null,
            null,
            $hit,
            $auth,
            null,
        );

        return [$c, $auth];
    }

    /** @return array<string,mixed>|null */
    private function call(DashboardController $c, string $action, array $post): ?array
    {
        $_POST = $post;
        ob_start();
        @$c->admin($action);

        return json_decode((string) ob_get_clean(), true);
    }

    public function test_vulns_save_is_atomic_and_not_world_writable(): void
    {
        [$c, $auth] = $this->authedController();
        $csrf = (string) $auth->csrfToken();

        $json = $this->call($c, 'vulns-save', ['csrf' => $csrf, 'changes' => json_encode(new \stdClass())]);
        self::assertTrue($json['ok'] ?? false, 'the save must report success: ' . json_encode($json));

        self::assertFileExists($this->vulnsPath, 'the file must exist after a successful save');
        self::assertFileDoesNotExist($this->vulnsPath . '.tmp', 'no .tmp residue after a successful atomic rename');

        $raw = (string) file_get_contents($this->vulnsPath);
        $decoded = json_decode($raw, true);
        self::assertIsArray($decoded, 'the written file must be valid JSON');
        self::assertArrayHasKey('vulns', $decoded);
        self::assertSame(1, $decoded['version'] ?? null);

        $perms = fileperms($this->vulnsPath) & 0777;
        self::assertSame(0644, $perms, sprintf('perms must be 0644, got 0%o', $perms));
        self::assertSame(0, $perms & 0022, 'the file must not be group/world-WRITABLE');
    }

    /**
     * A save that fails to rename (simulated by making the parent dir unwritable to rename() — here by
     * pre-creating a DIRECTORY at the target path, which rename() cannot replace) must report ok:false
     * and must never leave a torn/partial funnypot-vulns.json behind — only the pre-existing (or absent)
     * state, plus the removed .tmp.
     */
    public function test_vulns_save_reports_failure_and_leaves_no_torn_file_on_a_failed_rename(): void
    {
        [$c, $auth] = $this->authedController();
        $csrf = (string) $auth->csrfToken();

        @mkdir(dirname($this->vulnsPath), 0755, true);
        @mkdir($this->vulnsPath); // a DIRECTORY sits where the file should go — rename() onto it fails

        $json = $this->call($c, 'vulns-save', ['csrf' => $csrf, 'changes' => json_encode(new \stdClass())]);
        self::assertFalse($json['ok'] ?? true, 'a failed rename must report ok:false, not a false success');
        self::assertFileDoesNotExist($this->vulnsPath . '.tmp', 'the failed .tmp must be cleaned up, not left as debris');
        self::assertDirectoryExists($this->vulnsPath, 'the pre-existing state (the directory) is untouched — no torn write landed');

        @rmdir($this->vulnsPath);
    }
}
