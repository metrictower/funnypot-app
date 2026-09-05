<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Admin\ServiceProfileAdmin;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Identity\ServiceProfileIdentity;
use Funnypot\App\Service\ServiceCapabilityPolicy;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceProfileInput;
use Funnypot\App\Service\ServiceProfilePreparer;
use Funnypot\App\Service\ServiceProfileResolver;
use Funnypot\App\Service\ServiceProfileStore;
use Funnypot\App\Service\ServicePaths;
use Funnypot\App\Service\ServiceStatusReader;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

final class DashboardServiceProfileTest extends TestCase
{
    private const PASS = 'correct-horse-battery-staple';
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-dsp-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/storage', 0777, true);
        $_GET = [];
        $_POST = [];
        // Bootstrap a desired profile (revision 1) so apply has something to CAS against.
        $this->preparer()->prepare();
    }

    protected function tearDown(): void
    {
        $_GET = [];
        $_POST = [];
        unset($_COOKIE[AdminAuth::COOKIE]);
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    private function paths(): ServicePaths
    {
        return ServicePaths::forStorage($this->dir . '/storage', $this->dir . '/run', $this->dir . '/status');
    }

    private function preparer(): ServiceProfilePreparer
    {
        return new ServiceProfilePreparer(
            $this->paths(),
            ServiceCatalog::fromPackage(),
            ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('admin-test')),
            ServiceCapabilityPolicy::create('deploy', ['docker' => false]),
            'deploy',
            'exact',
            'fpph1_' . str_repeat('f', 64),
            null,
            null,
            static fn (string $k) => false,
        );
    }

    private function admin(): ServiceProfileAdmin
    {
        $paths = $this->paths();
        $catalog = ServiceCatalog::fromPackage();
        $identity = ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('admin-test'));
        $policy = ServiceCapabilityPolicy::create('deploy', ['docker' => false]);

        return new ServiceProfileAdmin(
            $catalog,
            new ServiceProfileStore($paths->desiredDbPath()),
            new ServiceStatusReader($paths->statusFile()),
            $this->preparer(),
            new ServiceProfileResolver(),
            $policy,
            $identity,
        );
    }

    private function auth(): AdminAuth
    {
        $auth = new AdminAuth($this->dir . '/auth.sqlite');
        $auth->createOrResetUser('admin', self::PASS);

        return $auth;
    }

    private function controller(?AdminAuth $auth): DashboardController
    {
        $hit = new SqliteHitStore($this->dir . '/hit.sqlite');
        $admin = $this->admin();

        return new DashboardController(
            $hit,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            AppConfig::fromEnv(sys_get_temp_dir()),
            sys_get_temp_dir(),
            null,
            null,
            $hit,
            $auth,
            null,
            null,
            static fn () => $admin,
        );
    }

    /** @return array<string,mixed>|null */
    private function call(DashboardController $c, string $action): ?array
    {
        ob_start();
        @$c->admin($action);

        return json_decode((string) ob_get_clean(), true);
    }

    public function testUnauthenticatedServicesCatalogIsForbidden(): void
    {
        unset($_COOKIE[AdminAuth::COOKIE]);
        $json = $this->call($this->controller($this->auth()), 'services-catalog');
        self::assertSame('forbidden', $json['error'] ?? null);
    }

    public function testAuthenticatedCatalogAndStatusRead(): void
    {
        $auth = $this->auth();
        $auth->login('admin', self::PASS, '203.0.113.5');
        $c = $this->controller($auth);
        $catalog = $this->call($c, 'services-catalog');
        self::assertTrue($catalog['ok'] ?? false);
        self::assertArrayHasKey('bundles', $catalog);
        $status = $this->call($c, 'services-status');
        self::assertTrue($status['ok'] ?? false);
        self::assertSame('missing', $status['status_freshness'] ?? null); // no heartbeat published in prep
    }

    public function testApplyRequiresCsrf(): void
    {
        $auth = $this->auth();
        $auth->login('admin', self::PASS, '203.0.113.5');
        $_POST = ['input' => json_encode(['mode' => 'named', 'bundle_id' => 'windows-business', 'max_exposure' => 10])];
        $json = $this->call($this->controller($auth), 'services-apply');
        self::assertSame('bad csrf token', $json['error'] ?? null);
    }

    public function testPreviewThenApplyAdvancesTheRevisionAndAStaleApplyConflicts(): void
    {
        $auth = $this->auth();
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        $csrf = (string) $res['csrf'];
        $c = $this->controller($auth);

        $inputArr = ['mode' => 'named', 'bundle_id' => 'windows-business', 'max_exposure' => 10];
        $_POST = ['input' => json_encode($inputArr), 'csrf' => $csrf];
        $preview = $this->call($c, 'services-preview');
        self::assertTrue($preview['ok'] ?? false, json_encode($preview));
        self::assertSame(1, $preview['current_revision']);
        $previewHash = (string) $preview['preview_hash'];

        $_POST = ['input' => json_encode($inputArr), 'csrf' => $csrf, 'expected_revision' => '1', 'preview_hash' => $previewHash];
        $apply = $this->call($c, 'services-apply');
        self::assertTrue($apply['ok'] ?? false, json_encode($apply));
        self::assertSame(2, $apply['revision']);

        // A stale apply (expected_revision still 1) conflicts.
        $_POST = ['input' => json_encode($inputArr), 'csrf' => $csrf, 'expected_revision' => '1', 'preview_hash' => $previewHash];
        $conflict = $this->call($c, 'services-apply');
        self::assertFalse($conflict['ok'] ?? true);
        self::assertSame('stale-revision', $conflict['reason'] ?? null);
    }

    public function testMalformedInputIsRejected(): void
    {
        $auth = $this->auth();
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        $_POST = ['input' => json_encode(['mode' => 'bananas']), 'csrf' => (string) $res['csrf']];
        $json = $this->call($this->controller($auth), 'services-preview');
        self::assertFalse($json['ok'] ?? true);
    }
}
