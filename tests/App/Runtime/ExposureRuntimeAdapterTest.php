<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Runtime;

use Funnypot\App\Runtime\ExposureRuntimeAdapter;
use Funnypot\App\Runtime\RuntimePolicyException;
use Funnypot\App\Service\CanonicalJson;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;
use PHPUnit\Framework\TestCase;

final class ExposureRuntimeAdapterTest extends TestCase
{
    private string $temp = '';

    protected function tearDown(): void
    {
        if ($this->temp !== '') {
            exec('rm -rf ' . escapeshellarg($this->temp));
        }
    }

    private static function manifest(): ServiceExposureManifest
    {
        $catalog = ServiceCatalog::fromPackage();

        return ServiceExposureManifest::build(
            'deploy', 'exact', $catalog->catalogHash(), 'fpph1_' . str_repeat('b', 64), 1, str_repeat('c', 64), 1,
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('d', 32)],
            ['ssh'], ['ssh'],
            [
                ['endpoint_id' => 'http-80', 'transport' => 'tcp', 'container_port' => 80],
                ['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222],
            ],
            ['tcp/2222'], ['deploy tcp/80:80', 'deploy tcp/2222:2222'], [], [],
        );
    }

    public function testMapsOnlyTheExactEndpointOwnerKinds(): void
    {
        $rows = (new ExposureRuntimeAdapter())->bindings(self::manifest());
        self::assertSame([
            ['endpoint_id' => 'http-80', 'transport' => 'tcp', 'container_port' => 80, 'role_id' => 'edge'],
            ['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222, 'role_id' => 'protocols'],
        ], array_map(static fn ($b): array => $b->toArray(), $rows));
    }

    public function testCanonicalPersistentRoundTripMapsTheSameBindings(): void
    {
        $this->temp = sys_get_temp_dir() . '/fp-runtime-' . bin2hex(random_bytes(6));
        $dir = $this->temp . '/.funnypot/services';
        mkdir($dir, 0700, true);
        chmod($this->temp . '/.funnypot', 0700);
        chmod($dir, 0700);
        $path = $dir . '/exposure-manifest.json';
        file_put_contents($path, self::manifest()->toJson());
        chmod($path, 0600);

        $bindings = (new ExposureRuntimeAdapter())->bindings(ServiceExposureManifest::fromPersistentFile($path));
        self::assertSame(['edge', 'protocols'], array_map(static fn ($binding): string => $binding->roleId, $bindings));
    }

    public function testAcceptedNginxAliasMapsToEdgeOnlyWhenItsServiceIsInEffectiveClosure(): void
    {
        $catalog = ServiceCatalog::fromPackage();
        $manifest = ServiceExposureManifest::build(
            'deploy', 'exact', $catalog->catalogHash(), 'fpph1_' . str_repeat('b', 64), 1, str_repeat('c', 64), 1,
            ['mode' => 'manual', 'bundle' => null, 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('d', 32)],
            ['web-alt-http'], [], [['endpoint_id' => 'http-8080', 'transport' => 'tcp', 'container_port' => 8080]],
            ['tcp/8080'], ['deploy tcp/8080:8080'], ['http-8080'], [],
        );
        $bindings = (new ExposureRuntimeAdapter())->bindings($manifest, $catalog);
        self::assertSame([['endpoint_id' => 'http-8080', 'transport' => 'tcp', 'container_port' => 8080, 'role_id' => 'edge']], array_map(static fn ($b): array => $b->toArray(), $bindings));
    }

    /** @dataProvider tamperedDocuments */
    public function testRejectsTamperedStaleDuplicateAndOutOfClosureManifests(callable $mutate): void
    {
        $doc = self::manifest()->toArray();
        $mutate($doc);
        $doc = self::rehashPlan($doc);
        $manifest = ServiceExposureManifest::fromArray($doc);
        $this->expectException(RuntimePolicyException::class);
        (new ExposureRuntimeAdapter())->bindings($manifest);
    }

    public static function tamperedDocuments(): iterable
    {
        yield 'catalog mismatch' => [static function (array &$d): void { $d['catalog_hash'] = str_repeat('0', 64); }];
        yield 'duplicate bind id' => [static function (array &$d): void { $d['bind_endpoints'][] = $d['bind_endpoints'][0]; }];
        yield 'duplicate bind socket' => [static function (array &$d): void {
            $d['bind_endpoints'][] = ['endpoint_id' => 'ssh-alias-22', 'transport' => 'tcp', 'container_port' => 2222];
        }];
        yield 'listener outside accepted set' => [static function (array &$d): void {
            $d['bind_endpoints'][] = ['endpoint_id' => 'mysql-3306', 'transport' => 'tcp', 'container_port' => 3306];
        }];
        yield 'nginx alias outside accepted set' => [static function (array &$d): void {
            $d['bind_endpoints'][] = ['endpoint_id' => 'http-8080', 'transport' => 'tcp', 'container_port' => 8080];
        }];
        yield 'duplicate published tuple' => [static function (array &$d): void { $d['published'][] = $d['published'][0]; }];
        yield 'outer effective mismatch' => [static function (array &$d): void { $d['desired_exposures'][] = 'tcp/9999'; }];
    }

    /** @param array<string,mixed> $doc @return array<string,mixed> */
    private static function rehashPlan(array $doc): array
    {
        $keys = [
            'schema', 'target', 'publish_mode', 'catalog_hash', 'identity_public_hash', 'desired_revision',
            'desired_hash', 'profile', 'desired_service_ids', 'desired_process_ids', 'bind_endpoints',
            'desired_exposures', 'published', 'published_hash', 'nginx_http_alias_endpoint_ids',
            'nginx_https_alias_endpoint_ids',
        ];
        $plan = [];
        foreach ($keys as $key) {
            $plan[$key] = $doc[$key];
        }
        $doc['plan_hash'] = CanonicalJson::digest(ServiceExposureManifest::PLAN_HASH_DOMAIN, $plan);

        return $doc;
    }
}
