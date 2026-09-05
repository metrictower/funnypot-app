<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ResolvedServiceProfile;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;
use Funnypot\App\Service\ServiceHealthProbeRegistry;
use Funnypot\App\Service\ServiceHeartbeatWriter;
use Funnypot\App\Service\ServiceProcessControl;
use Funnypot\App\Service\ServiceProfileStore;
use Funnypot\App\Service\ServiceRuntimeStore;
use Funnypot\App\Service\ServiceSupervisor;
use PHPUnit\Framework\TestCase;

final class ServiceSupervisorTest extends TestCase
{
    private string $dir = '';
    private ServiceCatalog $catalog;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-sup-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $this->catalog = ServiceCatalog::fromPackage();
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    /** @param list<string> $serviceIds @param list<string> $processIds */
    private function resolved(array $serviceIds, array $processIds, string $variant = 'v1'): ResolvedServiceProfile
    {
        return new ResolvedServiceProfile('named', 'linux-web', 'linux', 'spv1_' . str_repeat($variant === 'v1' ? 'd' : 'e', 32), $serviceIds, $processIds, [], [], [], [], []);
    }

    private function manifest(ResolvedServiceProfile $r, int $rev = 1): ServiceExposureManifest
    {
        return ServiceExposureManifest::build(
            'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64), $rev, hash('sha256', 'd' . $rev), $rev,
            $r->profileTuple(), $r->serviceIds, $r->processIds, [], $r->exposures, [], [], [],
        );
    }

    private function probes(bool $pass): ServiceHealthProbeRegistry
    {
        $fn = static fn (string $h, int $p, int $t): bool => $pass;

        return new ServiceHealthProbeRegistry($fn, $fn);
    }

    public function testBootConvergePublishesReconcilingBeforeAnyFork(): void
    {
        $log = [];
        $proc = $this->fakeProc($log);
        $writer = $this->spyWriter($log);
        $r = $this->resolved(['ssh'], ['ssh']);
        $runtime = new ServiceRuntimeStore($this->dir . '/runtime.sqlite');
        $runtime->bootstrapAccept($this->manifest($r));

        $sup = new ServiceSupervisor($runtime, $proc, $this->probes(true), $writer, $this->catalog);
        $state = $sup->bootConverge($r);

        self::assertSame('ready', $state);
        self::assertSame('publish:reconciling', $log[0]);
        $firstStart = array_search('start:ssh', $log, true);
        $reconcile = array_search('publish:reconciling', $log, true);
        self::assertLessThan($firstStart, $reconcile, 'first heartbeat must precede the first fork');
        self::assertSame(ServiceRuntimeStore::MODE_HEALTH, $runtime->acceptanceMode());
    }

    public function testFirstBootProbeFailureStaysDegradedWithNoRollback(): void
    {
        $log = [];
        $proc = $this->fakeProc($log);
        $writer = $this->spyWriter($log);
        $r = $this->resolved(['ssh'], ['ssh']);
        $runtime = new ServiceRuntimeStore($this->dir . '/runtime.sqlite');
        $runtime->bootstrapAccept($this->manifest($r));
        $before = $runtime->acceptedArtifact()->hash();

        $sup = new ServiceSupervisor($runtime, $proc, $this->probes(false), $writer, $this->catalog);
        $state = $sup->bootConverge($r);

        self::assertSame('degraded', $state);
        self::assertSame(ServiceRuntimeStore::MODE_BOOTSTRAP, $runtime->acceptanceMode(), 'a failed first boot does not flip to health');
        self::assertSame($before, $runtime->acceptedArtifact()->hash(), 'the accepted artifact is untouched');
        self::assertContains('publish:degraded', $log);
    }

    public function testCutoverStopsBeforeStartAndCommitsThenPersistsThenPublishes(): void
    {
        $log = [];
        $running = ['ftp']; // an old-only listener that must stop before the new one starts
        $proc = $this->fakeProc($log, $running);
        $writer = $this->spyWriter($log);
        $persistLog = [];
        $old = $this->resolved(['ftp'], ['ftp']);
        $new = $this->resolved(['ssh'], ['ssh'], 'v2');
        $runtime = new ServiceRuntimeStore($this->dir . '/runtime.sqlite');
        $runtime->bootstrapAccept($this->manifest($old));

        $desired = new ServiceProfileStore($this->dir . '/service-profile.sqlite');
        $desired->initializeIfEmpty($this->fields('old'), 'system');

        $newManifest = $this->manifest($new, 2);
        $sup = new ServiceSupervisor($runtime, $proc, $this->probes(true), $writer, $this->catalog, null, static function ($m) use (&$persistLog, &$log): void {
            $log[] = 'persist';
            $persistLog[] = $m;
        });
        $state = $sup->cutover($old, $new, $newManifest, false, $desired, 2, $this->fields('old')['input_json'], 1);

        self::assertSame('ready', $state);
        $stopFtp = array_search('stop:ftp', $log, true);
        $startSsh = array_search('start:ssh', $log, true);
        self::assertLessThan($startSsh, $stopFtp, 'removals reaped before additions (no simultaneous superset)');
        $persist = array_search('persist', $log, true);
        $publishReady = array_search('publish:ready', $log, true);
        self::assertLessThan($publishReady, $persist, 'persistent manifest rewritten before the heartbeat');
        self::assertCount(1, $persistLog, 'persistent manifest rewritten exactly once');
        self::assertSame(2, $runtime->acceptedArtifact()->revision());
    }

    public function testCutoverFailureRestoresLkgAndRollsBackUnderTheGuard(): void
    {
        $log = [];
        $proc = $this->fakeProc($log, ['ftp']);
        $writer = $this->spyWriter($log);
        $old = $this->resolved(['ftp'], ['ftp']);
        $new = $this->resolved(['ssh'], ['ssh'], 'v2');
        $runtime = new ServiceRuntimeStore($this->dir . '/runtime.sqlite');
        $runtime->bootstrapAccept($this->manifest($old));
        $desired = new ServiceProfileStore($this->dir . '/service-profile.sqlite');
        $desired->initializeIfEmpty($this->fields('old'), 'system');
        $desired->applyCas(1, $this->fields('new')['preview_hash'], fn () => $this->fields('new'), 'op', '1.1.1.1'); // rev 2

        $sup = new ServiceSupervisor($runtime, $proc, $this->probes(false), $writer, $this->catalog);
        $state = $sup->cutover($old, $new, $this->manifest($new, 2), false, $desired, 2, $this->fields('old')['input_json'], 2);

        self::assertSame('degraded', $state);
        self::assertContains('start:ftp', $log, 'LKG process set restored');
        self::assertSame('rollback', $desired->audits()[0]['result']);
        self::assertSame(3, $desired->currentRevision());
    }

    /** @return array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string} */
    private function fields(string $tag): array
    {
        return [
            'input_json' => '{"mode":"named","bundle_id":"' . $tag . '"}',
            'resolved_json' => '{}',
            'preview_hash' => hash('sha256', 'preview-' . $tag),
            'desired_hash' => hash('sha256', 'desired-' . $tag),
            'catalog_hash' => str_repeat('c', 64),
            'published_hash' => str_repeat('p', 64),
        ];
    }

    /** @param list<string> $running */
    private function fakeProc(array &$log, array $running = []): ServiceProcessControl
    {
        return new class($log, $running) implements ServiceProcessControl {
            /** @param list<string> $running */
            public function __construct(private array &$log, private array $running)
            {
            }

            public function start(string $processId): void
            {
                $this->log[] = 'start:' . $processId;
                if (!in_array($processId, $this->running, true)) {
                    $this->running[] = $processId;
                }
            }

            public function stop(string $processId): void
            {
                $this->log[] = 'stop:' . $processId;
                $this->running = array_values(array_filter($this->running, static fn (string $p): bool => $p !== $processId));
            }

            public function isAlive(string $processId): bool
            {
                return in_array($processId, $this->running, true);
            }

            public function running(): array
            {
                $r = $this->running;
                sort($r);

                return $r;
            }
        };
    }

    private function spyWriter(array &$log): ServiceHeartbeatWriter
    {
        return new class($log) implements ServiceHeartbeatWriter {
            public function __construct(private array &$log)
            {
            }

            public function publish(EffectiveExposureArtifact $artifact, string $state, string $acceptanceMode, array $processHealth, int $statusRevision, ?int $writtenAt = null): void
            {
                $this->log[] = 'publish:' . $state;
            }
        };
    }
}
