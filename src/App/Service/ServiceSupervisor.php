<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The profile-aware reconciliation state machine. It replaces unconditional listener spawning:
 * newly-enabled catalog listeners start, disabled listeners stop and stay stopped, and between
 * cutovers heartbeat process health is child liveness (no periodic socket probe). Probes run ONLY at
 * first-boot convergence and cutover. Canonical web runs independently and is never in this set.
 *
 * The supervisor publishes its first `reconciling` heartbeat BEFORE its first fork or probe, so the
 * entrypoint's --wait-ready and the web reader always find a fresh heartbeat during the first-boot
 * probe window. A first-boot probe failure stays `degraded` and retries — it never appends a rollback
 * (the loop guard); a real cutover commits effective/LKG then rewrites the persistent manifest then
 * publishes the heartbeat, in that order, or restores LKG on failure.
 */
final class ServiceSupervisor
{
    /** @var callable():int */
    private $clock;
    /** @var callable(ServiceExposureManifest):void */
    private $persistManifest;

    public function __construct(
        private ServiceRuntimeStore $runtime,
        private ServiceProcessControl $proc,
        private ServiceHealthProbeRegistry $probes,
        private ServiceHeartbeatWriter $publisher,
        private ServiceCatalog $catalog,
        ?callable $clock = null,
        ?callable $persistManifest = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        $this->persistManifest = $persistManifest ?? static function (ServiceExposureManifest $m): void {};
    }

    /**
     * First run after bootstrap acceptance: start the accepted set and probe it. On success flip the
     * runtime acceptance mode to `health` (the artifact bytes/revision/generation/hash are unchanged,
     * so downstream views do not rotate); on failure stay degraded and retry — never a rollback.
     *
     * @return string 'ready' | 'degraded'
     */
    public function bootConverge(ResolvedServiceProfile $resolved): string
    {
        $accepted = $this->runtime->acceptedArtifact();
        // 1. First heartbeat BEFORE any fork or probe.
        $this->publisher->publish($accepted, 'reconciling', ServiceRuntimeStore::MODE_BOOTSTRAP, [], 1);
        // 2. Start the accepted set.
        foreach ($resolved->processIds as $pid) {
            $this->proc->start($pid);
        }
        // 3. Probe.
        [$ok, $health] = $this->probeSet($resolved);
        if ($ok) {
            $this->runtime->confirmHealth($accepted);
            $this->publisher->publish($accepted, 'ready', ServiceRuntimeStore::MODE_HEALTH, $health, 2);

            return 'ready';
        }
        $this->publisher->publish($accepted, 'degraded', ServiceRuntimeStore::MODE_BOOTSTRAP, $health, 2);

        return 'degraded';
    }

    /**
     * A live cutover to a new resolved desired. Stop-before-start with no simultaneous superset; commit
     * effective/LKG, rewrite the persistent manifest, then publish — or restore LKG and roll back under
     * the loop guard on failure.
     *
     * @return string 'ready' | 'degraded'
     */
    public function cutover(
        ResolvedServiceProfile $old,
        ResolvedServiceProfile $new,
        ServiceExposureManifest $newManifest,
        bool $baseFamilyChanged,
        ServiceProfileStore $desired,
        int $newRevision,
        string $lkgInputJson,
        int $lkgFailedGuardRevision,
    ): string {
        $lease = $desired->claimForReconcile($newRevision);
        $this->publisher->publish($this->runtime->acceptedArtifact(), 'reconciling', ServiceRuntimeStore::MODE_HEALTH, [], 1);

        $plan = ServiceReconciler::plan($new->processIds, $this->proc->running(), $baseFamilyChanged);
        foreach ($plan['stop'] as $pid) {
            $this->proc->stop($pid);
        }
        foreach ($plan['start'] as $pid) {
            $this->proc->start($pid);
        }
        [$ok, $health] = $this->probeSet($new);
        if ($ok) {
            $this->runtime->commitHealth($newManifest);            // 1. runtime store commit
            ($this->persistManifest)($newManifest);                 // 2. persistent manifest rewrite
            $this->publisher->publish($newManifest->effectiveArtifact(), 'ready', ServiceRuntimeStore::MODE_HEALTH, $health, 2); // 3. heartbeat
            $desired->finishReconcile($lease);

            return 'ready';
        }

        // Failure: stop the additions and restore the exact prior (LKG) process set.
        foreach ($plan['start'] as $pid) {
            $this->proc->stop($pid);
        }
        foreach ($old->processIds as $pid) {
            $this->proc->start($pid);
        }
        // Loop guard: append a system rollback only when the failed revision is still current AND its
        // set differs from LKG's — rollbackClaimed enforces the revision half; a same-set (first-boot)
        // case is handled by bootConverge (no cutover). Here a genuine cutover failure rolls back to LKG.
        $desired->rollbackClaimed($lease, $lkgFailedGuardRevision, static function () use ($lkgInputJson): array {
            return [
                'input_json' => $lkgInputJson,
                'resolved_json' => '{}',
                'preview_hash' => hash('sha256', 'lkg-restore'),
                'desired_hash' => hash('sha256', $lkgInputJson),
                'catalog_hash' => str_repeat('0', 64),
                'published_hash' => str_repeat('0', 64),
            ];
        }, 'health-failed');
        $this->publisher->publish($this->runtime->acceptedArtifact(), 'degraded', ServiceRuntimeStore::MODE_HEALTH, $health, 2);

        return 'degraded';
    }

    /**
     * @return array{0:bool,1:array<string,string>}
     */
    private function probeSet(ResolvedServiceProfile $resolved): array
    {
        $ok = true;
        $health = [];
        foreach ($resolved->serviceIds as $sid) {
            $desc = $this->catalog->descriptor($sid);
            if ($desc === null || $desc->processUnits === 0) {
                continue;
            }
            $pass = $this->probes->probe($desc);
            foreach ($desc->endpoints as $ep) {
                if ($ep->processId !== null && $ep->ownerKind === 'listener') {
                    $health[$ep->processId] = $pass ? 'alive' : 'failed';
                }
            }
            $ok = $ok && $pass;
        }

        return [$ok, $health];
    }
}
