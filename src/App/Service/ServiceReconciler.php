<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * Pure listener reconciliation: given the desired process-id set, the currently running set and
 * whether the base family/variant changed, produce the stop/start/keep plan. It computes sets only;
 * the supervisor enforces the ordering (stop and reap every removal before starting any addition, so
 * at no instant are old-only and new-only processes both retained). When the base family changes,
 * common processes are stopped and started so stale persona state cannot survive.
 */
final class ServiceReconciler
{
    /**
     * @param list<string> $desired
     * @param list<string> $running
     * @return array{stop:list<string>,start:list<string>,keep:list<string>}
     */
    public static function plan(array $desired, array $running, bool $baseFamilyChanged): array
    {
        $desiredSet = array_fill_keys($desired, true);
        $runningSet = array_fill_keys($running, true);

        $stop = [];
        $start = [];
        $keep = [];

        foreach ($running as $pid) {
            if (!isset($desiredSet[$pid])) {
                $stop[$pid] = true;          // removed
            } elseif ($baseFamilyChanged) {
                $stop[$pid] = true;          // common, but restart on a family change
            } else {
                $keep[$pid] = true;          // common, unchanged
            }
        }
        foreach ($desired as $pid) {
            if (!isset($runningSet[$pid])) {
                $start[$pid] = true;         // new
            } elseif ($baseFamilyChanged) {
                $start[$pid] = true;         // common, restart on a family change
            }
        }

        return [
            'stop' => self::sortedKeys($stop),
            'start' => self::sortedKeys($start),
            'keep' => self::sortedKeys($keep),
        ];
    }

    /**
     * @param array<string,bool> $set
     * @return list<string>
     */
    private static function sortedKeys(array $set): array
    {
        $keys = array_keys($set);
        sort($keys);

        return $keys;
    }
}
