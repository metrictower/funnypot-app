<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

/**
 * Server health + storage telemetry for the operator dashboard (FP-0209).
 *
 * The SIP call-recording honeypot writes `.wav`/`.ulaw` audio to demo/storage/recordings and payload
 * drops (WARs, FastCGI webshells, WebDAV uploads) are quarantined under demo/storage/quarantine; an
 * aggressive campaign can fill the host disk. Silent exhaustion breaks SQLite writes and logging, so the
 * dashboard needs free/total disk, the recordings/quarantine/database footprints, and a `low_disk` flag
 * to warn the operator BEFORE the disk is full.
 *
 * Pure read, fully guarded: a missing directory, an unreadable file, or a failed stat degrades to
 * zero/null/false — never an exception (a dashboard 500 is a honeypot tell). The disk prober is
 * injectable so the behaviour (used-percent, the low-disk thresholds) is unit-testable deterministically
 * without depending on the test host's real free space. The directory walk is bounded (MAX_SCAN) so a
 * flood of recordings can never make the feed walk unboundedly.
 */
final class ServerStorageTelemetry
{
    private const MAX_SCAN = 100000;
    private const LOW_DISK_BYTES = 2147483648; // 2 GiB
    private const LOW_DISK_FRACTION = 0.15;     // 15% free

    /** @var callable(string):array{free:?int,total:?int} */
    private $diskProbe;

    public function __construct(
        private string $storageBase,
        private string $dbPath,
        ?callable $diskProbe = null
    ) {
        $this->diskProbe = $diskProbe ?? static function (string $path): array {
            $free = @\disk_free_space($path);
            $total = @\disk_total_space($path);

            return [
                'free' => \is_float($free) ? (int) $free : null,
                'total' => \is_float($total) ? (int) $total : null,
            ];
        };
    }

    /**
     * @return array{disk_free_bytes:?int,disk_total_bytes:?int,disk_used_percent:?int,
     *   recordings_bytes:int,recordings_count:int,database_bytes:int,
     *   quarantine_bytes:int,quarantine_count:int,low_disk:bool}
     */
    public function collect(): array
    {
        $recordings = $this->dirFootprint($this->storageBase . '/recordings');
        $quarantine = $this->dirFootprint($this->storageBase . '/quarantine');

        $disk = ($this->diskProbe)($this->storageBase);
        $free = $disk['free'] ?? null;
        $total = $disk['total'] ?? null;

        $usedPercent = null;
        if ($free !== null && $total !== null && $total > 0) {
            $usedPercent = (int) \round((($total - $free) / $total) * 100);
        }

        $dbBytes = 0;
        if (\is_file($this->dbPath)) {
            $dbBytes = (int) (@\filesize($this->dbPath) ?: 0);
        }

        return [
            'disk_free_bytes' => $free,
            'disk_total_bytes' => $total,
            'disk_used_percent' => $usedPercent,
            'recordings_bytes' => $recordings['bytes'],
            'recordings_count' => $recordings['count'],
            'database_bytes' => $dbBytes,
            'quarantine_bytes' => $quarantine['bytes'],
            'quarantine_count' => $quarantine['count'],
            'low_disk' => self::isLowDisk($free, $total),
        ];
    }

    /**
     * Critical when under 2 GiB free OR under 15% free (the spec thresholds). Only decidable when both
     * disk figures resolved — an unknowable mount is never flagged (no false alarm).
     */
    public static function isLowDisk(?int $free, ?int $total): bool
    {
        if ($free === null || $total === null || $total <= 0) {
            return false;
        }

        return $free < self::LOW_DISK_BYTES || ($free / $total) < self::LOW_DISK_FRACTION;
    }

    /**
     * Total byte size + regular-file count of a flat directory (recordings/quarantine are flat). Bounded
     * by MAX_SCAN; a missing/unreadable directory returns zeros.
     *
     * @return array{bytes:int,count:int}
     */
    private function dirFootprint(string $dir): array
    {
        if (!\is_dir($dir)) {
            return ['bytes' => 0, 'count' => 0];
        }
        $handle = @\opendir($dir);
        if ($handle === false) {
            return ['bytes' => 0, 'count' => 0];
        }
        $bytes = 0;
        $count = 0;
        while (($entry = \readdir($handle)) !== false) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (!\is_file($path)) {
                continue;
            }
            $size = @\filesize($path);
            if ($size !== false) {
                $bytes += (int) $size;
            }
            $count++;
            if ($count >= self::MAX_SCAN) {
                break;
            }
        }
        \closedir($handle);

        return ['bytes' => $bytes, 'count' => $count];
    }
}
