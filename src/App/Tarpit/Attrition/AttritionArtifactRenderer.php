<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

use Funnypot\App\Tarpit\InertSecret;

/**
 * The pure renderer for the fake audit export (FP-0272 §6.4/§6.5), append-only revision
 * `attrition-export/v1`. Given only typed, code-owned inputs — the install persona seed, the job id, and a
 * snapshot index — it emits deterministic NDJSON: at most 96 complete lines, stopping before the 32 KiB
 * cap and never truncating a line, each line built through {@see InertSecret::derive()} so no generated
 * byte trips the served-fingerprint denylist. It reads no request value, file, database, environment, URL,
 * socket, or process, and runs no compression, reflection, or dynamic code loading — every input is given.
 *
 * Snapshots differ by index, so the same job renders distinct bytes per generation. The manifest for
 * generation n declares the hash of snapshot n while the artifact endpoint serves snapshot n+1 (frozen at
 * the last snapshot), modelling data that advanced during finalization: two mismatches, then one match.
 */
final class AttritionArtifactRenderer
{
    public const REVISION = 'attrition-export/v1';
    private const MAX_LINES = 96;
    private const FILENAME = 'audit-export.ndjson';

    /** The closed audit-action vocabulary. Neutral, inert, carries no scanner/product signature. */
    private const ACTIONS = ['record.read', 'record.export', 'index.build', 'archive.read', 'checksum.verify'];

    /** The snapshot the artifact endpoint serves for a manifest generation: n+1, frozen at the last. */
    public static function artifactSnapshotIndex(int $generation): int
    {
        return min($generation + 1, AttritionLimits::GENERATIONS - 1);
    }

    public function renderSnapshot(int $personaSeed, string $jobId, int $snapshot): RenderedAttritionArtifact
    {
        $body = '';
        for ($i = 0; $i < self::MAX_LINES; $i++) {
            $line = $this->line($personaSeed, $jobId, $snapshot, $i) . "\n";
            if (strlen($body) + strlen($line) > AttritionLimits::ARTIFACT_MAX_BYTES) {
                break;
            }
            $body .= $line;
        }

        return new RenderedAttritionArtifact($body, strlen($body), hash('sha256', $body));
    }

    /**
     * Build MANIFEST.sha256 for one generation: a fixed neutral filename, a code-owned revision/snapshot
     * comment, the declared snapshot hash, the relative artifact URL, and — only when a next generation
     * exists — the relative refresh URL. Returns null if it would exceed the 4 KiB cap.
     */
    public function renderManifest(string $declaredHash, string $artifactUrl, ?string $nextManifestUrl, int $generation): ?RenderedAttritionManifest
    {
        $lines = [
            '# audit export manifest revision ' . self::REVISION,
            '# snapshot generation ' . $generation,
            $declaredHash . '  ' . self::FILENAME,
            '# artifact: ' . $artifactUrl,
        ];
        if ($nextManifestUrl !== null) {
            $lines[] = '# refresh: ' . $nextManifestUrl;
        }
        $body = implode("\n", $lines) . "\n";
        if (strlen($body) > AttritionLimits::MANIFEST_MAX_BYTES) {
            return null;
        }

        return new RenderedAttritionManifest($body, strlen($body));
    }

    private function line(int $seed, string $jobId, int $snapshot, int $i): string
    {
        $key = $seed . '|' . self::REVISION . '|' . $jobId . '|s' . $snapshot . '|' . $i;

        return InertSecret::derive($key, static function (string $k) use ($i): string {
            $h = static fn (string $field, int $n): string => substr(hash('sha256', $k . '|' . $field), 0, $n);
            $action = self::ACTIONS[hexdec(substr(hash('sha256', $k . '|action'), 0, 4)) % count(self::ACTIONS)];
            $ts = 1700000000 + (hexdec(substr(hash('sha256', $k . '|ts'), 0, 8)) % 60000000);

            return (string) json_encode([
                'seq' => $i,
                'ts' => $ts,
                'actor' => 'u_' . $h('actor', 10),
                'action' => $action,
                'resource' => '/records/' . $h('resource', 8),
                'object' => 'obj_' . $h('object', 12),
                'outcome' => 'ok',
                'request_id' => 'r_' . $h('request', 16),
            ], JSON_UNESCAPED_SLASHES);
        });
    }
}
