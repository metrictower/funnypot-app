<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\InertSecret;
use PHPUnit\Framework\TestCase;

/**
 * FP-0272 §6.5 — the pure artifact/manifest renderer: deterministic golden snapshots, bounded valid
 * NDJSON, the two-mismatch/one-match hash relationship, a fingerprint-clean surface, and a source scan
 * proving no filesystem/network/subprocess/compression/request API is present.
 */
final class AttritionArtifactRendererTest extends TestCase
{
    private const SEED = 4242;
    private const JOB = 'abababababababababababababababab';

    private function renderer(): AttritionArtifactRenderer
    {
        return new AttritionArtifactRenderer();
    }

    public function test_golden_snapshot_hashes_are_stable(): void
    {
        $r = $this->renderer();
        self::assertSame('66e5d0db813b67404f1a2ed9ca908e854d226e06fdffaaf5d0f77faf6f67894d', $r->renderSnapshot(self::SEED, self::JOB, 0)->sha256);
        self::assertSame('12943ed033f8163c7e4750a185870cdd208723ccfe8c43c16c1021520b6b9a27', $r->renderSnapshot(self::SEED, self::JOB, 1)->sha256);
        self::assertSame('9250ecfc291ab14e7f67925d72405bb69cce76fa6a2e7fbf7f815bb3a360dc18', $r->renderSnapshot(self::SEED, self::JOB, 2)->sha256);
        // Deterministic.
        self::assertSame($r->renderSnapshot(self::SEED, self::JOB, 0)->sha256, $r->renderSnapshot(self::SEED, self::JOB, 0)->sha256);
        // Snapshots differ.
        self::assertNotSame($r->renderSnapshot(self::SEED, self::JOB, 0)->sha256, $r->renderSnapshot(self::SEED, self::JOB, 1)->sha256);
    }

    public function test_artifact_is_bounded_valid_ndjson_ending_in_lf(): void
    {
        $r = $this->renderer();
        for ($k = 0; $k < 3; $k++) {
            $art = $r->renderSnapshot(self::SEED, self::JOB, $k);
            self::assertLessThanOrEqual(AttritionLimits::ARTIFACT_MAX_BYTES, $art->length);
            self::assertSame($art->length, strlen($art->body));
            self::assertSame("\n", substr($art->body, -1), 'body ends with LF');
            self::assertSame(hash('sha256', $art->body), $art->sha256);
            $lines = explode("\n", rtrim($art->body, "\n"));
            self::assertLessThanOrEqual(96, count($lines));
            foreach ($lines as $line) {
                $obj = json_decode($line, true);
                self::assertIsArray($obj, 'each NDJSON line decodes');
                self::assertSame(['seq', 'ts', 'actor', 'action', 'resource', 'object', 'outcome', 'request_id'], array_keys($obj));
            }
        }
    }

    public function test_snapshot_mapping_produces_two_mismatches_then_a_match(): void
    {
        $r = $this->renderer();
        // The manifest for generation n declares hash(snapshot n); the artifact serves snapshot n+1 frozen at 2.
        self::assertSame(1, AttritionArtifactRenderer::artifactSnapshotIndex(0));
        self::assertSame(2, AttritionArtifactRenderer::artifactSnapshotIndex(1));
        self::assertSame(2, AttritionArtifactRenderer::artifactSnapshotIndex(2));
        for ($gen = 0; $gen <= 2; $gen++) {
            $declared = $r->renderSnapshot(self::SEED, self::JOB, $gen)->sha256;
            $served = $r->renderSnapshot(self::SEED, self::JOB, AttritionArtifactRenderer::artifactSnapshotIndex($gen))->sha256;
            if ($gen < 2) {
                self::assertNotSame($declared, $served, "generation {$gen} must mismatch");
            } else {
                self::assertSame($declared, $served, 'the final generation matches');
            }
        }
    }

    public function test_manifest_is_fixed_shape_and_refresh_only_before_the_final(): void
    {
        $r = $this->renderer();
        $hash = str_repeat('a', 64);
        $g0 = $r->renderManifest($hash, '/admin/export/artifacts/A', '/admin/export/manifests/M1', 0);
        self::assertNotNull($g0);
        self::assertStringContainsString($hash . '  audit-export.ndjson', $g0->body);
        self::assertStringContainsString('# artifact: /admin/export/artifacts/A', $g0->body);
        self::assertStringContainsString('# refresh: /admin/export/manifests/M1', $g0->body);
        self::assertLessThanOrEqual(AttritionLimits::MANIFEST_MAX_BYTES, $g0->length);

        $g2 = $r->renderManifest($hash, '/admin/export/artifacts/A2', null, 2);
        self::assertNotNull($g2);
        self::assertStringNotContainsString('refresh', $g2->body, 'the final manifest carries no refresh link');
    }

    public function test_rendered_surface_is_fingerprint_clean(): void
    {
        $r = $this->renderer();
        for ($k = 0; $k < 3; $k++) {
            self::assertTrue(InertSecret::isClean($r->renderSnapshot(self::SEED, self::JOB, $k)->body), "snapshot {$k} carries no denylisted signature");
        }
        $m = $r->renderManifest(str_repeat('9', 64), '/admin/export/artifacts/A', '/admin/export/manifests/M', 0);
        self::assertTrue(InertSecret::isClean($m->body));
    }

    public function test_renderer_source_uses_no_forbidden_api(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Tarpit/Attrition/AttritionArtifactRenderer.php');
        foreach ([
            'file_get_contents', 'fopen', 'fwrite', 'file_put_contents', 'scandir', 'glob', 'unlink',
            'curl_', 'fsockopen', 'stream_socket', 'exec(', 'shell_exec', 'proc_open', 'system(', 'popen',
            'gzencode', 'gzcompress', 'gzdeflate', 'ZipArchive', 'eval(', 'include ', 'require ',
            '$_GET', '$_POST', '$_SERVER', '$_REQUEST', 'php://', 'getenv',
        ] as $forbidden) {
            self::assertStringNotContainsString($forbidden, $src, "the renderer must not use {$forbidden}");
        }
    }
}
