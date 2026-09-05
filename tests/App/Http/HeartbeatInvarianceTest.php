<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceStatusPublisher;
use PHPUnit\Framework\TestCase;

/**
 * The B2 gate. The web role must never vary an attacker-facing byte on runtime status heartbeat
 * availability: the full response (status line, headers, body) to a fixed request set is byte-identical
 * whether the heartbeat is fresh, stale, missing or corrupt. demo/index.php reads the heartbeat every
 * request (through EffectiveServiceProfileReader) and forwards only ->profile(), so this test is
 * non-vacuous — the reader IS in the request path — yet the responses cannot change.
 *
 * The comparison's sensitivity is proven by a control: a handler that leaks freshness (a stale-only
 * 503) is caught by the same equality check.
 */
final class HeartbeatInvarianceTest extends TestCase
{
    use DashboardHttpServerTrait;

    protected function tearDown(): void
    {
        $this->dashboardCleanupTmpDirs();
    }

    private static function artifact(): EffectiveExposureArtifact
    {
        return EffectiveExposureArtifact::create(
            1, 1, 'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64),
            str_repeat('c', 64), str_repeat('d', 64),
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('e', 32)],
            ['ssh'], ['ssh'], ['tcp/2222'],
        );
    }

    /** Rewrite the heartbeat file into the requested state. */
    private function setState(string $statusDir, string $state): void
    {
        $file = $statusDir . '/effective.json';
        if (is_file($file)) {
            @chmod($file, 0644);
            @unlink($file);
        }
        if ($state === 'missing') {
            return;
        }
        if ($state === 'corrupt') {
            file_put_contents($file, 'not a heartbeat');
            @chmod($file, 0444);

            return;
        }
        $writtenAt = $state === 'stale' ? time() - 120 : time();
        (new ServiceStatusPublisher($file))->publish(self::artifact(), 'ready', 'health', ['ssh' => 'alive'], 1, $writtenAt);
    }

    /** Strip volatile bytes (Date, nonces, ids) so only heartbeat-driven differences remain. */
    private static function normalize(int $status, array $headers, string $body): string
    {
        unset($headers['date']);
        ksort($headers);
        $blob = 'STATUS ' . $status . "\n";
        foreach ($headers as $k => $v) {
            $blob .= $k . ': ' . $v . "\n";
        }
        $blob .= "\n" . $body;
        // Collapse per-request nonces / long hex / base64 tokens (these vary regardless of heartbeat).
        $blob = preg_replace('/[A-Fa-f0-9]{16,}/', 'HEX', $blob) ?? $blob;
        $blob = preg_replace('/[A-Za-z0-9+\/]{24,}={0,2}/', 'TOKEN', $blob) ?? $blob;

        return $blob;
    }

    public function testAttackerFacingResponsesAreIdenticalAcrossHeartbeatStates(): void
    {
        $data = $this->dashboardTempDir('fp_hb_data');
        $statusDir = $this->dashboardTempDir('fp_hb_status');
        $env = $this->dashboardBootEnv($data, ['FUNNYPOT_SERVICE_STATUS_DIR' => $statusDir]);

        $this->setState($statusDir, 'fresh');
        $root = dirname(__DIR__, 3);
        [$proc, $pipes, $port] = $this->startDashboardServer($root . '/demo/index.php', $root . '/demo', $env);

        $paths = ['/wp-login.php', '/.git/config', '/xmlrpc.php', '/actuator/health'];
        $baseline = null;
        try {
            foreach (['fresh', 'stale', 'missing', 'corrupt'] as $state) {
                $this->setState($statusDir, $state);
                $captured = [];
                foreach ($paths as $p) {
                    [$status, $headers, $body] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', $p);
                    $captured[$p] = self::normalize($status, $headers, $body);
                }
                if ($baseline === null) {
                    $baseline = $captured;
                    // sanity: the server actually served something
                    self::assertNotSame('', $baseline['/wp-login.php']);
                } else {
                    self::assertSame($baseline, $captured, "response changed under heartbeat state '{$state}' — B2 violation");
                }
            }
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
    }

    public function testTheComparisonCatchesAFreshnessLeak(): void
    {
        // Control: a handler that leaks freshness (a stale-only 503) must be caught by the same equality
        // the invariance assertion uses — proving that test would fail on an inserted 503.
        $leak = static fn (string $freshness): string => self::normalize(
            $freshness === 'stale' ? 503 : 200,
            ['content-type' => 'text/html'],
            'decoy',
        );
        self::assertNotSame($leak('fresh'), $leak('stale'));
    }
}
