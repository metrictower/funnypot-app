<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

/** Runs only the pure bounded shell log checker on test-owned files, never the image runner. */
final class IngressLogProofTest extends TestCase
{
    public function test_host_log_requires_both_positive_controls_and_no_rejected_bytes(): void
    {
        $positive = "ingress-positive-container-stdout\ningress-positive-container-stderr\n";
        foreach (['good' => $positive, 'empty' => '',
            'stdout-only' => "ingress-positive-container-stdout\n",
            'stderr-only' => "ingress-positive-container-stderr\n",
            'leaked' => $positive . 'ingress-reject-7b6e4d',
            'oversized' => $positive . str_repeat('x', 1048576),
            'missing' => null, 'symlink' => $positive] as $case => $bytes) {
            [$code, $stdout, $stderr] = $this->checkLog($case, $bytes);
            self::assertSame($case === 'good' ? 0 : ($case === 'missing' || $case === 'symlink' ? 2 : 1), $code, $case);
            self::assertSame('', $stderr, $case);
            if ($case === 'good') {
                $receipt = json_decode($stdout, true, 512, JSON_THROW_ON_ERROR);
                self::assertSame('passed', $receipt['status']);
                self::assertSame(['container stdout', 'container stderr'], $receipt['sink_controls']);
                self::assertTrue($receipt['negative_marker_absent']);
                self::assertSame(1048576, $receipt['max_log_bytes']);
            } else {
                self::assertSame('', $stdout, 'no false success receipt: ' . $case);
            }
        }
    }

    /** @return array{int,string,string} */
    private function checkLog(string $case, ?string $bytes): array
    {
        $dir = sys_get_temp_dir() . '/fp-ingress-log-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        $path = $dir . '/container.log';
        $proc = null;
        $pipes = [];
        try {
            if ($bytes !== null) {
                file_put_contents($path, $bytes);
            }
            if ($case === 'symlink') {
                symlink($path, $dir . '/linked.log');
                $path = $dir . '/linked.log';
            }
            $script = dirname(__DIR__, 2) . '/acceptance/ingress/verify-container-log.sh';
            $proc = proc_open(['/bin/bash', $script, $path],
                [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, $dir, ['PATH' => '/usr/bin:/bin']);
            self::assertIsResource($proc);
            fclose($pipes[0]);
            unset($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            $stdout = $stderr = '';
            $until = hrtime(true) + 3_000_000_000;
            do {
                $stdout .= stream_get_contents($pipes[1]);
                $stderr .= stream_get_contents($pipes[2]);
                if (strlen($stdout) + strlen($stderr) > 4096 || hrtime(true) >= $until) {
                    self::fail('pure log checker exceeded its output/wall bound');
                }
                $state = proc_get_status($proc);
                if ($state['running']) {
                    usleep(1000);
                }
            } while ($state['running']);
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            self::assertLessThanOrEqual(4096, strlen($stdout) + strlen($stderr));
            return [$state['exitcode'], $stdout, $stderr];
        } finally {
            if (is_resource($proc)) {
                if (proc_get_status($proc)['running']) {
                    proc_terminate($proc, 9);
                }
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                proc_close($proc);
            }
            foreach (['linked.log', 'container.log'] as $file) {
                if (is_file($dir . '/' . $file) || is_link($dir . '/' . $file)) {
                    unlink($dir . '/' . $file);
                }
            }
            rmdir($dir);
        }
    }
}
