<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use PHPUnit\Framework\TestCase;

/**
 * demo/entrypoint.sh with php/php-fpm/nginx/sleep stubbed: a listener that keeps exiting is respawned
 * on a bounded backoff (2, 4, 8, 16, 32, 60, 60 ...) with its non-zero rc captured under `set -e` —
 * so the loop survives the failure instead of dying with it — and the streak resets after a run that
 * stayed up past the healthy threshold. FUNNYPOT_DEV=1 writes the opcache override; its absence
 * removes a stale one.
 */
final class EntrypointBackoffTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !is_executable('/bin/sh')) {
            self::markTestSkipped('needs proc_open and /bin/sh');
        }
        $this->tmp = sys_get_temp_dir() . '/fp_backoff_' . bin2hex(random_bytes(5));
        foreach (['bin', 'out', 'confd', 'phpconfd'] as $d) {
            mkdir($this->tmp . '/' . $d, 0755, true);
        }
        // redis: crashes at once (rc=1) every time. ftp: the first two runs stay up 2 s (healthy
        // under FUNNYPOT_LISTENER_HEALTHY_S=2 — the threshold is whole seconds, so an instant run that
        // straddles a second boundary still reads as < 2) then crash at once. Everything else exits 0
        // at once.
        $this->stub('php', <<<'SH'
#!/bin/sh
case "$*" in
  *listen.php\ redis*) exit 1 ;;
  *listen.php\ ftp*)
    n=$(cat "$FP_STUB_DIR/ftp.runs" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FP_STUB_DIR/ftp.runs"
    if [ "$n" -le 2 ]; then /bin/sleep 2; fi
    exit 1 ;;
  *) exit 0 ;;
esac
SH);
        $this->stub('php-fpm', "#!/bin/sh\nexit 0\n");
        $this->stub('nginx', "#!/bin/sh\nexit 0\n");
        // Records each requested delay per calling loop; ends that loop after seven iterations.
        $this->stub('sleep', <<<'SH'
#!/bin/sh
f="$FP_STUB_DIR/sleeps.$PPID"
echo "$1" >> "$f"
if [ "$(wc -l < "$f")" -ge 7 ]; then kill "$PPID" 2>/dev/null; fi
exit 0
SH);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            exec('rm -rf ' . escapeshellarg($this->tmp));
        }
    }

    private function stub(string $name, string $body): void
    {
        file_put_contents($this->tmp . '/bin/' . $name, $body . "\n");
        chmod($this->tmp . '/bin/' . $name, 0755);
    }

    /** @param array<string,string> $env */
    private function runEntrypoint(array $env): void
    {
        $env += [
            'PATH' => $this->tmp . '/bin:/usr/bin:/bin',
            'FP_STUB_DIR' => $this->tmp . '/out',
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->tmp . '/runtime',
            'FUNNYPOT_NGINX_CONFD' => $this->tmp . '/confd',
            'FUNNYPOT_PHP_CONFD' => $this->tmp . '/phpconfd',
            'FUNNYPOT_LISTENER_HEALTHY_S' => '2',
        ];
        $p = proc_open(['/bin/sh', dirname(__DIR__, 3) . '/demo/entrypoint.sh'], [
            0 => ['file', '/dev/null', 'r'],
            1 => ['file', $this->tmp . '/out/stdout', 'w'],
            2 => ['file', $this->tmp . '/out/stderr', 'w'],
        ], $pipes, $this->tmp, $env);
        self::assertIsResource($p);
        $deadline = microtime(true) + 20;
        while (microtime(true) < $deadline && proc_get_status($p)['running']) {
            usleep(50000);
        }
        if (proc_get_status($p)['running']) {
            proc_terminate($p, 9);
            self::fail('entrypoint did not finish: ' . (string) file_get_contents($this->tmp . '/out/stderr'));
        }
        proc_close($p);
    }

    /** @return list<array{rc:int, streak:int, delay:int}> */
    private function respawns(string $proto): array
    {
        $out = [];
        preg_match_all("/listener '" . preg_quote($proto, '/') . "' exited rc=(\d+) after \d+s \(short runs in a row: (\d+)\); respawning in (\d+)s/", (string) file_get_contents($this->tmp . '/out/stderr'), $mm, PREG_SET_ORDER);
        foreach ($mm as $m) {
            $out[] = ['rc' => (int) $m[1], 'streak' => (int) $m[2], 'delay' => (int) $m[3]];
        }

        return $out;
    }

    private function waitForRespawns(): void
    {
        $deadline = microtime(true) + 15;
        while (microtime(true) < $deadline && (count($this->respawns('redis')) < 7 || count($this->respawns('ftp')) < 7)) {
            usleep(100000);
        }
    }

    public function test_crash_loop_backs_off_exponentially_and_captures_rc_under_set_e(): void
    {
        $this->runEntrypoint(['FUNNYPOT_PROTOCOLS' => '1', 'FUNNYPOT_DEV' => '1']);
        $this->waitForRespawns();

        $redis = $this->respawns('redis');
        self::assertGreaterThanOrEqual(7, count($redis), (string) file_get_contents($this->tmp . '/out/stderr'));
        self::assertSame([2, 4, 8, 16, 32, 60, 60], array_column(array_slice($redis, 0, 7), 'delay'));
        self::assertSame([1, 2, 3, 4, 5, 6, 7], array_column(array_slice($redis, 0, 7), 'streak'));
        self::assertSame([1, 1, 1, 1, 1, 1, 1], array_column(array_slice($redis, 0, 7), 'rc'), 'a non-zero exit is captured, not fatal to the loop');

        // ftp stayed up past the healthy threshold twice: each such run resets the streak.
        $ftp = $this->respawns('ftp');
        self::assertGreaterThanOrEqual(7, count($ftp));
        self::assertSame([2, 2, 4, 8, 16, 32, 60], array_column(array_slice($ftp, 0, 7), 'delay'));
        self::assertSame([1, 1, 2, 3, 4, 5, 6], array_column(array_slice($ftp, 0, 7), 'streak'));

        // A clean exit (a catalog-disabled service) is retried on the same capped cadence.
        $smtp = $this->respawns('smtp');
        self::assertGreaterThanOrEqual(6, count($smtp));
        self::assertSame(0, $smtp[0]['rc']);
        self::assertSame([2, 4, 8, 16, 32, 60], array_column(array_slice($smtp, 0, 6), 'delay'));

        // One compact line per exit: no banner, no repeated multi-line block.
        $lines = array_filter(explode("\n", (string) file_get_contents($this->tmp . '/out/stderr')), static fn (string $l): bool => str_contains($l, "'redis'"));
        self::assertSame(count($redis), count($lines));

        // FUNNYPOT_DEV=1: the opcache override was written before php-fpm started.
        $override = $this->tmp . '/phpconfd/zzz-funnypot-dev.ini';
        self::assertFileExists($override);
        self::assertSame("opcache.validate_timestamps=1\nopcache.revalidate_freq=0\n", (string) file_get_contents($override));
    }

    public function test_without_the_dev_flag_a_stale_override_is_removed(): void
    {
        file_put_contents($this->tmp . '/phpconfd/zzz-funnypot-dev.ini', "opcache.validate_timestamps=1\n");
        $this->runEntrypoint(['FUNNYPOT_PROTOCOLS' => '0']);
        self::assertFileDoesNotExist($this->tmp . '/phpconfd/zzz-funnypot-dev.ini');
        self::assertSame([], $this->respawns('redis'), 'no listeners with FUNNYPOT_PROTOCOLS=0');
    }
}
