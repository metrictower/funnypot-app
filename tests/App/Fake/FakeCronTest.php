<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeCron;
use PHPUnit\Framework\TestCase;

final class FakeCronTest extends TestCase
{
    public function test_is_deterministic_per_seed(): void
    {
        $a = FakeCron::fromSeed(4242);
        $b = FakeCron::fromSeed(4242);
        self::assertSame($a->cronJobs(), $b->cronJobs());
        self::assertSame($a->processes(), $b->processes());
    }

    public function test_different_seeds_differ(): void
    {
        $a = FakeCron::fromSeed(1);
        $b = FakeCron::fromSeed(2);
        self::assertNotSame($a->cronJobs(), $b->cronJobs());
        self::assertNotSame($a->processes(), $b->processes());
    }

    public function test_cron_jobs_shape_and_count(): void
    {
        foreach ([1, 2, 99, 12345, 987654321] as $seed) {
            $rows = FakeCron::fromSeed($seed)->cronJobs();
            self::assertGreaterThanOrEqual(8, count($rows));
            self::assertLessThanOrEqual(16, count($rows));
            foreach ($rows as $r) {
                self::assertSame(['schedule', 'user', 'command'], array_keys($r));
                foreach ($r as $v) {
                    self::assertIsString($v);
                    self::assertNotSame('', $v);
                }
                // Schedule is a 5-field crontab line with the hour clustered in 00-04.
                $fields = explode(' ', $r['schedule']);
                self::assertCount(5, $fields);
                self::assertLessThanOrEqual(4, (int) $fields[1]);
            }
        }
    }

    public function test_processes_shape_and_count(): void
    {
        foreach ([1, 2, 99, 12345, 987654321] as $seed) {
            $rows = FakeCron::fromSeed($seed)->processes();
            self::assertGreaterThanOrEqual(12, count($rows));
            self::assertLessThanOrEqual(24, count($rows));
            $prevPid = 0;
            foreach ($rows as $r) {
                self::assertSame(['pid', 'user', 'cpu', 'mem', 'command'], array_keys($r));
                foreach ($r as $v) {
                    self::assertIsString($v);
                    self::assertNotSame('', $v);
                }
                // PIDs strictly ascending, like a real ps snapshot.
                self::assertGreaterThan($prevPid, (int) $r['pid']);
                $prevPid = (int) $r['pid'];
                // cpu/mem render as one-decimal percentages.
                self::assertMatchesRegularExpression('/^\d+\.\d$/', $r['cpu']);
                self::assertMatchesRegularExpression('/^\d+\.\d$/', $r['mem']);
            }
        }
    }

    public function test_juicy_bait_present(): void
    {
        $cron = FakeCron::fromSeed(4242)->cronJobs();
        $cronText = implode("\n", array_column($cron, 'command'));
        self::assertStringContainsString('mysqldump', $cronText);
        self::assertStringContainsString('s3://', $cronText);
        self::assertStringContainsString('Bearer ', $cronText);
        self::assertStringContainsString('REDACTED', $cronText);

        $procs = FakeCron::fromSeed(4242)->processes();
        $procText = implode("\n", array_column($procs, 'command'));
        self::assertStringContainsString('secrets.yaml', $procText);
        self::assertStringContainsString('backup.sh', $procText);
    }

    public function test_no_real_routable_ips(): void
    {
        // Any IP a command reaches must be RFC1918/TEST-NET. Grab every dotted quad and check it.
        foreach ([1, 2, 99, 12345, 987654321] as $seed) {
            $gen = FakeCron::fromSeed($seed);
            $text = implode("\n", array_column($gen->cronJobs(), 'command'))
                . "\n" . implode("\n", array_column($gen->processes(), 'command'));
            if (preg_match_all('/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/', $text, $m, PREG_SET_ORDER)) {
                foreach ($m as $ip) {
                    self::assertTrue(
                        $this->isPrivateOrTestNet((int) $ip[1], (int) $ip[2], (int) $ip[3]),
                        'Non-private IP leaked: ' . $ip[0]
                    );
                }
            }
        }
    }

    private function isPrivateOrTestNet(int $a, int $b, int $c): bool
    {
        if ($a === 10) {
            return true;
        }
        if ($a === 172 && $b >= 16 && $b <= 31) {
            return true;
        }
        if ($a === 192 && $b === 168) {
            return true;
        }
        if ($a === 192 && $b === 0 && $c === 2) {
            return true;   // TEST-NET-1
        }
        if ($a === 198 && $b === 51 && $c === 100) {
            return true;   // TEST-NET-2
        }
        if ($a === 203 && $b === 0 && $c === 113) {
            return true;   // TEST-NET-3
        }
        if ($a === 127) {
            return true;   // loopback (redis bind)
        }
        return false;
    }
}
