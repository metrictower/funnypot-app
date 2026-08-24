<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\Fake\ServerProfile;
use PHPUnit\Framework\TestCase;

/**
 * Realism-audit de-tells: backup filename dates must agree with their own age label and never land in
 * the future, loot password hashes must be real-shaped bcrypt, CPU core/thread counts must follow the
 * picked model, and the auth-log path must follow the picked OS family.
 */
final class ServerProfileTest extends TestCase
{
    public function test_is_deterministic_per_seed(): void
    {
        $a = ServerProfile::fromSeed(4242);
        $b = ServerProfile::fromSeed(4242);
        self::assertSame($a->backups(), $b->backups());
        self::assertSame($a->lootUsers('example.internal'), $b->lootUsers('example.internal'));
        self::assertSame($a->cpu(), $b->cpu());
    }

    public function test_backup_filename_date_agrees_with_its_own_age_and_is_never_future(): void
    {
        foreach ([1, 2, 42, 4242, 987654321] as $seed) {
            $today = FrozenClock::nowDays();
            foreach (ServerProfile::fromSeed($seed)->backups() as $b) {
                if (preg_match('/^backup-(\d+)\.(\d+)\.(\d+)_(\d{2})-(\d{2})-(\d{2})_/', $b['name'], $m) !== 1) {
                    continue; // the .sql.gz sibling row carries no date in its filename
                }
                $days = FrozenClock::daysFromCivil((int) $m[3], (int) $m[1], (int) $m[2]);
                self::assertLessThanOrEqual($today, $days, "backup '{$b['name']}' is future-dated");

                // The age label must describe the SAME elapsed span as the filename date (same day,
                // or within the coarse rounding of the "Xh ago"/"X days ago" bucket it renders in).
                $ageDays = $today - $days;
                if (preg_match('/^(\d+)h ago$/', $b['age'], $am) === 1) {
                    self::assertLessThanOrEqual(2, $ageDays, "'{$b['age']}' should still be today or yesterday's date, got {$b['name']}");
                } elseif (preg_match('/^(\d+) days ago$/', $b['age'], $am) === 1) {
                    self::assertGreaterThanOrEqual(1, $ageDays, "'{$b['age']}' should be at least a day back, got {$b['name']}");
                } else {
                    self::fail("unrecognised age label shape: {$b['age']}");
                }
            }
        }
    }

    public function test_backup_rows_stay_newest_first(): void
    {
        foreach ([1, 2, 42, 4242] as $seed) {
            $prevDays = null;
            foreach (ServerProfile::fromSeed($seed)->backups() as $b) {
                if (preg_match('/^backup-(\d+)\.(\d+)\.(\d+)_/', $b['name'], $m) !== 1) {
                    continue;
                }
                $days = FrozenClock::daysFromCivil((int) $m[3], (int) $m[1], (int) $m[2]);
                if ($prevDays !== null) {
                    self::assertLessThanOrEqual($prevDays, $days, 'backup rows must stay newest-first');
                }
                $prevDays = $days;
            }
        }
    }

    public function test_loot_password_hashes_are_real_shaped_bcrypt(): void
    {
        foreach ([1, 2, 42, 4242] as $seed) {
            foreach (ServerProfile::fromSeed($seed)->lootUsers('example.internal') as $row) {
                self::assertMatchesRegularExpression('/^\$2y\$\d\d\$[.\/A-Za-z0-9]{53}$/', $row[4]);
            }
        }
    }

    public function test_cpu_core_and_thread_counts_follow_the_picked_model(): void
    {
        for ($seed = 1; $seed <= 200; $seed++) {
            $cpu = ServerProfile::fromSeed($seed)->cpu();
            if (strpos($cpu['model'], '6338') !== false) {
                self::assertSame(32, $cpu['coresPerSocket']);
                self::assertSame(64, $cpu['cores']);
                self::assertSame(128, $cpu['threads']);
            } else {
                self::assertStringContainsString('6342', $cpu['model']);
                self::assertSame(24, $cpu['coresPerSocket']);
                self::assertSame(48, $cpu['cores']);
                self::assertSame(96, $cpu['threads']);
            }
            self::assertSame(2, $cpu['sockets']);
        }
    }

    public function test_auth_log_path_follows_the_os_family(): void
    {
        for ($seed = 1; $seed <= 200; $seed++) {
            $sp = ServerProfile::fromSeed($seed);
            $distro = $sp->os()['distro'];
            if (strpos($distro, 'Rocky') !== false || strpos($distro, 'RHEL') !== false || strpos($distro, 'CentOS') !== false) {
                self::assertSame('/var/log/secure', $sp->authLogPath(), $distro);
            } else {
                self::assertSame('/var/log/auth.log', $sp->authLogPath(), $distro);
            }
        }
    }
}
