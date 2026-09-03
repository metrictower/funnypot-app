<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Admin;

use Funnypot\App\Admin\AdminAuth;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * FP-0250 §2.4/§4.3 — per-username exponential backoff, layered ALONGSIDE the pre-existing per-IP hard
 * lockout (AdminAuthTest). Closes the gap a per-IP-only lockout leaves open: a rotating botnet gets N
 * free guesses per IP against the SAME username, i.e. effectively unlimited online guessing against the
 * one username that matters. Capped at 60s — never a hard lock (operator-DoS guard, plan §5 risk 2).
 * Uses the injected clock so the backoff is provable without real sleeping.
 */
final class AdminAuthLockoutTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
        unset($_COOKIE[AdminAuth::COOKIE]);
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_auth_lo_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** A fake clock the test can advance deterministically — no real sleeping. */
    private function fakeClock(int $start): array
    {
        $now = $start;
        $clock = static function () use (&$now): int {
            return $now;
        };

        return [$clock, static function (int $seconds) use (&$now): void {
            $now += $seconds;
        }];
    }

    public function test_rotating_ips_hit_the_per_username_backoff(): void
    {
        [$clock, $advance] = $this->fakeClock(1_000_000);
        $db = $this->dbPath();
        // maxFailures = 5 (default), wide window (900s, default) — 5 fails from 5 DISTINCT IPs never
        // trips the per-IP lockout (each IP has only 1 fail), but DOES trip the per-username backoff.
        $auth = new AdminAuth($db, '/', false, 5, 900, 1800, 43200, $clock);
        $auth->createOrResetUser('admin', 'pw-123');

        for ($i = 0; $i < 5; $i++) {
            $ip = "203.0.113.{$i}";
            $r = $auth->login('admin', 'wrong', $ip);
            self::assertFalse($r['ok'], "rotating-IP attempt {$i} must fail");
            self::assertStringContainsString('invalid', $r['error'], 'attempt below the threshold is a plain credential failure, not a lockout');
        }

        // A 6th attempt from a FRESH IP with the CORRECT password is still denied — backed off by
        // USERNAME, not by any single IP's own history.
        $denied = $auth->login('admin', 'pw-123', '198.51.100.9');
        self::assertFalse($denied['ok'], 'the per-username backoff denies a fresh IP with the right password');
        self::assertStringContainsString('locked', $denied['error']);

        // Advance the clock past the delay (fails=5, maxFailures=5 -> 2**0 = 1s) — the SAME correct
        // attempt now succeeds.
        $advance(2);
        $ok = $auth->login('admin', 'pw-123', '198.51.100.9');
        self::assertTrue($ok['ok'], 'past the backoff delay, the correct password succeeds');
    }

    public function test_backoff_is_bounded_never_a_permanent_lock(): void
    {
        // Precondition planted directly via raw SQL (not by driving 30 real login() calls): once the
        // backoff itself starts denying attempts, a further wrong-password attempt is recorded as
        // 'lockout' (not 'fail') and so does not itself grow the fail count or move "last fail" forward
        // — looping login() calls 1s apart would self-interfere with the very thing being measured. A
        // planted precondition is the deterministic way to prove the CAP specifically.
        $now = 2_000_000;
        $lastFailTs = $now - 5; // the last of 30 fails landed 5s before "now"
        $db = $this->dbPath();
        $pdo = new PDO('sqlite:' . $db);
        $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ts INTEGER NOT NULL, result TEXT NOT NULL, username TEXT NOT NULL DEFAULT "")');
        for ($i = 0; $i < 30; $i++) {
            $ts = $lastFailTs - (29 - $i); // 30 fails ending exactly at $lastFailTs
            $pdo->exec("INSERT INTO login_attempts (ip, ts, result, username) VALUES ('203.0.113.{$i}', {$ts}, 'fail', 'admin')");
        }
        // Uncapped, 2**(30-3) would be ~134 million seconds — the cap must hold this to 60.
        $clock = static function () use (&$now): int {
            return $now;
        };
        $auth = new AdminAuth($db, '/', false, 3, 900, 1800, 43200, $clock); // maxFailures = 3
        $auth->createOrResetUser('admin', 'pw-123');

        // now = lastFailTs + 5s: still well inside a 60s cap.
        $denied = $auth->login('admin', 'pw-123', '198.51.100.5');
        self::assertFalse($denied['ok'], '5s after the last of 30 fails, still inside the capped 60s window');

        // now = lastFailTs + 59s: still inside.
        $now = $lastFailTs + 59;
        $stillDenied = $auth->login('admin', 'pw-123', '198.51.100.6');
        self::assertFalse($stillDenied['ok'], 'delay is capped at 60s, not unbounded (2**27 uncapped) — 59s since the last fail must still deny');

        // now = lastFailTs + 61s: past the 60s cap.
        $now = $lastFailTs + 61;
        $ok = $auth->login('admin', 'pw-123', '198.51.100.7');
        self::assertTrue($ok['ok'], 'a correct login past the 60s cap must succeed — never a permanent lock');
    }

    public function test_lockout_and_backoff_denials_are_indistinguishable(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db, '/', false, 2, 900); // maxFailures = 2, real clock (message text only)
        $auth->createOrResetUser('admin', 'pw-123');
        $auth->createOrResetUser('other', 'pw-456');

        // Trip the per-IP lockout (same IP, same username).
        $ip = '203.0.113.50';
        $auth->login('admin', 'wrong', $ip);
        $auth->login('admin', 'wrong', $ip);
        $ipLockedMsg = $auth->login('admin', 'pw-123', $ip)['error'];

        // Trip the per-USERNAME backoff (rotating IPs, same username) on a FRESH db so the per-IP
        // lockout above cannot also fire.
        $db2 = $this->dbPath();
        $auth2 = new AdminAuth($db2, '/', false, 2, 900);
        $auth2->createOrResetUser('admin', 'pw-123');
        $auth2->login('admin', 'wrong', '198.51.100.1');
        $auth2->login('admin', 'wrong', '198.51.100.2');
        $usernameBackedOffMsg = $auth2->login('admin', 'pw-123', '198.51.100.3')['error'];

        self::assertSame($ipLockedMsg, $usernameBackedOffMsg, 'the two mechanisms must be indistinguishable by their denial message');
    }

    public function test_login_attempts_table_is_pruned(): void
    {
        [$clock, $advance] = $this->fakeClock(3_000_000);
        $db = $this->dbPath();
        $auth = new AdminAuth($db, '/', false, 5, 900, 1800, 43200, $clock);
        $auth->createOrResetUser('admin', 'pw-123');

        // A very old row (well beyond max(30d, lockoutWindowS) retention) plus one recent row, inserted
        // directly so pruning is proven independent of how the row got there.
        $pdo = new PDO('sqlite:' . $db);
        $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ts INTEGER NOT NULL, result TEXT NOT NULL, username TEXT NOT NULL DEFAULT "")');
        $veryOldTs = $clock() - (60 * 86400); // 60 days back — well past the 30-day floor
        $pdo->exec("INSERT INTO login_attempts (ip, ts, result, username) VALUES ('203.0.113.1', {$veryOldTs}, 'fail', 'ghost')");
        $recentTs = $clock() - 10;
        $pdo->exec("INSERT INTO login_attempts (ip, ts, result, username) VALUES ('203.0.113.2', {$recentTs}, 'fail', 'ghost2')");

        self::assertSame(2, (int) $pdo->query('SELECT COUNT(*) FROM login_attempts')->fetchColumn(), 'sanity: both rows present before a prune runs');

        // record()'s prune runs on every 'ok' result (deterministic, no probabilistic skip) — trigger
        // one via a real successful login.
        $ok = $auth->login('admin', 'pw-123', '203.0.113.99');
        self::assertTrue($ok['ok']);

        $rows = $pdo->query('SELECT ip, ts FROM login_attempts ORDER BY ts')->fetchAll(PDO::FETCH_ASSOC);
        $ips = array_column($rows, 'ip');
        self::assertNotContains('203.0.113.1', $ips, 'the very old row must be pruned');
        self::assertContains('203.0.113.2', $ips, 'the recent row must survive');
        self::assertContains('203.0.113.99', $ips, "the login attempt that triggered the prune survives (it is the pruning trigger's own row)");
    }

    public function test_schema_migration_is_idempotent(): void
    {
        // Open an admin.sqlite TWICE (simulating a process restart) — the guarded ALTER TABLE adding
        // the username column must not throw the second time.
        $db = $this->dbPath();
        $a1 = new AdminAuth($db);
        $a1->createOrResetUser('admin', 'pw-123');
        $a1->login('admin', 'wrong', '203.0.113.1'); // forces db()/schema creation + a login_attempts row

        $a2 = new AdminAuth($db); // fresh instance, same file — re-runs the guarded ALTER
        $r = $a2->login('admin', 'pw-123', '203.0.113.2');
        self::assertTrue($r['ok'], 'a second AdminAuth instance over the same db must construct + operate without throwing');
    }

    /**
     * Pre-existing rows (from before this migration) have username='' by the column's DEFAULT — they
     * must not be mistaken for a real empty-username's backoff history (login() never looks up a
     * '' username's backoff since isUsernameBackedOff('') short-circuits false).
     */
    public function test_pre_migration_rows_with_empty_username_do_not_wedge_login(): void
    {
        $db = $this->dbPath();
        $pdo = new PDO('sqlite:' . $db);
        $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ts INTEGER NOT NULL, result TEXT NOT NULL)');
        for ($i = 0; $i < 10; $i++) {
            $pdo->exec("INSERT INTO login_attempts (ip, ts, result) VALUES ('9.9.9.{$i}', " . time() . ", 'fail')");
        }
        $auth = new AdminAuth($db);
        $auth->createOrResetUser('admin', 'pw-123');
        $r = $auth->login('admin', 'pw-123', '203.0.113.1');
        self::assertTrue($r['ok'], 'legacy pre-username rows must not deny a real login');
    }
}
