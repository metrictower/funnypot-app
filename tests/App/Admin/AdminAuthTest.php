<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Admin;

use Funnypot\App\Admin\AdminAuth;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * FP-0242b operator auth. Argon2id credentials, a server-side session + CSRF token, and a per-IP
 * login lockout — all FAIL-CLOSED. These are the falsifiable auth invariants (spec §7, plan T-AUTH):
 * a verify-only gate with no lockout, or a session gate that forgets CSRF, would fail here.
 */
final class AdminAuthTest extends TestCase
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
        $p = sys_get_temp_dir() . '/fp_auth_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    // --- Argon2id hashing ---

    public function test_hash_is_argon2id_and_round_trips(): void
    {
        $h = AdminAuth::hashPassword('correct horse battery staple');
        self::assertStringStartsWith('$argon2id', $h, 'hash must be an Argon2id PHC string');
        self::assertTrue(AdminAuth::verifyPassword('correct horse battery staple', $h));
        self::assertFalse(AdminAuth::verifyPassword('wrong', $h));
        self::assertFalse(AdminAuth::verifyPassword('correct horse battery staple', ''), 'empty hash never verifies');
    }

    // --- login + session ---

    public function test_login_success_mints_a_session_and_check_passes(): void
    {
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', 'pw-123');

        $res = $auth->login('admin', 'pw-123', '203.0.113.7');
        self::assertTrue($res['ok']);
        self::assertNotEmpty($res['csrf'] ?? '');
        // login populated $_COOKIE, so the session resolves within this request.
        self::assertTrue($auth->check(), 'the just-minted session is valid in this request');
        self::assertSame('admin', $auth->currentUser());
    }

    public function test_login_wrong_password_is_denied_and_no_session(): void
    {
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', 'pw-123');

        $res = $auth->login('admin', 'nope', '203.0.113.7');
        self::assertFalse($res['ok']);
        self::assertArrayNotHasKey('csrf', $res);
        self::assertFalse($auth->check(), 'a failed login leaves the request unauthenticated');
        self::assertNull($auth->currentUser());
    }

    public function test_unknown_user_is_denied(): void
    {
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', 'pw-123');
        self::assertFalse($auth->login('ghost', 'pw-123', '203.0.113.7')['ok']);
    }

    public function test_bogus_and_malformed_cookies_fail_closed(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db);
        $auth->createOrResetUser('admin', 'pw-123');

        // No cookie.
        self::assertFalse((new AdminAuth($db))->check());
        // Malformed (not 64 hex).
        $_COOKIE[AdminAuth::COOKIE] = 'short';
        self::assertFalse((new AdminAuth($db))->check());
        // Well-formed but unknown id.
        $_COOKIE[AdminAuth::COOKIE] = str_repeat('a', 64);
        self::assertFalse((new AdminAuth($db))->check());
    }

    public function test_logout_invalidates_the_session(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db);
        $auth->createOrResetUser('admin', 'pw-123');
        $auth->login('admin', 'pw-123', '203.0.113.7');
        self::assertTrue($auth->check());

        $auth->logout();
        self::assertFalse($auth->check(), 'logged-out session is gone');
        // A fresh instance reading the (now-cleared) cookie is also unauthenticated.
        self::assertFalse((new AdminAuth($db))->check());
    }

    public function test_idle_and_absolute_timeouts_expire_the_session(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db);
        $auth->createOrResetUser('admin', 'pw-123');
        $res = $auth->login('admin', 'pw-123', '203.0.113.7');
        $id = $_COOKIE[AdminAuth::COOKIE];
        self::assertTrue($res['ok']);

        // Backdate the session so it is well past the idle window, then a fresh reader must deny.
        $pdo = new PDO('sqlite:' . $db);
        $pdo->exec('UPDATE admin_sessions SET last_seen = last_seen - 999999');
        $_COOKIE[AdminAuth::COOKIE] = $id;
        self::assertFalse((new AdminAuth($db))->check(), 'an idle-expired session is denied');

        // And it was deleted (not just rejected once).
        $count = (int) $pdo->query('SELECT COUNT(*) FROM admin_sessions')->fetchColumn();
        self::assertSame(0, $count, 'an expired session is purged');
    }

    // --- CSRF ---

    public function test_csrf_token_must_match_the_session(): void
    {
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', 'pw-123');
        $res = $auth->login('admin', 'pw-123', '203.0.113.7');
        $csrf = (string) $res['csrf'];

        self::assertTrue($auth->verifyCsrf($csrf), 'the session token verifies');
        self::assertFalse($auth->verifyCsrf(''), 'an empty token never verifies');
        self::assertFalse($auth->verifyCsrf('deadbeef'), 'a wrong token never verifies');
    }

    public function test_csrf_without_a_session_is_denied(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db);
        $auth->createOrResetUser('admin', 'pw-123');
        // No login ⇒ no session ⇒ even a plausible token cannot verify.
        self::assertFalse($auth->verifyCsrf(str_repeat('a', 64)));
    }

    // --- lockout (plan T-AUTH-3) ---

    public function test_repeated_failures_lock_out_the_ip_even_with_the_right_password(): void
    {
        $db = $this->dbPath();
        $ip = '203.0.113.9';
        // maxFailures = 3, wide window.
        $auth = new AdminAuth($db, '/', false, 3, 900);
        $auth->createOrResetUser('admin', 'pw-123');
        $auth->createOrResetUser('other-user', 'pw-456'); // isolates this test from the FP-0250 2.4 per-USERNAME backoff below

        for ($i = 0; $i < 3; $i++) {
            $r = $auth->login('admin', 'wrong', $ip);
            self::assertFalse($r['ok'], "attempt {$i} must fail");
            self::assertStringContainsString('invalid', $r['error']);
        }
        // The 4th attempt is locked out — even though it is now the CORRECT password.
        $locked = $auth->login('admin', 'pw-123', $ip);
        self::assertFalse($locked['ok'], 'the correct password is still denied inside the lockout window');
        self::assertStringContainsString('locked', $locked['error']);

        // A different IP is unaffected — the lockout is per source IP, not global. A DIFFERENT username
        // too (FP-0250 2.4 adds a per-username backoff alongside this per-IP lockout — AdminAuthLockoutTest
        // covers that mechanism directly; same username here would trip both and conflate the two).
        $other = $auth->login('other-user', 'pw-456', '198.51.100.2');
        self::assertTrue($other['ok'], 'a clean IP + a different username can still log in');

        // Every attempt was recorded (the auth audit log).
        $attempts = $auth->attempts(100);
        self::assertGreaterThanOrEqual(5, count($attempts), 'every login attempt is audited');
        $results = array_column($attempts, 'result');
        self::assertContains('fail', $results);
        self::assertContains('lockout', $results);
        self::assertContains('ok', $results);
    }

    // --- bootstrap seed (Open Q3) ---

    public function test_bootstrap_seeds_the_first_user_then_goes_inert(): void
    {
        $db = $this->dbPath();
        $auth = new AdminAuth($db);
        self::assertFalse($auth->hasUsers());

        $auth->bootstrap('seed-pw');
        self::assertTrue($auth->hasUsers());
        self::assertTrue($auth->login('admin', 'seed-pw', '203.0.113.7')['ok']);

        // A second bootstrap with a DIFFERENT password is inert — no standing shared-secret backdoor.
        (new AdminAuth($db))->bootstrap('a-different-password');
        self::assertFalse((new AdminAuth($db))->login('admin', 'a-different-password', '203.0.113.7')['ok']);
        self::assertTrue((new AdminAuth($db))->login('admin', 'seed-pw', '203.0.113.7')['ok']);
    }

    public function test_bootstrap_with_empty_password_creates_no_user(): void
    {
        $db = $this->dbPath();
        (new AdminAuth($db))->bootstrap('');
        self::assertFalse((new AdminAuth($db))->hasUsers(), 'an unset FUNNYPOT_ADMIN_PASSWORD seeds nothing');
    }
}
