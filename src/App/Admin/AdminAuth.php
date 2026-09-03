<?php

declare(strict_types=1);

namespace Funnypot\App\Admin;

use Funnypot\App\Storage\Sqlite;
use PDO;
use Throwable;

/**
 * Operator authentication for the colocated admin section (FP-0242b). Upgrades the retired shared
 * FUNNYPOT_ADMIN_PASSWORD + hash_equals pop-box into a real login: an Argon2id password hash, a
 * server-side session cookie, a per-session CSRF token, and a per-IP login rate-limit / lockout.
 *
 * Owns its own SQLite file (admin.sqlite, on the persisted data volume) via the shared
 * {@see Sqlite::open()} WAL/busy_timeout idiom — kept SEPARATE from config.sqlite so auth state never
 * rides the config store's fail-SAFE read path. This class is FAIL-CLOSED throughout: any error
 * resolving a session or a credential yields "not authenticated" / "denied", never a partial grant
 * (spec §6.2). That is the deliberate opposite of the config read path, which fails safe.
 *
 *   admin_users(username PK, pw_hash, created_at)            — the operator credentials
 *   admin_sessions(id PK, username, created_at, last_seen, csrf) — live server-side sessions
 *   login_attempts(id PK, ip, ts, result)                    — the auth audit log + lockout source
 *
 * Session id + CSRF token are each 256 bits of CSPRNG hex. The cookie is Secure (over HTTPS),
 * HttpOnly, SameSite=Strict, scoped to the dashboard path so it is never sent on the decoy surface.
 */
final class AdminAuth
{
    public const COOKIE = 'fp_admin_sid';

    private ?PDO $db = null;

    /** Per-instance memo of the resolved session so feed()+shell()+admin() don't each re-query. */
    private ?bool $checked = null;
    private ?string $currentUser = null;
    private ?string $currentCsrf = null;

    /**
     * @param string $dbPath          path to admin.sqlite (its dir is created on first write)
     * @param string $cookiePath      Path= attribute for the session cookie (the dashboard base) so the
     *                                cookie is scoped to the dashboard surface, never the decoy paths
     * @param bool   $secure          set the cookie Secure flag (derive from HTTPS/X-Forwarded-Proto)
     * @param int    $maxFailures     failed logins from one IP within the window before lockout
     * @param int    $lockoutWindowS  the rolling lockout window, seconds
     * @param int    $idleTimeoutS    a session expires this long after its last request
     * @param int    $absoluteTimeoutS a session expires this long after login regardless of activity
     */
    public function __construct(
        private string $dbPath,
        private string $cookiePath = '/',
        private bool $secure = false,
        private int $maxFailures = 5,
        private int $lockoutWindowS = 900,
        private int $idleTimeoutS = 1800,
        private int $absoluteTimeoutS = 43200,
        /** FP-0250 2.4: injectable time source, defaulting to time(). A test passes a fake clock so the
         *  per-username exponential backoff (and everything else time-based in this class) is provable
         *  without real sleeping. */
        private ?\Closure $clock = null,
    ) {
        $this->clock ??= static fn (): int => time();
    }

    // ---------------------------------------------------------------- bootstrap / users ------------

    /**
     * One-time bootstrap seed (Open Q3). If NO operator exists yet AND $envPassword is non-empty,
     * create the first user from it — so an existing deploy that set FUNNYPOT_ADMIN_PASSWORD is not
     * locked out on first boot. The username is the configured operator name (FP-0295: FUNNYPOT_ADMIN_USER,
     * default 'admin'), so a fresh install with a non-obvious username seeds THAT user. Once any user
     * exists this is inert: the env password becomes a dead value and there is no standing shared-secret
     * backdoor — changing the username on an existing install needs the recovery CLI (demo/admin-user.php),
     * not this seed. Best-effort (never throws on the boot path): a failure here just leaves the panel
     * unreachable until that CLI runs.
     */
    public function bootstrap(string $envPassword, string $username = 'admin'): void
    {
        if ($envPassword === '') {
            return;
        }
        $username = trim($username) !== '' ? trim($username) : 'admin';
        try {
            if ($this->hasUsers()) {
                return;
            }
            $this->createOrResetUser($username, $envPassword);
        } catch (Throwable $e) {
            error_log('AdminAuth bootstrap: ' . $e->getMessage());
        }
    }

    public function hasUsers(): bool
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM admin_users')->fetchColumn() > 0;
        } catch (Throwable $e) {
            return false;
        }
    }

    /** Whether a specific operator username already exists (for the CLI's create-vs-reset message). */
    public function userExists(string $username): bool
    {
        try {
            $st = $this->db()->prepare('SELECT 1 FROM admin_users WHERE username = :u');
            $st->execute([':u' => trim($username)]);

            return $st->fetchColumn() !== false;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Create or reset an operator credential (idempotent upsert). Used by the bootstrap seed and by the
     * recovery CLI (demo/admin-user.php). Fail-CLOSED: throws on a write error so the CLI reports it.
     */
    public function createOrResetUser(string $username, string $password): void
    {
        $username = trim($username);
        if ($username === '' || $password === '') {
            throw new \RuntimeException('username and password are both required');
        }
        $st = $this->db()->prepare(
            'INSERT INTO admin_users (username, pw_hash, created_at) VALUES (:u, :h, :t)
             ON CONFLICT(username) DO UPDATE SET pw_hash = :h'
        );
        $st->execute([':u' => $username, ':h' => self::hashPassword($password), ':t' => gmdate('c')]);
    }

    // ---------------------------------------------------------------- login / lockout --------------

    /**
     * The one denial message shared by the per-IP hard lockout AND the per-username backoff (FP-0250
     * 2.4) — a probe must not be able to tell which mechanism tripped from the wording alone (that
     * would itself be an oracle for "this username exists / has failures pending").
     */
    private const LOCKOUT_MSG = 'too many attempts — locked out, try again later';

    /**
     * Attempt a login. Order matters and is security-load-bearing:
     *   1. per-IP hard lockout FIRST (unchanged) — stops a single-IP spray outright;
     *   2. per-username exponential BACKOFF (FP-0250 2.4) — a rotating botnet buys at most one guess
     *      per username per (capped) delay window, closing the gap a per-IP-only lockout leaves open;
     *      capped, never a hard lock (an attacker spraying the real operator's username must not be
     *      able to permanently lock the operator out of their own honeypot — the recovery CLI,
     *      demo/admin-user.php, is untouched by either mechanism regardless);
     *   3. credential verify (dummy-hash timing defence, unchanged).
     * Every attempt (lockout / fail / ok) is written to login_attempts (the auth audit log). Only 'fail'
     * rows count toward either lockout mechanism, so a locked/backed-off attempt does not itself extend
     * the window indefinitely. Fail-CLOSED: any error returns denied.
     *
     * @return array{ok:bool,error?:string,csrf?:string}
     */
    public function login(string $username, string $password, string $ip): array
    {
        $username = trim($username);
        try {
            if ($this->isLockedOut($ip)) {
                $this->record($ip, 'lockout', $username);

                return ['ok' => false, 'error' => self::LOCKOUT_MSG];
            }
            if ($this->isUsernameBackedOff($username)) {
                $this->record($ip, 'lockout', $username);

                return ['ok' => false, 'error' => self::LOCKOUT_MSG];
            }
            $hash = $this->lookupHash($username);
            // Verify against a FIXED dummy hash when the username is unknown, so an unknown user pays the
            // same ~Argon2id cost as a known user with a wrong password — otherwise the timing gap
            // (~0ms vs ~50-100ms) leaks which usernames exist. The lockout checks above still run first.
            $ok = $hash === null
                ? (self::verifyPassword($password, self::dummyHash()) && false)
                : self::verifyPassword($password, $hash);
            if (!$ok) {
                $this->record($ip, 'fail', $username);

                return ['ok' => false, 'error' => 'invalid credentials'];
            }
            $id = bin2hex(random_bytes(32));
            $csrf = bin2hex(random_bytes(32));
            $now = ($this->clock)();
            $st = $this->db()->prepare(
                'INSERT INTO admin_sessions (id, username, created_at, last_seen, csrf)
                 VALUES (:id, :u, :c, :s, :x)'
            );
            $st->execute([':id' => $id, ':u' => $username, ':c' => $now, ':s' => $now, ':x' => $csrf]);
            $this->record($ip, 'ok', $username);
            $this->setCookie($id, $now + $this->absoluteTimeoutS);
            // Make the just-minted session usable within this same request (the cookie only arrives on
            // the NEXT request), so a login handler that immediately renders the authed shell works.
            $_COOKIE[self::COOKIE] = $id;
            $this->checked = true;
            $this->currentUser = $username;
            $this->currentCsrf = $csrf;

            return ['ok' => true, 'csrf' => $csrf];
        } catch (Throwable $e) {
            error_log('AdminAuth login: ' . $e->getMessage());

            return ['ok' => false, 'error' => 'login unavailable'];
        }
    }

    public function logout(): void
    {
        $id = (string) ($_COOKIE[self::COOKIE] ?? '');
        if ($id !== '') {
            try {
                $this->db()->prepare('DELETE FROM admin_sessions WHERE id = :id')->execute([':id' => $id]);
            } catch (Throwable $e) {
                // best-effort: the cookie is cleared below regardless
            }
        }
        $this->setCookie('', time() - 3600);
        unset($_COOKIE[self::COOKIE]);
        $this->checked = false;
        $this->currentUser = null;
        $this->currentCsrf = null;
    }

    // ---------------------------------------------------------------- session resolution -----------

    /**
     * Is the current request bound to a valid, unexpired session? Resolves the cookie once per instance
     * and memoises the result. Enforces both an idle timeout (last_seen) and an absolute timeout
     * (created_at); an expired session is deleted. Rotates last_seen on a live hit. FAIL-CLOSED: a
     * missing cookie, an unknown/expired session, or ANY db error ⇒ false.
     */
    public function check(): bool
    {
        if ($this->checked !== null) {
            return $this->checked;
        }
        $this->checked = false;
        $id = (string) ($_COOKIE[self::COOKIE] ?? '');
        // A session id is 64 hex chars; reject anything else without touching the db.
        if (strlen($id) !== 64 || !ctype_xdigit($id)) {
            return false;
        }
        try {
            $st = $this->db()->prepare('SELECT username, created_at, last_seen, csrf FROM admin_sessions WHERE id = :id');
            $st->execute([':id' => $id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                return false;
            }
            $now = time();
            $created = (int) $row['created_at'];
            $lastSeen = (int) $row['last_seen'];
            if (($now - $created) > $this->absoluteTimeoutS || ($now - $lastSeen) > $this->idleTimeoutS) {
                $this->db()->prepare('DELETE FROM admin_sessions WHERE id = :id')->execute([':id' => $id]);

                return false;
            }
            // Rotate last_seen so an active session slides its idle window forward.
            $this->db()->prepare('UPDATE admin_sessions SET last_seen = :s WHERE id = :id')
                ->execute([':s' => $now, ':id' => $id]);
            $this->currentUser = (string) $row['username'];
            $this->currentCsrf = (string) $row['csrf'];

            return $this->checked = true;
        } catch (Throwable $e) {
            error_log('AdminAuth check: ' . $e->getMessage());

            return false;
        }
    }

    public function currentUser(): ?string
    {
        $this->check();

        return $this->currentUser;
    }

    public function csrfToken(): ?string
    {
        $this->check();

        return $this->currentCsrf;
    }

    /**
     * Verify a synchroniser token against the current session's CSRF token. Requires a valid session
     * (so an unauthenticated caller can never satisfy it) and a non-empty token compared with
     * hash_equals (constant time). FAIL-CLOSED.
     */
    public function verifyCsrf(string $token): bool
    {
        if (!$this->check() || $this->currentCsrf === null) {
            return false;
        }

        return $token !== '' && hash_equals($this->currentCsrf, $token);
    }

    /** @return list<array{ts:string,ip:string,result:string}> recent auth attempts, newest first */
    public function attempts(int $limit = 100): array
    {
        try {
            $st = $this->db()->prepare('SELECT ts, ip, result FROM login_attempts ORDER BY id DESC LIMIT :n');
            $st->bindValue(':n', max(1, $limit), PDO::PARAM_INT);
            $st->execute();

            return array_map(static fn (array $r): array => [
                'ts' => gmdate('c', (int) $r['ts']),
                'ip' => (string) $r['ip'],
                'result' => (string) $r['result'],
            ], $st->fetchAll(PDO::FETCH_ASSOC) ?: []);
        } catch (Throwable $e) {
            return [];
        }
    }

    // ---------------------------------------------------------------- login-form oracle rate limit ---
    // (FP-0250 2.6 — the GET ?admin=login knock itself, distinct from the credential lockout above.)

    /**
     * Record that the GET ?admin=login form was rendered for $ip. A 'form' result — like 'lockout', it
     * never counts toward the credential lockout/backoff above (only 'fail' does); it exists solely so
     * {@see isFormRateLimited()} can bound how many times the form itself may be fetched.
     */
    public function recordFormView(string $ip): void
    {
        $this->record($ip, 'form');
    }

    /**
     * True when the login-form oracle should be decoyed for $ip: the per-IP 'form'+'fail' count within
     * the lockout window exceeds $cap. A scanner spraying `?admin=login` across many paths (only one of
     * which is the real hidden dashboard path) trips this on the real path long before it could ever
     * brute-force a credential — the point is bounding the SCAN rate of the knock itself, not guessing.
     */
    public function isFormRateLimited(string $ip, int $cap = 30): bool
    {
        if ($ip === '') {
            return false;
        }
        $cut = ($this->clock)() - $this->lockoutWindowS;
        $st = $this->db()->prepare(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = :ip AND result IN ('form', 'fail') AND ts >= :cut"
        );
        $st->execute([':ip' => $ip, ':cut' => $cut]);

        return (int) $st->fetchColumn() > $cap;
    }

    // ---------------------------------------------------------------- internals --------------------

    private function isLockedOut(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }
        $cut = ($this->clock)() - $this->lockoutWindowS;
        $st = $this->db()->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip = :ip AND result = 'fail' AND ts >= :cut");
        $st->execute([':ip' => $ip, ':cut' => $cut]);

        return (int) $st->fetchColumn() >= $this->maxFailures;
    }

    /**
     * Per-username exponential backoff (FP-0250 2.4) — the gap a per-IP-only lockout leaves open: a
     * rotating botnet gets N free guesses per IP against the SAME username, i.e. effectively unlimited
     * online guessing. Below maxFailures within the window ⇒ no backoff. At/after ⇒ a delay of
     * `min(60, 2 ** (fails - maxFailures))` seconds since the LAST fail — capped at 60s so this can
     * never become a permanent lock (operator-DoS guard, plan §5 risk 2): a rotating botnet buys at
     * most ~1 guess/minute against the real operator's username at the cap, while the operator with the
     * right password waits at most 60s worst case.
     */
    private function isUsernameBackedOff(string $username): bool
    {
        if ($username === '') {
            return false;
        }
        $now = ($this->clock)();
        $cut = $now - $this->lockoutWindowS;
        $st = $this->db()->prepare(
            "SELECT COUNT(*) AS c, MAX(ts) AS last FROM login_attempts WHERE username = :u AND result = 'fail' AND ts >= :cut"
        );
        $st->execute([':u' => $username, ':cut' => $cut]);
        $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];
        $fails = (int) ($row['c'] ?? 0);
        if ($fails < $this->maxFailures) {
            return false;
        }
        $delay = min(60, 2 ** ($fails - $this->maxFailures));
        $lastFailTs = (int) ($row['last'] ?? 0);

        return $now < ($lastFailTs + $delay);
    }

    /**
     * @param string $username the submitted username (trimmed + length-capped so a garbage/huge
     *                          username can't bloat the table — it is audit data, not a credential)
     */
    private function record(string $ip, string $result, string $username = ''): void
    {
        $username = substr(trim($username), 0, 64);
        try {
            $now = ($this->clock)();
            $this->db()->prepare('INSERT INTO login_attempts (ip, ts, result, username) VALUES (:ip, :ts, :r, :u)')
                ->execute([':ip' => $ip, ':ts' => $now, ':r' => $result, ':u' => $username]);
            // Growth cap (FP-0250 2.4): the table has no cap otherwise. Prune on every successful login
            // (cheap, infrequent) and probabilistically (~1-in-32) on every other record, so a sustained
            // failure/lockout flood still gets pruned without paying the DELETE cost on every single row.
            if ($result === 'ok' || random_int(1, 32) === 1) {
                $cut = $now - max(30 * 86400, $this->lockoutWindowS);
                $this->db()->prepare('DELETE FROM login_attempts WHERE ts < :cut')->execute([':cut' => $cut]);
            }
        } catch (Throwable $e) {
            error_log('AdminAuth record: ' . $e->getMessage());
        }
    }

    private function lookupHash(string $username): ?string
    {
        if ($username === '') {
            return null;
        }
        $st = $this->db()->prepare('SELECT pw_hash FROM admin_users WHERE username = :u');
        $st->execute([':u' => $username]);
        $h = $st->fetchColumn();

        return $h === false ? null : (string) $h;
    }

    /**
     * Hash a password with Argon2id. Prefers PHP's password_hash(PASSWORD_ARGON2ID) (present in the
     * base php:8.3-fpm-alpine image, built --with-password-argon2); falls back to ext-sodium's
     * sodium_crypto_pwhash_str (also Argon2id, required by composer.json) if the constant is absent on
     * some other base. Both emit the same $argon2id$ PHC string, so a hash from either verifies with
     * either — the fallback is safe across an image swap.
     */
    public static function hashPassword(string $password): string
    {
        if (defined('PASSWORD_ARGON2ID')) {
            $h = password_hash($password, PASSWORD_ARGON2ID);
            if (is_string($h)) {
                return $h;
            }
        }
        if (function_exists('sodium_crypto_pwhash_str')) {
            return sodium_crypto_pwhash_str(
                $password,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        throw new \RuntimeException('no Argon2id backend available (need PASSWORD_ARGON2ID or ext-sodium)');
    }

    /**
     * A fixed dummy Argon2id hash, computed once per process, for the unknown-user timing defence in
     * {@see login()}. Verifying against it costs the same as a real (failed) verify, so an unknown
     * username is indistinguishable by timing from a known one with a wrong password. Its plaintext is
     * a random value never accepted as a password.
     */
    private static function dummyHash(): string
    {
        static $h = null;
        if ($h === null) {
            $h = self::hashPassword(bin2hex(random_bytes(16)));
        }

        return $h;
    }

    public static function verifyPassword(string $password, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }
        // password_verify reads the algorithm from the PHC prefix and verifies an Argon2id string when
        // the algo is compiled in — true on the base image, whichever backend wrote the hash.
        if (defined('PASSWORD_ARGON2ID') && password_verify($password, $hash)) {
            return true;
        }
        if (function_exists('sodium_crypto_pwhash_str_verify')) {
            try {
                return sodium_crypto_pwhash_str_verify($hash, $password);
            } catch (Throwable $e) {
                return false;
            }
        }

        return false;
    }

    private function setCookie(string $id, int $expires): void
    {
        // Under the CLI/phpunit SAPI headers are already "sent" (stdout), so setcookie() is a no-op
        // there; suppress its warning. The security attributes are the load-bearing part in prod.
        @setcookie(self::COOKIE, $id, [
            'expires' => $expires,
            'path' => $this->cookiePath !== '' ? $this->cookiePath : '/',
            'secure' => $this->secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        if (!extension_loaded('pdo_sqlite')) {
            throw new \RuntimeException('AdminAuth needs ext-pdo_sqlite');
        }
        $db = Sqlite::open($this->dbPath); // shared WAL/busy_timeout/chmod idiom (docs/DATA-LAYER-DECISION.md)
        $db->exec('CREATE TABLE IF NOT EXISTS admin_users (
            username   TEXT PRIMARY KEY,
            pw_hash    TEXT NOT NULL,
            created_at TEXT NOT NULL
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS admin_sessions (
            id         TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL,
            csrf       TEXT NOT NULL
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS login_attempts (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            ip     TEXT NOT NULL,
            ts     INTEGER NOT NULL,
            result TEXT NOT NULL
        )');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts ON login_attempts (ip, ts)');
        // FP-0250 2.4: per-username backoff needs a username column on a table that predates it — a
        // guarded ALTER so an existing admin.sqlite upgrades in place, idempotent on every re-run
        // (SQLite has no "ADD COLUMN IF NOT EXISTS"; the duplicate-column error is the signal it is
        // already there).
        try {
            $db->exec('ALTER TABLE login_attempts ADD COLUMN username TEXT NOT NULL DEFAULT ""');
        } catch (Throwable $e) {
            // already has the column — expected on every boot after the first.
        }
        $db->exec('CREATE INDEX IF NOT EXISTS idx_login_attempts_user_ts ON login_attempts (username, ts)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_login_attempts_ts ON login_attempts (ts)'); // prune scan

        return $this->db = $db;
    }
}
