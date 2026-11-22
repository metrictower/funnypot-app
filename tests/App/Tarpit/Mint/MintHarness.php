<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Closure;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\SleepDecoy;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\AccountFront;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PDO;

require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';

/**
 * Drives the real HoneypotController::handle() with the real engine, armed or not: temp hit, mint
 * and intel stores, an injected clock, a capturing emitter (CLI cannot read sent headers), a counting
 * serve delayer, and the real reporters so their queues can be compared.
 */
final class MintHarness
{
    public const KEY = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
    public const IP = '45.79.12.34';

    public int $now = 1763800000;
    public int $delays = 0;
    public string $dir;
    public SqliteHitStore $hits;
    public ?TokenMintStore $store = null;
    public ?TokenMintDecoy $decoy = null;
    public ?AccountFront $front = null;
    public ?ProbeGate $gate = null;
    public HoneypotController $controller;
    public AppConfig $config;
    public MintPersona $persona;
    public ?MintPlan $last = null;

    /** @var list<string> PHP warnings and notices raised while handling, other than the CLI header noise */
    public array $warnings = [];

    /** Set only by tests that inject non-store faults on purpose. */
    public bool $allowFaults = false;

    /** @var array<string,string> cookie name => value, per jar name */
    public array $jars = ['default' => []];

    /**
     * @param array{friction?:bool,llm?:?int,probeGate?:bool,decoyArchive?:bool,storeLimits?:array<string,int>,storeFaults?:?Closure,sleepDecoy?:?SleepDecoy,storePath?:string,velocity?:array{0:int,1:int}} $opts
     */
    public function __construct(public bool $armed = true, array $opts = [])
    {
        $this->dir = sys_get_temp_dir() . '/fp0815h_' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0777, true);
        $this->config = AppConfig::fromEnv($this->dir);
        $this->config->latencyMs = 0;
        $this->config->jitterMs = 0;
        $this->config->decoyArchive = $opts['decoyArchive'] ?? true;
        $this->config->vulnsPath = $this->dir . '/none.json';
        $this->hits = new SqliteHitStore($this->dir . '/hits.sqlite');
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $this->persona = MintPersona::fromSeed($seed);

        $llm = null;
        if (($opts['probeGate'] ?? false) || array_key_exists('llm', $opts)) {
            [$v60, $v10] = $opts['velocity'] ?? [5, 15];
            $this->gate = new ProbeGate(new ProbeClassifier(), new VelocityTracker($v60, $v10), $this->hits, 24, $opts['allowIps'] ?? []);
        }
        if (array_key_exists('llm', $opts) && $opts['llm'] !== null) {
            $status = $opts['llm'];
            $llm = new LlmFakeResponder(
                $this->gate,
                new LlmFakeCache($this->dir . '/llm.sqlite'),
                new LlmClient('http://sidecar/completion', 1500, 320, null, static fn (): array => [
                    'status' => $status,
                    'body' => (string) json_encode(['content' => '<!doctype html><html><head><title>Customers</title></head><body><h1>Customers</h1><p>Records</p></body></html>']),
                ]),
                new LlmOutputSanitizer(),
                $this->hits,
                new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"'),
                'v1',
                4,
            );
        }

        if ($armed) {
            $this->store = new TokenMintStore($opts['storePath'] ?? $this->dir . '/token-mint.sqlite', $opts['storeLimits'] ?? [], $opts['storeFaults'] ?? null);
            $this->decoy = TokenMintDecoy::build(
                self::KEY,
                $seed,
                $this->store,
                $opts['friction'] ?? true,
                $this->gate,
                fn (): int => $this->now,
                function (MintPlan $p): void {
                    $this->last = $p;
                    echo $p->body;
                },
            );
            $this->front = new AccountFront($this->decoy->context());
        }
        $this->controller = new HoneypotController(
            $this->hits,
            new \Geo($this->dir . '/geo.csv'),
            $this->config,
            dirname(__DIR__, 4) . '/demo/decoys',
            IdentityTestSupport::coreConfigFactory(),
            null,
            new AbuseIpdb('k', $this->dir . '/intel.sqlite', ['10.0.0.1']),
            new ThreatIntelReporter('http://ti.invalid', 'k', $this->dir . '/intel.sqlite', ['10.0.0.1']),
            $llm,
            new AttackClassifier(),
            null,
            $opts['sleepDecoy'] ?? null,
            $this->decoy,
            function (): void {
                $this->delays++;
            },
        );
    }

    /** Point the surface at another store (same keys and clock), e.g. one whose file cannot open. */
    public function swapStore(TokenMintStore $store): void
    {
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $this->store = $store;
        $this->decoy = TokenMintDecoy::build(self::KEY, $seed, $store, true, $this->gate, fn (): int => $this->now, function (MintPlan $p): void {
            $this->last = $p;
            echo $p->body;
        });
        $this->front = new AccountFront($this->decoy->context());
        $rp = new \ReflectionProperty(HoneypotController::class, 'tokenMint');
        $rp->setValue($this->controller, $this->decoy);
    }

    public function cleanup(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    /**
     * The hit rows written after row $id, mapped exactly as the store maps them for its readers.
     *
     * @return list<array<string,mixed>>
     */
    public function rowsSince(int $id): array
    {
        $db = new PDO('sqlite:' . $this->dir . '/hits.sqlite');
        $st = $db->prepare('SELECT * FROM hits WHERE id > :id ORDER BY id');
        $st->execute([':id' => $id]);
        $map = new \ReflectionMethod(SqliteHitStore::class, 'mapRow');
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $raw) {
            $out[] = ['id' => (int) $raw['id']] + $map->invoke($this->hits, $raw);
        }

        return $out;
    }

    private function maxHitId(): int
    {
        $db = new PDO('sqlite:' . $this->dir . '/hits.sqlite');

        return (int) $db->query('SELECT COALESCE(MAX(id),0) FROM hits')->fetchColumn();
    }

    /**
     * One request through handle(). Returns the plan the surface emitted (null when it did not
     * answer), the body that went out, every hit row the request wrote and the main row.
     *
     * @param array<string,string> $headers
     * @return array{plan:?MintPlan,body:string,rows:list<array<string,mixed>>,main:?array<string,mixed>,status:?int}
     */
    public function request(string $method, string $path, string $query = '', ?string $body = null, array $headers = [], string $ip = self::IP, string $jar = 'default'): array
    {
        $cookies = [];
        foreach ($this->jars[$jar] ?? [] as $k => $v) {
            $cookies[] = $k . '=' . $v;
        }
        if ($cookies !== [] && !isset($headers['Cookie'])) {
            $headers['Cookie'] = implode('; ', $cookies);
        }
        if ($body !== null && !isset($headers['Content-Type'])) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        $headers += ['User-Agent' => 'Mozilla/5.0'];
        $this->last = null;
        $before = $this->maxHitId();
        $faults = $this->decoy?->faults() ?? 0;
        ob_start();
        // CLI has no real response: header() after test output warns "headers already sent", which
        // is the harness, not the code. Every other warning or notice is recorded for the tests.
        set_error_handler(function (int $no, string $msg, string $file = '', int $line = 0): bool {
            // An @-suppressed call reports nothing in production either.
            if ((error_reporting() & $no) === 0) {
                return true;
            }
            if (!str_contains($msg, 'headers already sent')) {
                $this->warnings[] = "{$msg} @ {$file}:{$line}";
            }

            return true;
        });
        try {
            $this->controller->handle(new RequestContext($method, $path, $query, $headers, $body), $ip, 'off');
        } finally {
            restore_error_handler();
            $out = (string) ob_get_clean();
        }
        if (!$this->allowFaults && $this->decoy !== null && $this->decoy->faults() > $faults) {
            $e = $this->decoy->lastFault();
            throw new \RuntimeException("fault path on {$method} {$path}: " . ($e ? get_class($e) . ' ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() : '?'));
        }
        $plan = $this->last;
        if ($plan !== null) {
            foreach ($plan->headers() as [$n, $v]) {
                if ($n === 'Set-Cookie' && preg_match('/\Asession=([^;]*)/', $v, $m) === 1) {
                    if ($m[1] === '') {
                        unset($this->jars[$jar]['session']);
                    } else {
                        $this->jars[$jar]['session'] = $m[1];
                    }
                }
            }
        }
        $rows = $this->rowsSince($before);
        $main = null;
        foreach ($rows as $r) {
            if (!in_array($r['event'] ?? '', ['llm-fake', 'panel', 'decoy-archive'], true)) {
                $main = $r;
            }
        }

        return ['plan' => $plan, 'body' => $out, 'rows' => $rows, 'main' => $main, 'status' => $plan?->status];
    }

    /** @param array<string,mixed> $fields */
    public function post(string $path, array $fields, string $jar = 'default', string $ip = self::IP): array
    {
        return $this->request('POST', $path, '', http_build_query($fields), [], $ip, $jar);
    }

    public function get(string $path, string $query = '', string $jar = 'default', string $ip = self::IP, array $headers = []): array
    {
        return $this->request('GET', $path, $query, null, $headers, $ip, $jar);
    }

    public static function csrf(string $body): string
    {
        return preg_match("/name=csrf_token value='([^']+)'/", $body, $m) === 1 ? $m[1] : '';
    }

    /** Sign up an account from $ip into $jar; returns the username. */
    public function join(string $username = 'artex1', string $password = 'Passw0rd!x', string $jar = 'default', string $ip = self::IP): string
    {
        $page = $this->get('/join', '', $jar, $ip);
        $r = $this->post('/join', [
            'csrf_token' => self::csrf($page['body']), 'username' => $username, 'email' => $username . '@example.com',
            'password' => $password, 'password_confirmation' => $password,
        ], $jar, $ip);
        if (($r['status'] ?? 0) !== 303) {
            throw new \RuntimeException('join failed: ' . ($r['status'] ?? 'null'));
        }

        return $username;
    }

    /** Sign in through the account front, as the "/" form would. */
    public function signIn(string $username, string $password, string $jar = 'default', string $ip = self::IP): ?array
    {
        $res = $this->front?->signIn(new RequestContext('POST', '/'), $ip, $username, $password);
        if (isset($res['cookie']) && preg_match('/\Asession=([^;]*)/', $res['cookie'], $m) === 1) {
            $this->jars[$jar]['session'] = $m[1];
        }

        return $res;
    }

    /** @return array{abuse:list<array<string,mixed>>,ti:list<array<string,mixed>>} */
    public function reports(): array
    {
        $path = $this->dir . '/intel.sqlite';
        if (!is_file($path)) {
            return ['abuse' => [], 'ti' => []];
        }
        $db = new PDO('sqlite:' . $path);
        $q = static function (string $sql) use ($db): array {
            try {
                return $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
            } catch (\Throwable $e) {
                return [];
            }
        };

        return [
            'abuse' => $q('SELECT ip, categories, comment FROM abuse_queue ORDER BY id'),
            'ti' => $q('SELECT ip, categories, comment, signals, confidence FROM ti_queue ORDER BY id'),
        ];
    }

    /**
     * Mint a personal access token through the real forms, retrying past friction. Returns the token.
     *
     * @param list<string> $scopes
     */
    public function mint(array $scopes, string $note = 'ci token', string $jar = 'default', string $ip = self::IP, string $password = 'Passw0rd!x', string $username = 'artex1', int $maxTries = 40): string
    {
        for ($i = 0; $i < $maxTries; $i++) {
            $this->now += 7;
            $form = $this->get('/settings/tokens/new', '', $jar, $ip);
            if (($form['status'] ?? 0) === 303) {
                $this->signIn($username, $password, $jar, $ip);
                continue;
            }
            $r = $this->post('/settings/tokens', ['csrf_token' => self::csrf($form['body']), 'note' => $note . ' ' . $i, 'expiration' => '30', 'scopes' => $scopes], $jar, $ip);
            $loc = $r['plan']?->header('Location');
            if (($r['status'] ?? 0) === 303 && $loc === '/settings/tokens') {
                $list = $this->get('/settings/tokens', '', $jar, $ip);
                if (preg_match('/([a-z]{2,4}_pat_[0-9A-Za-z]{31})/', $list['body'], $m) === 1) {
                    return $m[1];
                }
            } elseif ($loc === '/settings/confirm') {
                $this->confirm($jar, $ip, $password, $this->totp);
            } elseif ($loc === '/') {
                $this->signIn($username, $password, $jar, $ip);
            } elseif (($r['status'] ?? 0) === 429) {
                $this->now += (int) ($r['plan']?->header('Retry-After') ?? 60) + 1;
            }
        }
        throw new \RuntimeException('could not mint');
    }

    /** The TOTP secret once enable2fa() ran, so retries can pass confirm-access. */
    public ?string $totp = null;

    /**
     * Retry a form submission past friction: re-sign-in after a lapsed session, pass confirm-access,
     * wait out a throttle, reload a stale form. $attempt does one GET-then-POST and returns the POST.
     *
     * @param callable():array $attempt
     * @param callable(array):bool $done
     */
    public function until(callable $attempt, callable $done, string $jar = 'default', string $ip = self::IP, int $max = 40): array
    {
        for ($i = 0; $i < $max; $i++) {
            $this->now += 7;
            $r = $attempt();
            if ($done($r)) {
                return $r;
            }
            $loc = $r['plan']?->header('Location');
            if ($loc === '/') {
                $this->signIn('artex1', 'Passw0rd!x', $jar, $ip);
            } elseif ($loc === '/settings/confirm') {
                $this->confirm($jar, $ip, 'Passw0rd!x', $this->totp);
            } elseif (($r['status'] ?? 0) === 429) {
                $this->now += (int) ($r['plan']?->header('Retry-After') ?? 60) + 1;
            }
        }
        throw new \RuntimeException('form never succeeded');
    }

    /** Pass confirm-access (with the account's TOTP when 2FA is on). */
    public function confirm(string $jar = 'default', string $ip = self::IP, string $password = 'Passw0rd!x', ?string $totpSecret = null): array
    {
        $page = $this->get('/settings/confirm', '', $jar, $ip);
        $fields = ['csrf_token' => self::csrf($page['body']), 'password' => $password];
        if ($totpSecret !== null) {
            $this->now += 31;
            $fields['otp'] = \Funnypot\App\Tarpit\Mint\Totp::code($totpSecret, \Funnypot\App\Tarpit\Mint\Totp::step($this->now));
        }

        return $this->post('/settings/confirm', $fields, $jar, $ip);
    }

    /** Enable 2FA; returns [raw secret, recovery codes]. @return array{0:string,1:list<string>} */
    public function enable2fa(string $jar = 'default', string $ip = self::IP): array
    {
        $page = $this->get('/settings/security', '', $jar, $ip);
        preg_match('/<p class=mono>([A-Z2-7]{32})<\/p>/', $page['body'], $m);
        $raw = self::base32decode($m[1]);
        $r = $this->post('/settings/security', ['csrf_token' => self::csrf($page['body']), 'otp' => \Funnypot\App\Tarpit\Mint\Totp::code($raw, \Funnypot\App\Tarpit\Mint\Totp::step($this->now))], $jar, $ip);
        $this->totp = $raw;
        $codes = [];
        if (preg_match('~<p class=mono>((?:[a-z2-7]{5}-[a-z2-7]{5}(?:<br>)?)+)</p>~', $r['body'], $block) === 1) {
            $codes = explode('<br>', $block[1]);
        }

        return [$raw, $codes];
    }

    public static function base32decode(string $b32): string
    {
        $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($b32) as $ch) {
            $bits .= str_pad(decbin((int) strpos($alpha, $ch)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }
}
