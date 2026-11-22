<?php

declare(strict_types=1);

namespace Funnypot\App\Bench;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\AccountFront;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\App\Tarpit\Mint\Totp;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;

/**
 * A scripted mint-and-use agent against the token-mint surface, shaped on the live run that spent
 * most of two hours in a settings form: sign up, try to mint a token with an organisation scope,
 * fight whatever the form answers, use what it gets, chase the wall it hits, repeat.
 *
 * Every owned path goes through the real Router into HoneypotController::handle(); the "/" sign-in
 * goes through AccountFront::signIn(), which is what HomeController::login calls (the CLI cannot read
 * a cookie HomeController sends itself). Four profiles: fast and slow think time, a cookie-dropping
 * client that loses its jar every 3–6 steps, and a zero-think client that resends an identical form
 * up to five times. Fully deterministic for a profile and seed: no wall clock, no randomness beyond
 * the seeded generator.
 */
final class TokenMintLoop
{
    public const PROFILES = ['fast', 'slow', 'cookie-drop', 'zero-think'];
    private const IP = '45.90.1.1';

    public int $now = 1763798400;
    private string $dir;
    private Router $router;
    private AccountFront $front;
    private TokenMintDecoy $decoy;
    private TokenMintStore $store;
    private ?MintPlan $last = null;
    private ?string $cookie = null;
    private bool $joined = false;
    private ?string $totp = null;
    /** @var list<string> */
    private array $tokens = [];

    /** @var array<string,mixed> */
    public array $report = [
        'steps' => 0, 'mint_posts' => 0, 'outcomes' => [], 'mints' => 0, 'api_calls' => 0, 'goal_2xx' => 0, 'admin_roles' => 0,
        'sso_successes' => 0, 'goal_proof_bytes' => 0, 'max_status' => 0, 'after_loss' => [], 'losses' => 0, 'resend_pairs' => 0, 'resend_mismatch' => 0,
    ];
    /** @var list<string> */
    private array $trace = [];

    public function __construct(public readonly string $profile, public readonly int $seed)
    {
        if (!in_array($profile, self::PROFILES, true)) {
            throw new \InvalidArgumentException('unknown profile');
        }
        $this->dir = sys_get_temp_dir() . '/fp_mintloop_' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $config = AppConfig::fromEnv($this->dir);
        $config->latencyMs = 0;
        $config->jitterMs = 0;
        $hits = new SqliteHitStore($this->dir . '/hits.sqlite');
        $geo = new \Geo($this->dir . '/geo.csv');
        $this->store = new TokenMintStore($this->dir . '/token-mint.sqlite');
        $persona = IdentityTestSupport::httpIdentity()->personaSeed();
        $this->decoy = TokenMintDecoy::build(str_repeat("\x42", 32), $persona, $this->store, true, null, fn (): int => $this->now, function (MintPlan $p): void {
            $this->last = $p;
            echo $p->body;
        });
        $this->front = new AccountFront($this->decoy->context());
        $root = dirname(__DIR__, 2);
        $honeypot = new HoneypotController($hits, $geo, $config, $root . '/demo/decoys', IdentityTestSupport::coreConfigFactory(), null, null, null, null, new AttackClassifier(), null, null, $this->decoy, static function (): void {
        });
        $dashboard = new DashboardController($hits, $geo, $config, $root . '/demo/assets', null, null, $hits, new AdminAuth($this->dir . '/admin.sqlite'), new ConfigStore($this->dir . '/cfg.sqlite'));
        $corporate = new CorporateController($hits, $geo, $config, $root . '/demo/assets', null, null);
        $home = new HomeController($hits, $geo, $config, $root . '/demo/assets', null, null, null, $this->front);
        $this->router = new Router($config, $honeypot, $dashboard, $corporate, $home);
        mt_srand($seed * 7919 + crc32($profile));
    }

    public function cleanup(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    public function store(): TokenMintStore
    {
        return $this->store;
    }

    /** One request through the Router. */
    private function send(string $method, string $path, string $query = '', ?array $fields = null, array $headers = []): ?MintPlan
    {
        if ($this->cookie !== null) {
            $headers['Cookie'] = 'session=' . $this->cookie;
        }
        $body = $fields === null ? null : http_build_query($fields);
        if ($body !== null) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        $this->last = null;
        $_GET = [];
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = $method;
        ob_start();
        try {
            @$this->router->dispatch(new RequestContext($method, $path, $query, $headers + ['User-Agent' => 'python-requests/2.31'], $body), self::IP, 'off');
        } finally {
            ob_end_clean();
        }
        $p = $this->last;
        if ($p !== null) {
            $this->report['max_status'] = max($this->report['max_status'], $p->status);
            foreach ($p->headers() as [$n, $v]) {
                if ($n === 'Set-Cookie' && preg_match('/\Asession=([^;]*)/', $v, $m) === 1) {
                    $this->cookie = $m[1] === '' ? null : $m[1];
                }
            }
            $this->trace[] = $method . ' ' . $path . ' ' . $p->status . ' ' . hash('crc32b', $p->body);
        }

        return $p;
    }

    private static function csrf(?MintPlan $p): string
    {
        return $p !== null && preg_match("/name=csrf_token value='([^']+)'/", $p->body, $m) === 1 ? $m[1] : '';
    }

    private function think(): void
    {
        $this->now += match ($this->profile) {
            'slow' => mt_rand(60, 240),
            'zero-think' => 0,
            default => mt_rand(1, 5),
        };
    }

    private function signIn(): void
    {
        $r = $this->front->signIn(new RequestContext('POST', '/'), self::IP, 'agent01', 'Passw0rd!x');
        if (isset($r['cookie']) && preg_match('/\Asession=([^;]*)/', $r['cookie'], $m) === 1) {
            $this->cookie = $m[1];
        }
        $this->trace[] = 'signin ' . (isset($r['cookie']) ? 'ok' : json_encode($r));
    }

    /** @return array<string,mixed> */
    public function run(int $steps): array
    {
        $dropEvery = mt_rand(3, 6);
        $lostAt = null;
        for ($i = 0; $i < $steps; $i++) {
            $this->report['steps']++;
            $this->think();
            if ($this->profile === 'cookie-drop' && $i > 0 && $i % $dropEvery === 0 && $this->cookie !== null) {
                $this->cookie = null;
                $this->report['losses']++;
                $lostAt = $i;
                $dropEvery = mt_rand(3, 6);
            }
            if (!$this->joined) {
                $join = $this->send('GET', '/join');
                $r = $this->send('POST', '/join', '', ['csrf_token' => self::csrf($join), 'username' => 'agent01', 'email' => 'agent01@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x']);
                $this->joined = $r !== null && $r->status === 303;
                continue;
            }
            if ($this->cookie === null) {
                $this->signIn();
                continue;
            }
            $outcome = $this->mintAttempt($i, $lostAt);
            if ($outcome === 'minted' && $this->tokens !== []) {
                $this->useToken(end($this->tokens));
            }
        }

        return $this->finish();
    }

    /** One mint attempt; returns the attribution outcome of the POST. */
    private function mintAttempt(int $i, ?int $lostAt): string
    {
        $scopes = $this->totp === null ? ['read:user'] : ['read:user', 'orders:read'];
        $form = $this->send('GET', '/settings/tokens/new');
        if ($form === null || $form->status !== 200) {
            if ($form?->header('Location') === '/') {
                $this->cookie = null;
            }

            return 'no_form';
        }
        $fields = ['csrf_token' => self::csrf($form), 'note' => 'ci token ' . $i, 'expiration' => '30', 'scopes' => $scopes];
        $resends = $this->profile === 'zero-think' ? mt_rand(1, 5) : 1;
        $outcome = 'none';
        $previous = null;
        for ($k = 0; $k < $resends; $k++) {
            $before = $this->rowJson();
            $p = $this->send('POST', '/settings/tokens', '', $fields);
            $this->report['mint_posts']++;
            if ($p === null) {
                return 'unanswered';
            }
            $kind = (string) ($p->turn['friction'] ?? $p->turn['outcome'] ?? 'other');
            $this->report['outcomes'][] = $kind;
            if ($lostAt !== null && $lostAt === $i - 1) {
                $this->report['after_loss'][] = $kind;
            }
            if ($previous !== null && $previous[0] === $before) {
                $this->report['resend_pairs']++;
                if ($previous[1] !== $p->body) {
                    $this->report['resend_mismatch']++;
                }
            }
            $previous = [$before, $p->body];
            $outcome = $this->react($p);
            if ($outcome === 'minted') {
                break;
            }
        }

        return $outcome;
    }

    private function rowJson(): string
    {
        $db = $this->store->db();

        return $db === null ? '' : (string) json_encode($db->query('SELECT state FROM mint_state ORDER BY k')->fetchAll(\PDO::FETCH_COLUMN));
    }

    private function react(MintPlan $p): string
    {
        $loc = $p->header('Location');
        if ($p->status === 303 && $loc === '/settings/tokens') {
            $list = $this->send('GET', '/settings/tokens');
            if ($list !== null && preg_match('/([a-z]{2,4}_pat_[0-9A-Za-z]{31})/', $list->body, $m) === 1) {
                $this->tokens[] = $m[1];
                $this->report['mints']++;
            }

            return 'minted';
        }
        if ($loc === '/settings/confirm') {
            $page = $this->send('GET', '/settings/confirm');
            $f = ['csrf_token' => self::csrf($page), 'password' => 'Passw0rd!x'];
            if ($this->totp !== null) {
                $this->now += 31;
                $f['otp'] = Totp::code($this->totp, Totp::step($this->now));
            }
            $this->send('POST', '/settings/confirm', '', $f);

            return 'confirm';
        }
        if ($loc === '/') {
            $this->cookie = null;

            return 'signed_out';
        }
        if ($p->status === 429) {
            $this->now += (int) ($p->header('Retry-After') ?? 60);

            return 'throttled';
        }
        if ($p->status === 422 && str_contains($p->body, 'two-factor')) {
            $sec = $this->send('GET', '/settings/security');
            if ($sec !== null && preg_match('/<p class=mono>([A-Z2-7]{32})<\/p>/', $sec->body, $m) === 1) {
                $raw = self::b32($m[1]);
                $r = $this->send('POST', '/settings/security', '', ['csrf_token' => self::csrf($sec), 'otp' => Totp::code($raw, Totp::step($this->now))]);
                if ($r !== null && $r->status === 200) {
                    $this->totp = $raw;
                }
            }

            return 'enrolled';
        }

        return 'retry';
    }

    /** Use a minted token the way the agent would: whoami, the goal endpoints, then chase the wall. */
    private function useToken(string $tok): void
    {
        $auth = ['Authorization' => 'Bearer ' . $tok];
        foreach (['/api/v2/user', '/api/v2/orders', '/v2/users', '/api/v2/orders/10422', '/api/v2/user/orgs'] as $path) {
            $p = $this->send('GET', $path, '', null, $auth);
            if ($p === null) {
                continue;
            }
            $this->report['api_calls']++;
            $j = json_decode($p->body, true);
            if (is_array($j) && in_array($j['role'] ?? null, ['owner', 'admin'], true)) {
                $this->report['admin_roles']++;
            }
            $goal = in_array($path, ['/api/v2/orders', '/v2/users', '/api/v2/orders/10422'], true);
            if ($goal && $p->status < 300) {
                $this->report['goal_2xx']++;
                $this->report['goal_proof_bytes'] += strlen($p->body);
            }
            if ($goal && is_array($j) && isset($j['sso_url']) && is_string($j['sso_url'])) {
                $this->chaseSso($j['sso_url']);
            }
        }
    }

    private function chaseSso(string $url): void
    {
        $slugPath = (string) parse_url($url, PHP_URL_PATH);
        $page = $this->send('GET', $slugPath, (string) parse_url($url, PHP_URL_QUERY));
        $to = $this->send('POST', $slugPath, '', ['csrf_token' => self::csrf($page), 'authorization_request' => '']);
        $idpPath = (string) ($to?->header('Location') ?? '');
        if ($idpPath === '') {
            return;
        }
        $idp = $this->send('GET', $idpPath);
        $r = $this->send('POST', $idpPath, '', ['csrf_token' => self::csrf($idp), 'username' => 'agent01', 'password' => 'Passw0rd!x']);
        if ($r !== null && $r->status === 303) {
            $this->report['sso_successes']++;
        }
    }

    private static function b32(string $s): string
    {
        $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($s) as $c) {
            $bits .= str_pad(decbin((int) strpos($alpha, $c)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $b) {
            if (strlen($b) === 8) {
                $out .= chr(bindec($b));
            }
        }

        return $out;
    }

    /** @return array<string,mixed> */
    private function finish(): array
    {
        $phantoms = array_values(array_filter($this->report['outcomes'], static fn (string $k): bool => in_array($k, ['form_stale', 'session_lapsed', 'confirm_lapsed', 'throttled', 'edit_conflict', 'transient'], true)));
        $hist = array_count_values($this->report['outcomes']);
        arsort($hist);
        $total = max(1, count($this->report['outcomes']));
        $this->report['histogram'] = $hist;
        $this->report['phantom_kinds'] = count(array_unique($phantoms));
        $this->report['max_share'] = round(((int) (reset($hist) ?: 0)) / $total, 3);
        $this->report['longest_period'] = self::shortestPeriod(array_slice($this->report['outcomes'], 0, 24));
        $this->report['replay_hash'] = hash('sha256', implode("\n", $this->trace));
        $db = $this->store->db();
        $this->report['persisted_pats'] = 0;
        if ($db !== null) {
            foreach ($db->query('SELECT state FROM mint_state')->fetchAll(\PDO::FETCH_COLUMN) as $json) {
                $s = json_decode((string) $json, true);
                foreach ((array) ($s['a'] ?? []) as $a) {
                    $this->report['persisted_pats'] += count(array_filter((array) $a['k'], static fn (array $t): bool => $t['k'] === 'pat'));
                }
                $this->report['stored_history'] = array_column((array) ($s['o'] ?? []), 1);
            }
        }

        return $this->report;
    }

    /** The shortest exact period of a sequence (0 when it has none shorter than itself). */
    private static function shortestPeriod(array $seq): int
    {
        $n = count($seq);
        for ($p = 1; $p <= intdiv($n, 2); $p++) {
            $ok = true;
            for ($i = $p; $i < $n; $i++) {
                if ($seq[$i] !== $seq[$i - $p]) {
                    $ok = false;
                    break;
                }
            }
            if ($ok) {
                return $p;
            }
        }

        return 0;
    }
}
