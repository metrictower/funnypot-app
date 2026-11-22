<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Mint\MintState;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/**
 * Real multi-process contention on one token-mint.sqlite: two workers start on a shared barrier and
 * race 50 rounds each. A code or refresh token has exactly one winner, concurrent mints on one
 * account lose no update, and concurrent sign-ups on one source lose no account.
 */
final class TokenMintStoreConcurrencyTest extends TestCase
{
    private const NOW = 1763800000;
    private const IP = '45.79.30.30';
    /** Room for every pre-issued code and refresh token to stay live through the race. */
    private const LIMITS = ['codes_per_account' => 200, 'refresh_per_account' => 200];
    private string $dir = '';
    private string $db = '';
    private int $seed = 0;
    private ?TokenMintDecoy $decoy = null;
    private ?string $cookie = null;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite') || !function_exists('proc_open')) {
            self::markTestSkipped('pdo_sqlite / proc_open required');
        }
        $this->dir = sys_get_temp_dir() . '/fp_tmc_' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0777, true);
        $this->db = $this->dir . '/token-mint.sqlite';
        $this->seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $this->decoy = TokenMintDecoy::build(str_repeat("\x42", 32), $this->seed, new TokenMintStore($this->db, self::LIMITS), false, null, static fn (): int => self::NOW, static function (): void {
        });
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function send(string $method, string $path, string $query = '', ?array $fields = null): MintPlan
    {
        $h = ['Content-Type' => 'application/x-www-form-urlencoded'];
        if ($this->cookie !== null) {
            $h['Cookie'] = 'session=' . $this->cookie;
        }
        $p = $this->decoy->prepare(new RequestContext($method, $path, $query, $h, $fields === null ? null : http_build_query($fields)), self::IP, new IssuedValue(static fn (RequestContext $r): bool => false));
        self::assertNotNull($p, "{$method} {$path}");
        foreach ($p->headers() as [$n, $v]) {
            if ($n === 'Set-Cookie' && preg_match('/\Asession=([A-Za-z0-9_-]+)/', $v, $m) === 1) {
                $this->cookie = $m[1];
            }
        }

        return $p;
    }

    private static function csrf(string $body): string
    {
        return preg_match("/name=csrf_token value='([^']+)'/", $body, $m) === 1 ? $m[1] : '';
    }

    /** @return array{client:string,secret:string} */
    private function account(): array
    {
        $page = $this->send('GET', '/join');
        $this->send('POST', '/join', '', ['csrf_token' => self::csrf($page->body), 'username' => 'racer', 'email' => 'r@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x']);
        $form = $this->send('GET', '/settings/applications/new');
        $created = $this->send('POST', '/settings/applications', '', ['csrf_token' => self::csrf($form->body), 'name' => 'racer-app', 'homepage_url' => 'https://a.example.com', 'callback_url' => 'https://a.example.com/cb']);
        $page = (string) $created->header('Location');
        $show = $this->send('GET', $page);
        preg_match('~<p>Client ID</p><p class=mono>([a-f0-9]{20})</p>~', $show->body, $cm);
        $confirm = $this->send('GET', '/settings/confirm');
        $this->send('POST', '/settings/confirm', '', ['csrf_token' => self::csrf($confirm->body), 'password' => 'Passw0rd!x']);
        $show = $this->send('GET', $page);
        $this->send('POST', $page . '/secrets', '', ['csrf_token' => self::csrf(substr($show->body, (int) strpos($show->body, '/secrets')))]);
        $show = $this->send('GET', $page);
        preg_match('~<p class=mono>([a-f0-9]{40})</p>~', $show->body, $sm);

        return ['client' => $cm[1], 'secret' => $sm[1]];
    }

    private function code(string $client): string
    {
        $page = $this->send('GET', '/login/oauth/authorize', http_build_query(['client_id' => $client, 'scope' => 'read:user']));
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $page->body, $m);
        $code = $this->send('POST', '/login/oauth/authorize', '', ['csrf_token' => self::csrf($page->body), 'authorization_request' => $m[1], 'authorize' => '1']);
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code->body, $cm);

        return $cm[1];
    }

    /** @return list<array<string,mixed>> */
    private function race(string $action, array $argsA, array $argsB): array
    {
        $script = __DIR__ . '/support/token-mint-child.php';
        $barrier = $this->dir . '/go-' . bin2hex(random_bytes(3));
        $env = ['PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin')];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR', 'HOME'] as $k) {
            $v = getenv($k);
            if ($v !== false && $v !== '') {
                $env[$k] = $v;
            }
        }
        $procs = [];
        foreach ([$argsA, $argsB] as $args) {
            $args += ['seed' => $this->seed, 'now' => self::NOW, 'ip' => self::IP, 'limits' => self::LIMITS];
            $p = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', $script, $this->db, $action, $barrier, (string) json_encode($args)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->dir, $env);
            self::assertIsResource($p);
            $procs[] = [$p, $pipes];
        }
        touch($barrier);
        $facts = [];
        foreach ($procs as $i => [$p, $pipes]) {
            $out = trim((string) stream_get_contents($pipes[1]));
            $err = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(0, proc_close($p), "worker {$i}: {$err}");
            $facts[] = (array) json_decode($out, true);
        }

        return $facts;
    }

    private function state(): MintState
    {
        $s = (new TokenMintStore($this->db))->load(bin2hex((new \Funnypot\App\Tarpit\Mint\MintKeys(str_repeat("\x42", 32)))->kref(self::IP)));
        self::assertNotNull($s);

        return $s;
    }

    public function test_fifty_rounds_of_raced_codes_and_refresh_tokens_have_one_winner_each(): void
    {
        $app = $this->account();
        $codes = [];
        for ($i = 0; $i < 50; $i++) {
            $codes[] = $this->code($app['client']);
        }
        $refresh = [];
        foreach (array_splice($codes, 0, 25) as $c) {
            $p = $this->send('POST', '/login/oauth/access_token', '', ['grant_type' => 'authorization_code', 'code' => $c, 'client_id' => $app['client'], 'client_secret' => $app['secret']]);
            $refresh[] = json_decode($p->body, true)['refresh_token'];
        }
        $ex = $this->race('exchange-list', ['codes' => $codes] + $app, ['codes' => $codes] + $app);
        self::assertSame(count($codes), $ex[0]['ok'] + $ex[1]['ok'], 'exactly one access token per code across both workers');
        self::assertSame(count($codes), $ex[0]['fail'] + $ex[1]['fail']);
        self::assertSame(0, $ex[0]['other'] + $ex[1]['other']);
        $rf = $this->race('refresh-list', ['refreshes' => $refresh] + $app, ['refreshes' => $refresh] + $app);
        self::assertSame(count($refresh), $rf[0]['ok'] + $rf[1]['ok'], 'one winner per refresh token');
        self::assertSame(count($refresh), $rf[0]['fail'] + $rf[1]['fail']);
        self::assertSame(0, $rf[0]['other'] + $rf[1]['other']);
    }

    public function test_concurrent_mints_on_one_account_lose_no_update(): void
    {
        $this->account();
        $form = $this->send('GET', '/settings/tokens/new');
        $args = ['cookie' => $this->cookie, 'csrf' => self::csrf($form->body), 'rounds' => 50];
        $f = $this->race('mint', $args, $args);
        self::assertSame(0, $f[0]['other'] + $f[1]['other']);
        self::assertSame(100, $f[0]['ok'] + $f[1]['ok'] + $f[0]['fail'] + $f[1]['fail']);
        $s = $this->state();
        $pats = array_values(array_filter($s->d['a'][0]['k'], static fn (array $t): bool => $t['k'] === 'pat'));
        self::assertSame($f[0]['ok'] + $f[1]['ok'], count($pats), 'every success is persisted');
        self::assertSame(MintState::MAX_TOKENS, count($pats));
        self::assertSame(count($pats), (int) $s->d['a'][0]['mn'], 'the mint counter saw every success');
        self::assertCount(MintState::MAX_MINT_TS, $s->d['m'], 'every attempt reached the history');
    }

    public function test_concurrent_sign_ups_on_one_source_lose_no_account(): void
    {
        $page = $this->send('GET', '/join');
        $args = ['csrf' => self::csrf($page->body), 'rounds' => 50];
        $f = $this->race('join', $args, $args);
        self::assertSame(100, $f[0]['ok'] + $f[1]['ok'], (string) json_encode([$f[0]['why'] ?? null, $f[1]['why'] ?? null]));
        $s = $this->state();
        self::assertGreaterThanOrEqual(100, (int) $s->d['an'], 'every sign-up took a serial');
        self::assertCount(MintState::MAX_ACCOUNTS, $s->d['a']);
        $names = array_merge($f[0]['tokens'], $f[1]['tokens']);
        foreach ($s->d['a'] as $a) {
            self::assertContains($a['u'], $names);
        }
    }
}
