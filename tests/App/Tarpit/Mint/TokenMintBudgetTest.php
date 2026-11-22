<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use PHPUnit\Framework\TestCase;

/**
 * The surface's bounds through the real HoneypotController::handle(): the per-source hourly ledger sheds
 * at the same request whatever the clock, the store's speed or its write caps, a write cap refuses forms
 * without stopping reads, and fuzzed input stays in the closed answer sets with no fault and no warning.
 * Kept apart from the journey tests because each runs many requests.
 */
final class TokenMintBudgetTest extends TestCase
{
    /** @var list<MintHarness> */
    private array $harnesses = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        $warnings = [];
        foreach ($this->harnesses as $h) {
            $warnings = array_merge($warnings, $h->warnings);
            $h->cleanup();
        }
        $this->harnesses = [];
        self::assertSame([], $warnings, 'PHP warnings or notices while handling');
    }

    private function h(bool $armed = true, array $opts = []): MintHarness
    {
        return $this->harnesses[] = new MintHarness($armed, $opts);
    }

    public function test_the_unit_budget_sheds_at_the_same_request_whatever_the_clock_or_store_speed(): void
    {
        $indexes = [];
        foreach (['fast' => [0, false], 'slow' => [2, false], 'sleeping store' => [0, true]] as $case => [$step, $sleep]) {
            $h = $this->h(true, $sleep ? ['storeFaults' => static function (string $s): void {
                if ($s === 'begin') {
                    usleep(300);
                }
            }] : []);
            $h->now = 1763798400; // an hour boundary, so the slow clock stays in one bucket
            $h->join();
            $shed = null;
            for ($i = 0; $i < 1600; $i++) {
                $h->now += $step;
                $r = $h->get('/settings/tokens');
                if ($r['status'] === 429) {
                    $shed = $i;
                    self::assertSame((string) (3600 - ($h->now % 3600)), $r['plan']->header('Retry-After'), $case);
                    break;
                }
            }
            $indexes[$case] = $shed;
        }
        self::assertNotNull($indexes['fast']);
        self::assertSame(1, count(array_unique($indexes)), 'shed index per clock: ' . json_encode($indexes));
        self::assertSame(1500 - 3, $indexes['fast'], 'the sign-up POST cost 3 units, then one per page');
        $clockReads = 0;
        foreach (glob(dirname(__DIR__, 4) . '/src/App/Tarpit/Mint/*.php') ?: [] as $f) {
            $src = (string) file_get_contents($f);
            self::assertStringNotContainsString('TarpitBudget', $src, basename($f) . ' takes no tarpit slot');
            self::assertDoesNotMatchRegularExpression('/hrtime|microtime|usleep|\bsleep\(/', $src, basename($f) . ' reads no wall clock');
            $clockReads += preg_match_all('/\btime\(\)/', $src);
        }
        self::assertSame(1, $clockReads, 'the only clock is the injectable default in TokenMintDecoy::build()');
    }

    public function test_past_the_source_write_cap_forms_throttle_and_api_reads_still_answer(): void
    {
        $h = $this->h(true, ['storeLimits' => ['source_writes_hr' => 40]]);
        $h->join();
        $tok = $h->mint(['read:user']);
        $capped = false;
        for ($i = 0; $i < 60 && !$capped; $i++) {
            $page = $h->get('/settings/profile');
            $r = $h->post('/settings/profile', ['csrf_token' => MintHarness::csrf($page['body']), 'name' => 'n' . $i]);
            $capped = $r['status'] === 429;
        }
        self::assertTrue($capped, 'the cap was reached');
        $form = $h->get('/settings/tokens/new');
        $mint = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'after cap', 'expiration' => '30', 'scopes' => ['read:user']]);
        self::assertSame(429, $mint['status']);
        self::assertNotNull($mint['plan']->header('Retry-After'));
        $api = $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok]);
        self::assertSame(200, $api['status'], 'reads answer from loaded state');
    }

    public function test_a_capped_source_is_shed_at_the_same_request_as_an_uncapped_one(): void
    {
        $shed = [];
        $outcomes = [];
        foreach (['uncapped' => [], 'capped' => ['source_writes_hr' => 5]] as $case => $limits) {
            $h = $this->h(true, ['storeLimits' => $limits]);
            $h->now = 1763798400; // an hour boundary, so the run stays in one ledger bucket
            $h->join();
            $page = $h->get('/settings/profile');
            $csrf = MintHarness::csrf($page['body']);
            for ($i = 0; $i < 1000 && !isset($shed[$case]); $i++) {
                $r = $h->post('/settings/profile', ['csrf_token' => $csrf, 'name' => 'n' . $i]);
                $o = (string) ($r['plan']->turn['outcome'] ?? '');
                $outcomes[$case][$o] = ($outcomes[$case][$o] ?? 0) + 1;
                if ($o === 'throttled') {
                    $shed[$case] = $i;
                }
            }
        }
        self::assertArrayHasKey('uncapped', $shed, 'the ledger shed the uncapped source');
        self::assertGreaterThan(0, $outcomes['capped']['store_cap'] ?? 0, 'sanity: the capped source hit its write cap: ' . json_encode($outcomes));
        self::assertSame($shed['uncapped'], $shed['capped'] ?? null, 'a capped write is charged like any other: ' . json_encode($outcomes));
    }

    public function test_fuzz_stays_in_the_closed_sets_with_no_fault_and_no_warning(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user']);
        $slug = $h->persona->slug;
        $session = $h->jars['default']['session'];
        // A real form token with its origin tag replaced: right length and head, wrong tag.
        $real = MintHarness::csrf($h->get('/settings/tokens/new')['body']);
        self::assertSame(36, strlen($real));
        $forged = substr($real, 0, 28) . (substr($real, 28) === str_repeat('A', 8) ? str_repeat('B', 8) : str_repeat('A', 8));
        mt_srand(815);
        $paths = \Funnypot\Tests\App\Tarpit\Mint\MintCorpus::ownedPaths($slug);
        $methods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
        $cookies = [null, 'session=' . $session, 'session=' . substr($session, 0, -2) . 'AA', 'session=' . str_repeat('A', 60), 'session=x', str_repeat('a=b; ', 900)];
        $auths = [[], ['Authorization' => 'Bearer ' . $tok], ['Authorization' => 'Bearer ' . str_repeat('A', 5000)], ['Authorization' => 'Bearer a.b.c'],
            ['Authorization' => 'Bearer ' . substr($tok, 0, -1) . 'Q'], ['X-Api-Key' => $tok], ['Authorization' => 'Basic Zm9vOmJhcg=='], ['Authorization' => str_repeat('x', 300)]];
        // Inputs cheap for the engine go through handle(); the few the engine itself spends seconds on
        // (huge pair counts, brace floods) are run through the surface's own prepare() below.
        $bodies = [
            null,
            'csrf_token=' . str_repeat('A', 36) . '&note=x&scopes%5B%5D=read%3Auser&expiration=30',
            'csrf_token=' . $forged . '&note=x&scopes%5B%5D=read%3Auser&expiration=30',
            str_repeat('a=1&', 120),
            'note%5B%5D=x&scopes=read%3Auser&scopes%5Ba%5D%5Bb%5D=c&csrf_token%5B%5D=y&expiration%5B%5D=30',
            '[1,2,3]',
            '{"name":["a"],"bio":{"x":1},"username":5,"password":true}',
            '{"a":{"b":{"c":{"d":{"e":1}}}}}',
            str_repeat('{', 40),
            'grant_type%5B%5D=authorization_code&code%5B%5D=x&client_id=' . str_repeat('9', 2000),
            'username=' . str_repeat('a', 1500) . '&password=x',
            "\x00\xff\xfe" . str_repeat("\x80", 500),
            'authorization_request=ab12cd34ef56&authorize=1&deny=1&csrf_token=' . str_repeat('A', 36),
            'authorization_request=ab12cd34ef56&authorize=1&csrf_token=' . $forged,
        ];
        $queries = ['', 'scopes=a,b,read:user', 'client_id=' . str_repeat('a', 20) . '&state=%3Cscript%3E', str_repeat('x=1&', 90), 'access_token=' . $tok, 'authorization_request=../../etc/passwd'];
        for ($i = 0; $i < 2000; $i++) {
            $path = $paths[mt_rand(0, count($paths) - 1)];
            $method = $methods[mt_rand(0, count($methods) - 1)];
            $headers = $auths[mt_rand(0, count($auths) - 1)];
            $cookie = $cookies[mt_rand(0, count($cookies) - 1)];
            if ($cookie !== null) {
                $headers['Cookie'] = $cookie;
            }
            $body = in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) ? null : $bodies[mt_rand(0, count($bodies) - 1)];
            if ($body !== null) {
                $headers['Content-Type'] = mt_rand(0, 1) === 1 ? 'application/json' : 'application/x-www-form-urlencoded';
            }
            $h->now += mt_rand(0, 90);
            $r = $h->request($method, $path, $queries[mt_rand(0, count($queries) - 1)], $body, $headers, '45.79.' . mt_rand(1, 3) . '.9', 'fuzz');
            self::assertNotNull($r['plan'], "{$method} {$path} was answered");
            MintHarness::assertClosed($r['plan'], $slug, "#{$i} {$method} {$path}");
        }
        $heavy = [
            ['POST', str_repeat('a=1&', 4000), ''], ['POST', str_repeat('{', 3000), ''], ['POST', 'username=' . str_repeat('a', 9000) . '&password=x', ''],
            ['GET', null, str_repeat('x=1&', 3000)], ['POST', str_repeat('scopes%5B%5D=read%3Auser&', 700), ''], ['POST', str_repeat('A', 20000), ''],
        ];
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return true;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        $issued = \Funnypot\App\Tarpit\Mint\IssuedValue::forEngine(MintCorpus::engine(), new \Funnypot\App\ThreatIntel\AttackClassifier());
        try {
            foreach ($paths as $path) {
                foreach ($heavy as [$m, $b, $q]) {
                    foreach (['application/json', 'application/x-www-form-urlencoded'] as $ct) {
                        $p = $h->decoy->prepare(new \Funnypot\Core\RequestContext($m, $path, $q, ['Content-Type' => $ct, 'Cookie' => 'session=' . $session], $b), '45.79.4.9', $issued);
                        self::assertNotNull($p, "{$m} {$path} heavy input");
                        MintHarness::assertClosed($p, $slug, "heavy {$m} {$path}");
                    }
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame(0, $h->decoy->faults());
    }
}
