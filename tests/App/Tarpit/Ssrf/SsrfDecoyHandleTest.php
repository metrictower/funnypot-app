<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * The SSRF decoy through the real HoneypotController::handle(): session and API journeys, the owner
 * key, IDOR, methods, forms, logging and reporting parity, the delivery model, imports and the export
 * destination.
 */
final class SsrfDecoyHandleTest extends TestCase
{
    /** @var list<MintHarness> */
    private array $harnesses = [];

    protected function tearDown(): void
    {
        foreach ($this->harnesses as $h) {
            $h->cleanup();
        }
    }

    private function h(bool $armed = true, array $opts = [], array $ssrf = []): MintHarness
    {
        $h = new MintHarness($armed, $armed ? $opts + ['ssrf' => $ssrf] : $opts);

        return $this->harnesses[] = $h;
    }

    /** @return list<string> */
    private static function tokens(string $body): array
    {
        preg_match_all("/name=csrf_token value='([^']+)'/", $body, $m);

        return $m[1];
    }

    private static function createHook(MintHarness $h, string $url, array $extra = [], string $jar = 'default', string $ip = MintHarness::IP): string
    {
        $form = $h->get('/settings/webhooks/new', '', $jar, $ip);
        $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body'])] + $extra + ['content_type' => 'json', 'secret' => 'whsec-1', 'events' => ['token.created'], 'active' => '1', 'payload_url' => $url], $jar, $ip);
        self::assertSame(303, $r['status'], 'hook created: ' . substr(strip_tags($r['body']), 0, 300));

        return basename((string) $r['plan']?->header('Location'));
    }

    private static function ping(MintHarness $h, string $id, string $jar = 'default', string $ip = MintHarness::IP): array
    {
        $show = $h->get('/settings/webhooks/' . $id, '', $jar, $ip);

        return $h->post('/settings/webhooks/' . $id . '/pings', ['csrf_token' => self::tokens($show['body'])[0]], $jar, $ip);
    }

    /** @return list<string> delivery ids on the hook page, newest first */
    private static function deliveries(MintHarness $h, string $id): array
    {
        preg_match_all('~/settings/webhooks/' . $id . "/deliveries/([a-f0-9]{12})'~", $h->get('/settings/webhooks/' . $id)['body'], $m);

        return $m[1];
    }

    private static function text(string $body): string
    {
        return html_entity_decode(strip_tags((string) preg_replace('~<style>.*?</style>~s', '', $body)), ENT_QUOTES);
    }

    private static function generated(MintHarness $h, string $kind = 'http_api'): string
    {
        $g = $h->ssrf->network()->generated();
        for ($i = 1; $g->node($i)?->kind !== $kind; $i++) {
        }

        return 'http://' . $g->name($i) . ':' . $g->node($i)->ports[0];
    }

    public function test_session_journey_create_ping_pending_then_done(): void
    {
        $h = $this->h();
        $h->join();
        $slow = self::createHook($h, 'http://172.16.40.9:8080/hooks');
        self::ping($h, $slow);
        [$did] = self::deliveries($h, $slow);
        self::assertStringContainsString('Pending', self::text($h->get('/settings/webhooks/' . $slow . '/deliveries/' . $did)['body']));
        $h->now += 11;
        $page = self::text($h->get('/settings/webhooks/' . $slow . '/deliveries/' . $did)['body']);
        self::assertStringContainsString('Retrying', $page);
        self::assertStringContainsString('Connection timed out after 10000 ms', $page);
        $fast = self::createHook($h, self::generated($h) . '/health');
        self::ping($h, $fast);
        [$did2] = self::deliveries($h, $fast);
        $h->now += 3;
        $page = self::text($h->get('/settings/webhooks/' . $fast . '/deliveries/' . $did2)['body']);
        self::assertStringContainsString('200 delivered', $page);
        self::assertStringContainsString('"status":"ok"', $page);
        $list = self::text($h->get('/settings/webhooks')['body']);
        self::assertStringContainsString($slow, $list);
        self::assertStringContainsString('172.16.40.9', $list);
    }

    public function test_api_journey_with_pat_scopes(): void
    {
        $h = $this->h();
        $h->join();
        $pat = $h->mint(['read:user', 'webhooks:write']);
        $narrow = $h->mint(['read:user'], 'narrow');
        $auth = static fn (string $t): array => ['Authorization' => 'Bearer ' . $t, 'Content-Type' => 'application/json'];
        $r = $h->request('POST', '/api/v2/user/hooks', '', '{"content_type":"json","events":["token.created"],"active":true,"url":"' . self::generated($h) . '/healthz"}', $auth($pat));
        self::assertSame(200, $r['status'], $r['body']);
        $id = json_decode($r['body'], true)['id'];
        $list = $h->request('GET', '/v2/user/hooks', '', null, $auth($pat), '198.51.100.20');
        self::assertSame(200, $list['status'], 'a token works from another address');
        self::assertSame($id, json_decode($list['body'], true)[0]['id']);
        self::assertSame($list['body'], $h->request('GET', '/api/v2/user/hooks', '', null, $auth($pat), '198.51.100.20')['body'], 'both API spellings answer byte for byte');
        $no = $h->request('GET', '/api/v2/user/hooks', '', null, $auth($narrow));
        self::assertSame(403, $no['status']);
        self::assertSame('webhooks:write', $no['plan']?->header('X-Required-Scopes'));
        self::assertSame(403, $h->request('GET', '/api/v2/user/imports', '', null, $auth($pat))['status'], 'each family has its own scope');
        $jwt = (string) (json_decode($h->request('POST', '/api/v2/auth/login', '', '{"username":"artex1","password":"Passw0rd!x"}', ['Content-Type' => 'application/json'])['body'], true)['access_token'] ?? '');
        self::assertNotSame('', $jwt);
        self::assertSame(403, $h->request('GET', '/api/v2/user/hooks', '', null, $auth($jwt))['status'], 'a login token is never enough');
        self::assertSame(401, $h->request('GET', '/api/v2/user/hooks')['status']);
        $ping = $h->request('POST', '/api/v2/user/hooks/' . $id . '/pings', '', '{}', $auth($pat));
        self::assertSame(200, $ping['status']);
        $did = json_decode($ping['body'], true)['id'];
        $h->now += 3;
        $detail = json_decode($h->request('GET', '/api/v2/user/hooks/' . $id . '/deliveries/' . $did, '', null, $auth($pat))['body'], true);
        self::assertSame('delivered', $detail['status']);
        self::assertStringContainsString('"status":"ok"', $detail['response']['body']);
        $patch = $h->request('PATCH', '/api/v2/user/hooks/' . $id, '', '{"active":false}', $auth($pat));
        self::assertFalse(json_decode($patch['body'], true)['active']);
        self::assertSame(204, $h->request('DELETE', '/api/v2/user/hooks/' . $id, '', null, $auth($pat))['status']);
        self::assertSame(404, $h->request('GET', '/api/v2/user/hooks/' . $id, '', null, $auth($pat))['status']);
    }

    public function test_owner_key_uses_the_row_epoch(): void
    {
        $h = $this->h();
        $h->join();
        $id = self::createHook($h, 'http://172.16.0.5/');
        $nonexistent = $h->get('/settings/webhooks/4b7e19a2c0a1')['body'];
        $h->now += 86400 + 10;
        $h->get('/join', '', 'other', '203.0.113.77');
        $h->join('other1', 'Passw0rd!x', 'other', '203.0.113.77');
        $h->jars['default'] = [];
        $h->join('artex1', 'Passw0rd!x');
        self::assertStringContainsString('No webhooks yet', $h->get('/settings/webhooks')['body'], 'a new row after idle expiry sees no old hooks');
        self::assertSame(404, $h->get('/settings/webhooks/' . $id)['status']);
        self::assertSame(self::text($nonexistent), self::text($h->get('/settings/webhooks/' . $id)['body']), 'the old id answers like a nonexistent one');

        $lru = $this->h(true, ['storeLimits' => ['rows' => 1]]);
        $lru->join();
        $old = self::createHook($lru, 'http://172.16.0.6/');
        $lru->now += 5;
        $lru->join('evictor', 'Passw0rd!x', 'e', '203.0.113.78');
        $lru->jars['default'] = [];
        $lru->join('artex1', 'Passw0rd!x');
        self::assertSame(404, $lru->get('/settings/webhooks/' . $old)['status'], 'a row evicted and re-created gets a new epoch');
    }

    public function test_bearer_use_touches_last_used_at_most_hourly(): void
    {
        $h = $this->h();
        $h->join();
        $pat = $h->mint(['read:user', 'webhooks:write']);
        $auth = ['Authorization' => 'Bearer ' . $pat];
        self::assertStringContainsString('Never used', $h->get('/settings/tokens')['body']);
        $h->now += 10;
        $h->request('GET', '/api/v2/user/hooks', '', null, $auth);
        self::assertStringNotContainsString('Never used', $h->get('/settings/tokens')['body'], 'the tokens page shows the use');
        $seen = static fn (): int => (int) $h->store->db()->query('SELECT MAX(seen) FROM mint_state')->fetchColumn();
        $before = $seen();
        $h->now += 60;
        $h->request('GET', '/api/v2/user/hooks', '', null, $auth);
        self::assertSame($before, $seen(), 'a second use within the hour writes nothing');
        $h->now += 3600;
        $h->request('GET', '/api/v2/user/hooks', '', null, $auth);
        self::assertSame($h->now, $seen(), 'an hour later the use is recorded again');

        $tok = $this->h(true);
        $tok->join();
        $p = $tok->mint(['webhooks:write']);
        $row = static fn (): array => $tok->store->db()->query('SELECT state, seen FROM mint_state')->fetchAll(\PDO::FETCH_ASSOC);
        $tok->now += 10;
        $tok->store->db()->prepare('INSERT OR REPLACE INTO mint_gauge (hour, writes) VALUES (:h, 999999)')->execute([':h' => intdiv($tok->now, 3600)]);
        $was = $row();
        self::assertStringContainsString('"lu":0', $was[0]['state'], 'the token was never used');
        $r = $tok->request('GET', '/api/v2/user/hooks', '', null, ['Authorization' => 'Bearer ' . $p]);
        self::assertSame(200, $r['status'], 'a capped token-mint store still answers');
        self::assertSame($was, $row(), 'a capped token-mint store skips the touch: last used and seen are unchanged');
    }

    public function test_idor_byte_identical_to_nonexistent(): void
    {
        $h = $this->h();
        $h->join();
        $id = self::createHook($h, 'http://172.16.0.5/');
        self::ping($h, $id);
        [$did] = self::deliveries($h, $id);
        $h->join('mallory', 'Passw0rd!x', 'm', '198.51.100.9');
        foreach (['/settings/webhooks/%s', '/settings/webhooks/%s/deliveries/' . $did] as $shape) {
            $theirs = $h->get(sprintf($shape, $id), '', 'm', '198.51.100.9');
            $none = $h->get(sprintf($shape, '4b7e19a2c0a1'), '', 'm', '198.51.100.9');
            self::assertSame(404, $theirs['status']);
            self::assertSame($none['body'], $theirs['body']);
            self::assertFalse($theirs['main']['served']);
        }
        $theirs = $h->post('/settings/webhooks/' . $id . '/delete', ['csrf_token' => 'x'], 'm', '198.51.100.9');
        self::assertSame(422, $theirs['status'], 'a forged form is refused before any lookup');
        self::assertNotEmpty(self::deliveries($h, $id), 'the owner\'s hook is untouched');
    }

    public function test_methods_head_options_405(): void
    {
        $h = $this->h();
        $h->join();
        $o = $h->request('OPTIONS', '/settings/webhooks');
        self::assertSame(204, $o['status']);
        self::assertSame('GET, POST, HEAD, OPTIONS', $o['plan']?->header('Allow'));
        $p = $h->request('PUT', '/settings/webhooks/new', '', 'x=1');
        self::assertSame(405, $p['status']);
        self::assertSame('GET, HEAD', $p['plan']?->header('Allow'));
        $head = $h->request('HEAD', '/settings/webhooks');
        self::assertSame(200, $head['status']);
        self::assertSame('', $head['body']);
        self::assertSame(405, $h->request('POST', '/api/v2/user/hooks/4b7e19a2c0a1/deliveries', '', '{}', ['Content-Type' => 'application/json'])['status']);
        self::assertSame(413, $h->request('POST', '/settings/webhooks', '', str_repeat('a', 17000))['status']);
    }

    public function test_csrf_and_type_confusion_never_warn(): void
    {
        $h = $this->h();
        $h->join();
        foreach ([[], ['csrf_token' => ['x']], ['csrf_token' => 'x', 'payload_url' => ['a']], ['events' => 'x'], ['active' => ['1']]] as $f) {
            $r = $h->post('/settings/webhooks', $f);
            self::assertSame(422, $r['status']);
        }
        $form = $h->get('/settings/webhooks/new');
        foreach ([['payload_url' => ['http://x/']], ['events' => [['a']]], ['secret' => ['s']], ['content_type' => ['json']], ['payload_url' => "http://a\x01b/"]] as $f) {
            $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body'])] + $f);
            self::assertSame(422, $r['status'], json_encode($f));
        }
        $api = $h->mint(['webhooks:write']);
        foreach (['{"url":5}', '{"url":["x"]}', '{"events":{"a":1},"url":"http://172.16.0.1/"}', '{"active":"yes","url":"http://172.16.0.1/"}', '[]', '{"url":null}'] as $body) {
            $r = $h->request('POST', '/api/v2/user/hooks', '', $body, ['Authorization' => 'Bearer ' . $api, 'Content-Type' => 'application/json']);
            self::assertContains($r['status'], [400, 422], $body);
        }
        self::assertSame([], $h->warnings);
    }

    public function test_non_disclosing_answers_log_unserved_and_pin(): void
    {
        $paths = [];
        for ($i = 0; $i < 8; $i++) {
            $id = sprintf('%012x', 0xabc000 + $i);
            $paths[] = '/settings/webhooks/' . $id;
            $paths[] = '/api/v2/user/hooks/' . $id . '/deliveries';
            $paths[] = '/settings/imports/' . $id;
            $paths[] = '/v2/user/hooks/' . $id . '/deliveries/' . $id;
            $paths[] = '/settings/webhooks/' . $id . '/deliveries/4b7e19a2c0a1';
        }
        self::assertCount(40, $paths);
        $llm = ['llm' => 500, 'probeGate' => true];
        foreach (['GET', 'PUT', 'DELETE', 'POST', 'OPTIONS'] as $method) {
            $pinAt = function (bool $armed, string $ip) use ($paths, $llm, $method): ?int {
                $h = $this->h($armed, $llm);
                foreach ($paths as $i => $p) {
                    $h->request($method, $p, '', $method === 'GET' || $method === 'OPTIONS' ? null : 'csrf_token=x', [], $ip, 'nojar');
                    if ($h->hits->isBulkFlagged($ip)) {
                        return $i;
                    }
                }

                return null;
            };
            $unarmed = $pinAt(false, '45.87.0.1');
            self::assertNotNull($unarmed, "{$method}: sanity, the unarmed spray pins");
            self::assertSame($unarmed, $pinAt(true, '45.87.0.2'), "{$method}: the same request index");
        }
        $h = $this->h(true, $llm);
        $h->join();
        $id = self::createHook($h, 'http://172.16.0.5/');
        $csrf = $h->post('/settings/webhooks/' . $id . '/pings', ['csrf_token' => 'bad']);
        self::assertSame(422, $csrf['status']);
        self::assertFalse($csrf['main']['served'], 'a CSRF 422 on an id path is non-disclosing');
        self::assertTrue(TokenMintDecoy::nonDisclosing($csrf['plan']));
        $lapsed = $this->h(true, $llm);
        $r = $lapsed->get('/settings/webhooks/' . $id);
        self::assertSame(303, $r['status']);
        self::assertFalse($r['main']['served'], 'the no-session 303 on an id path counts like a miss');
    }

    public function test_hit_row_and_report_parity(): void
    {
        $cases = [
            ['GET', '/settings/webhooks', '', null],
            ['GET', '/settings/webhooks/4b7e19a2c0a1', 'q=1%20union%20select%201,2--', null],
            ['POST', '/settings/imports', '', 'csrf_token=x&kind=orders_csv&source_url=' . rawurlencode('file:///etc/passwd')],
            ['POST', '/api/v2/user/hooks', '', '{"url":"http://[::1]:22/","active":true}'],
            ['GET', '/settings/storage', 'next=http://evil.example/', null],
        ];
        $armed = $this->h();
        $unarmed = $this->h(false);
        foreach ($cases as $i => [$m, $p, $q, $b]) {
            $headers = $b !== null && $b[0] === '{' ? ['Content-Type' => 'application/json'] : [];
            $a = $armed->request($m, $p, $q, $b, $headers, '45.88.0.' . $i);
            $u = $unarmed->request($m, $p, $q, $b, $headers, '45.88.0.' . $i);
            self::assertNotNull($a['plan'], "{$m} {$p} answered by the decoy");
            foreach (['matched', 'severity', 'templates', 'method', 'path', 'body'] as $field) {
                self::assertSame($u['main'][$field], $a['main'][$field], "{$m} {$p}: {$field}");
            }
        }
        self::assertSame($unarmed->reports(), $armed->reports(), 'the same reports queue, armed or not');
        self::assertNotSame(['abuse' => [], 'ti' => []], $armed->reports(), 'sanity: the attack cases report');
    }

    public function test_serve_delay_parity(): void
    {
        $armed = $this->h();
        $unarmed = $this->h(false);
        foreach ([['GET', '/settings/webhooks', ''], ['GET', '/settings/webhooks/4b7e19a2c0a1', 'q=1%20union%20select%201,2--'], ['POST', '/api/v2/user/imports', '']] as [$m, $p, $q]) {
            $a0 = $armed->delays;
            $u0 = $unarmed->delays;
            $armed->request($m, $p, $q, $m === 'POST' ? '{}' : null);
            $unarmed->request($m, $p, $q, $m === 'POST' ? '{}' : null);
            self::assertSame($unarmed->delays - $u0, $armed->delays - $a0, "{$m} {$p}");
        }
    }

    public function test_unwired_is_byte_identical(): void
    {
        $off = $this->h(true, [], []);
        $plain = new MintHarness(true);
        $this->harnesses[] = $plain;
        $none = $this->h(false);
        foreach (SsrfRoutes::examples() as [, $p]) {
            $a = $plain->get($p);
            $b = $none->get($p);
            self::assertNull($a['plan'], "unwired: {$p} is not answered by any surface");
            self::assertSame($b['body'], $a['body'], "unwired: {$p} answers as today");
        }
        self::assertNotNull($off->get('/settings/webhooks')['plan'], 'sanity: wired, the decoy answers');
        $plain->join();
        self::assertStringNotContainsString('Webhooks', $plain->get('/settings/tokens')['body'], 'unwired: no nav item');
        self::assertStringNotContainsString('webhooks:write', $plain->get('/settings/tokens/new')['body'], 'unwired: no scope');
    }

    /**
     * The account's own pages are served content: their rows say served, and an armed, signed-in walk
     * of the account's own pages never pins. A rate-limited ping carrying our own form token stays served,
     * as FP-0815's own-token exemption says.
     */
    public function test_own_pages_are_served_and_never_pin(): void
    {
        $h = $this->h(true, ['llm' => 500, 'probeGate' => true]);
        $h->join();
        $pat = $h->mint(['webhooks:write', 'imports:write', 'storage:write']);
        $id = self::createHook($h, 'http://172.16.0.5/');
        self::ping($h, $id);
        $h->now += 3;
        [$did] = self::deliveries($h, $id);
        $form = $h->get('/settings/imports/new');
        $imp = (string) $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($form['body']), 'kind' => 'orders_csv', 'source_url' => 'http://172.16.0.5/a.csv'])['plan']?->header('Location');
        $pages = ['/settings/webhooks', '/settings/webhooks/new', '/settings/webhooks/' . $id, '/settings/webhooks/' . $id . '/deliveries/' . $did, '/settings/imports',
            '/settings/imports/new', $imp, '/settings/storage'];
        foreach ($pages as $p) {
            $r = $h->get($p);
            self::assertSame(200, $r['status'], $p);
            self::assertTrue($r['main']['served'], "{$p} is served content");
        }
        foreach (['/api/v2/user/hooks', '/api/v2/user/hooks/' . $id, '/v2/user/hooks/' . $id . '/deliveries', '/api/v2/user/hooks/' . $id . '/deliveries/' . $did, '/api/v2/user/imports', '/api/v2/user/storage'] as $p) {
            $r = $h->request('GET', $p, '', null, ['Authorization' => 'Bearer ' . $pat]);
            self::assertSame(200, $r['status'], $p);
            self::assertTrue($r['main']['served'], "{$p} is served content");
        }
        for ($i = 0; $i < 5; $i++) {
            foreach ($pages as $p) {
                $h->now += 2;
                $h->get($p);
            }
        }
        self::assertFalse($h->hits->isBulkFlagged(MintHarness::IP), 'a walk of 40 of the account\'s own pages never pins');
        $show = $h->get('/settings/webhooks/' . $id);
        $own = self::tokens($show['body'])[0];
        $last = null;
        for ($i = 0; $i < 31; $i++) {
            $last = $h->post('/settings/webhooks/' . $id . '/pings', ['csrf_token' => $own]);
        }
        self::assertSame(429, $last['status'], 'the ten-minute rate');
        self::assertTrue($last['main']['served'], 'a 429 to our own form token on an id path stays served');
        $stranger = $h->post('/settings/webhooks/' . $id . '/pings', ['csrf_token' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']);
        self::assertFalse($stranger['main']['served'], 'a forged token does not');
        $dup = $h->post('/settings/webhooks/' . $id . '/pings', ['csrf_token' => $own]);
        self::assertTrue($dup['main']['served']);
    }

    /** Off the owned set, a host with the SSRF decoy armed answers byte for byte as one without it. */
    public function test_unowned_paths_answer_identically(): void
    {
        $armed = $this->h();
        $plain = new MintHarness(true);
        $this->harnesses[] = $plain;
        $paths = [...\Funnypot\Tests\App\Tarpit\Mint\MintCorpus::notOwned(), '/settings/webhook', '/api/v2/user/hook', '/settings/webhooks/x.php', '/settings/webhooks/a1b2.zip',
            '/settings', '/api/v2/users/hooks', '/settings/webhooks/1windows', '/settings/storage/x', '/v3/user/hooks', '/settings/tokens', '/api/v2/user', '/.env'];
        foreach ($paths as $p) {
            foreach (['GET', 'POST'] as $m) {
                $a = $armed->request($m, $p, 'x=1', $m === 'POST' ? 'a=1' : null);
                $b = $plain->request($m, $p, 'x=1', $m === 'POST' ? 'a=1' : null);
                self::assertSame($b['body'], $a['body'], "{$m} {$p}");
                self::assertSame($b['status'], $a['status'], "{$m} {$p}");
                foreach (['matched', 'severity', 'templates', 'served'] as $f) {
                    self::assertSame($b['main'][$f] ?? null, $a['main'][$f] ?? null, "{$m} {$p}: {$f}");
                }
            }
        }
        self::assertSame($plain->reports(), $armed->reports());
    }

    public function test_harness_fails_on_any_warning_or_fault_fallback(): void
    {
        $h = $this->h(true, [], ['faults' => new class () {
            public function stage(string $s): void
            {
                throw new \LogicException('not a store error');
            }
        }]);
        $h->join();
        $thrown = false;
        try {
            $h->get('/settings/webhooks');
        } catch (\RuntimeException $e) {
            $thrown = str_contains($e->getMessage(), 'fault path');
        }
        self::assertTrue($thrown, 'a non-store fault falls back to today\'s answer and the harness fails on it');
        $h->allowFaults = true;
        $r = $h->get('/settings/webhooks');
        self::assertNull($r['plan']);
        self::assertStringContainsString('404 Not Found', $r['body']);
    }

    public function test_delivery_shows_the_url_version_it_was_sent_to(): void
    {
        $h = $this->h();
        $h->join();
        $id = self::createHook($h, 'http://172.16.0.5/first');
        self::ping($h, $id);
        $show = $h->get('/settings/webhooks/' . $id);
        [$edit] = self::tokens($show['body']);
        $edit = self::tokens($show['body'])[1];
        $r = $h->post('/settings/webhooks/' . $id, ['csrf_token' => $edit, 'content_type' => 'json', 'events' => ['token.created'], 'active' => '1', 'payload_url' => 'http://172.16.0.6/second']);
        self::assertSame(303, $r['status']);
        self::ping($h, $id);
        [$newer, $older] = self::deliveries($h, $id);
        self::assertStringContainsString('172.16.0.5/first', self::text($h->get('/settings/webhooks/' . $id . '/deliveries/' . $older)['body']));
        self::assertStringContainsString('172.16.0.6/second', self::text($h->get('/settings/webhooks/' . $id . '/deliveries/' . $newer)['body']));
    }

    public function test_redelivery_goes_to_the_current_url_version(): void
    {
        $h = $this->h();
        $h->join();
        $id = self::createHook($h, 'http://172.16.0.5/first');
        self::ping($h, $id);
        [$first] = self::deliveries($h, $id);
        $edit = self::tokens($h->get('/settings/webhooks/' . $id)['body'])[1];
        $h->post('/settings/webhooks/' . $id, ['csrf_token' => $edit, 'payload_url' => 'http://172.16.0.7/now']);
        $page = $h->get('/settings/webhooks/' . $id . '/deliveries/' . $first);
        $r = $h->post('/settings/webhooks/' . $id . '/redeliveries', ['csrf_token' => self::tokens($page['body'])[0], 'delivery' => $first]);
        self::assertSame(303, $r['status']);
        [$re] = self::deliveries($h, $id);
        self::assertNotSame($first, $re, 'a redelivery is a new delivery');
        $text = self::text($h->get('/settings/webhooks/' . $id . '/deliveries/' . $re)['body']);
        self::assertStringContainsString('172.16.0.7/now', $text);
        self::assertStringContainsString('ping event', $text, 'with the original event');
    }

    public function test_the_sts_gateway_answers_with_its_own_request_ids(): void
    {
        $h = $this->h();
        $h->join();
        $pat = $h->mint(['read:user', 'webhooks:write', 'imports:write']);
        $api = static function (string $m, string $path, ?array $b = null) use ($h, $pat): array {
            $r = $h->request($m, $path, '', $b === null ? null : (string) json_encode($b, JSON_UNESCAPED_SLASHES), ['Authorization' => 'Bearer ' . $pat, 'Content-Type' => 'application/json']);

            return (array) json_decode($r['body'], true);
        };
        $p = PersonaIdentity::fromSeed(IdentityTestSupport::httpIdentity()->personaSeed());
        $region = (string) $p->field('cloud.aws.region');
        $sts = 'http://sts.' . $region . '.internal/?Action=GetCallerIdentity&X-Amz-Credential=' . $p->field('cloud.aws.accessKeyId')
            . '%2F20251122%2F' . $region . '%2Fsts%2Faws4_request&X-Amz-Signature=' . str_repeat('ab', 32);
        $rid = static function (string $body): string {
            self::assertSame(1, preg_match('~<RequestId>([^<]*)</RequestId>~', $body, $m), substr($body, 0, 200));

            return $m[1];
        };

        $imp = $api('POST', '/api/v2/user/imports', ['kind' => 'orders_json', 'source_url' => $sts])['id'];
        $h->now += 6;
        $excerpt = (string) $api('GET', '/api/v2/user/imports/' . $imp)['excerpt'];
        $first = $rid($excerpt);
        $hook = $api('POST', '/api/v2/user/hooks', ['content_type' => 'json', 'events' => ['token.created'], 'active' => true, 'url' => $sts])['id'];
        $d1 = $api('POST', '/api/v2/user/hooks/' . $hook . '/pings', [])['id'];
        $h->now += 4;
        $body1 = (string) $api('GET', '/api/v2/user/hooks/' . $hook . '/deliveries/' . $d1)['response']['body'];
        $d2 = $api('POST', '/api/v2/user/hooks/' . $hook . '/pings', [])['id'];
        $h->now += 4;
        $body2 = (string) $api('GET', '/api/v2/user/hooks/' . $hook . '/deliveries/' . $d2)['response']['body'];
        self::assertSame($rid($body1), $rid((string) $api('GET', '/api/v2/user/hooks/' . $hook . '/deliveries/' . $d1)['response']['body']), 'a re-view shows the same id');
        $page = $h->get('/settings/imports/' . $imp);
        self::assertSame(303, $h->post('/settings/imports/' . $imp . '/retry', ['csrf_token' => MintHarness::csrf($page['body'])])['status']);
        $h->now += 6;
        $retried = (string) $api('GET', '/api/v2/user/imports/' . $imp)['excerpt'];

        $ids = [$first, $rid($body1), $rid($body2), $rid($retried)];
        self::assertCount(4, array_unique($ids), 'each attempt gets its own id');
        foreach ($ids as $id) {
            self::assertMatchesRegularExpression(FakeFetchTest::UUID4, $id, 'STS request ids are version-4 UUIDs');
        }
        foreach ([$excerpt, $body1, $body2, $retried] as $answer) {
            foreach ([$imp, $hook, $d1, $d2] as $platformId) {
                self::assertStringNotContainsString($platformId, $answer, 'no fake-network answer carries a platform id');
            }
        }
    }

    public function test_a_signature_after_many_pairs_is_masked_and_masking_never_breaks_a_url(): void
    {
        $h = $this->h();
        $h->join();
        $canary = 'SIGCANARY' . str_repeat('9', 6);
        $id = self::createHook($h, 'http://172.16.0.5/?' . str_repeat('a&', 65) . 'X-Amz-Signature=' . $canary);
        self::assertStringNotContainsString($canary, $h->get('/settings/webhooks/' . $id)['body']);
        self::assertStringNotContainsString($canary, (string) $h->ssrfStore->db()->query('SELECT state FROM ssrf_owner')->fetchColumn());

        $long = 'http://a@172.16.0.5/' . str_repeat('p', 512 - strlen('http://a@172.16.0.5/'));
        $form = $h->get('/settings/webhooks/new');
        $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'content_type' => 'json', 'events' => ['token.created'], 'active' => '1', 'payload_url' => $long]);
        self::assertNotSame(303, $r['status'], 'a URL its masked form could not carry is refused at create');
        self::assertStringContainsString('Enter a valid http:// or https:// URL.', self::text($r['body']));
        self::assertSame([$id], self::hookIds($h), 'no second hook was stored');
    }

    /** @return list<string> */
    private static function hookIds(MintHarness $h): array
    {
        preg_match_all("~/settings/webhooks/([a-f0-9]{12})'~", $h->get('/settings/webhooks')['body'], $m);

        return array_values(array_unique($m[1]));
    }

    public function test_blank_url_on_edit_keeps_the_credential_reference(): void
    {
        $h = $this->h();
        $h->join();
        $key = 'AK' . 'IA' . 'QZT4CANARYKEY7XQ';
        $id = self::createHook($h, 'http://' . $key . ':pw@172.16.0.5/x');
        $show = $h->get('/settings/webhooks/' . $id);
        self::assertStringNotContainsString($key, $show['body'], 'userinfo is never shown');
        self::assertStringContainsString('***@172.16.0.5', $show['body']);
        self::assertDoesNotMatchRegularExpression("~name=payload_url value='[^']~", $show['body'], 'the edit form never re-sends the stored URL');
        $before = $h->ssrfStore->load(self::owner($h))?->d['h'][0]['u'];
        $r = $h->post('/settings/webhooks/' . $id, ['csrf_token' => self::tokens($show['body'])[1], 'content_type' => 'form', 'active' => '0', 'payload_url' => '']);
        self::assertSame(303, $r['status']);
        $after = $h->ssrfStore->load(self::owner($h))?->d['h'][0];
        self::assertSame($before, $after['u'], 'blank keeps the URL version and its credential reference');
        self::assertSame('form', $after['ct']);
        self::assertStringNotContainsString($key, (string) $h->ssrfStore->db()->query('SELECT state FROM ssrf_owner')->fetchColumn());
    }

    private static function owner(MintHarness $h): string
    {
        return (string) $h->ssrfStore->db()->query('SELECT o FROM ssrf_owner LIMIT 1')->fetchColumn();
    }

    public function test_signature_header_verifies(): void
    {
        $h = $this->h();
        $h->join();
        foreach (['json', 'form'] as $ct) {
            $id = self::createHook($h, 'http://172.16.0.5/', ['secret' => 'S3cret.value', 'content_type' => $ct]);
            self::ping($h, $id);
            [$did] = self::deliveries($h, $id);
            $page = $h->get('/settings/webhooks/' . $id . '/deliveries/' . $did)['body'];
            preg_match('~<h2>Request</h2><pre class=mono>(.*?)</pre>~s', $page, $m);
            $req = html_entity_decode($m[1], ENT_QUOTES);
            [$head, $body] = explode("\n\n", $req, 2);
            preg_match('/-Signature-256: sha256=([a-f0-9]{64})/', $head, $sig);
            self::assertSame(hash_hmac('sha256', $body, 'S3cret.value'), $sig[1], "{$ct}: the signature is over the body as sent");
            if ($ct === 'json') {
                self::assertSame($did, json_decode($body, true)['delivery']);
            } else {
                self::assertStringStartsWith('payload=', $body, 'a form hook sends the payload as a form field');
                parse_str($body, $form);
                self::assertSame($did, json_decode((string) $form['payload'], true)['delivery']);
            }
        }
    }

    public function test_pages_escape_what_the_network_returned_and_link_only_to_themselves(): void
    {
        $h = $this->h();
        $h->join();
        $id = self::createHook($h, 'http://127.1:8080/login?next=%2Fadmin');
        self::ping($h, $id);
        $h->now += 4;
        [$did] = self::deliveries($h, $id);
        $dl = $h->get('/settings/webhooks/' . $id . '/deliveries/' . $did);
        self::assertSame('no-store', $dl['plan']?->header('Cache-Control'), 'a delivery page is never cached');
        self::assertStringContainsString('&lt;h1&gt;Forbidden&lt;/h1&gt;', $dl['body'], 'the response body is shown as escaped text');
        self::assertStringNotContainsString('<body><h1>Forbidden</h1>', $dl['body']);
        $imp = (string) self::import($h, 'orders_csv', 'http://127.1:8080/orders.csv')['plan']?->header('Location');
        $h->now += 6;
        $pages = ['/settings/webhooks', '/settings/webhooks/' . $id, '/settings/webhooks/' . $id . '/deliveries/' . $did, '/settings/imports', $imp, '/settings/storage'];
        self::assertStringContainsString('http://127.1:8080/login?next=%2Fadmin', self::text($h->get('/settings/webhooks')['body']), 'the list shows the stored URL');
        foreach ($pages as $path) {
            preg_match_all("~<[a-z][^<>]*\\s(?:href|action|src)=(['\"]?)([^'\" >]*)\\1~i", $h->get($path)['body'], $m);
            self::assertNotEmpty($m[2], $path);
            foreach ($m[2] as $target) {
                self::assertStringStartsWith('/', $target, "{$path} links only within the site");
                self::assertStringNotContainsString('//', $target, $path);
            }
        }
    }

    public function test_an_import_excerpt_is_at_most_512_bytes(): void
    {
        $h = $this->h();
        $h->join();
        $g = $h->ssrf->network()->generated();
        $lengths = [];
        for ($i = 1, $n = 0; $n < 4 && $i < 6000; $i++) {
            if ($g->node($i)?->kind !== 'http_api') {
                continue;
            }
            $n++;
            $loc = (string) self::import($h, 'orders_json', 'http://' . $g->name($i) . ':' . $g->node($i)->ports[0] . '/')['plan']?->header('Location');
            $h->now += 6;
            self::assertSame(1, preg_match('~<h2>Response excerpt</h2><pre class=mono>(.*?)</pre>~s', $h->get($loc)['body'], $m), $loc);
            $lengths[] = strlen(html_entity_decode($m[1], ENT_QUOTES));
        }
        self::assertSame(512, max($lengths), 'a service listing longer than the excerpt is cut at 512 bytes');
        self::assertLessThan(512, min($lengths), 'and a shorter one is shown whole');
    }

    public function test_ui_routes_need_a_session_and_exact_routes_stay_served(): void
    {
        $h = $this->h();
        $h->join();
        $pat = $h->mint(['read:user', 'webhooks:write', 'imports:write', 'storage:write']);
        foreach (['/settings/webhooks', '/settings/imports', '/settings/storage', '/settings/webhooks/new'] as $path) {
            $r = $h->request('GET', $path, '', null, ['Authorization' => 'Bearer ' . $pat], MintHarness::IP, 'bearer-only');
            self::assertSame(303, $r['status'], "{$path} with a bearer and no session");
            self::assertSame('/', $r['plan']?->header('Location'), $path);
        }
        $narrow = $h->mint(['read:user'], 'narrow');
        $cases = [
            ['DELETE', '/settings/webhooks', [], 405], ['PUT', '/api/v2/user/imports', [], 405], ['PATCH', '/settings/storage', [], 405],
            ['GET', '/api/v2/user/hooks', ['Authorization' => 'Bearer ' . $narrow], 403],
        ];
        foreach ($cases as [$method, $path, $headers, $status]) {
            $r = $h->request($method, $path, '', null, $headers, MintHarness::IP, 'anon');
            self::assertSame($status, $r['status'], "{$method} {$path}");
            self::assertTrue($r['main']['served'], "{$method} {$path}: an exact route's {$status} stays served");
        }
        $anon = $h->request('GET', '/api/v2/user/hooks', '', null, [], MintHarness::IP, 'anon');
        self::assertSame(401, $anon['status']);
        self::assertFalse($anon['main']['served'], 'an anonymous API call is unserved, as on the token-mint API');
    }

    // --- imports -----------------------------------------------------------------------------------

    private static function import(MintHarness $h, string $kind, string $url): array
    {
        $form = $h->get('/settings/imports/new');

        return $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($form['body']), 'kind' => $kind, 'source_url' => $url]);
    }

    public function test_import_internal_target_fails_validation_with_excerpt(): void
    {
        $h = $this->h();
        $h->join();
        $r = self::import($h, 'orders_csv', self::generated($h) . '/orders.csv?CANARYZQX=1');
        self::assertSame(303, $r['status']);
        $h->now += 6;
        $page = $h->get((string) $r['plan']?->header('Location'));
        $text = self::text($page['body']);
        self::assertStringContainsString('Row 1: expected header `order_id`', $text);
        self::assertStringContainsString('Response excerpt', $text);
        preg_match('~<h2>Response excerpt</h2><pre class=mono>(.*?)</pre>~s', $page['body'], $m);
        self::assertLessThanOrEqual(512, strlen(html_entity_decode($m[1], ENT_QUOTES)));
        self::assertSame(1, substr_count($page['body'], 'CANARYZQX'), 'the target canary appears only in the stored source URL');
    }

    public function test_mirror_import_from_github_never_claims_progress(): void
    {
        $h = $this->h();
        $h->join();
        $loc = (string) self::import($h, 'mirror', 'https://github.com/torvalds/linux.git')['plan']?->header('Location');
        $seen = [];
        for ($i = 0; $i < 40; $i++) {
            $text = self::text($h->get($loc)['body']);
            self::assertDoesNotMatchRegularExpression('/\d+\s*%|objects|MiB|KiB/', $text);
            $seen[str_contains($text, 'Waiting') ? 'w' : (str_contains($text, 'Cloning into \'linux\'') ? 'c' : (str_contains($text, 'no data received from github.com') ? 'f' : '?'))] = true;
            $h->now += 60;
        }
        self::assertSame(['w', 'c', 'f'], array_keys($seen));
    }

    public function test_mirror_url_on_github_must_be_repository_shaped(): void
    {
        $h = $this->h();
        $h->join();
        foreach (['https://github.com/', 'https://github.com/torvalds', 'https://github.com/a/b/tree/main', 'http://github.com/a/b', 'https://github.com/a/b?x=1'] as $bad) {
            $r = self::import($h, 'mirror', $bad);
            self::assertSame(422, $r['status'], $bad);
            self::assertStringContainsString('Repository URL must look like', self::text($r['body']));
        }
        self::assertSame(303, self::import($h, 'mirror', 'https://github.com/a-b/c.d_e.git')['status']);
    }

    public function test_orders_import_refuses_repository_hosts(): void
    {
        $h = $this->h();
        $h->join();
        $r = self::import($h, 'orders_json', 'https://github.com/a/b.git');
        self::assertSame(422, $r['status']);
        self::assertStringContainsString('repository hosts are not supported', self::text($r['body']));
    }

    public function test_mirror_import_of_an_internal_node_reports_a_git_failure(): void
    {
        $h = $this->h();
        $h->join();
        $loc = (string) self::import($h, 'mirror', self::generated($h) . '/repo.git')['plan']?->header('Location');
        $h->now += 4;
        self::assertStringContainsString('the remote did not answer as a Git repository (HTTP', self::text($h->get($loc)['body']));
    }

    public function test_import_retry_cap(): void
    {
        $h = $this->h();
        $h->join();
        $loc = (string) self::import($h, 'orders_csv', 'http://nosuch.internal/a.csv')['plan']?->header('Location');
        for ($i = 0; $i < 5; $i++) {
            $page = $h->get($loc);
            $r = $h->post($loc . '/retry', ['csrf_token' => MintHarness::csrf($page['body'])]);
            self::assertSame(303, $r['status'], "retry {$i}");
        }
        $page = $h->get($loc);
        self::assertStringNotContainsString('Retry import', $page['body'], 'no retry form past the cap');
        self::assertStringContainsString('retries 5 of 5', self::text($page['body']));
        $other = (string) self::import($h, 'orders_csv', 'http://nosuch.internal/b.csv')['plan']?->header('Location');
        $capped = $h->post($loc . '/retry', ['csrf_token' => MintHarness::csrf($h->get($other)['body'])]);
        self::assertSame(422, $capped['status']);
        self::assertStringContainsString('This import has been retried the most times allowed.', self::text($capped['body']));
    }

    public function test_a_retry_the_page_does_not_offer_says_why_in_the_page_s_terms(): void
    {
        $h = $this->h();
        $h->join();
        $counter = static fn (string $loc): string => preg_match('~retries \d+ of \d+~', self::text($h->get($loc)['body']), $m) === 1 ? $m[0] : '?';
        $slow = (string) self::import($h, 'orders_csv', 'http://172.16.9.9/b.csv')['plan']?->header('Location');
        $h->now += 11;
        $token = MintHarness::csrf($h->get($slow)['body']);
        self::assertSame(303, $h->post($slow . '/retry', ['csrf_token' => $token])['status']);
        $again = $h->post($slow . '/retry', ['csrf_token' => $token]);
        self::assertSame(422, $again['status'], 'a double submit changes nothing');
        self::assertStringContainsString('A retry of this import is already queued.', self::text($again['body']));
        self::assertSame('retries 1 of 5', $counter($slow));

        $failed = (string) self::import($h, 'orders_csv', 'http://nosuch.internal/a.csv')['plan']?->header('Location');
        $other = MintHarness::csrf($h->get($failed)['body']);
        $mirror = (string) self::import($h, 'mirror', 'https://github.com/torvalds/linux')['plan']?->header('Location');
        $waiting = $h->post($mirror . '/retry', ['csrf_token' => $other]);
        self::assertSame(422, $waiting['status']);
        self::assertStringContainsString('This import is still running. Retry it once it has failed.', self::text($waiting['body']));
        self::assertSame('retries 0 of 5', $counter($mirror));
        self::assertStringNotContainsString('retried the most times allowed', self::text($waiting['body'] . $again['body']));
    }

    // --- export destination ------------------------------------------------------------------------

    private static function storage(MintHarness $h, string $bucket, string $url, string $ak = 'exportbot'): array
    {
        $page = $h->get('/settings/storage');

        return $h->post('/settings/storage', ['csrf_token' => self::tokens($page['body'])[0], 'bucket' => $bucket, 'access_key' => $ak, 'secret_key' => 'Rk2mQ9xLw4', 'endpoint_url' => $url]);
    }

    private static function verify(MintHarness $h): string
    {
        $page = $h->get('/settings/storage');
        $h->post('/settings/storage/verify', ['csrf_token' => self::tokens($page['body'])[1]]);
        $h->now += 4;

        return self::text($h->get('/settings/storage')['body']);
    }

    public function test_storage_verify_answers_per_class(): void
    {
        $h = $this->h();
        $h->join();
        self::assertSame(303, self::storage($h, 'exports-acme', self::generated($h))['status']);
        $text = self::verify($h);
        self::assertStringContainsString('405', $text, 'an API service refuses the PUT');
        self::assertMatchesRegularExpression('~PUT http://[a-z0-9.-]+:\d+/exports-acme/\.verify-[a-f0-9]{12}~', $text, 'a path-style PUT to the endpoint host');
        self::storage($h, 'exports-acme', 'https://s3.example.net');
        self::assertStringContainsString('Request denied by egress policy', self::verify($h));
        self::storage($h, 'exports-acme', 'http://10.213.87.5:9000');
        self::assertStringContainsString('Pending', self::text($h->get('/settings/storage')['body']) . self::verify($h));
    }

    public function test_bucket_naming_rules(): void
    {
        $h = $this->h();
        $h->join();
        foreach (['', 'ab', 'Upper', 'a..b', '169.254.169.254', '-x-', str_repeat('a', 64), 'a_b'] as $bad) {
            self::assertSame(422, self::storage($h, $bad, 'http://172.16.0.5')['status'], $bad);
        }
        self::assertSame(422, self::storage($h, 'exports', 'http://172.16.0.5/?x=1')['status'], 'no query on an endpoint');
        self::assertSame(303, self::storage($h, 'exports.backup-1', 'http://172.16.0.5/base')['status']);
    }

    public function test_storage_verify_against_metadata_is_403(): void
    {
        $h = $this->h();
        $h->join();
        self::storage($h, 'exports', 'http://0xa9fea9fe');
        $text = self::verify($h);
        self::assertStringContainsString('403', $text, 'metadata answers a PUT on a non-token path with 403');
        self::assertStringNotContainsString('AccessKeyId', $text);
    }
}
