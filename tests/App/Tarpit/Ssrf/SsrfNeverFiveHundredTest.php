<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * 5,000 seeded random requests over the owned set (methods, ids, form and JSON bodies of every shape,
 * stale and fresh form tokens, a session, a token, neither) stay in the closed status set with no fault
 * and no warning, and at least 1,000 of them reach the signed-in, CSRF-valid branches.
 */
final class SsrfNeverFiveHundredTest extends TestCase
{
    private const REQUESTS = 5000;
    private const PRE_AUTH = ['csrf', 'no_session', 'unauthorized', 'method', 'too_large', 'scope_403', 'bad_body', ''];

    public function test_random_requests_never_leave_the_closed_set(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $pat = $h->mint(['read:user', 'webhooks:write', 'imports:write', 'storage:write']);
            mt_srand(81605);
            $ids = ['4b7e19a2c0a1', '1', 'a1b2c3d4e5f6a7b8c9d0'];
            $tokens = [];
            $urls = [...SsrfCorpus::urls(), 'http://[::1]/', 'gopher://x/', '', 'http://127.0.0.1/', 'https://github.com/a/b.git', "http://x/\x01", str_repeat('a', 600), 'http://0x7f000001:6379/', 'http://sts.x.internal/?X-Amz-Credential=AKIA'];
            $shapes = [null, '', 'x', '1', ['a'], ['a' => 'b'], true, 5];
            $reached = 0;
            $statuses = [];
            $routes = SsrfRoutes::examples();
            for ($i = 0; $i < self::REQUESTS; $i++) {
                $h->now += 13;
                if ($i % 400 === 0) {
                    $h->signIn('artex1', 'Passw0rd!x');
                }
                [$route, $path] = $routes[mt_rand(0, count($routes) - 1)];
                $path = (string) preg_replace('/4b7e19a2c0a1|5c8f2a91d0b3/', $ids[mt_rand(0, count($ids) - 1)], $path);
                $own = SsrfRoutes::methods($route);
                $methods = mt_rand(0, 3) > 0 ? $own : ['PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'POST'];
                $method = $methods[mt_rand(0, count($methods) - 1)];
                if (in_array('POST', $own, true) && mt_rand(0, 1) === 0) {
                    $method = 'POST';
                }
                $api = str_contains($path, '/user/');
                $headers = [];
                $mode = mt_rand(0, 9);
                if ($api) {
                    $headers['Authorization'] = 'Bearer ' . ($mode < 8 ? $pat : 'x' . $mode);
                }
                $fields = ['csrf_token' => $tokens !== [] && $mode < 8 ? $tokens[mt_rand(0, count($tokens) - 1)] : 'stale'];
                if (!$api && $method === 'POST' && $mode < 7) {
                    $fields['csrf_token'] = self::formToken($h, $path) ?? $fields['csrf_token'];
                }
                foreach (['payload_url', 'source_url', 'endpoint_url', 'url'] as $f) {
                    if (mt_rand(0, 2) > 0) {
                        $fields[$f] = $urls[mt_rand(0, count($urls) - 1)];
                    }
                }
                foreach (['kind' => ['orders_csv', 'orders_json', 'mirror', 'x'], 'content_type' => ['json', 'form', 'xml'], 'bucket' => ['exports-a', 'A..B'], 'access_key' => ['k1', '<x>'], 'secret_key' => ['s1'], 'active' => ['0', '1', 'yes'], 'delivery' => ['4b7e19a2c0a1', 'x']] as $f => $vals) {
                    if (mt_rand(0, 2) === 0) {
                        $fields[$f] = $vals[mt_rand(0, count($vals) - 1)];
                    }
                }
                if (mt_rand(0, 3) === 0) {
                    $fields['events'] = $shapes[mt_rand(0, count($shapes) - 1)];
                }
                $body = null;
                if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
                    if ($api || mt_rand(0, 4) === 0) {
                        $headers['Content-Type'] = 'application/json';
                        $body = mt_rand(0, 9) === 0 ? '{bad' : (string) json_encode($fields + ($mt = mt_rand(0, 1) ? ['active' => (bool) mt_rand(0, 1)] : []));
                    } else {
                        $body = http_build_query($fields);
                    }
                }
                $r = $h->request($method, $path, '', $body, $headers);
                $plan = $r['plan'];
                self::assertInstanceOf(MintPlan::class, $plan, "{$method} {$path}: the decoy answered");
                self::assertContains($plan->status, MintPlan::STATUSES, "{$method} {$path}");
                self::assertLessThan(500, $plan->status);
                $statuses[$plan->status] = ($statuses[$plan->status] ?? 0) + 1;
                if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) && !in_array((string) ($plan->turn['outcome'] ?? ''), self::PRE_AUTH, true)) {
                    $reached++;
                }
                preg_match_all("/name=csrf_token value='([^']+)'/", $r['body'], $m);
                if ($m[1] !== []) {
                    $tokens = array_slice([...$tokens, ...$m[1]], -20);
                }
                if ($i % 50 === 0) {
                    $ids = array_slice(array_values(array_unique([...$ids, ...self::issuedIds($h)])), -12);
                }
            }
            fwrite(STDERR, "\nstatuses: " . json_encode($statuses) . " reached: {$reached}\n");
            self::assertSame(0, $h->ssrf->faults());
            self::assertSame([], $h->warnings);
            self::assertGreaterThanOrEqual(1000, $reached, 'the fuzz reached the signed-in, CSRF-valid branches');
        } finally {
            $h->cleanup();
        }
    }

    /** The token of the form that posts to $action, fetched from the page that renders it. */
    private static function formToken(MintHarness $h, string $action): ?string
    {
        $page = match (true) {
            $action === '/settings/webhooks' => '/settings/webhooks/new',
            $action === '/settings/imports' => '/settings/imports/new',
            str_starts_with($action, '/settings/storage') => '/settings/storage',
            preg_match('~\A(/settings/webhooks/[a-z0-9]+)(?:/pings|/delete)?\z~', $action, $m) === 1 => $m[1],
            preg_match('~\A(/settings/imports/[a-z0-9]+)/retry\z~', $action, $m) === 1 => $m[1],
            default => null,
        };
        if ($page === null) {
            return null;
        }
        $body = $h->get($page)['body'];

        return preg_match("~action='" . preg_quote($action, '~') . "'><input type=hidden name=csrf_token value='([^']+)'~", $body, $t) === 1 ? $t[1] : null;
    }

    /** @return list<string> */
    private static function issuedIds(MintHarness $h): array
    {
        $json = (string) $h->ssrfStore->db()->query('SELECT state FROM ssrf_owner LIMIT 1')->fetchColumn();
        preg_match_all('/"id":"([a-f0-9]{12})"/', $json, $m);

        return $m[1];
    }
}
