<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Tarpit\Mint\MintRoutes;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\CoreWords;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;
use PHPUnit\Framework\TestCase;

/**
 * The SSRF decoy's owned set: a function of the path alone, closed, disjoint from the token-mint
 * surface, the web-shell console, the root panel mounts and the decoy files, and never a path the
 * engine answers by path alone.
 */
final class SsrfOwnershipTest extends TestCase
{
    private static function paths(): array
    {
        return array_map(static fn (array $e): string => $e[1], SsrfRoutes::examples());
    }

    public function test_no_owned_route_is_an_exact_core_route_key(): void
    {
        $compiled = require dirname(__DIR__, 3) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $keys = array_flip(array_keys($compiled['routes']));
        self::assertGreaterThan(1000, count($keys));
        foreach (self::paths() as $p) {
            foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as $m) {
                self::assertArrayNotHasKey("{$m} {$p}", $keys, "{$m} {$p} is a core route");
            }
        }
    }

    public function test_no_compiled_core_route_falls_inside_an_owned_path(): void
    {
        $compiled = require dirname(__DIR__, 3) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $r = new SsrfRoutes();
        $hits = [];
        foreach (array_keys($compiled['routes']) as $key) {
            $path = (string) substr((string) $key, (int) strpos((string) $key, ' ') + 1);
            if ($r->owns(substr($path, 0, (int) strcspn($path, '?') ?: strlen($path)))) {
                $hits[] = $key;
            }
        }
        self::assertSame([], $hits, 'core keeps every route it compiles');
    }

    /**
     * Wherever the engine answers a bare GET by path alone, the path is not ours: every word core's
     * compiled artifacts hold or its patterns can spell, as an id (as written when id-shaped, else
     * wrapped x…1) in a UI and an API id slot.
     */
    public function test_core_keeps_every_path_it_answers_inside_the_owned_grammar(): void
    {
        $words = CoreWords::all();
        self::assertGreaterThan(40000, count($words));
        $hp = MintCorpus::engine();
        $r = new SsrfRoutes();
        $owned = 0;
        $collisions = [];
        foreach ($words as $w) {
            if (preg_match('~\A' . MintRoutes::ID . '\z~', $w) === 1) {
                $id = $w;
            } elseif (preg_match('~\A[a-z]{1,18}\z~', $w) === 1) {
                $id = 'x' . $w . '1';
            } else {
                continue;
            }
            foreach (['/settings/webhooks/' . $id, '/api/v2/user/hooks/' . $id . '/deliveries'] as $p) {
                if ($r->owns($p)) {
                    $owned++;
                    $resp = $hp->respond(new RequestContext('GET', $p, '', [], null));
                    if ($resp !== null) {
                        $collisions[] = $p . ' -> ' . implode(',', array_slice($resp->satisfies->templateIds(), 0, 2));
                    }
                }
            }
        }
        self::assertGreaterThan(40000, $owned, 'the probe reached the owned grammar');
        self::assertSame([], $collisions, 'core answers these by path alone, so they must not be owned');
    }

    public function test_id_ownership_is_contiguous_in_length_and_never_takes_a_word(): void
    {
        $r = new SsrfRoutes();
        foreach (['/settings/webhooks/%s', '/settings/webhooks/%s/deliveries/4b7e19a2c0a1', '/settings/imports/%s/retry', '/api/v2/user/hooks/%s', '/v2/user/imports/%s'] as $base) {
            for ($len = 1; $len <= 20; $len++) {
                $id = substr('a1b2c3d4e5f6a7b8c9d0', 0, $len);
                if (preg_match('/[0-9]/', $id) === 1) {
                    self::assertTrue($r->owns(sprintf($base, $id)), sprintf($base, $id));
                }
            }
            foreach (['export', 'abcdefgh', 'abcdefghijklmnopqrst', str_repeat('9', 21), 'ABC123', 'a1-b2'] as $word) {
                self::assertFalse($r->owns(sprintf($base, $word)), sprintf($base, $word) . ' is not an id');
            }
        }
        self::assertTrue($r->owns('/settings/webhooks/new'), 'the new-hook page is an exact route');
    }

    public function test_unowned_paths_stay_unowned(): void
    {
        $r = new SsrfRoutes();
        foreach (['.tar.gz', '.tgz', '.zip', '.sql', '.pem', '.cer', 'wallet.json'] as $suffix) {
            foreach (['/settings/webhooks/a1b2c3', '/api/v2/user/hooks/a1b2c3', '/settings/storage'] as $base) {
                $p = $base . ($suffix[0] === '.' ? $suffix : '/' . $suffix);
                self::assertNotNull(HoneypotController::decoyForPath($p));
                self::assertFalse($r->owns($p), "{$p} is a decoy file path");
            }
        }
        foreach (['/settings/webhooks/a1.php', '/api/v2/user/hooks/1.PHP', '/settings/webhooks/x', '/settings/webhook', '/api/v2/user/hook',
            '/api/v3/user/hooks', '/settings/webhooks/a1b2/pings/x', '/user/hooks', '/settings/storage/x', '/api/v2/users/hooks'] as $p) {
            self::assertFalse($r->owns($p), "{$p} must not be owned");
        }
        foreach (MintRoutes::CORE_KEYED as $word) {
            self::assertFalse($r->owns('/settings/webhooks/1' . $word), $word);
            self::assertFalse($r->owns('/api/v2/user/hooks/1' . $word . '/pings'), $word);
        }
        self::assertTrue($r->owns('/settings/webhooks/'), 'one trailing slash is stripped');
        self::assertTrue($r->owns('/settings/webhooks#frag'));
        self::assertFalse($r->owns('/settings/webhooks/' . str_repeat('1', 190)), 'past 200 bytes');
        foreach (self::paths() as $p) {
            self::assertFalse(PanelRoute::mountedAtRoot($p), "{$p} is never a root panel mount");
            self::assertNull(HoneypotController::decoyForPath($p));
        }
    }

    public function test_disjoint_from_the_token_mint_surface_both_ways(): void
    {
        $slug = MintCorpus::slug();
        $mint = new MintRoutes($slug);
        $ssrf = new SsrfRoutes();
        foreach (self::paths() as $p) {
            self::assertFalse($mint->owns($p), "{$p} is the token-mint surface's");
        }
        foreach (MintCorpus::ownedPaths($slug) as $p) {
            self::assertFalse($ssrf->owns($p), "{$p} is the SSRF decoy's");
        }
        self::assertCount(33, self::paths(), "6 exact UI pages, 7 UI patterns and 10 API routes under both prefixes");
    }

    public function test_disjoint_from_the_web_shell_console_grammar(): void
    {
        $ssrf = new SsrfRoutes();
        foreach (MintCorpus::FP0814_CONSOLE_PATHS as $p) {
            self::assertFalse($ssrf->owns($p));
        }
        foreach (self::paths() as $p) {
            self::assertDoesNotMatchRegularExpression(MintCorpus::FP0814_SHELL_FILE, $p);
            self::assertDoesNotMatchRegularExpression('~\.php\z~i', $p);
            self::assertMatchesRegularExpression('~\A/(?:settings/(?:webhooks|imports|storage)|api/v2/user/|v2/user/)~', $p);
        }
    }
}
