<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Tarpit\Mint\MintForms;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintRoutes;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Fake\FakePeople;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Tests\App\Tarpit\Mint\CoreWords;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Which paths the token-mint surface owns, derived against the installed engine at run time rather
 * than trusted from a table: what core detects on each owned path, that no owned path collides with a
 * core route or a backup-file decoy, that the surface's own benign traffic trips no attack class, and
 * that its set is disjoint from the web-shell console's.
 */
final class TokenMintOwnershipTest extends TestCase
{
    private static function routes(): MintRoutes
    {
        return new MintRoutes(MintCorpus::slug());
    }

    /**
     * Every attack class is detected on every owned path. Only a POST to an `auth/login` path is won
     * by core's /login-suffix oracle instead. A core bump that changes a row prints the whole table.
     */
    public function test_engine_detects_each_attack_class_on_every_owned_path(): void
    {
        $hp = MintCorpus::engine();
        $table = [];
        $mismatch = 0;
        foreach (MintCorpus::ownedPaths(MintCorpus::slug()) as $p) {
            self::assertTrue(self::routes()->owns($p), "{$p} is owned");
            foreach (MintCorpus::attacks() as $name => [$m, $q, $b, $h, $expected]) {
                $ctx = new RequestContext($m, $p, $q, $h, $b);
                $ids = $hp->detect($ctx)->templateIds();
                $resp = $hp->respond($ctx);
                $want = $m === 'POST' && str_ends_with($p, '/auth/login') ? 'attack-cpsrvd-login' : $expected;
                $got = $ids[0] ?? '(none)';
                $table[] = sprintf('%-6s %-34s %-10s detect=%-24s respond=%s', $m, $p, $name, $got, $resp?->status ?? 'null');
                if ($got !== $want) {
                    $mismatch++;
                }
            }
        }
        self::assertSame(0, $mismatch, "engine table changed:\n" . implode("\n", $table));
        self::assertGreaterThanOrEqual(400, count($table));
    }

    public function test_no_owned_route_is_an_exact_core_route_key(): void
    {
        $compiled = require dirname(__DIR__, 3) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $keys = array_flip(array_keys($compiled['routes']));
        self::assertGreaterThan(1000, count($keys), 'sanity: the compiled route map is the real one');
        foreach (MintCorpus::ownedPaths(MintCorpus::slug()) as $p) {
            foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as $m) {
                self::assertArrayNotHasKey("{$m} {$p}", $keys, "{$m} {$p} is a core route");
            }
        }
    }

    /** Ownership of an id never depends on its length: every length from 1 to 20 answers alike. */
    public function test_id_ownership_is_contiguous_in_length_and_never_takes_a_word(): void
    {
        $r = self::routes();
        foreach (['/api/v2/orders/', '/v2/orders/', '/settings/applications/', '/settings/tokens/%s/delete', '/settings/applications/%s/secrets'] as $base) {
            for ($len = 1; $len <= 20; $len++) {
                foreach ([str_repeat('9', $len), substr('a1b2c3d4e5f6a7b8c9d0', 0, $len), str_pad('7', $len, 'z')] as $id) {
                    if (preg_match('/[0-9]/', $id) !== 1) {
                        continue;
                    }
                    $p = str_contains($base, '%s') ? sprintf($base, $id) : $base . $id;
                    self::assertTrue($r->owns($p), "{$p} ({$len} chars) is owned");
                }
            }
            foreach (['export', 'abcdefgh', 'new', 'abcdefghijklmnopqrst', str_repeat('9', 21), 'ABC123', 'a1-b2'] as $word) {
                $p = str_contains($base, '%s') ? sprintf($base, $word) : $base . $word;
                if (isset(MintRoutes::EXACT[$p])) {
                    continue; // an exact page such as /settings/applications/new, not an id
                }
                self::assertFalse($r->owns($p), "{$p} is not an id");
            }
        }
    }

    public function test_no_compiled_core_route_falls_inside_an_owned_path(): void
    {
        $compiled = require dirname(__DIR__, 3) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $r = self::routes();
        $hits = [];
        foreach (array_keys($compiled['routes']) as $key) {
            $path = (string) substr((string) $key, (int) strpos((string) $key, ' ') + 1);
            if ($r->owns(substr($path, 0, (int) (strcspn($path, '?')) ?: strlen($path)))) {
                $hits[] = $key;
            }
        }
        self::assertSame([], $hits, 'the core keeps every route it compiles');
    }

    /**
     * Core first: wherever the engine answers a bare GET on a single word by path alone, the path is
     * not ours. The candidates are every word core's compiled artifacts hold or its compiled patterns
     * can spell (CoreWords), lowercased, since core's word rules ignore case (exact compiled routes are
     * checked as written by the test above). Each word is tried as a final `{login}` segment and, when
     * it is id-shaped, as an inner `{id}` segment. An owned instance core answers fails, so a core bump
     * that keys a bare GET on a new word inside the grammar fails here until the word joins
     * MintRoutes::CORE_KEYED, and every listed word must still be keyed on some unowned candidate
     * holding no other listed word.
     * Words core keys only with a method or a body are owned on purpose and pinned below.
     */
    public function test_core_keeps_every_path_it_answers_inside_the_owned_grammar(): void
    {
        $words = CoreWords::all();
        self::assertGreaterThan(40000, count($words), 'sanity: the artifacts were read');
        foreach (['setenv', 'busybox', 'unionselect', 'schema_name', '5cwindows'] as $spelt) {
            self::assertContains($spelt, $words, "{$spelt} is spelt only by a compiled pattern or an encoded path");
        }
        $hp = MintCorpus::engine();
        $r = self::routes();
        $owned = 0;
        $collisions = [];
        $witness = [];
        foreach ($words as $w) {
            $paths = ['/api/v2/users/' . $w];
            if (preg_match('~\A' . MintRoutes::ID . '\z~', $w) === 1) {
                $paths[] = '/settings/tokens/' . $w . '/delete';
            }
            foreach ($paths as $p) {
                if ($r->owns($p)) {
                    $owned++;
                    $resp = $hp->respond(new RequestContext('GET', $p, '', [], null));
                    if ($resp !== null) {
                        $collisions[] = $p . ' -> ' . implode(',', array_slice($resp->satisfies->templateIds(), 0, 2));
                    }
                } else {
                    // A witness holds exactly one excluded word, so only that word explains core's answer.
                    // One per word is enough: core pauses before each answer it serves.
                    $held = array_values(array_filter(MintRoutes::CORE_KEYED, static fn (string $k): bool => str_contains($w, $k)));
                    if (count($held) === 1 && !isset($witness[$held[0]]) && $hp->respond(new RequestContext('GET', $p, '', [], null)) !== null) {
                        $witness[$held[0]] = true;
                    }
                }
            }
        }
        self::assertGreaterThan(40000, $owned, 'sanity: the probe reached the owned grammar');
        self::assertSame([], $collisions, 'core answers these by path alone, so they must not be owned');
        self::assertSame([], array_values(array_diff(MintRoutes::CORE_KEYED, array_keys($witness))), 'every excluded word is still keyed by core');
        foreach (MintRoutes::CORE_KEYED as $a) {
            foreach (MintRoutes::CORE_KEYED as $b) {
                self::assertFalse($a !== $b && str_contains($a, $b), "{$a} already holds {$b}");
            }
        }
        foreach (MintRoutes::CORE_KEYED as $word) {
            self::assertFalse($r->owns('/api/v2/users/x' . strtoupper($word) . '1'));
            self::assertFalse($r->owns('/settings/tokens/1' . $word . '/delete'));
        }

        // Keyed only with a method or a body: owned on purpose, since a substring rule would also reserve
        // ordinary names such as `denver`. There the surface answers and detection keeps core's class.
        foreach ([['POST', 'env', 'a=1', MintCorpus::F], ['PATCH', 'alert', '{}', MintCorpus::J], ['POST', 'login', null, []]] as [$method, $w, $body, $headers]) {
            $p = '/api/v2/users/' . $w;
            self::assertTrue($r->owns($p), "{$p} stays owned");
            self::assertNull($hp->respond(new RequestContext('GET', $p, '', [], null)), "a bare GET on {$p} is not keyed");
            self::assertNotNull($hp->respond(new RequestContext($method, $p, '', $headers, $body)), "{$method} {$p} is keyed");
        }
        self::assertTrue($r->owns('/api/v2/users/denver'));

        // Persona names never hold an excluded word, so the persona's own org and member paths stay owned:
        // every pool core draws from, every first-last author slug, and the members MintPersona builds.
        foreach ([PersonaIdentity::class, FakePeople::class] as $class) {
            foreach ((new \ReflectionClass($class))->getReflectionConstants() as $c) {
                $v = $c->getValue();
                if (is_array($v)) {
                    array_walk_recursive($v, static function ($x) use ($c): void {
                        self::assertFalse(is_string($x) && MintRoutes::coreKeyed($x), $c->getName() . ': ' . (is_string($x) ? $x : ''));
                    });
                }
            }
        }
        $people = new \ReflectionClass(FakePeople::class);
        $slug = new ReflectionMethod(PersonaIdentity::class, 'slug');
        foreach ((array) $people->getConstant('FIRST_NAMES') as $first) {
            foreach ((array) $people->getConstant('LAST_NAMES') as $last) {
                $login = (string) $slug->invoke(null, $first . '-' . $last);
                self::assertFalse(MintRoutes::coreKeyed($login), $login);
            }
        }
        for ($seed = 1; $seed <= 5000; $seed++) {
            $persona = MintPersona::fromSeed($seed);
            $pr = new MintRoutes($persona->slug);
            foreach (['/api/v2/orgs/' . $persona->slug . '/members', '/orgs/' . $persona->slug . '/sso', '/idp/' . $persona->slug . '/signin'] as $p) {
                self::assertTrue($pr->owns($p), "seed {$seed}: {$p}");
            }
            foreach (array_keys($persona->members) as $login) {
                self::assertTrue($pr->owns('/api/v2/users/' . $login), "seed {$seed}: member {$login}");
            }
        }
    }

    public function test_unowned_paths_stay_unowned_whatever_core_answers(): void
    {
        $r = self::routes();
        foreach (MintCorpus::notOwned() as $p) {
            self::assertFalse($r->owns($p), "{$p} must not be owned");
        }
        foreach (['.tar.gz', '.tar.bz2', '.tbz2', '.tgz', '.tar', '.gz', '.zip', '.sql', '.pem', '.cer', 'wallet.json'] as $suffix) {
            foreach (['/api/v2/users/backup', '/v2/users/x', '/settings/applications/abcdefgh'] as $base) {
                $p = $base . ($suffix[0] === '.' ? $suffix : '/' . $suffix);
                self::assertNotNull(HoneypotController::decoyForPath($p));
                self::assertFalse($r->owns($p), "{$p} is a backup-file decoy path");
            }
        }
        foreach (MintCorpus::ownedPaths(MintCorpus::slug()) as $p) {
            self::assertFalse(PanelRoute::mountedAtRoot($p), "{$p} must never be a root panel mount");
            self::assertNull(HoneypotController::decoyForPath($p));
        }
    }

    public function test_benign_owned_traffic_trips_no_attack_class(): void
    {
        self::assertCount(2, MintCorpus::EXEMPT, 'the exemption list is exactly the two documented login paths');
        $hp = MintCorpus::engine();
        $flagged = [];
        foreach (MintCorpus::benign(MintCorpus::slug()) as [$m, $p, $q, $b, $h]) {
            self::assertTrue(self::routes()->owns($p), $p);
            $d = $hp->detect(new RequestContext($m, $p, $q, $h, $b));
            if (in_array('attack', $d->tags(), true) && !in_array("{$m} {$p}", MintCorpus::EXEMPT, true)) {
                $flagged[] = "{$m} {$p} " . implode(',', $d->templateIds());
            }
        }
        self::assertSame([], $flagged);

        // The names an earlier draft used are kept as negative fixtures: they would fail this invariant.
        $slug = MintCorpus::slug();
        foreach ([['POST', '/idp/' . $slug . '/login', 'username=a%40b.co&password=x'], ['POST', '/api/v2/orders/export', 'format=csv&since=2024-01-01'], ['POST', '/v2/orders/export', 'format=csv&since=2024-01-01']] as [$m, $p, $b]) {
            self::assertContains('attack', $hp->detect(new RequestContext($m, $p, '', MintCorpus::F, $b))->tags(), "{$p} stays a negative fixture");
            self::assertFalse(self::routes()->owns($p));
        }
    }

    public function test_every_supported_callback_form_is_engine_clean_and_ipv6_loopback_is_refused(): void
    {
        $hp = MintCorpus::engine();
        $routes = [
            fn (string $cb): RequestContext => new RequestContext('POST', '/settings/applications', '', MintCorpus::F, MintCorpus::CSRF . '&name=my-app&homepage_url=https%3A%2F%2Fapp.example.com&callback_url=' . rawurlencode($cb) . '&description=build+bot'),
            fn (string $cb): RequestContext => new RequestContext('GET', '/login/oauth/authorize', 'client_id=0123456789abcdef0123&redirect_uri=' . rawurlencode($cb) . '&scope=read%3Auser&state=abc', []),
            fn (string $cb): RequestContext => new RequestContext('POST', '/login/oauth/access_token', '', MintCorpus::F, 'grant_type=authorization_code&code=0123456789abcdef0123&client_id=0123456789abcdef0123&client_secret=x&redirect_uri=' . rawurlencode($cb)),
        ];
        $forms = 0;
        foreach (MintForms::CALLBACK_FORMS as $kind => $form) {
            foreach ($form['examples'] as $cb) {
                $forms++;
                self::assertTrue(MintForms::validCallback($cb), "{$cb} ({$kind}) is accepted");
                foreach ($routes as $i => $make) {
                    self::assertSame([], $hp->detect($make($cb))->templateIds(), "{$cb} on route {$i} must be engine-clean");
                }
            }
        }
        self::assertGreaterThanOrEqual(15, $forms);
        foreach (MintForms::REFUSED_CALLBACKS as $cb) {
            self::assertFalse(MintForms::validCallback($cb), "{$cb} is refused");
            foreach ($routes as $make) {
                self::assertContains('attack-crs-rce', $hp->detect($make($cb))->templateIds(), "{$cb} stays flagged, which is why it is refused");
            }
        }
    }

    public function test_owned_set_is_disjoint_from_the_web_shell_console_grammar(): void
    {
        $r = self::routes();
        $slug = MintCorpus::slug();
        $samples = MintCorpus::ownedPaths($slug);
        foreach (['shell.php', 'Shell.PHP', 'cmd.Php', 'c99.php', 'WSO.php', 'r57.PHP', 'b374k.php', 'alfa.php', 'indoxploit.php'] as $file) {
            foreach (['/api/v2/users/', '/v2/users/', '/settings/applications/', '/api/v2/orders/', '/settings/tokens/1/', '/orgs/' . $slug . '/'] as $base) {
                $p = $base . $file;
                self::assertMatchesRegularExpression(MintCorpus::FP0814_SHELL_FILE, $p);
                self::assertFalse($r->owns($p), "{$p} belongs to the console, never to this surface");
            }
        }
        foreach ($samples as $p) {
            self::assertNotContains($p, MintCorpus::FP0814_CONSOLE_PATHS);
            self::assertDoesNotMatchRegularExpression(MintCorpus::FP0814_SHELL_FILE, $p);
            self::assertStringStartsNotWith('/admin/', $p);
        }
        foreach (MintCorpus::FP0814_CONSOLE_PATHS as $p) {
            self::assertFalse($r->owns($p));
        }
        $owns = new ReflectionMethod(TokenMintDecoy::class, 'owns');
        self::assertSame(['path'], array_map(static fn ($p) => $p->getName(), $owns->getParameters()), 'ownership is a function of the path alone');
    }
}
