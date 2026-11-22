<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Bench\TokenMintLoop;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;
use Funnypot\Tests\App\Tarpit\Mint\MintCrawl;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/scripts/support/TokenMintLoop.php';
require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';

/**
 * The token-mint surface with the SSRF extension unwired answers byte for byte as it did before the
 * extension existed: every MintCrawl answer for seeds 1–8, and the scripted mint loop's replay hash for
 * every profile on seeds 1–2, against constants recorded on the FP-0815 head this branch is built on.
 *
 * The constants depend on the installed core (issued values re-roll through the engine) and on the
 * token-mint code itself. After a core bump, or any change to the token-mint surface, run record() on
 * the new base and commit what it prints; a reviewer re-runs it on the recorded base to confirm.
 */
final class Fp0815SurfacePinTest extends TestCase
{
    public const BASE = '1059dbe';
    private const LOOP_STEPS = 40;

    /** sha256 over every MintCrawl plan for seeds 1–8 at the base. */
    private const CRAWL = [
        1 => 'dbc9db3d292e69f3558c6b5bc7fe1e9d5071c5da9c9a226da44694b9a3ab1edc',
        2 => 'fe808966d91ca56b7b84f72ad45362a0904ca6261f7fdcdf83436969b000535c',
        3 => 'fe808966d91ca56b7b84f72ad45362a0904ca6261f7fdcdf83436969b000535c',
        4 => '4cacb8a79e7078daa5a0122f4ba93a31839528b2fe0cfc15426b515633d9b77c',
        5 => 'db59283e3fbd6bc0246e5717cf21e40d048ff4a633d62f64f44e17b3f9a4e41a',
        6 => 'f477c59737359f2f39b45bfc43886a235945d9a6bb3f4d0699113eb6f69c3483',
        7 => '9f1171d334a2ff5b64966f6b43a48b08dec80130e22f1b62e63cc9c7fd6e22f2',
        8 => '4cacb8a79e7078daa5a0122f4ba93a31839528b2fe0cfc15426b515633d9b77c',
    ];

    /** TokenMintLoop replay_hash per "profile seed" at the base. */
    private const LOOP = [
        'fast 1' => '2929c5e084b887ccc9841c6e4473dd708466c88c51197a3c318449d6a1d642ed',
        'fast 2' => '056450772b259bf2e20491a21ba430bc8ce5e318e10e3ef22bc7e0ce8050afef',
        'slow 1' => 'a97b90fda9ffe0bf82af18769be09a9f15587029c25e1f6b3d82b48eecd171d0',
        'slow 2' => 'b224d3256c9f29e2807780f8f26835d601bc72f2a1b4a41540bdf8f90f8886f1',
        'cookie-drop 1' => '5a545652293e447267ff49695de7aa478751171179953a1e377a302bc2fc9360',
        'cookie-drop 2' => '02c9da59faa9f0fa9583a4c9e343991d195ecbcb646806701c0faa4eb7697272',
        'zero-think 1' => '8b635082d17691e3cffbc91599f9fbad7d2219237f7f4b12626c538906f5679c',
        'zero-think 2' => 'f5c869af05c0bffb8ea8b3e73275c50e816a23b542d26e60521fae11a551fc62',
    ];

    public static function crawlHash(int $seed): string
    {
        $c = new MintCrawl($seed);
        try {
            $c->run();
            $h = hash_init('sha256');
            foreach ($c->plans as [$label, $p]) {
                $headers = $p->headers();
                sort($headers);
                hash_update($h, $label . "\0" . $p->status . "\0" . json_encode($headers) . "\0" . $p->body . "\0");
            }

            return hash_final($h);
        } finally {
            $c->cleanup();
        }
    }

    public static function loopHash(string $profile, int $seed): string
    {
        $loop = new TokenMintLoop($profile, $seed);
        try {
            return (string) $loop->run(self::LOOP_STEPS)['replay_hash'];
        } finally {
            $loop->cleanup();
        }
    }

    /** Print the constants for the current tree (run on the base, then commit the output). */
    public static function record(): string
    {
        $out = "CRAWL:\n";
        foreach (array_keys(self::CRAWL) as $seed) {
            $out .= "        {$seed} => '" . self::crawlHash($seed) . "',\n";
        }
        $out .= "LOOP:\n";
        foreach (array_keys(self::LOOP) as $key) {
            [$profile, $seed] = explode(' ', $key);
            $out .= "        '{$key}' => '" . self::loopHash($profile, (int) $seed) . "',\n";
        }

        return $out;
    }

    public function test_unwired_mint_crawl_is_byte_identical(): void
    {
        foreach (self::CRAWL as $seed => $want) {
            self::assertSame($want, self::crawlHash($seed), "MintCrawl seed {$seed} differs from the base " . self::BASE);
        }
    }

    public function test_unwired_token_mint_loop_is_byte_identical(): void
    {
        foreach (self::LOOP as $key => $want) {
            [$profile, $seed] = explode(' ', $key);
            self::assertSame($want, self::loopHash($profile, (int) $seed), "TokenMintLoop {$key} differs from the base " . self::BASE);
        }
    }

    /**
     * A PAT minted with webhooks:write while the extension was wired keeps working on the account's own
     * pages and API once the extension is switched off; SSRF paths then answer as today.
     */
    public function test_flipping_the_flag_after_a_mint_faults_no_page(): void
    {
        $wired = new MintHarness(true, ['ssrf' => []]);
        try {
            $wired->join();
            $pat = $wired->mint(['read:user', 'webhooks:write']);
            $form = $wired->get('/settings/webhooks/new');
            $r = $wired->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/']);
            self::assertSame(303, $r['status']);
            $plain = new MintHarness(true, ['storePath' => $wired->dir . '/token-mint.sqlite']);
            $plain->now = $wired->now;
            $plain->jars = $wired->jars;
            $checked = 0;
            foreach (MintCorpus::ownedPaths(MintCorpus::slug()) as $p) {
                foreach ([[], ['Authorization' => 'Bearer ' . $pat]] as $headers) {
                    $res = $plain->get($p, '', 'default', MintHarness::IP, $headers);
                    if ($res['plan'] !== null) {
                        MintHarness::assertClosed($res['plan'], MintCorpus::slug(), $p);
                        $checked++;
                    }
                }
            }
            self::assertGreaterThan(40, $checked);
            self::assertSame(0, $plain->decoy->faults());
            self::assertSame([], $plain->warnings);
            self::assertStringContainsString('webhooks:write', $plain->get('/settings/tokens')['body'], 'the stored scope still lists');
            self::assertSame(200, $plain->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $pat])['status']);
            $ssrf = $plain->get('/settings/webhooks');
            self::assertNull($ssrf['plan'], 'SSRF paths answer as today once unwired');
            self::assertStringContainsString('404 Not Found', $ssrf['body']);
            $plain->cleanup();
        } finally {
            $wired->cleanup();
        }
    }
}
