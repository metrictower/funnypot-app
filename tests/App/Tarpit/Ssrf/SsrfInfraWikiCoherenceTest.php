<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\Tests\App\Http\SsrfFrontControllerTest;
use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Second-lander rule (FP-0808 x FP-0816): whichever of the infra wiki and the SSRF decoy reaches main
 * second passes the wiki's hosts to SsrfDecoy::build() in demo/index.php
 * (`[InfraWikiHosts::fromServices((new InfraWiki($personaSeed))->services())]` as its extra hosts) and
 * removes this skip.
 *
 * The test drives the real composition root through the front-controller fixture and asks the SSRF
 * network it built what a live wiki host resolves to. Without the composition line the host is unknown
 * and the test fails; the positive control is an unknown name in the same zone, which never resolves.
 */
final class SsrfInfraWikiCoherenceTest extends TestCase
{
    public function test_wiki_hosts_resolve_through_the_composition_root(): void
    {
        if (!class_exists('Funnypot\\App\\Tarpit\\InfraWiki')) {
            self::markTestSkipped('FP-0808 (InfraWiki) is not on this branch; the second lander wires InfraWikiHosts into SsrfDecoy::build() and removes this skip');
        }
        $dir = sys_get_temp_dir() . '/fp-ssrf-wiki-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $dir = (string) realpath($dir);
        try {
            PreparedIdentityFixture::prepare($dir, 'ssrf-wiki')['result']->close();
            $r = SsrfFrontControllerTest::runFixture($dir, [], '/settings/webhooks');
            self::assertTrue($r['ssrf'], $r['err']);
            self::assertIsArray($r['wiki'], 'the fixture found a live wiki service');
            self::assertSame('wk:' . $r['wiki']['host'], $r['wiki']['node'], 'the composition root wires the wiki hosts into the fake network');
            self::assertNull($r['wiki']['unknown'], 'positive control: an unknown name in the same zone does not resolve');
        } finally {
            MintHarness::removeTree($dir);
        }
    }
}
