<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Second-lander rule (FP-0808 x FP-0816): whichever of the infra wiki and the SSRF decoy reaches main
 * second adds the composition-root line `InfraWikiHosts::fromServices($infraWiki->services())` to
 * SsrfDecoy::build() in demo/index.php and removes this skip. The test then fails without that line: a
 * live wiki host resolves (its ping is pending, then answers) while an unknown name in the same zone fails
 * at once.
 */
final class SsrfInfraWikiCoherenceTest extends TestCase
{
    public function test_wiki_hosts_resolve_on_the_fake_network(): void
    {
        if (!class_exists('Funnypot\\App\\Tarpit\\InfraWiki')) {
            self::markTestSkipped('FP-0808 (InfraWiki) is not on this branch; the second lander wires InfraWikiHosts and removes this skip');
        }
        $index = (string) file_get_contents(dirname(__DIR__, 4) . '/demo/index.php');
        self::assertStringContainsString('InfraWikiHosts::fromServices(', $index, 'the composition root wires the wiki hosts');
        $wiki = new \Funnypot\App\Tarpit\InfraWiki(\Funnypot\Tests\App\Identity\IdentityTestSupport::httpIdentity()->personaSeed());
        $live = null;
        foreach ($wiki->services() as $s) {
            if (($s['status'] ?? '') !== 'archived') {
                $live = $s;
                break;
            }
        }
        self::assertNotNull($live);
        $h = new MintHarness(true, ['ssrf' => ['extraHosts' => [\Funnypot\App\Tarpit\Ssrf\InfraWikiHosts::fromServices($wiki->services())]]]);
        try {
            $h->join();
            foreach ([['http://' . $live['host'] . ':' . $live['port'] . '/', 'Pending'], ['http://zzunknown0.' . substr((string) $live['host'], (int) strpos((string) $live['host'], '.') + 1) . '/', 'Could not resolve host']] as [$url, $want]) {
                $form = $h->get('/settings/webhooks/new');
                $loc = (string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => $url])['plan']?->header('Location');
                $show = $h->get($loc);
                preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
                $h->post($loc . '/pings', ['csrf_token' => $m[1][0]]);
                self::assertStringContainsString($want, html_entity_decode($h->get($loc)['body']) . html_entity_decode($h->get($loc . '/deliveries/' . (preg_match("~/deliveries/([a-f0-9]{12})'~", $h->get($loc)['body'], $d) ? $d[1] : 'x'))['body']), $url);
            }
        } finally {
            $h->cleanup();
        }
    }
}
