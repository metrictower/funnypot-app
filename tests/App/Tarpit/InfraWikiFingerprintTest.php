<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\InfraWiki;
use Funnypot\App\Tarpit\InfraWikiRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0808 SF3 — the dedicated fingerprint sweep for the infra-wiki tarpit. This is a real served surface
 * (its own InfraDocController, which ServedSurfacesFingerprintTest explicitly excludes, like the labyrinth/
 * polluter), so it gets its OWN gate over the FULL RENDERED PROSE — not just the InertSecret-cleaned token
 * fields. The plan-review fold (SF3) requires: scan the whole top doc AND a sample of the on-demand
 * runbook/migration/backup sub-docs, across MANY seeds, for (a) the app fingerprint denylist (leak-IN
 * literals/patterns AND leak-OUT own_vocabulary) and (b) any honeypot-tell word. The prose is authored
 * human-ops English and the only interpolated values are cleaned tokens / vetted catalog facts, so a
 * regression in either is caught here.
 */
final class InfraWikiFingerprintTest extends TestCase
{
    /** @return array{literals:list<string>,patterns:list<string>,own_vocabulary:list<string>} */
    private static function denylist(): array
    {
        $d = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';

        return [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
            'own_vocabulary' => array_values((array) ($d['own_vocabulary'] ?? [])),
        ];
    }

    /** The first denylist hit in $t (leak-IN + leak-OUT), or null when clean. */
    private static function fingerprintHit(string $t): ?string
    {
        $d = self::denylist();
        foreach ($d['literals'] as $n) {
            if ($n !== '' && stripos($t, (string) $n) !== false) {
                return 'lit:' . $n;
            }
        }
        foreach ($d['patterns'] as $p) {
            if (@preg_match('~' . $p . '~i', $t) === 1) {
                return 'pat:' . $p;
            }
        }
        $ov = $d['own_vocabulary'];
        if ($ov !== [] && preg_match('/(?<![a-zA-Z0-9])(' . implode('|', $ov) . ')(?![a-zA-Z0-9])/i', $t, $m) === 1) {
            return 'own_vocabulary:' . strtolower($m[0]);
        }

        return null;
    }

    /**
     * The full rendered corpus for one deploy: the top doc + a sample of runbook docs (across categories)
     * + the migration docs + the backup catalog + an unresolved sub-doc. This is the exact prose an agent
     * can read, token fields and authored sentences alike.
     */
    private static function corpus(int $seed): string
    {
        $wiki = new InfraWiki($seed);
        $r = new InfraWikiRenderer($wiki, ['/admin/export/settings.py', '/admin/export/app.log', '/admin/audit-archive']);
        $out = $r->topDoc();
        $out .= $r->backupCatalogDoc();
        $out .= $r->notFoundDoc('archived-example-id');
        // A spread of runbooks across the fleet (every 11th service), so the sweep covers many categories.
        $svc = $wiki->services();
        for ($i = 0; $i < count($svc); $i += 11) {
            $out .= $r->runbookDoc($svc[$i]);
        }
        foreach ($wiki->migratingPairs() as $pair) {
            $out .= $r->migrationDoc($pair['from'], $pair['to']);
        }

        return $out;
    }

    /**
     * @dataProvider seeds
     */
    public function test_full_rendered_prose_trips_no_fingerprint_signature(int $seed): void
    {
        $corpus = self::corpus($seed);
        self::assertNotSame('', $corpus);
        self::assertNull(self::fingerprintHit($corpus), "fingerprint signature in the infra-wiki corpus (seed {$seed})");
    }

    /**
     * @dataProvider seeds
     */
    public function test_no_honeypot_tell_word_anywhere_agent_visible(int $seed): void
    {
        // Scan the VISIBLE prose: strip the LLM-only base64 `<code>` blobs and HTML comments first (an
        // encoded path can coincidentally spell a tell inside its base64 run — that is not agent-visible
        // wording), then match each tell on a WORD BOUNDARY so a tell inside a seeded slug/host run (an
        // alnum sequence) is not a false positive. Authored prose using any tell would still be caught.
        $visible = (string) preg_replace('~<code>[^<]*</code>~', ' ', self::corpus($seed));
        $visible = (string) preg_replace('~<!--.*?-->~s', ' ', $visible);
        foreach (['honeypot', 'decoy', 'tarpit', 'trap', 'lure', 'bait', 'fake', 'funnypot', 'metrictower'] as $tell) {
            self::assertSame(
                0,
                preg_match('/(?<![a-z0-9])' . preg_quote($tell, '/') . '(?![a-z0-9])/i', $visible),
                "tell word '{$tell}' leaked in the visible prose at seed {$seed}"
            );
        }
    }

    public function test_no_real_third_party_endpoint_in_the_corpus(): void
    {
        $corpus = self::corpus(4242) . self::corpus(7);
        foreach (['amazonaws.com', 'arn:aws:', 'sk_live_', 'googleapis.com', '.stripe.com', 'windows.net',
            'herokuapp.com', 'firebaseio.com', 'onmicrosoft.com', ] as $needle) {
            self::assertStringNotContainsString($needle, $corpus, "real third-party token '{$needle}' in the corpus");
        }
    }

    /** @return array<string,array{0:int}> a broad seed sweep (prose + sub-docs), not just one seed. */
    public static function seeds(): array
    {
        $seeds = [4242, 99991, 957659, 992929, 935109, 1, 123456789];
        for ($s = 1; $s <= 24; $s++) {
            $seeds[] = $s;
        }
        $out = [];
        foreach (array_values(array_unique($seeds)) as $s) {
            $out['seed ' . $s] = [$s];
        }

        return $out;
    }
}
