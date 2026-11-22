<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use PHPUnit\Framework\TestCase;

/**
 * No body the SSRF surface renders satisfies a core nuclei template's whole body-word list, so a scanner
 * that fingerprints by those templates cannot recognise the fake network's answers as a known product.
 * A list of short generic words (`select`, `code` + `data`) is matched by any form or JSON and says
 * nothing about a product. A word is distinctive at ten or more characters, or six or more with a
 * structural character (`_ " : < = { /`); a list counts when it has two distinctive words, or one of 14
 * or more characters (`go_goroutines` + `kube-state-metrics` counts; `"code":` alone does not).
 */
final class SsrfNucleiMatcherTest extends TestCase
{
    /** @return list<list<string>> every compiled body-word list */
    private static function wordLists(): array
    {
        $index = require dirname(__DIR__, 4) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $out = [];
        foreach ($index['routes'] as $entry) {
            foreach ((array) ($entry['b'] ?? []) as $b) {
                $words = array_values(array_map('strval', (array) ($b['bw'] ?? [])));
                $distinctive = array_filter($words, static fn (string $w): bool => strlen($w) >= 10 || (strlen($w) >= 6 && strpbrk($w, '_":<={/') !== false));
                if (count($distinctive) >= 2 || array_filter($distinctive, static fn (string $w): bool => strlen($w) >= 14) !== []) {
                    $out[implode("\0", $words)] = $words;
                }
            }
        }

        return array_values($out);
    }

    /** @param list<list<string>> $lists */
    private static function satisfied(string $body, array $lists): ?string
    {
        foreach ($lists as $words) {
            $all = true;
            foreach ($words as $w) {
                if ($w === '' || !str_contains($body, $w)) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                return implode(' + ', $words);
            }
        }

        return null;
    }

    public function test_no_core_nuclei_template_matches_an_ssrf_body(): void
    {
        $lists = self::wordLists();
        self::assertGreaterThan(1000, count($lists));
        self::assertNotNull(self::satisfied("# HELP go_goroutines Number of goroutines.\nkube-state-metrics up", array_merge($lists, [['go_goroutines', 'kube-state-metrics']])), 'positive control: a planted Go metrics body');
        $checked = 0;
        foreach (range(1, 8) as $seed) {
            $kinds = [];
            foreach (SsrfTour::networkCorpus($seed) as [$kind, $label, $body]) {
                self::assertNull(self::satisfied($body, $lists), "seed {$seed} network answer {$label} satisfies a nuclei template");
                $kinds[$kind] = ($kinds[$kind] ?? 0) + 1;
                $checked++;
            }
            SsrfTour::assertEveryKind($kinds, "seed {$seed} network corpus");
            $tour = (new SsrfTour($seed))->run();
            try {
                SsrfTour::assertEveryKind($tour->kinds, "seed {$seed} tour");
                foreach ($tour->plans as [$label, $plan]) {
                    $texts = [$plan->body, html_entity_decode($plan->body, ENT_QUOTES)];
                    $j = json_decode($plan->body, true);
                    if (is_array($j) && is_string($j['response']['body'] ?? null)) {
                        $texts[] = $j['response']['body'];
                    }
                    foreach ($texts as $t) {
                        self::assertNull(self::satisfied($t, $lists), "seed {$seed} {$label} satisfies a nuclei template");
                        $checked++;
                    }
                }
            } finally {
                $tour->cleanup();
            }
        }
        self::assertGreaterThan(2000, $checked);
        foreach (SsrfTour::networkCorpus(1) as [$kind, , $body]) {
            if ($kind === 'metrics') {
                $planted = $body . "\ngo_goroutines 12\n# kube-state-metrics\n";
                self::assertNotNull(self::satisfied($planted, array_merge($lists, [['go_goroutines', 'kube-state-metrics']])), 'positive control: planted in a metrics answer, the scan flags it');
                break;
            }
        }
    }
}
