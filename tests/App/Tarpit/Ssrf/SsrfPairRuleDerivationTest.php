<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Ssrf\SsrfIds;
use Funnypot\App\Tarpit\Ssrf\SsrfKeys;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\CoreWords;
use PHPUnit\Framework\TestCase;

/**
 * The pair rule SsrfIds probes for, re-derived from the installed engine: one of core's rules reads the
 * end of the path (an id ending in certain hex) together with the end of the last form field (a URL
 * ending in certain words). A core change that adds a word family or an id ending fails here.
 */
final class SsrfPairRuleDerivationTest extends TestCase
{
    private const FLAGGED_ID = '4b7e19a2c3df';
    private const NEUTRAL_ID = '4b7e19a2c0a1';

    private static function probe(string $id, string $tail): RequestContext
    {
        return new RequestContext('POST', '/settings/webhooks/' . $id, '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode('http://10.41.7.19:8080/x' . $tail));
    }

    public function test_pair_words_cover_the_engine(): void
    {
        $words = array_values(array_filter(CoreWords::all(), static fn (string $w): bool => preg_match('/\A[a-z]{3,12}\z/', $w) === 1));
        self::assertGreaterThan(8000, count($words), 'the engine vocabulary was read');
        $paired = [];
        foreach ($words as $w) {
            if (SsrfCorpus::flags(self::probe(self::FLAGGED_ID, $w)) && !SsrfCorpus::flags(self::probe(self::NEUTRAL_ID, $w))) {
                $paired[] = $w;
            }
        }
        fwrite(STDERR, "\npair-rule words over " . count($words) . ' candidates: ' . count($paired) . "\n");
        self::assertNotEmpty($paired, 'the rule still exists');
        foreach ($paired as $w) {
            $covered = array_filter(SsrfIds::PAIR_WORDS, static fn (string $p): bool => str_ends_with($w, $p));
            self::assertNotEmpty($covered, "{$w} pairs with the id ending but no PAIR_WORDS family covers it");
        }
    }

    /**
     * issue() runs the plain checks (field probes on every path, and the id as a path segment of every
     * route) as well as the pair probes, so a candidate either flags is re-rolled.
     */
    public function test_issue_rerolls_a_candidate_its_plain_probes_flag(): void
    {
        $ids = new SsrfIds(new SsrfKeys(str_repeat('k', 32)));
        [$routes, $pairs] = SsrfIds::hookRoutes();
        $label = 'hook|owner|1';
        for ($v = 0; ($first = $ids->candidate($label, $v)) === null; $v++) {
        }
        $quiet = new IssuedValue(static fn (RequestContext $r): bool => false);
        self::assertSame($first, $ids->issue($quiet, $label, $routes, $pairs), 'control: nothing flags, the first candidate is issued');
        $stubs = [
            'a field probe on the catch-all' => static fn (RequestContext $r): bool => $r->path === IssuedValue::CATCH_ALL && str_contains((string) $r->rawBody, $first),
            'a field probe on a listed path' => static fn (RequestContext $r): bool => $r->path === '/settings/webhooks/x/redeliveries' && str_contains((string) $r->rawBody, $first),
            'the id as a path segment' => static fn (RequestContext $r): bool => $r->path === '/settings/webhooks/' . $first . '/delete' && $r->rawBody === 'csrf_token=x',
        ];
        foreach ($stubs as $what => $flags) {
            $id = $ids->issue(new IssuedValue($flags), $label, $routes, $pairs, ['/settings/webhooks/x/redeliveries']);
            self::assertNotSame($first, $id, "{$what} re-rolls the candidate");
            self::assertFalse(($flags)(IssuedValue::pathProbe($id, 'POST /settings/webhooks/{v}/delete')));
        }
    }

    public function test_pair_id_endings_are_refused(): void
    {
        $bad = [];
        foreach ([2, 3] as $len) {
            for ($n = 0; $n < 16 ** $len; $n++) {
                $end = str_pad(dechex($n), $len, '0', STR_PAD_LEFT);
                $id = substr(self::NEUTRAL_ID, 0, 12 - $len) . $end;
                if (SsrfCorpus::flags(self::probe($id, 'uptime'))) {
                    $bad[$end] = $id;
                }
            }
        }
        fwrite(STDERR, 'bad id endings: ' . implode(', ', array_keys($bad)) . "\n");
        self::assertNotEmpty($bad);
        $iv = SsrfCorpus::issued();
        [$routes, $pairs] = SsrfIds::hookRoutes();
        foreach ($bad as $end => $id) {
            self::assertFalse(SsrfIds::fit($iv, $id, $routes, $pairs), "an id ending {$end} is refused");
        }
        self::assertTrue(SsrfIds::fit($iv, self::NEUTRAL_ID, $routes, $pairs), 'the neutral id is accepted');
    }
}
