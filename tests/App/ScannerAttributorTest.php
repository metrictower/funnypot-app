<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\Attribution;
use Funnypot\App\ThreatIntel\ScannerAttributor;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * Scanner attribution: name the tool behind a probe from the fixed canary tokens it emits, advisory
 * only. High-precision — a known tell attributes, an ambiguous/benign request does not (a false tool
 * label is worse than none). Matching is bounded: literal needles, an anchored version extractor, and a
 * linear fixed-slice tplmap fence scan.
 */
final class ScannerAttributorTest extends TestCase
{
    private ScannerAttributor $a;

    protected function setUp(): void
    {
        $this->a = new ScannerAttributor();
    }

    // --- A. Known tool → correct label, from GET query AND POST body alike (MF2) -------------------

    /** @dataProvider injectedTokens */
    public function test_injected_token_attributes_from_get_query(string $token, string $tool): void
    {
        $ctx = new RequestContext('GET', '/x', 'param=' . $token);
        $attr = $this->a->attribute($ctx);
        self::assertNotNull($attr, "expected {$tool} from GET query");
        self::assertSame($tool, $attr->tool);
    }

    /** @dataProvider injectedTokens */
    public function test_injected_token_attributes_from_post_body(string $token, string $tool): void
    {
        $ctx = new RequestContext('POST', '/x', '', [], 'param=' . $token);
        $attr = $this->a->attribute($ctx);
        self::assertNotNull($attr, "expected {$tool} from POST body");
        self::assertSame($tool, $attr->tool);
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function injectedTokens(): array
    {
        return [
            'dalfox sentinel' => ['dlfx_sentinel_q_8a3f', 'dalfox'],
            'ghauri marker' => ['r0oth3x49', 'ghauri'],
            'xsstrike canary' => ['v3dm0s', 'xsstrike'],
            'tplmap fences' => ['{{1234567890}}payload{{0987654321}}', 'tplmap'],
        ];
    }

    public function test_encoded_injected_token_still_attributes(): void
    {
        // A double-encoded dalfox sentinel must still resolve on the decoded param surface.
        $ctx = new RequestContext('GET', '/x', 'q=%2564%256c%2566%2578_sentinel_q_8a3f');
        $attr = $this->a->attribute($ctx);
        self::assertNotNull($attr);
        self::assertSame('dalfox', $attr->tool);
    }

    public function test_crlfuzz_token_in_request_target_attributes(): void
    {
        // CRLFuzz injects the token into the request target via CRLF; it lives on the decoded path.
        $viaPath = new RequestContext('GET', '/x%0d%0aX-Injected-Header-By%3A%20crlfuzz', '');
        self::assertSame('crlfuzz', $this->a->attribute($viaPath)?->tool);

        $viaQuery = new RequestContext('GET', '/x', 'a=%0d%0aX-Injected-Header-By%3A%20crlfuzz');
        self::assertSame('crlfuzz', $this->a->attribute($viaQuery)?->tool);
    }

    public function test_crlfuzz_as_a_discrete_header_does_not_attribute(): void
    {
        // MF1: a legitimate inbound header by that name is NOT the crlfuzz tell (it is a URL/target
        // token). PHP would never surface the injected header as a real header, so this must be null.
        $ctx = new RequestContext('GET', '/x', '', ['X-Injected-Header-By' => 'CRLFuzz']);
        self::assertNull($this->a->attribute($ctx));
    }

    public function test_jaeles_probe_path_attributes(): void
    {
        self::assertSame('jaeles', $this->a->attribute(new RequestContext('GET', '/hopefully404.lock', ''))?->tool);
    }

    public function test_nessus_header_presence_attributes(): void
    {
        $ctx = new RequestContext('GET', '/x', '', ['X-Nessus-Scan' => 'anything']);
        self::assertSame('nessus', $this->a->attribute($ctx)?->tool);
    }

    public function test_ua_needle_attributes_and_captures_version_without_polluting_the_tool_name(): void
    {
        $ctx = new RequestContext('GET', '/x', '', ['User-Agent' => 'sqlmap/1.8.3#stable (https://sqlmap.org)']);
        $attr = $this->a->attribute($ctx);
        self::assertNotNull($attr);
        // The bounded name is the only thing that would ever be persisted; the version is DTO-only.
        self::assertSame('sqlmap', $attr->tool);
        self::assertSame('medium', $attr->confidence);
        self::assertSame('1.8.3', $attr->version);
    }

    // --- B. Ambiguous / unknown probe → NO attribution (false attribution is the worst outcome) ----

    /** @dataProvider unattributable */
    public function test_no_attribution_for_ambiguous_or_benign(string $label, RequestContext $ctx): void
    {
        self::assertNull($this->a->attribute($ctx), $label);
    }

    /** @return array<string,array{0:string,1:RequestContext}> */
    public static function unattributable(): array
    {
        return [
            'benign search' => ['benign', new RequestContext('GET', '/search', 'q=quarterly report 2026')],
            'burp calibration path' => ['burp', new RequestContext('GET', '/e3a1b7c9d/', '')],
            'nikto calibration path' => ['nikto-cal', new RequestContext('GET', '/xxxx_test_404_xxxx', '')],
            'bare CORS origin' => ['origin', new RequestContext('GET', '/api', '', ['Origin' => 'https://example.com'])],
            'lfi is an attack class not a tool' => ['lfi', new RequestContext('GET', '/index.php', 'file=../../../../etc/passwd', ['User-Agent' => 'curl/8.0'])],
        ];
    }

    // --- E. Pack shape: flat rows, closed vocab, not a served/compiled artifact --------------------

    public function test_pack_is_not_a_compiled_served_artifact(): void
    {
        $root = dirname(__DIR__, 2);
        self::assertFileExists($root . '/resources/scanner-fingerprints.php');
        self::assertFileDoesNotExist($root . '/resources/compiled/scanner-fingerprints.php');
    }

    public function test_pack_rows_use_only_allowed_keys_and_closed_vocab(): void
    {
        /** @var list<array<string,mixed>> $pack */
        $pack = require dirname(__DIR__, 2) . '/resources/scanner-fingerprints.php';
        $allowed = ['surface', 'needle', 'matcher', 'header', 'tool', 'confidence', 'version'];
        foreach ($pack as $i => $row) {
            self::assertIsArray($row, "row {$i}");
            foreach (array_keys($row) as $k) {
                self::assertContains($k, $allowed, "row {$i} has unexpected key {$k}");
            }
            self::assertContains($row['confidence'], ['high', 'medium'], "row {$i} confidence");
            self::assertSame(1, preg_match('~\A[a-z0-9][a-z0-9-]{0,31}\z~', (string) $row['tool']), "row {$i} tool vocab");
        }
        // The constructor's validator accepts the shipped pack unchanged.
        self::assertNotEmpty((new ScannerAttributor($pack))->toolLabels());
    }

    // --- F. ReDoS budget: schema lint + bounded matchers ------------------------------------------

    /** @dataProvider malformedPacks */
    public function test_validator_rejects_unsafe_or_malformed_rows(string $label, array $row): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ScannerAttributor([$row]);
    }

    /** @return array<string,array{0:string,1:array<string,mixed>}> */
    public static function malformedPacks(): array
    {
        return [
            'bad surface' => ['surface', ['surface' => 'cookie', 'needle' => 'x', 'tool' => 'x', 'confidence' => 'high']],
            'bad confidence' => ['confidence', ['surface' => 'ua', 'needle' => 'x', 'tool' => 'x', 'confidence' => 'certain']],
            'tool not closed vocab' => ['tool', ['surface' => 'ua', 'needle' => 'x', 'tool' => 'Bad_Tool!', 'confidence' => 'high']],
            'needle and matcher both' => ['both', ['surface' => 'params', 'needle' => 'x', 'matcher' => ['kind' => 'fence_pair', 'max_gap' => 8, 'max_starts' => 8], 'tool' => 'x', 'confidence' => 'high']],
            'neither needle nor matcher' => ['neither', ['surface' => 'ua', 'tool' => 'x', 'confidence' => 'high']],
            'empty needle non-header' => ['empty-needle', ['surface' => 'ua', 'needle' => '', 'tool' => 'x', 'confidence' => 'high']],
            'header surface without header name' => ['no-header', ['surface' => 'header', 'needle' => '', 'tool' => 'x', 'confidence' => 'high']],
            'unknown matcher kind' => ['matcher-kind', ['surface' => 'params', 'matcher' => ['kind' => 'regex', 'max_gap' => 8, 'max_starts' => 8], 'tool' => 'x', 'confidence' => 'high']],
            'gap over 256' => ['gap', ['surface' => 'params', 'matcher' => ['kind' => 'fence_pair', 'max_gap' => 257, 'max_starts' => 8], 'tool' => 'x', 'confidence' => 'high']],
            'unanchored version regex' => ['unanchored', ['surface' => 'ua', 'needle' => 'x', 'tool' => 'x', 'confidence' => 'medium', 'version' => ['re' => '~x/(\d+)~', 'group' => 1]]],
            'unbounded version quantifier' => ['unbounded', ['surface' => 'ua', 'needle' => 'x', 'tool' => 'x', 'confidence' => 'medium', 'version' => ['re' => '~\Ax/(\d+).*\z~', 'group' => 1]]],
            'open-ended version quantifier' => ['open-ended', ['surface' => 'ua', 'needle' => 'x', 'tool' => 'x', 'confidence' => 'medium', 'version' => ['re' => '~\Ax/(\d{1,3}).{5,}\z~', 'group' => 1]]],
        ];
    }

    public function test_fence_matcher_honours_the_gap_ceiling_and_the_start_cap(): void
    {
        $first = '{{1234567890}}';
        $second = '{{0987654321}}';

        // A second fence exactly at the gap ceiling matches; one byte beyond does not.
        $ok = ScannerAttributor::fencePair($first . str_repeat('a', 256) . $second, 256, 128);
        self::assertTrue($ok['matched'], 'gap of exactly 256 must match');
        $tooFar = ScannerAttributor::fencePair($first . str_repeat('a', 257) . $second, 256, 128);
        self::assertFalse($tooFar['matched'], 'gap of 257 must not match');

        // A valid first fence with no second fence never matches.
        self::assertFalse(ScannerAttributor::fencePair($first . str_repeat('a', 10), 256, 128)['matched']);

        // An adversarial all-brace surface is bounded: it bails at the start cap, never scanning it all.
        $adversarial = ScannerAttributor::fencePair(str_repeat('{', 50000), 256, 128);
        self::assertFalse($adversarial['matched']);
        self::assertLessThanOrEqual(128, $adversarial['starts'], 'candidate inspection stays under the cap');

        // Off-by-one fence widths (13/15 digits) are never valid fences.
        self::assertFalse(ScannerAttributor::fencePair('{{123456789}}x{{123456789}}', 256, 128)['matched']);
        self::assertFalse(ScannerAttributor::fencePair('{{12345678901}}x{{12345678901}}', 256, 128)['matched']);
    }

    public function test_version_extractor_stays_bounded_on_an_overlong_suffix(): void
    {
        // The UA needle still attributes, but the anchored+bounded version regex fails on a long suffix,
        // so the tool stays name-only and the version is null.
        $ctx = new RequestContext('GET', '/x', '', ['User-Agent' => 'sqlmap/1.8.3' . str_repeat('x', 400)]);
        $attr = $this->a->attribute($ctx);
        self::assertNotNull($attr);
        self::assertSame('sqlmap', $attr->tool);
        self::assertNull($attr->version);
    }

    public function test_returns_an_attribution_value_object(): void
    {
        $attr = $this->a->attribute(new RequestContext('GET', '/hopefully404.lock', ''));
        self::assertInstanceOf(Attribution::class, $attr);
        self::assertSame('high', $attr->confidence);
        self::assertNull($attr->version);
    }
}
