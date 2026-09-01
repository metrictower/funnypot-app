<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\SleepProbe;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0228 — the structure-only SLEEP reader. It pulls the requested seconds out of a time-based
 * blind-injection payload (or returns null for baseline traffic), reading the SAME decoded surface the
 * AttackClassifier matches on, and NEVER echoes the payload — the return is an int or null only.
 */
final class SleepProbeTest extends TestCase
{
    private static function ctx(string $query = '', ?string $body = null, string $path = '/products.php'): RequestContext
    {
        return new RequestContext('GET', $path, $query, [], $body);
    }

    /** @dataProvider sleepStructures */
    public function test_extracts_the_requested_seconds(string $query, ?string $body, ?int $expected): void
    {
        self::assertSame($expected, SleepProbe::requestedSeconds(self::ctx($query, $body)));
    }

    /** @return array<string,array{0:string,1:?string,2:?int}> */
    public static function sleepStructures(): array
    {
        return [
            'sql sleep(2)'             => ['id=1 AND SLEEP(2)', null, 2],
            'sql sleep(0) is zero'     => ['id=1 AND SLEEP(0)', null, 0],
            'sql sleep spaced'         => ['id=1 AND SLEEP ( 5 )', null, 5],
            'pg_sleep(3)'              => ['id=1;SELECT PG_SLEEP(3)', null, 3],
            'waitfor delay 0:0:7'      => ["id=1;WAITFOR DELAY '0:0:7'", null, 7],
            'oracle dbms_pipe'         => ["id=1||dbms_pipe.receive_message('a',10)", null, 10],
            'benchmark -> nominal 1'   => ['id=1 AND BENCHMARK(5000000,MD5(1))', null, 1],
            'cmdi ;sleep 4'            => ['q=x;sleep 4', null, 4],
            'cmdi | sleep 6'           => ['q=x| sleep 6', null, 6],
            'cmdi && sleep 8'          => ['q=x&&sleep 8', null, 8],
            'cmdi $(sleep 3)'          => ['q=$(sleep 3)', null, 3],
            'cmdi backtick sleep 5'    => ['q=`sleep 5`', null, 5],
            'in the body'              => ['', 'user=admin&p=1 OR SLEEP(2)', 2],
            'benign query'             => ['id=42&name=bob', null, null],
            'no sleep at all'          => ['q=hello world', null, null],
            'the word sleep alone'     => ['q=i need sleep tonight', null, null],
        ];
    }

    /** URL-encoded payloads are read the same way the classifier decodes them (single + double pass). */
    public function test_reads_url_encoded_payloads(): void
    {
        // sleep%282%29 -> sleep(2)
        self::assertSame(2, SleepProbe::requestedSeconds(self::ctx('id=1%20AND%20SLEEP%282%29')));
        // double-encoded: %2531 -> %31 -> 1 ... test a double-encoded paren/digit survives the 2nd pass.
        self::assertSame(9, SleepProbe::requestedSeconds(self::ctx('id=1%20AND%20SLEEP%25289%2529')));
    }

    /** A wild value is clamped to a sane ceiling BEFORE the caller's per-request cap — no overflow. */
    public function test_parsed_seconds_are_clamped_to_a_ceiling(): void
    {
        $n = SleepProbe::requestedSeconds(self::ctx('id=1 AND SLEEP(999999999)'));
        self::assertNotNull($n);
        self::assertLessThanOrEqual(300, $n, 'a huge SLEEP is clamped so seconds*1000 cannot overflow');
        self::assertGreaterThan(0, $n);
    }

    /** Structure-only: the return is always an int or null, never any slice of the payload text. */
    public function test_return_is_only_an_int_or_null(): void
    {
        $out = SleepProbe::requestedSeconds(self::ctx("id=1 AND SLEEP(2)-- injected'nasty<script>"));
        self::assertIsInt($out);
    }
}
