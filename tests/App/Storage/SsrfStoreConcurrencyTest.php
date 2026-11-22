<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\SsrfKeyIndex;
use Funnypot\App\Storage\SsrfStore;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use PHPUnit\Framework\TestCase;

/** Two worker processes on one store file: no lost write, and a consistent key index. */
final class SsrfStoreConcurrencyTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp0816conc_' . bin2hex(random_bytes(5));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
    }

    /** @return list<array{ok:int,failed:int}> */
    private function children(string $mode, string $db, int $n): array
    {
        $script = __DIR__ . '/support/ssrf-child.php';
        $procs = [];
        for ($i = 0; $i < 2; $i++) {
            $procs[] = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', $script, $mode, $db, (string) $n], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $out[$i] = $pipes;
        }
        $res = [];
        foreach ($procs as $i => $p) {
            $line = stream_get_contents($out[$i][1]);
            $err = stream_get_contents($out[$i][2]);
            proc_close($p);
            $decoded = json_decode(trim((string) $line), true);
            self::assertIsArray($decoded, 'child output: ' . $line . $err);
            $res[] = $decoded;
        }

        return $res;
    }

    public function test_two_processes_never_lose_a_write(): void
    {
        $db = $this->dir . '/ssrf.sqlite';
        (new SsrfStore($db))->ready();
        $res = $this->children('store', $db, 150);
        $ok = $res[0]['ok'] + $res[1]['ok'];
        $count = (new SsrfStore($db))->load('shared-owner')?->d['hn'];
        self::assertSame($ok, $count, 'every committed transaction is in the row; a busy one changed nothing');
        self::assertGreaterThan(150, $ok, 'most transactions commit under contention');
    }

    public function test_concurrent_index_slices(): void
    {
        $db = $this->dir . '/idx.sqlite';
        $res = $this->children('index', $db, 200);
        $builder = new KeyIndexBuilder(4242, 'fs', 1 << 20);
        $idx = new SsrfKeyIndex($db, 'idx-key', $builder, SsrfKeyIndex::deployId('idx-key', 4242, 1 << 20, false, 'b'));
        self::assertTrue($idx->complete());
        self::assertSame($builder->slices(), $res[0]['ok'] + $res[1]['ok'], 'each slice ran exactly once between the two');
        $stats = $idx->stats();
        $expected = [];
        for ($s = 0; $s < $builder->slices(); $s++) {
            foreach ($builder->slice($s) as [$kind, $value]) {
                $expected[$idx->hashOf($kind, $value)] = true;
            }
        }
        self::assertSame(count($expected), $stats['rows'], 'every expected fact present once');
        $f = (new ConfigDump(4242))->sectionFacts($builder->sections() - 1);
        self::assertTrue($idx->contains('stripe', $f['stripeKey']));
        self::assertSame((string) $builder->slices(), $stats['next'], 'next slice is monotonic and ends at the last');
    }
}
