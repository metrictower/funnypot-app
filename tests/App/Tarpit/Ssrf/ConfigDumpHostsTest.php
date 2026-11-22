<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\Ssrf\Network;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use PHPUnit\Framework\TestCase;

final class ConfigDumpHostsTest extends TestCase
{
    private const SEED = 4242;

    /** Index every section the cap can serve, as the key index does. */
    private static function indexed(int $cap, bool $complete = true): array
    {
        $w = SsrfCorpus::network(self::SEED, $complete, true, $cap);
        $dump = new ConfigDump(self::SEED);
        for ($k = 0; $k < Network::sections($cap); $k++) {
            $f = $dump->sectionFacts($k);
            $w['index']->add('host', $f['svcHost']);
            $w['index']->add('host', $f['cacheHost']);
        }

        return $w;
    }

    /** @return list<string> host:port pairs read from the served body */
    private static function servedHosts(int $cap, bool $lastOnly = false): array
    {
        $last = '';
        $prev = '';
        $all = [];
        foreach ((new ConfigDump(self::SEED))->chunks($cap) as $chunk) {
            $prev = $last;
            $last = $chunk;
            if (!$lastOnly) {
                $all[] = $chunk;
            }
        }
        $last = $prev . $last;
        $text = $lastOnly ? $last : implode('', $all);
        preg_match_all('~(?:https://|redis://)([a-z0-9.-]+)(?::(\d+))?~', $text, $m, PREG_SET_ORDER);

        return array_values(array_unique(array_map(static fn (array $x): string => $x[1] . ':' . ($x[2] ?? '') , $m)));
    }

    public function test_every_streamed_host_resolves_once_indexed(): void
    {
        foreach ([[2 << 20, false], [8 << 20, true]] as [$cap, $lastOnly]) {
            $w = self::indexed($cap);
            $hosts = self::servedHosts($cap, $lastOnly);
            self::assertGreaterThan($lastOnly ? 1 : 4000, count($hosts), 'the body names many hosts');
            foreach ($hosts as $hp) {
                [$host, $port] = explode(':', $hp);
                $port = $port === '' ? 443 : (int) $port;
                $t = TargetParser::parse('http://' . $host . ':' . $port . '/');
                $r = $w['net']->resolve($t, '203.0.113.9', Role::Hook);
                self::assertSame('open', $r->outcome, "{$hp} resolves and its port is open");
            }
        }
        $w = self::indexed(2 << 20);
        foreach (['db-primary.eu-west-2.internal:5432'] as $hp) {
            self::assertSame('open', $w['net']->resolve(TargetParser::parse('http://' . $hp . '/'), '203.0.113.9', Role::Hook)->outcome);
        }
    }

    public function test_shaped_names_are_transient_while_incomplete_then_nxdomain(): void
    {
        $f = (new ConfigDump(self::SEED))->sectionFacts(1);
        $unknown = 'cache-zzzzzz.zzzz.internal';
        $incomplete = SsrfCorpus::network(self::SEED, false);
        self::assertSame('dns_transient', $incomplete['net']->resolve(TargetParser::parse('http://' . $f['cacheHost'] . ':6379/'), '1.2.3.4', Role::Hook)->outcome, 'not indexed yet');
        self::assertSame('dns_transient', $incomplete['net']->resolve(TargetParser::parse('http://' . $unknown . ':6379/'), '1.2.3.4', Role::Hook)->outcome);
        $complete = self::indexed(64 << 10);
        self::assertSame('open', $complete['net']->resolve(TargetParser::parse('http://' . $f['cacheHost'] . ':6379/'), '1.2.3.4', Role::Hook)->outcome);
        self::assertSame('nxdomain', $complete['net']->resolve(TargetParser::parse('http://' . $unknown . ':6379/'), '1.2.3.4', Role::Hook)->outcome, 'complete and not indexed: no such name');
    }

    public function test_min_section_bytes_is_a_lower_bound(): void
    {
        $min = PHP_INT_MAX;
        foreach ([1, 7, 4242, 99991, 123456789, 31337, 2026, 8] as $seed) {
            $dump = new ConfigDump($seed);
            $r = new \ReflectionMethod(ConfigDump::class, 'section');
            for ($k = 0; $k < 10000; $k += 37) {
                $min = min($min, strlen((string) $r->invoke($dump, $k)));
            }
            $sections = 0;
            foreach ($dump->chunks(1 << 20) as $_) {
                $sections++;
            }
            self::assertLessThanOrEqual(Network::sections(1 << 20) + 1, $sections, "seed {$seed}: chunks() never serves more sections than the index covers");
        }
        self::assertGreaterThanOrEqual(ConfigDump::MIN_SECTION_BYTES, $min);
    }

    public function test_section_facts_match_the_rendered_section(): void
    {
        $dump = new ConfigDump(self::SEED);
        $r = new \ReflectionMethod(ConfigDump::class, 'section');
        for ($k = 0; $k < 200; $k++) {
            $f = $dump->sectionFacts($k);
            $text = (string) $r->invoke($dump, $k);
            foreach (['awsKey', 'stripeKey', 'svcHost', 'cacheHost', 'flag'] as $field) {
                self::assertStringContainsString($f[$field], $text, "{$k} {$field}");
            }
        }
    }
}
