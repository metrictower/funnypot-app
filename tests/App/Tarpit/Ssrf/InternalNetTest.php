<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\FakeFetch;
use Funnypot\App\Tarpit\Ssrf\NodeAnswers;
use Funnypot\App\Tarpit\Ssrf\PathClass;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use PHPUnit\Framework\TestCase;

final class InternalNetTest extends TestCase
{
    /** @return array{0:string,1:string} [answer body, status] after a fetch has finished */
    private static function fetch(array $w, string $url, string $method = 'GET', string $source = '203.0.113.9', Role $role = Role::Hook): array
    {
        $t = TargetParser::parse($url);
        self::assertNotNull($t, $url);
        $r = $w['net']->resolve($t, $source, $role);
        $res = $w['fetch']->delivery(FakeFetch::facts($r, $method, PathClass::of($t->path)), 0, 100000, 'd1');

        return [($res->reply?->body ?? '') . '|' . ($res->error ?? ''), (string) ($res->reply?->status ?? '-')];
    }

    public function test_answers_are_a_function_of_deploy_and_target(): void
    {
        $a = SsrfCorpus::network();
        $b = SsrfCorpus::network();
        $g = $a['net']->generated();
        $n = 0;
        for ($i = 1; $i < 600; $i++) {
            $node = $g->node($i);
            if ($node === null) {
                continue;
            }
            foreach (['/', '/health', '/metrics', '/v2/', '/x'] as $path) {
                $url = 'http://' . $node->host . ':' . $node->ports[0] . $path;
                self::assertSame(self::fetch($a, $url), self::fetch($b, $url), $url);
                self::assertSame(self::fetch($a, $url), self::fetch($a, $url, 'GET', '198.51.100.7'), 'the same from another source');
                $n++;
            }
            self::assertSame(self::fetch($a, 'http://' . $node->host . ':' . $node->ports[0] . '/'), self::fetch($a, 'http://' . $g->ip($i) . ':' . $node->ports[0] . '/'), 'by name and by address alike');
        }
        self::assertGreaterThan(500, $n);
        $other = SsrfCorpus::network(4242, true, true, 8 << 20, str_repeat("\x07", 32));
        self::assertNotSame($a['net']->generated()->subnetOctet() . $g->name(7), $other['net']->generated()->subnetOctet() . $other['net']->generated()->name(7), 'another deploy is another network');
    }

    public function test_the_frontier_never_closes(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        for ($start = 1; $g->node($start) === null || $g->node($start)->kind !== 'http_api'; $start++) {
        }
        $queue = [$g->node($start)->host . ':' . $g->node($start)->ports[0]];
        $seen = [];
        $steps = 0;
        while ($queue !== [] && $steps < 300) {
            $hp = array_shift($queue);
            if (isset($seen[$hp])) {
                continue;
            }
            $seen[$hp] = true;
            $steps++;
            [$body] = self::fetch($w, 'http://' . $hp . '/');
            preg_match_all('/"([a-z0-9.-]+\.[a-z0-9.-]+:\d{1,5})"/', $body, $m);
            preg_match_all('/upstream="([a-z0-9.-]+:\d{1,5})"/', $body, $m2);
            foreach ([...$m[1], ...$m2[1]] as $next) {
                if (!isset($seen[$next])) {
                    $queue[] = $next;
                }
            }
        }
        self::assertSame(300, $steps, 'a crawl never runs out of new hosts');
        self::assertNotEmpty($queue);
    }

    public function test_bodies_are_bounded_and_carry_no_target_bytes(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        $max = 0;
        for ($i = 1; $i < 800; $i++) {
            $node = $g->node($i);
            if ($node === null) {
                continue;
            }
            foreach (['/CANARYZQX', '/health?CANARYZQX=1', '/v2/CANARYZQX', '/admin/CANARYZQX', '/metrics#CANARYZQX'] as $path) {
                foreach (['GET', 'POST', 'PUT'] as $m) {
                    [$body] = self::fetch($w, 'http://' . $node->host . ':' . $node->ports[0] . $path, $m);
                    self::assertStringNotContainsStringIgnoringCase('canaryzqx', $body);
                    $max = max($max, strlen($body));
                }
            }
        }
        self::assertLessThanOrEqual(2048 + 64, $max);
        [$err] = self::fetch($w, 'http://nosuchhost-CANARYZQX.internal/');
        self::assertSame('|Could not resolve host', $err, 'error strings never name the host');
    }

    public function test_imds_is_v2_on_every_method(): void
    {
        $w = SsrfCorpus::network();
        foreach (['GET', 'POST', 'HEAD'] as $m) {
            self::assertSame('401', self::fetch($w, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', $m)[1], $m);
        }
        self::assertSame('400', self::fetch($w, 'http://169.254.169.254/latest/api/token', 'PUT')[1], 'a token request without its TTL header');
        self::assertSame('401', self::fetch($w, 'http://[fd00:ec2::254]/latest/meta-data/')[1]);
        self::assertSame('401', self::fetch($w, 'http://instance-data/latest/user-data')[1]);
    }

    public function test_imds_put_on_another_path_is_403(): void
    {
        $w = SsrfCorpus::network();
        foreach (['/latest/meta-data/', '/2021-03-23/api/token', '/exports/.verify-4b7e19a2c0a1', '/'] as $p) {
            [$body, $status] = self::fetch($w, 'http://169.254.169.254' . $p, 'PUT');
            self::assertSame('403', $status, $p);
            self::assertSame('|HTTP 403', $body, 'empty body');
        }
    }

    public function test_loopback_port_map(): void
    {
        $w = SsrfCorpus::network();
        self::assertStringContainsString('SSH-2.0-', self::fetch($w, 'http://127.0.0.1:22/')[0]);
        self::assertSame('|Empty reply from server', self::fetch($w, 'http://0:6379/')[0]);
        self::assertSame('200', self::fetch($w, 'http://localhost:8080/')[1]);
        self::assertStringContainsString('delivery_worker_queue_depth', self::fetch($w, 'http://[::1]:9090/metrics')[0]);
        self::assertSame('|Failed to connect: connection refused', self::fetch($w, 'http://127.0.0.2:3306/')[0]);
    }

    public function test_source_carve_changes_reachability_only(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        for ($i = 300; $g->node($i) === null; $i++) {
        }
        $url = 'http://' . $g->ip($i) . ':' . $g->node($i)->ports[0] . '/';
        $source = '10.' . $g->subnetOctet() . '.' . ($i >> 8) . '.' . ((($i & 255) % 250) + 2 === ($i & 255) ? 3 : 2);
        $carved = self::fetch($w, $url, 'GET', $source);
        self::assertSame('|Connection timed out after 10000 ms', $carved[0], 'the source\'s own /24 has no route back');
        $outside = self::fetch($w, $url, 'GET', '10.' . $g->subnetOctet() . '.' . ((($i >> 8) + 1) % 256) . '.9');
        self::assertSame(self::fetch($w, $url), $outside, 'another source sees the node unchanged');
        self::assertSame('200', $outside[1]);
    }

    public function test_metrics_bodies_carry_no_go_series(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        $seen = 0;
        for ($i = 1; $i < 3000 && $seen < 20; $i++) {
            $node = $g->node($i);
            if ($node !== null && $node->kind === 'metrics') {
                [$body] = self::fetch($w, 'http://' . $node->host . ':9100/metrics');
                self::assertStringContainsString('_upstream_up{upstream=', $body);
                self::assertDoesNotMatchRegularExpression('/^(?:go_|process_)/m', $body);
                $seen++;
            }
        }
        self::assertSame(20, $seen);
        self::assertDoesNotMatchRegularExpression('/^go_/m', self::fetch($w, 'http://127.0.0.1:9090/metrics')[0]);
    }

    public function test_db_cache_and_ssh_answer_as_protocol_errors(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        $kinds = [];
        for ($i = 1; $i < 3000; $i++) {
            $node = $g->node($i);
            if ($node !== null && in_array($node->kind, ['db', 'cache', 'ssh'], true) && !isset($kinds[$node->kind])) {
                $kinds[$node->kind] = self::fetch($w, 'http://' . $node->host . ':' . $node->ports[0] . '/')[0];
            }
        }
        self::assertSame('|Recv failure: connection reset by peer', $kinds['db']);
        self::assertSame('|Empty reply from server', $kinds['cache']);
        self::assertStringContainsString('Received HTTP/0.9 when not allowed', $kinds['ssh']);
        self::assertSame(NodeAnswers::LOOPBACK_PORTS, [22, 6379, 8080, 9090]);
    }
}
