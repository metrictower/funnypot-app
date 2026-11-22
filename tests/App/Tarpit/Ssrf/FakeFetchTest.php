<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\FakeFetch;
use Funnypot\App\Tarpit\Ssrf\PathClass;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use PHPUnit\Framework\TestCase;

final class FakeFetchTest extends TestCase
{
    private static function facts(array $w, string $url, string $method = 'POST', Role $role = Role::Hook): array
    {
        $t = TargetParser::parse($url);

        return FakeFetch::facts($w['net']->resolve($t, '203.0.113.9', $role), $method, PathClass::of($t->path));
    }

    public const UUID4 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /**
     * Every answer the fake network gives, for every service kind, carries no platform id, and the one
     * service that returns a request id (STS) returns its own version-4 UUID: the same on a re-view, new
     * for each attempt and each target. Every other service returns no request id at all.
     */
    public function test_every_service_mints_its_own_request_id_and_echoes_no_platform_id(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        $targets = [];
        $seen = [];
        for ($i = 1; $i < 6000 && count($seen) < 8; $i++) {
            $node = $g->node($i);
            if ($node === null || isset($seen[$node->kind])) {
                continue;
            }
            $seen[$node->kind] = true;
            foreach ($node->ports as $port) {
                $targets[] = [$port === 22 ? 'ssh' : $node->kind, 'http://' . $g->name($i) . ':' . $port . '/', null];
            }
        }
        foreach ([8080, 9090, 22, 6379] as $port) {
            $targets[] = ['loopback', 'http://127.1:' . $port . '/', null];
        }
        $targets[] = ['metadata', 'http://169.254.169.254/latest/meta-data/', null];
        $targets[] = ['proxied', 'http://example.com/', null];
        [$stsHost, $payHost] = $w['net']->credentials()->pointers();
        foreach (\Funnypot\App\Tarpit\Ssrf\CredentialEndpoints::VERDICTS as $v) {
            $targets[] = ['sts', 'http://' . $stsHost . '/?Action=GetCallerIdentity', $v];
            $targets[] = ['payments', 'https://' . $payHost . '/v1/charges', $v];
        }
        $platform = ['dc55d2f7c9b7', '9d1b7594d3a5|0', '9d1b7594d3a5', '4b7e19a2c0a1'];
        $ids = [];
        $kinds = [];
        foreach ($targets as [$kind, $url, $verdict]) {
            $t = TargetParser::parse($url);
            self::assertNotNull($t, $url);
            foreach (['GET', 'POST', 'PUT'] as $m) {
                $f = FakeFetch::facts($w['net']->resolve($t, '203.0.113.9', Role::Hook), $m, PathClass::of($t->path), $verdict);
                foreach ($platform as $attempt) {
                    $reply = $w['fetch']->reply($f, $attempt);
                    self::assertNotNull($reply, "{$kind} {$url}");
                    $text = $reply->body . "\n" . (string) $reply->error;
                    foreach ($platform as $pid) {
                        self::assertStringNotContainsString(explode('|', $pid)[0], $text, "{$kind} {$m} {$url} echoes a platform id");
                    }
                    if ($kind !== 'sts') {
                        self::assertSame(0, preg_match('/request.?id/i', $text), "{$kind} {$m} {$url} returns no request id");
                        continue;
                    }
                    self::assertSame(1, preg_match('~<RequestId>([^<]*)</RequestId>~', $reply->body, $mm), "{$m} {$url}");
                    self::assertMatchesRegularExpression(self::UUID4, $mm[1], 'STS request ids are version-4 UUIDs');
                    self::assertSame($mm[1], $w['fetch']->requestId($f, $attempt), 'stable on a re-view');
                    $ids[$mm[1]] = true;
                }
                $kinds[$kind] = true;
            }
        }
        self::assertCount(3 * count($platform), $ids, 'a new id for each attempt and each request (method), whatever the verdict');
        foreach (SsrfTour::ANSWER_KINDS as $k) {
            self::assertArrayHasKey($k, $kinds, "the {$k} service was asked");
        }
        $f = self::facts($w, 'http://' . $stsHost . '/', 'GET');
        $other = (new FakeFetch($w['answers'], str_repeat("\x53", 32)))->requestId($f, 'dc55d2f7c9b7');
        self::assertNotSame($w['fetch']->requestId($f, 'dc55d2f7c9b7'), $other, 'the id is keyed, so the attempt cannot be recovered from it');
    }

    public function test_state_is_a_pure_function_of_facts_attempt_and_now(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        for ($i = 1; $g->node($i)?->kind !== 'http_api'; $i++) {
        }
        $f = self::facts($w, 'http://' . $g->name($i) . ':8080/', 'GET');
        $ms = FakeFetch::durationMs('open', 'd1');
        self::assertGreaterThanOrEqual(1000, $ms);
        self::assertLessThanOrEqual(3000, $ms);
        $doneAt = (int) ceil($ms / 1000);
        self::assertSame('pending', $w['fetch']->delivery($f, 1000, 1000 + $doneAt - 1, 'd1')->state);
        self::assertSame('delivered', $w['fetch']->delivery($f, 1000, 1000 + $doneAt, 'd1')->state);
        self::assertSame('delivered', $w['fetch']->delivery($f, 1000, 1000 + $doneAt + 1, 'd1')->state);
        self::assertEquals($w['fetch']->delivery($f, 1000, 5000, 'd1'), $w['fetch']->delivery($f, 1000, 5000, 'd1'));
        $timeout = self::facts($w, 'http://10.213.87.5:8080/');
        self::assertSame('pending', $w['fetch']->delivery($timeout, 0, 9, 'x')->state);
        self::assertSame('retrying', $w['fetch']->delivery($timeout, 0, 10, 'x')->state);
        self::assertSame('Connection timed out after 10000 ms', $w['fetch']->delivery($timeout, 0, 10, 'x')->error);
        $denied = self::facts($w, 'https://oob.example.net/');
        self::assertSame('failed', $w['fetch']->delivery($denied, 0, 0, 'x')->state, 'a proxy denial is at once');
        self::assertSame(403, $w['fetch']->delivery($denied, 0, 0, 'x')->reply?->status);
    }

    public function test_timeout_attempts_are_derived_not_stored(): void
    {
        $w = SsrfCorpus::network();
        $f = self::facts($w, 'http://172.16.9.9/');
        $counts = [];
        foreach ([0, 10, 29, 30, 40, 120, 130, 600, 610, 3600, 3609, 3610, 99999] as $now) {
            $r = $w['fetch']->delivery($f, 0, $now, 'x');
            $counts[$now] = [count($r->attempts), $r->state];
        }
        self::assertSame([1, 'pending'], $counts[0]);
        self::assertSame([1, 'retrying'], $counts[29]);
        self::assertSame([2, 'retrying'], $counts[30]);
        self::assertSame([5, 'retrying'], $counts[3609]);
        self::assertSame([5, 'failed'], $counts[3610]);
        self::assertSame([5, 'failed'], $counts[99999]);
        self::assertSame(FakeFetch::RETRY_OFFSETS, array_map(static fn (array $a): int => $a['at'], $w['fetch']->delivery($f, 0, 99999, 'x')->attempts));
    }

    public function test_mirror_import_never_claims_progress(): void
    {
        $w = SsrfCorpus::network();
        $f = self::facts($w, 'https://github.com/torvalds/linux.git', 'GET', Role::Import);
        self::assertSame('code_host', $f['o']);
        $states = [];
        for ($now = 0; $now <= 2000; $now += 7) {
            $r = $w['fetch']->import('mirror', $f, 0, $now, 'imp1');
            $states[$r->state] = true;
            self::assertDoesNotMatchRegularExpression('/\d+\s*%|\bobjects?\b|\b\d+(?:\.\d+)?\s*(?:KiB|MiB|bytes)\b/i', (string) $r->error);
            self::assertNull($r->reply);
        }
        self::assertSame(['waiting', 'cloning', 'failed'], array_keys($states));
        self::assertSame('timed out after 600 s with no data received from github.com', $w['fetch']->import('mirror', $f, 0, 5000, 'imp1')->error);
    }

    public function test_orders_import_fails_validation_with_an_excerpt(): void
    {
        $w = SsrfCorpus::network();
        $g = $w['net']->generated();
        for ($i = 1; $g->node($i)?->kind !== 'http_api'; $i++) {
        }
        $f = self::facts($w, 'http://' . $g->ip($i) . ':8080/', 'GET', Role::Import);
        self::assertSame('queued', $w['fetch']->import('orders_csv', $f, 100, 100, 'i')->state);
        self::assertSame('fetching', $w['fetch']->import('orders_csv', $f, 100, 104, 'i')->state);
        $done = $w['fetch']->import('orders_csv', $f, 100, 105, 'i');
        self::assertSame('failed', $done->state);
        self::assertSame('validation: Row 1: expected header `order_id`', $done->error);
        self::assertSame(200, $done->reply?->status);
        $git = $w['fetch']->import('mirror', $f, 100, 200, 'i');
        self::assertSame('the remote did not answer as a Git repository (HTTP 200)', $git->error);
    }

    public function test_storage_put_reaches_the_endpoint_host_only(): void
    {
        $w = SsrfCorpus::network();
        $f = self::facts($w, 'http://169.254.169.254/exports/.verify-4b7e19a2c0a1', 'PUT', Role::Storage);
        self::assertSame(403, $w['fetch']->delivery($f, 0, 10, 'v')->reply?->status, 'metadata answers any non-token PUT with 403');
    }

    public function test_no_primitive_reaches_an_imds_token(): void
    {
        $w = SsrfCorpus::network();
        foreach (['GET', 'POST', 'PUT', 'HEAD'] as $m) {
            foreach (['/latest/api/token', '/latest/meta-data/iam/security-credentials/role', '/x/.verify-1a2b3c4d5e6f'] as $p) {
                foreach ([Role::Hook, Role::Import, Role::Storage] as $role) {
                    $r = $w['fetch']->delivery(self::facts($w, 'http://169.254.169.254' . $p, $m, $role), 0, 10, 'x');
                    self::assertGreaterThanOrEqual(400, $r->reply?->status ?? 999, "{$m} {$p}");
                    self::assertSame('', $r->reply?->body);
                }
            }
        }
    }
}
