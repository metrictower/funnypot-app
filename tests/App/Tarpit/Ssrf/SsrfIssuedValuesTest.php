<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\SsrfForms;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * Every value the SSRF surface issues and expects back, and every host name its network hands out, is
 * quiet in core's eyes on the routes it really travels: ids in their paths with the real bodies (URL
 * last), form tokens on their own forms, generated names as the last URL field. A flagged one would be
 * logged and reported as an attack on a visitor using the surface as intended.
 */
final class SsrfIssuedValuesTest extends TestCase
{
    /** Verdicts the engine gives on purpose: the visitor's own payloads, at parity with the unarmed host. */
    private const RECORDED_VERDICTS = ['http://[::1]:22/', 'file:///etc/passwd'];

    public function test_ids_and_form_tokens_are_quiet_on_their_real_paths(): void
    {
        $values = 0;
        foreach (range(1, 8) as $seed) {
            $tour = (new SsrfTour($seed))->run();
            try {
                $ids = [];
                $forms = [];
                foreach ($tour->plans as [, $plan]) {
                    preg_match_all('~/(?:settings/(?:webhooks|imports)|user/(?:hooks|imports))/([a-f0-9]{12})(?:/deliveries/([a-f0-9]{12}))?~', $plan->body . (string) $plan->header('Location'), $m, PREG_SET_ORDER);
                    foreach ($m as $x) {
                        $ids[$x[1]] = $x[2] ?? '';
                    }
                    preg_match_all("~<form method=post action='([^']+)'><input type=hidden name=csrf_token value='([^']+)'>~", $plan->body, $f, PREG_SET_ORDER);
                    foreach ($f as [, $action, $token]) {
                        $forms[$action . ' ' . $token] = [$action, $token];
                    }
                }
                self::assertGreaterThan(5, count($ids), "seed {$seed}: ids issued");
                self::assertGreaterThan(20, count($forms), "seed {$seed}: forms rendered");
                foreach ($ids as $id => $did) {
                    foreach (SsrfCorpus::routes(1) as [$route, $method]) {
                        $path = SsrfCorpus::routePath($route, $id, $did !== '' ? $did : $id);
                        $reqs = [new RequestContext('GET', $path, '', [])];
                        $b = SsrfCorpus::body($route, $method, 'http://172.16.0.5:8080/health', $did !== '' ? $did : $id);
                        if ($b !== null) {
                            $reqs[] = new RequestContext($method, $path, '', $b[1], $b[0]);
                        }
                        foreach ($reqs as $r) {
                            self::assertFalse(SsrfCorpus::flags($r), "seed {$seed}: {$r->method} {$path} " . json_encode(SsrfCorpus::why($r)));
                            $values++;
                        }
                    }
                }
                $eventSets = [...array_map(static fn (string $e): array => [$e], array_keys(SsrfForms::EVENTS)), array_keys(SsrfForms::EVENTS)];
                foreach ($forms as [$action, $token]) {
                    foreach ($eventSets as $events) {
                        $ev = implode('', array_map(static fn (string $e): string => '&events%5B%5D=' . rawurlencode($e), $events));
                        $body = 'csrf_token=' . $token . '&content_type=json' . $ev . '&active=0&active=1&payload_url=' . rawurlencode('http://172.16.0.5/hook');
                        $r = new RequestContext('POST', $action, '', SsrfCorpus::F, $body);
                        self::assertFalse(SsrfCorpus::flags($r), "seed {$seed}: the form token for {$action} with " . implode(',', $events));
                        $values++;
                    }
                }
            } finally {
                $tour->cleanup();
            }
        }
        self::assertGreaterThan(5000, $values, 'values checked');
    }

    public function test_network_vocabulary_verdicts_are_recorded(): void
    {
        $sent = 0;
        foreach (range(1, 8) as $seed) {
            $w = SsrfCorpus::network(1000 + $seed, true, true, 8 << 20, str_repeat(chr(0x30 + $seed), 32));
            $hosts = [...$w['net']->generated()->sample('vocab', 60), ...$w['net']->providers()->sample('vocab', 12), ...$w['net']->credentials()->pointers()];
            foreach ($hosts as $hp) {
                foreach (['/', '/health', '/metrics', '/v2/', ''] as $path) {
                    $url = 'http://' . $hp . $path;
                    foreach ([['/settings/webhooks', 'payload_url'], ['/settings/imports', 'source_url'], ['/settings/storage', 'endpoint_url']] as [$p, $field]) {
                        $r = new RequestContext('POST', $p, '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&' . $field . '=' . rawurlencode($url));
                        self::assertFalse(SsrfCorpus::flags($r), "{$url} as {$field}");
                        $j = new RequestContext('POST', '/api/v2/user/hooks', '', SsrfCorpus::J, (string) json_encode(['active' => true, 'url' => $url], JSON_UNESCAPED_SLASHES));
                        self::assertFalse(SsrfCorpus::flags($j), "{$url} in JSON");
                        $sent += 2;
                    }
                }
            }
        }
        self::assertGreaterThan(5000, $sent);
        foreach (self::RECORDED_VERDICTS as $url) {
            $r = new RequestContext('POST', '/settings/webhooks', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode($url));
            self::assertTrue(SsrfCorpus::flags($r), "recorded: {$url} is the visitor's own payload and stays flagged");
        }
    }
}
