<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Tarpit\Ssrf\SsrfForms;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use Funnypot\Tests\App\Tarpit\Ssrf\SsrfCorpus;
use PHPUnit\Framework\TestCase;

/**
 * Core stays quiet on what the SSRF surface really receives: every owned route on both API spellings,
 * with real ids for eight key seeds, as a bare GET and as the benign request each form or API call
 * sends, in its real field order (form token first, URL last). A flagged request here would be logged
 * and reported as an attack on a visitor using the surface as intended.
 */
final class SsrfRouteQuietTest extends TestCase
{
    public function test_owned_routes_are_quiet_in_their_real_field_order(): void
    {
        $sent = 0;
        $routes = 0;
        foreach (range(1, 8) as $seed) {
            foreach (SsrfCorpus::routes($seed) as [$route, $method, $path]) {
                $routes++;
                $reqs = [new RequestContext('GET', $path, '', ['User-Agent' => 'Mozilla/5.0'])];
                foreach (SsrfCorpus::urls() as $url) {
                    $b = SsrfCorpus::body($route, $method, $url);
                    if ($b !== null) {
                        $reqs[] = new RequestContext($method, $path, '', $b[1], $b[0]);
                    }
                }
                foreach ($reqs as $r) {
                    $sent++;
                    self::assertFalse(SsrfCorpus::flags($r), "{$r->method} {$path} body " . $r->rawBody . ' flagged ' . json_encode(SsrfCorpus::why($r)));
                }
            }
        }
        self::assertGreaterThanOrEqual($routes, $sent);
        self::assertGreaterThanOrEqual(count(SsrfRoutes::examples()) * 8, $routes, 'every route and method, for every seed');
        self::assertSame([], SsrfRoutes::QUIET_EXEMPT, 'no route is exempt');
    }

    /**
     * Every value the API docs and errors name, sent back as its field (alone, and every event together)
     * on each create and edit route in both encodings, is quiet: following the docs never gets an agent
     * logged as an attacker.
     */
    public function test_every_documented_value_is_quiet_where_it_is_sent(): void
    {
        $values = [];
        foreach (['events_invalid' => 'events', 'kind_invalid' => 'kind', 'content_type_invalid' => 'content_type', 'active_invalid' => 'active'] as $key => $field) {
            foreach ((array) SsrfForms::allowed($key) as $v) {
                $values[] = [$field, $field === 'events' ? [$v] : ($field === 'active' ? $v === 'true' : $v)];
            }
        }
        $values[] = ['events', array_keys(SsrfForms::EVENTS)];
        $url = 'http://172.16.0.5:8080/hooks';
        $sent = 0;
        $reqs = [];
        foreach ($values as [$field, $value]) {
            $last = $field === 'kind' ? 'source_url' : 'payload_url';
            $routes = $field === 'kind' ? ['/settings/imports'] : ['/settings/webhooks', '/settings/webhooks/4b7e19a2c0a1'];
            $apiRoutes = $field === 'kind' ? [['POST', '/api/v2/user/imports'], ['POST', '/v2/user/imports']]
                : [['POST', '/api/v2/user/hooks'], ['POST', '/v2/user/hooks'], ['PATCH', '/api/v2/user/hooks/4b7e19a2c0a1']];
            $form = is_bool($value) ? ($value ? '1' : '0') : $value;
            foreach ($routes as $path) {
                $reqs[] = new RequestContext('POST', $path, '', SsrfCorpus::F, http_build_query(['csrf_token' => SsrfCorpus::CSRF, $field => $form, $last => $url]));
            }
            foreach ($apiRoutes as [$m, $path]) {
                $reqs[] = new RequestContext($m, $path, '', SsrfCorpus::J, (string) json_encode([$field => $value, $field === 'kind' ? 'source_url' : 'url' => $url], JSON_UNESCAPED_SLASHES));
            }
        }
        foreach ($reqs as $r) {
            $sent++;
            self::assertFalse(SsrfCorpus::flags($r), "{$r->method} {$r->path} " . $r->rawBody . ' flagged ' . json_encode(SsrfCorpus::why($r)));
        }
        self::assertGreaterThanOrEqual(40, $sent);
    }

    public function test_the_pair_rule_controls(): void
    {
        $url = 'http://10.41.7.19:8080/x/uptime';
        $flagged = new RequestContext('POST', '/settings/webhooks/4b7e19a2c3df', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode($url));
        self::assertTrue(SsrfCorpus::flags($flagged), 'positive control: an id ending df with a URL ending in a pair word is flagged');
        $clean = new RequestContext('POST', '/settings/webhooks/4b7e19a2c0a1', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode($url));
        self::assertFalse(SsrfCorpus::flags($clean), 'negative control: the same request on a neutral id is clean');
        $cancel = new RequestContext('POST', '/settings/imports/7h2p9k/cancel', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&active=1');
        self::assertTrue(SsrfCorpus::flags($cancel), 'positive control: a form ending active=1 on a cancel path is flagged, so no route uses that shape');
    }

    /** A visitor's own URL-first JSON ending in a pair word is flagged today; recorded, not failed. */
    public function test_url_first_json_is_recorded_as_the_visitors_own(): void
    {
        $r = new RequestContext('POST', '/api/v2/user/hooks', '', SsrfCorpus::J, '{"url":"http://10.41.7.19:8080/actuator/env","active":true}');
        self::assertTrue(SsrfCorpus::flags($r), 'recorded: a URL-first body ending /env reads as RCE, at parity with the unarmed answer');
    }

    /**
     * Every form the surface renders, parsed from the real pages: its fields in order, each select
     * option, every subset of each checkbox group and each single checkbox on and off (the hook form's
     * hidden `active=0` alone and with the checked `active=1`), with the URL last. Nothing is hand-listed,
     * so a new option or field is swept the moment a page renders it.
     *
     * @return list<array{0:string,1:string}> [action, body]
     */
    public static function formVariants(MintHarness $h, array $urls): array
    {
        $pages = ['/settings/webhooks/new', '/settings/imports/new', '/settings/storage'];
        $form = $h->get('/settings/webhooks/new');
        $hook = basename((string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/'])['plan']?->header('Location'));
        $pages[] = '/settings/webhooks/' . $hook;
        $show = $h->get('/settings/webhooks/' . $hook);
        preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
        $h->post('/settings/webhooks/' . $hook . '/pings', ['csrf_token' => $m[1][0]]);
        $h->now += 3;
        preg_match("~/deliveries/([a-f0-9]{12})'~", $h->get('/settings/webhooks/' . $hook)['body'], $dm);
        $pages[] = '/settings/webhooks/' . $hook . '/deliveries/' . $dm[1];
        $imp = $h->get('/settings/imports/new');
        $loc = (string) $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($imp['body']), 'kind' => 'orders_csv', 'source_url' => 'http://nosuch.internal/a.csv'])['plan']?->header('Location');
        $pages[] = $loc;
        $st = $h->get('/settings/storage');
        preg_match_all("/name=csrf_token value='([^']+)'/", $st['body'], $sm);
        $h->post('/settings/storage', ['csrf_token' => $sm[1][0], 'bucket' => 'exports-a', 'access_key' => 'k1', 'secret_key' => 's1', 'endpoint_url' => 'http://172.16.0.5']);
        $out = [];
        foreach ($pages as $page) {
            preg_match_all("~<form method=post action='([^']+)'>(.*?)</form>~s", $h->get($page)['body'], $forms, PREG_SET_ORDER);
            foreach ($forms as [, $action, $inner]) {
                $fields = [];
                preg_match_all("~<input type=(\w+) name=([\w\[\]']+) value='([^']*)'[^>]*>|<select name=(\w+)>(.*?)</select>~s", $inner, $f, PREG_SET_ORDER);
                foreach ($f as $x) {
                    if (($x[4] ?? '') !== '') {
                        preg_match_all("~<option value='([^']*)'~", $x[5], $o);
                        $fields[] = ['select', $x[4], $o[1]];
                    } else {
                        $fields[] = [$x[1], trim($x[2], "'"), $x[3]];
                    }
                }
                $variants = [[]];
                $groups = [];
                foreach ($fields as [$type, $name, $value]) {
                    if ($type === 'checkbox' && str_ends_with($name, '[]')) {
                        $groups[$name][] = $value;
                    }
                }
                $emitted = [];
                foreach ($fields as [$type, $name, $value]) {
                    $next = [];
                    foreach ($variants as $v) {
                        if ($type === 'select') {
                            foreach ($value as $opt) {
                                $next[] = [...$v, [$name, $opt]];
                            }
                        } elseif ($type === 'checkbox' && str_ends_with($name, '[]')) {
                            if (isset($emitted[$name])) {
                                $next[] = $v;
                                continue;
                            }
                            $vals = $groups[$name];
                            for ($mask = 0; $mask < (1 << count($vals)); $mask++) {
                                $set = $v;
                                foreach ($vals as $k => $val) {
                                    if ($mask & (1 << $k)) {
                                        $set[] = [$name, $val];
                                    }
                                }
                                $next[] = $set;
                            }
                        } elseif ($type === 'checkbox') {
                            $next[] = $v;
                            $next[] = [...$v, [$name, $value]];
                        } elseif ($type === 'hidden') {
                            $next[] = [...$v, [$name, $value]];
                        } else {
                            $next[] = [...$v, [$name, str_ends_with($name, 'url') ? '{URL}' : ($type === 'password' ? 'Rk2mQ9xLw4' : ($name === 'bucket' ? 'exports-backup' : 'exportbot'))]];
                        }
                    }
                    if ($type === 'checkbox' && str_ends_with($name, '[]')) {
                        $emitted[$name] = true;
                    }
                    $variants = $next;
                }
                foreach ($variants as $v) {
                    $pairs = array_map(static fn (array $p): string => rawurlencode($p[0]) . '=' . rawurlencode($p[1]), $v);
                    $body = implode('&', $pairs);
                    if (str_contains($body, '%7BURL%7D')) {
                        foreach ($urls as $u) {
                            $out[] = [$action, str_replace('%7BURL%7D', rawurlencode($u), $body)];
                        }
                    } else {
                        $out[] = [$action, $body];
                    }
                }
            }
        }

        return $out;
    }

    public function test_every_rendered_form_option_combination_is_quiet(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $variants = self::formVariants($h, SsrfCorpus::urls());
            $actions = [];
            foreach ($variants as [$action, $body]) {
                $actions[(string) preg_replace('~/[a-f0-9]{12}~', '/{id}', $action)] = true;
                $r = new RequestContext('POST', $action, '', SsrfCorpus::F, $body);
                self::assertFalse(SsrfCorpus::flags($r), "POST {$action} {$body} " . json_encode(SsrfCorpus::why($r)));
            }
            self::assertGreaterThan(300, count($variants), 'every option combination of every form');
            foreach (['/settings/webhooks', '/settings/webhooks/{id}', '/settings/webhooks/{id}/pings', '/settings/webhooks/{id}/delete', '/settings/webhooks/{id}/redeliveries',
                '/settings/imports', '/settings/imports/{id}/retry', '/settings/storage', '/settings/storage/verify'] as $want) {
                self::assertArrayHasKey($want, $actions, "the sweep reached the {$want} form");
            }
            $events = array_filter($variants, static fn (array $v): bool => substr_count($v[1], 'events%5B%5D=') === 4);
            self::assertNotEmpty($events, 'all four events together were sent');
        } finally {
            $h->cleanup();
        }
        $old = new RequestContext('POST', '/settings/webhooks', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&events%5B%5D=export&payload_url=' . rawurlencode('http://172.16.0.5/'));
        self::assertTrue(SsrfCorpus::flags($old), 'regression: a bare export event value reads as RCE to core, which is why the events are dotted names');
    }
}
