<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;

/**
 * Walks the SSRF surface for one persona through every page and answer kind it renders, UI and API:
 * lists, forms, validation errors, deliveries in every state, imports of each kind, the export
 * destination, the gateways' verdicts, and the error answers. Returns every plan, so a test can check
 * all of them without a hand-kept list going stale.
 */
final class SsrfTour
{
    /** @var list<array{0:string,1:MintPlan}> */
    public array $plans = [];
    public MintHarness $h;
    private string $pat = '';

    public function __construct(public readonly int $personaSeed, array $opts = [])
    {
        $this->h = new MintHarness(true, $opts + ['ssrf' => [], 'personaSeed' => $personaSeed]);
    }

    public function cleanup(): void
    {
        $this->h->cleanup();
    }

    private function keep(string $label, array $r): array
    {
        if ($r['plan'] instanceof MintPlan) {
            $this->plans[] = [$label, $r['plan']];
        }

        return $r;
    }

    private function get(string $p): array
    {
        return $this->keep('GET ' . $p, $this->h->get($p));
    }

    private function post(string $p, array $f): array
    {
        return $this->keep('POST ' . $p, $this->h->post($p, $f));
    }

    private function api(string $m, string $p, ?string $json = null): array
    {
        return $this->keep($m . ' ' . $p, $this->h->request($m, $p, '', $json, ['Authorization' => 'Bearer ' . $this->pat, 'Content-Type' => 'application/json']));
    }

    /** @return list<string> */
    private static function tokens(string $body): array
    {
        preg_match_all("/name=csrf_token value='([^']+)'/", $body, $m);

        return $m[1];
    }

    private function node(string $kind): string
    {
        $g = $this->h->ssrf->network()->generated();
        for ($i = 1; $g->node($i)?->kind !== $kind; $i++) {
        }

        return 'http://' . $g->name($i) . ':' . $g->node($i)->ports[0];
    }

    public function run(): self
    {
        $h = $this->h;
        $this->get('/settings/webhooks');
        $h->join();
        $this->pat = $h->mint(['read:user', 'webhooks:write', 'imports:write', 'storage:write']);
        foreach (['/settings/webhooks', '/settings/webhooks/new', '/settings/imports', '/settings/imports/new', '/settings/storage', '/settings/webhooks/4b7e19a2c0a1', '/settings/imports/4b7e19a2c0a1'] as $p) {
            $this->get($p);
        }
        $new = $h->get('/settings/webhooks/new');
        $this->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($new['body']), 'payload_url' => 'gopher://x/', 'secret' => '<bad>']);
        $this->post('/settings/webhooks', ['csrf_token' => 'stale']);
        $persona = PersonaIdentity::fromSeed($this->personaSeed);
        $region = (string) $persona->field('cloud.aws.region');
        $targets = [
            $this->node('http_api') . '/', $this->node('admin_ui') . '/', $this->node('metrics') . '/metrics', $this->node('registry') . '/',
            $this->node('db') . '/', $this->node('cache') . '/', $this->node('ssh') . '/', 'http://127.1:22/', 'http://127.1:9090/metrics',
            'http://127.1:8080/', 'http://0xa9fea9fe/latest/meta-data/', 'http://172.16.9.9/', 'https://collab.example.net/x', 'http://nosuch.internal/',
            'http://sts.' . $region . '.internal/?X-Amz-Credential=' . $persona->field('cloud.aws.accessKeyId') . '%2Fx&X-Amz-Signature=1',
            'http://' . $persona->field('cloud.stripe.secretKey') . ':@payments-gw.' . $region . '.internal:8443/v1/charges',
        ];
        $hooks = [];
        foreach (array_slice($targets, 0, 5) as $i => $url) {
            $form = $h->get('/settings/webhooks/new');
            $r = $this->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'content_type' => $i % 2 ? 'form' : 'json', 'secret' => 'sec-' . $i, 'events' => ['token'], 'active' => '1', 'payload_url' => $url]);
            $hooks[] = basename((string) $r['plan']?->header('Location'));
        }
        $hook = $hooks[0];
        foreach ($targets as $i => $url) {
            $show = $h->get('/settings/webhooks/' . $hook);
            $this->post('/settings/webhooks/' . $hook, ['csrf_token' => self::tokens($show['body'])[1], 'payload_url' => $url]);
            $show = $h->get('/settings/webhooks/' . $hook);
            $this->post('/settings/webhooks/' . $hook . '/pings', ['csrf_token' => self::tokens($show['body'])[0]]);
            $h->now += $i % 3 === 0 ? 0 : 15;
        }
        $h->now += 4000;
        $h->signIn('artex1', 'Passw0rd!x');
        $show = $this->get('/settings/webhooks/' . $hook);
        preg_match_all('~/settings/webhooks/' . $hook . "/deliveries/([a-f0-9]{12})'~", $show['body'], $m);
        foreach ($m[1] as $did) {
            $this->get('/settings/webhooks/' . $hook . '/deliveries/' . $did);
            $this->api('GET', '/api/v2/user/hooks/' . $hook . '/deliveries/' . $did);
        }
        $page = $h->get('/settings/webhooks/' . $hook . '/deliveries/' . ($m[1][0] ?? ''));
        $this->post('/settings/webhooks/' . $hook . '/redeliveries', ['csrf_token' => self::tokens($page['body'])[0] ?? '', 'delivery' => $m[1][0] ?? '']);
        $this->post('/settings/webhooks/' . $hook . '/redeliveries', ['csrf_token' => self::tokens($page['body'])[0] ?? '', 'delivery' => 'ffffffffffff']);
        foreach ([['orders_csv', $targets[0] . 'orders.csv'], ['orders_json', $targets[14]], ['orders_json', $targets[15]], ['mirror', 'https://github.com/torvalds/linux.git'],
            ['mirror', $targets[0] . 'repo.git'], ['orders_csv', $targets[12]], ['orders_csv', 'https://github.com/a/b'], ['mirror', 'https://github.com/a']] as [$kind, $url]) {
            $form = $h->get('/settings/imports/new');
            $r = $this->post('/settings/imports', ['csrf_token' => MintHarness::csrf($form['body']), 'kind' => $kind, 'source_url' => $url]);
            $loc = (string) $r['plan']?->header('Location');
            if ($loc !== '') {
                foreach ([0, 4, 6, 900, 1600] as $dt) {
                    $h->now += $dt;
                    $view = $this->get($loc);
                }
                $h->signIn('artex1', 'Passw0rd!x');
                if (str_contains($view['body'], 'Retry import')) {
                    $this->post($loc . '/retry', ['csrf_token' => MintHarness::csrf($view['body'])]);
                }
            }
        }
        $h->signIn('artex1', 'Passw0rd!x');
        foreach ([$this->node('http_api'), 'http://0xa9fea9fe', 'https://s3.example.net', 'http://sts.' . $region . '.internal'] as $ep) {
            $st = $h->get('/settings/storage');
            $this->post('/settings/storage', ['csrf_token' => self::tokens($st['body'])[0], 'bucket' => 'exports-tour', 'access_key' => (string) $persona->field('cloud.aws.accessKeyId'), 'secret_key' => 'x', 'endpoint_url' => $ep]);
            $st = $h->get('/settings/storage');
            $this->post('/settings/storage/verify', ['csrf_token' => self::tokens($st['body'])[1] ?? '']);
            $h->now += 5;
            $this->get('/settings/storage');
        }
        $this->post('/settings/storage', ['csrf_token' => 'x', 'bucket' => 'A']);
        foreach (['/api/v2/user/hooks', '/v2/user/hooks', '/api/v2/user/imports', '/api/v2/user/storage', '/api/v2/user/hooks/' . $hook, '/api/v2/user/hooks/' . $hook . '/deliveries', '/api/v2/user/hooks/4b7e19a2c0a1'] as $p) {
            $this->api('GET', $p);
        }
        $this->api('POST', '/api/v2/user/hooks', '{"url":"ftp://x/"}');
        $this->api('PATCH', '/api/v2/user/hooks/' . $hook, '{"active":false,"events":["order"]}');
        $this->api('POST', '/api/v2/user/hooks/' . $hook . '/pings', '{}');
        $this->api('POST', '/api/v2/user/imports', '{"kind":"mirror","source_url":"https://github.com/a/b"}');
        $this->api('PUT', '/api/v2/user/storage', '{"bucket":"b..b"}');
        $this->api('POST', '/api/v2/user/storage/verifications', '{}');
        $this->api('DELETE', '/api/v2/user/hooks/' . $hooks[1]);
        $this->keep('OPTIONS', $h->request('OPTIONS', '/settings/imports'));
        $this->keep('PUT', $h->request('PUT', '/settings/webhooks/new', '', 'x=1'));
        $this->keep('401', $h->request('GET', '/api/v2/user/hooks'));
        $this->keep('413', $h->request('POST', '/settings/imports', '', str_repeat('a', 17000)));
        $this->post('/settings/webhooks/' . $hook . '/delete', ['csrf_token' => self::tokens($h->get('/settings/webhooks/' . $hook)['body'])[2] ?? '']);

        return $this;
    }
}
