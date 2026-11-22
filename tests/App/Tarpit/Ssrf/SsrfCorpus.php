<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Ssrf\FakeFetch;
use Funnypot\App\Tarpit\Ssrf\Network;
use Funnypot\App\Tarpit\Ssrf\NodeAnswers;
use Funnypot\App\Tarpit\Ssrf\SsrfIds;
use Funnypot\App\Tarpit\Ssrf\SsrfKeys;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;

/**
 * Requests the SSRF surface really receives, in its real field order (form token first, URL last),
 * with ids the surface really issues, for tests that ask the engine what it makes of them.
 */
final class SsrfCorpus
{
    public const F = ['Content-Type' => 'application/x-www-form-urlencoded'];
    public const J = ['Content-Type' => 'application/json'];
    public const CSRF = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    private static ?Honeypot $engine = null;
    private static ?AttackClassifier $classifier = null;

    public const KEY = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";

    /**
     * The deploy's network for a persona seed, over an in-memory key index.
     *
     * @param list<\Funnypot\App\Tarpit\Ssrf\HostDirectory> $extra
     * @return array{net:Network,index:MemoryKeyIndex,answers:NodeAnswers,fetch:FakeFetch}
     */
    public static function network(int $personaSeed = 4242, bool $complete = true, bool $pointers = true, int $cap = 8 << 20, string $key = self::KEY, array $extra = []): array
    {
        $index = new MemoryKeyIndex($complete);
        $net = Network::build(new SsrfKeys($key), $personaSeed, $cap, $index, $pointers, $extra);
        $answers = new NodeAnswers($net, 'Acme');

        return ['net' => $net, 'index' => $index, 'answers' => $answers, 'fetch' => new FakeFetch($answers)];
    }

    public static function engine(): Honeypot
    {
        return self::$engine ??= MintCorpus::engine();
    }

    /** Whether core's detection or the app's classifier flags a request. */
    public static function flags(RequestContext $r): bool
    {
        $d = self::engine()->detect($r);
        self::$classifier ??= new AttackClassifier();

        return $d->matched || in_array('attack', $d->tags(), true) || self::$classifier->classify($r) !== null;
    }

    /** @return list<string> the template ids core matches, for a failure message */
    public static function why(RequestContext $r): array
    {
        return self::engine()->detect($r)->templateIds();
    }

    public static function issued(): IssuedValue
    {
        return IssuedValue::forEngine(self::engine(), new AttackClassifier());
    }

    /** Real ids for a seed: [hook id, delivery id, import id]. @return array{0:string,1:string,2:string} */
    public static function ids(int $seed): array
    {
        $ids = new SsrfIds(new SsrfKeys(str_repeat(chr(0x40 + $seed), 32)));
        $iv = self::issued();
        [$hr, $hp] = SsrfIds::hookRoutes();
        $hook = $ids->issue($iv, 'hook|corpus|' . $seed, $hr, $hp);
        [$dr, $dp] = SsrfIds::deliveryRoutes($hook);
        $did = $ids->issue($iv, 'dlv|corpus|' . $seed, $dr, $dp, ['/settings/webhooks/' . $hook . '/redeliveries']);
        [$ir, $ip] = SsrfIds::importRoutes();
        $imp = $ids->issue($iv, 'imp|corpus|' . $seed, $ir, $ip);

        return [$hook, $did, $imp];
    }

    /** Benign fetch URLs an agent would point the features at. @return list<string> */
    public static function urls(): array
    {
        return [
            'http://billing-day7vn.svc.eu-west-2.internal:8080/health',
            'http://10.119.0.6:8080/',
            'http://db-primary.eu-west-2.internal:5432/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://127.0.0.1:9090/metrics',
            'https://hooks.example.net/collect',
        ];
    }

    /**
     * The body a route really receives, URL last, or null for a route that takes none.
     *
     * @return array{0:string,1:array<string,string>}|null [body, headers]
     */
    public static function body(string $route, string $method, string $url, string $did = '5c8f2a91d0b3'): ?array
    {
        $form = static fn (array $f): array => [http_build_query(['csrf_token' => self::CSRF] + $f), self::F];
        $json = static fn (array $f): array => [(string) json_encode($f, JSON_UNESCAPED_SLASHES), self::J];
        $hookForm = ['content_type' => 'json', 'secret' => 'hook-signing-1', 'events' => ['token', 'order'], 'active' => '1', 'payload_url' => $url];
        $storage = ['bucket' => 'exports-backup', 'access_key' => 'exportbot', 'secret_key' => 'Rk2mQ9xLw4', 'endpoint_url' => $url];

        return match ($route . ' ' . $method) {
            'hooks POST', 'hook_show POST' => $form($hookForm),
            'hook_ping POST', 'hook_delete POST', 'import_retry POST', 'storage_verify POST' => $form([]),
            'hook_redeliver POST' => $form(['delivery' => $did]),
            'imports POST' => $form(['kind' => 'orders_csv', 'source_url' => $url]),
            'storage POST' => $form($storage),
            'api_hooks POST' => $json(['content_type' => 'json', 'secret' => 'hook-signing-1', 'events' => ['token'], 'active' => true, 'url' => $url]),
            'api_hook PATCH' => $json(['active' => false, 'url' => $url]),
            'api_imports POST' => $json(['kind' => 'orders_csv', 'source_url' => $url]),
            'api_storage PUT' => $json($storage),
            'api_hook_ping POST', 'api_redeliver POST', 'api_storage_verify POST' => $json([]),
            default => null,
        };
    }

    /**
     * Every owned route and method, with real ids for a seed.
     *
     * @return list<array{0:string,1:string,2:string}> [route, method, path]
     */
    public static function routes(int $seed): array
    {
        [$hook, $did, $imp] = self::ids($seed);
        $out = [];
        foreach (SsrfRoutes::examples($hook, $did) as [$route, $path]) {
            if (str_contains($path, '/imports/' . $hook)) {
                $path = str_replace('/imports/' . $hook, '/imports/' . $imp, $path);
            }
            foreach (SsrfRoutes::methods($route) as $m) {
                $out[] = [$route, $m, $path];
            }
        }

        return $out;
    }
}
