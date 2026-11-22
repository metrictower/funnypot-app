<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\Core\RequestContext;

/**
 * Public ids for hooks, deliveries and imports: 12 hex characters holding a digit, fit to issue on
 * every route they sit in.
 *
 * One of core's rules reads the end of the path together with the end of the last form field, so an id
 * that ends a route's path (a hook's edit route, say) is also probed with a URL-valued last field
 * ending in each word family that rule pairs with (PAIR_WORDS). An id the engine would flag there is
 * re-rolled, as is one that would be flagged as a plain path segment. The word families are derived
 * from the engine by SsrfPairRuleDerivationTest, so a core change that adds one fails there.
 */
final class SsrfIds
{
    public const PAIR_WORDS = ['time', 'watch', 'env', 'command', 'eval'];
    public const TRIES = 8;
    public const PROBE_URL = 'http://10.41.7.19:8080/x';

    public function __construct(private SsrfKeys $keys)
    {
    }

    /** The candidate for a label at re-roll step $v, or null when it holds no digit. */
    public function candidate(string $label, int $v): ?string
    {
        $id = $this->keys->hex('ids', $label . ($v === 0 ? '' : '|v' . $v), 12);

        return preg_match('/[0-9]/', $id) === 1 ? $id : null;
    }

    /**
     * Whether an id is fit to issue: fingerprint-clean, quiet as a segment of each route in $routes
     * ("METHOD /path" with {v}), and quiet on each route in $pairRoutes ("METHOD /path [field]") when
     * that route's last field is a URL ending in a pair word.
     *
     * @param list<string> $routes
     * @param list<string> $pairRoutes
     * @param list<string> $paths where the id is also sent back as a form field
     */
    public static function fit(IssuedValue $issued, string $id, array $routes, array $pairRoutes, array $paths = []): bool
    {
        if (!$issued->fit($id, $paths, $routes)) {
            return false;
        }
        foreach ($pairRoutes as $route) {
            foreach (self::PAIR_WORDS as $word) {
                if ($issued->flagged(self::pairProbe($id, $route, $word))) {
                    return false;
                }
            }
        }

        return true;
    }

    /** The request a pair probe sends: the id in the path, a URL ending in $word as the last field. */
    public static function pairProbe(string $id, string $route, string $word): RequestContext
    {
        [$method, $path, $field] = explode(' ', $route, 3) + [2 => 'url'];
        $path = str_replace('{v}', $id, $path);
        $url = self::PROBE_URL . $word;
        if ($method === 'PATCH' || str_starts_with($path, '/api/') || str_starts_with($path, '/v2/')) {
            return new RequestContext($method, $path, '', ['Content-Type' => 'application/json'], (string) json_encode([$field => $url], JSON_UNESCAPED_SLASHES));
        }

        return new RequestContext($method, $path, '', ['Content-Type' => 'application/x-www-form-urlencoded'], 'csrf_token=x&' . $field . '=' . rawurlencode($url));
    }

    /**
     * The first fit id for a label.
     *
     * @param list<string> $routes
     * @param list<string> $pairRoutes
     * @param list<string> $paths
     */
    public function issue(IssuedValue $issued, string $label, array $routes, array $pairRoutes, array $paths = []): string
    {
        for ($v = 0; $v < self::TRIES; $v++) {
            $id = $this->candidate($label, $v);
            if ($id !== null && self::fit($issued, $id, $routes, $pairRoutes, $paths)) {
                return $id;
            }
        }

        throw new \LogicException('no fit id within the tries');
    }

    /** @return array{0:list<string>,1:list<string>} a hook id's routes and pair routes */
    public static function hookRoutes(): array
    {
        return [[
            'GET /settings/webhooks/{v}', 'POST /settings/webhooks/{v}', 'POST /settings/webhooks/{v}/pings',
            'POST /settings/webhooks/{v}/redeliveries', 'POST /settings/webhooks/{v}/delete',
            'GET /api/v2/user/hooks/{v}', 'PATCH /api/v2/user/hooks/{v}', 'DELETE /api/v2/user/hooks/{v}',
            'POST /api/v2/user/hooks/{v}/pings', 'GET /api/v2/user/hooks/{v}/deliveries',
        ], ['POST /settings/webhooks/{v} payload_url', 'PATCH /api/v2/user/hooks/{v} url']];
    }

    /** @return array{0:list<string>,1:list<string>} a delivery id's routes (within hook $hook) and pair routes */
    public static function deliveryRoutes(string $hook): array
    {
        return [[
            'GET /settings/webhooks/' . $hook . '/deliveries/{v}', 'GET /api/v2/user/hooks/' . $hook . '/deliveries/{v}',
            'POST /api/v2/user/hooks/' . $hook . '/deliveries/{v}/attempts', 'GET /v2/user/hooks/' . $hook . '/deliveries/{v}',
        ], ['POST /settings/webhooks/' . $hook . '/deliveries/{v} payload_url', 'POST /api/v2/user/hooks/' . $hook . '/deliveries/{v} url']];
    }

    /** @return array{0:list<string>,1:list<string>} an import id's routes and pair routes */
    public static function importRoutes(): array
    {
        return [[
            'GET /settings/imports/{v}', 'POST /settings/imports/{v}/retry', 'GET /api/v2/user/imports/{v}', 'GET /v2/user/imports/{v}',
        ], ['POST /settings/imports/{v} source_url', 'POST /api/v2/user/imports/{v} source_url']];
    }
}
