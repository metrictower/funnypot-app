<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Tarpit\Mint\MintRoutes;
use Funnypot\App\Tarpit\Mint\SurfaceExtension;

/**
 * The closed set of paths the SSRF decoy owns: account webhooks, imports and the export destination,
 * in the account UI and in the member API under both `/api/v2/` and `/v2/`. Ownership is a function of
 * the path alone: exact match after stripping `#…` and one trailing slash, at most 200 bytes, with ids
 * from the token-mint grammar. A segment holding a word the engine answers by path alone, a final
 * segment ending in `.php`, and any path a backup-archive or text decoy serves are never owned.
 *
 * Every owned path starts with /settings/webhooks, /settings/imports, /settings/storage,
 * /api/v2/user/ or /v2/user/, which keeps the set disjoint from the token-mint surface and the
 * web-shell console.
 */
final class SsrfRoutes
{
    /** Exact UI paths => [route, methods] */
    public const UI_EXACT = [
        '/settings/webhooks' => ['hooks', ['GET', 'POST']],
        '/settings/webhooks/new' => ['hook_new', ['GET']],
        '/settings/imports' => ['imports', ['GET', 'POST']],
        '/settings/imports/new' => ['import_new', ['GET']],
        '/settings/storage' => ['storage', ['GET', 'POST']],
        '/settings/storage/verify' => ['storage_verify', ['POST']],
    ];

    /** UI patterns ({id}, {did}) => [route, methods] */
    public const UI_PATTERNS = [
        '/settings/webhooks/{id}' => ['hook_show', ['GET', 'POST']],
        '/settings/webhooks/{id}/pings' => ['hook_ping', ['POST']],
        '/settings/webhooks/{id}/deliveries/{did}' => ['delivery_view', ['GET']],
        '/settings/webhooks/{id}/redeliveries' => ['hook_redeliver', ['POST']],
        '/settings/webhooks/{id}/delete' => ['hook_delete', ['POST']],
        '/settings/imports/{id}' => ['import_view', ['GET']],
        '/settings/imports/{id}/retry' => ['import_retry', ['POST']],
    ];

    /** API paths after the prefix => [route, methods] */
    public const API = [
        'user/hooks' => ['api_hooks', ['GET', 'POST']],
        'user/hooks/{id}' => ['api_hook', ['GET', 'PATCH', 'DELETE']],
        'user/hooks/{id}/pings' => ['api_hook_ping', ['POST']],
        'user/hooks/{id}/deliveries' => ['api_deliveries', ['GET']],
        'user/hooks/{id}/deliveries/{did}' => ['api_delivery', ['GET']],
        'user/hooks/{id}/deliveries/{did}/attempts' => ['api_redeliver', ['POST']],
        'user/imports' => ['api_imports', ['GET', 'POST']],
        'user/imports/{id}' => ['api_import', ['GET']],
        'user/storage' => ['api_storage', ['GET', 'PUT']],
        'user/storage/verifications' => ['api_storage_verify', ['POST']],
    ];

    /** Must stay empty: every owned route is quiet in core's eyes in its real field order. */
    public const QUIET_EXEMPT = [];

    /** The scope each API family needs. */
    public const SCOPES = ['hooks' => 'webhooks:write', 'imports' => 'imports:write', 'storage' => 'storage:write'];

    /** Where each form posts. */
    public const FORMS = [
        'hook_create' => '/settings/webhooks',
        'hook_edit' => '/settings/webhooks/{id}',
        'hook_ping' => '/settings/webhooks/{id}/pings',
        'hook_redeliver' => '/settings/webhooks/{id}/redeliveries',
        'hook_delete' => '/settings/webhooks/{id}/delete',
        'import_create' => '/settings/imports',
        'import_retry' => '/settings/imports/{id}/retry',
        'storage_save' => '/settings/storage',
        'storage_verify' => '/settings/storage/verify',
    ];

    /** The on-site pages an SSRF redirect may name. */
    public const LOCATIONS = [
        '~\A/settings/webhooks\z~',
        '~\A/settings/webhooks/[a-f0-9]{12}\z~',
        '~\A/settings/imports\z~',
        '~\A/settings/imports/[a-f0-9]{12}\z~',
        '~\A/settings/storage\z~',
    ];

    /** The token-mint extension the SSRF decoy needs: scopes, forms, redirect targets, nav and docs. */
    public static function extension(): SurfaceExtension
    {
        // The allowed values come from the same constants the forms render and the API's errors name.
        $ops = [
            ['GET', 'user/hooks', 'Your account webhooks', 'webhooks:write'],
            ['POST', 'user/hooks', 'Create a webhook. Fields: url (http or https); content_type (json or form, default json); secret '
                . '(optional, signs each delivery with HMAC-SHA256); events (one or more of ' . implode(', ', array_keys(SsrfForms::EVENTS))
                . '; default ' . SsrfForms::DEFAULT_EVENT . '); active (true or false). A webhook delivers when you send it a test delivery.', 'webhooks:write'],
            ['PATCH', 'user/hooks/{id}', 'Update a webhook: any create field; leave out url to keep the current one', 'webhooks:write'],
            ['POST', 'user/hooks/{id}/pings', 'Send a test delivery to the webhook\'s URL; the result appears in its recent deliveries', 'webhooks:write'],
            ['GET', 'user/hooks/{id}/deliveries', 'Recent deliveries', 'webhooks:write'],
            ['POST', 'user/hooks/{id}/deliveries/{did}/attempts', 'Redeliver to the current URL', 'webhooks:write'],
            ['POST', 'user/imports', 'Import into your sandbox. Fields: kind (' . implode(', ', array_keys(SsrfForms::KINDS))
                . '); source_url (a direct file URL, or https://github.com/<owner>/<repo> for mirror)', 'imports:write'],
            ['GET', 'user/imports/{id}', 'An import\'s progress', 'imports:write'],
            ['PUT', 'user/storage', 'Set the export destination. Fields: bucket (3 to 63 lowercase letters, digits, dots or hyphens); '
                . 'access_key; secret_key; endpoint_url (an S3-compatible http or https endpoint, no query)', 'storage:write'],
            ['POST', 'user/storage/verifications', 'Verify the export destination by writing a small test object', 'storage:write'],
        ];

        return new SurfaceExtension(
            ['webhooks:write' => 'Manage account webhooks', 'imports:write' => 'Run imports into your sandbox', 'storage:write' => 'Configure the export destination'],
            self::FORMS,
            self::LOCATIONS,
            [['/settings/webhooks', 'Webhooks'], ['/settings/imports', 'Imports'], ['/settings/storage', 'Export']],
            $ops,
        );
    }

    public function owns(string $path): bool
    {
        return $this->match($path) !== null;
    }

    /**
     * @return array{route:string,methods:list<string>,params:array<string,string>,api:bool,pattern:bool}|null
     */
    public function match(string $rawPath): ?array
    {
        if (strlen($rawPath) > 200 || HoneypotController::decoyForPath($rawPath) !== null) {
            return null;
        }
        $path = MintRoutes::normalise($rawPath);
        if (isset(self::UI_EXACT[$path])) {
            return ['route' => self::UI_EXACT[$path][0], 'methods' => self::UI_EXACT[$path][1], 'params' => [], 'api' => false, 'pattern' => false];
        }
        if (preg_match('~\.php\z~i', $path) === 1) {
            return null;
        }
        foreach (['/api/v2/', '/v2/'] as $prefix) {
            if (strncmp($path, $prefix . 'user/', strlen($prefix) + 5) === 0) {
                return self::find(substr($path, strlen($prefix)), self::API, true);
            }
        }

        return str_starts_with($path, '/settings/') ? self::find($path, self::UI_PATTERNS, false) : null;
    }

    /**
     * @param array<string,array{0:string,1:list<string>}> $table
     * @return array{route:string,methods:list<string>,params:array<string,string>,api:bool,pattern:bool}|null
     */
    private static function find(string $path, array $table, bool $api): ?array
    {
        foreach ($table as $shape => [$route, $methods]) {
            $re = '~\A' . str_replace(['\{id\}', '\{did\}'], ['(' . MintRoutes::ID . ')', '(' . MintRoutes::ID . ')'], preg_quote($shape, '~')) . '\z~';
            if (preg_match($re, $path, $m) !== 1) {
                continue;
            }
            $params = [];
            if (isset($m[1])) {
                $params['id'] = $m[1];
            }
            if (isset($m[2])) {
                $params['did'] = $m[2];
            }
            foreach ($params as $v) {
                if (MintRoutes::coreKeyed($v)) {
                    return null;
                }
            }

            return ['route' => $route, 'methods' => $methods, 'params' => $params, 'api' => $api, 'pattern' => $params !== []];
        }

        return null;
    }

    /** One concrete path per owned route (both API spellings), with the given ids. @return list<array{0:string,1:string}> [route, path] */
    public static function examples(string $id = '4b7e19a2c0a1', string $did = '5c8f2a91d0b3'): array
    {
        $out = [];
        foreach (self::UI_EXACT as $p => [$route]) {
            $out[] = [$route, $p];
        }
        foreach (self::UI_PATTERNS as $shape => [$route]) {
            $out[] = [$route, strtr($shape, ['{id}' => $id, '{did}' => $did])];
        }
        foreach (['/api/v2/', '/v2/'] as $prefix) {
            foreach (self::API as $shape => [$route]) {
                $out[] = [$route, $prefix . strtr($shape, ['{id}' => $id, '{did}' => $did])];
            }
        }

        return $out;
    }

    /** @return list<string> the methods a route answers */
    public static function methods(string $route): array
    {
        foreach ([self::UI_EXACT, self::UI_PATTERNS, self::API] as $table) {
            foreach ($table as [$r, $methods]) {
                if ($r === $route) {
                    return $methods;
                }
            }
        }

        return [];
    }

    /** The API family (hooks, imports, storage) a route belongs to. */
    public static function family(string $route): string
    {
        return str_contains($route, 'import') ? 'imports' : (str_contains($route, 'storage') ? 'storage' : 'hooks');
    }
}
