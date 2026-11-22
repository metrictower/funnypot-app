<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The SSRF surface's true validation, shared by the UI forms and the API. Every field is checked
 * against a charset and a length; a value of the wrong type reads as missing and never warns. An error
 * names a closed message key, never the submitted value.
 *
 * A URL must be http or https, parse cleanly and, while the denylist is on, not be one of the literal
 * spellings a quick filter catches (127.x.y.z, localhost, 0.0.0.0, [::1], 169.254.x.y); every other
 * spelling of the same address passes. A mirror import of github.com must be repository-shaped, and an
 * orders import refuses repository hosts. A storage endpoint has no query or fragment.
 */
final class SsrfForms
{
    /**
     * Event name => label. Every name is quiet in the engine's eyes in every combination the hook form can
     * send (SsrfRouteQuietTest re-derives that from the rendered form); a bare `export` value is flagged
     * by core's rules.
     */
    public const EVENTS = ['token.created' => 'Token created', 'member.added' => 'Member added', 'order.created' => 'Order created', 'export.completed' => 'Export completed'];
    public const DEFAULT_EVENT = 'token.created';
    public const KINDS = ['orders_csv' => 'Orders (CSV)', 'orders_json' => 'Orders (JSON)', 'mirror' => 'Mirror a Git repository'];
    public const CONTENT_TYPES = ['json', 'form'];

    public const MESSAGES = [
        'url_missing' => 'Enter a URL.',
        'url_invalid' => 'Enter a valid http:// or https:// URL.',
        'url_scheme' => 'Only http:// and https:// URLs are supported.',
        'url_denied' => 'URL host is not allowed.',
        'endpoint_query' => 'The endpoint URL cannot have a query or fragment.',
        'repo_shape' => 'Repository URL must look like https://github.com/<owner>/<repo>.',
        'repo_host' => 'Orders imports need a direct file URL; repository hosts are not supported.',
        'secret_invalid' => 'Use up to 64 letters, digits or the characters . _ ~ + / = -',
        'events_invalid' => 'Choose events from the list.',
        'content_type_invalid' => 'Choose json or form.',
        'active_invalid' => 'Choose active or inactive.',
        'kind_invalid' => 'Choose an import kind.',
        'bucket_invalid' => 'Bucket names are 3 to 63 lowercase letters, digits, dots or hyphens.',
        'key_invalid' => 'Keys are up to 128 letters, digits or the characters / + = _ -',
        'hooks_full' => 'You can have up to 5 webhooks. Delete one to add another.',
        'delivery_missing' => 'Choose a delivery to redeliver.',
        'retries_used' => 'This import has been retried the most times allowed.',
        'retry_queued' => 'A retry of this import is already queued.',
        'import_running' => 'This import is still running. Retry it once it has failed.',
        'storage_missing' => 'Save an export destination first.',
    ];

    public static function message(string $key): string
    {
        return self::MESSAGES[$key] ?? 'Check this field.';
    }

    /**
     * @return array{0:?Target,1:?string} the target, or the error key
     */
    public static function url(mixed $value, bool $denylist, string $purpose = 'hook', ?string $kind = null): array
    {
        if (!is_string($value) || trim($value) === '') {
            return [null, 'url_missing'];
        }
        [$t, $why] = TargetParser::check($value);
        if ($t === null) {
            return [null, $why === 'scheme' ? 'url_scheme' : 'url_invalid'];
        }
        if ($denylist && EgressPolicy::denylisted($t)) {
            return [null, 'url_denied'];
        }
        // The URL is stored masked and re-parsed on every send, so the masked form must parse too.
        if (TargetParser::parse(TargetParser::mask($value)) === null) {
            return [null, 'url_invalid'];
        }
        if ($purpose === 'storage' && strpbrk($value, '?#') !== false) {
            return [null, 'endpoint_query'];
        }
        if ($purpose === 'import' && $t->host === EgressPolicy::CODE_HOST) {
            if ($kind !== 'mirror') {
                return [null, 'repo_host'];
            }
            if ($t->scheme !== 'https' || $t->port !== 443 || $t->query !== '' || str_contains($value, '#')
                || preg_match('~\A/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}\z~', $t->path) !== 1) {
                return [null, 'repo_shape'];
            }
        }

        return [$t, null];
    }

    /** @return array{0:string,1:?string} */
    public static function secret(mixed $value): array
    {
        if ($value === null || $value === '') {
            return ['', null];
        }
        if (!is_string($value) || preg_match('~\A[A-Za-z0-9._\~+/=-]{1,64}\z~', $value) !== 1) {
            return ['', 'secret_invalid'];
        }

        return [$value, null];
    }

    /** @return array{0:list<string>,1:?string} */
    public static function events(mixed $value): array
    {
        if ($value === null) {
            return [[self::DEFAULT_EVENT], null];
        }
        if (is_string($value)) {
            $value = [$value];
        }
        if (!is_array($value) || !array_is_list($value) || $value === [] || count($value) > count(self::EVENTS)) {
            return [[], 'events_invalid'];
        }
        $out = [];
        foreach ($value as $e) {
            if (!is_string($e) || !isset(self::EVENTS[$e])) {
                return [[], 'events_invalid'];
            }
            $out[$e] = true;
        }

        return [array_values(array_intersect(array_keys(self::EVENTS), array_keys($out))), null];
    }

    /** @return array{0:string,1:?string} */
    public static function contentType(mixed $value): array
    {
        if ($value === null || $value === '') {
            return ['json', null];
        }

        return is_string($value) && in_array($value, self::CONTENT_TYPES, true) ? [$value, null] : ['json', 'content_type_invalid'];
    }

    /** @return array{0:bool,1:?string} */
    public static function active(mixed $value, bool $default = true): array
    {
        return match (true) {
            $value === null => [$default, null],
            $value === true, $value === '1', $value === 1 => [true, null],
            $value === false, $value === '0', $value === 0 => [false, null],
            default => [$default, 'active_invalid'],
        };
    }

    /** @return array{0:string,1:?string} */
    public static function kind(mixed $value): array
    {
        return is_string($value) && isset(self::KINDS[$value]) ? [$value, null] : ['', 'kind_invalid'];
    }

    /** @return array{0:string,1:?string} */
    public static function bucket(mixed $value): array
    {
        if (!is_string($value) || preg_match('/\A[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\z/', $value) !== 1 || str_contains($value, '..')
            || preg_match('/\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/', $value) === 1) {
            return ['', 'bucket_invalid'];
        }

        return [$value, null];
    }

    /** @return array{0:string,1:?string} */
    public static function accessKey(mixed $value): array
    {
        if (!is_string($value) || preg_match('~\A[A-Za-z0-9/+=_-]{1,128}\z~', $value) !== 1) {
            return ['', 'key_invalid'];
        }

        return [$value, null];
    }
}
