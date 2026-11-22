<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\Core\RequestContext;

/**
 * One request to the account surface, parsed under hard caps before anything reads it: the body is at
 * most 16 KB (larger is 413), a form body and the query string keep only their first 64 pairs before
 * parse_str() (so PHP's input-variable limit can never warn), JSON is at most 8 KB and four levels
 * deep, and a cookie header at most 4 KB. A multipart form, whose body PHP parses itself and never
 * hands over raw, is read from the parsed fields under the same size and pair caps; uploaded files are
 * ignored. Field accessors are type-strict: a value that is not the expected scalar or list of strings
 * reads as missing, never as a warning.
 */
final class MintRequest
{
    public const MAX_BODY = 16384;
    public const MAX_JSON = 8192;
    public const MAX_PAIRS = 64;
    public const MAX_COOKIE = 4096;
    public const MAX_LIST = 32;

    /** @param array<string,mixed> $query @param array<string,mixed> $body @param array<string,string> $headers */
    private function __construct(
        public readonly string $method,
        public readonly string $route,
        public readonly array $params,
        public readonly bool $api,
        public readonly bool $pattern,
        /** @var list<string> */
        public readonly array $methods,
        public readonly array $query,
        public readonly array $body,
        public readonly bool $json,
        public readonly bool $tooLarge,
        public readonly bool $badJson,
        private array $headers,
        public readonly string $ip,
        public readonly bool $https,
    ) {
    }

    /** @param array{route:string,methods:list<string>,params:array<string,string>,api:bool,pattern:bool} $match */
    public static function parse(RequestContext $ctx, array $match, string $ip): self
    {
        $headers = [];
        foreach ($ctx->headers as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[strtolower($name)] = $value;
            }
        }
        $method = strtoupper($ctx->method);
        $raw = $ctx->rawBody ?? '';
        $tooLarge = strlen($raw) > self::MAX_BODY;
        $json = false;
        $badJson = false;
        $body = [];
        $hasBody = !in_array($method, ['GET', 'HEAD', 'OPTIONS'], true);
        // FastCGI hands Content-Type and Content-Length over outside the HTTP_* headers.
        $ctype = strtolower($headers['content-type'] ?? (is_string($_SERVER['CONTENT_TYPE'] ?? null) ? $_SERVER['CONTENT_TYPE'] : ''));
        if ($hasBody && $raw === '' && str_contains($ctype, 'multipart/form-data')) {
            $length = $headers['content-length'] ?? (is_string($_SERVER['CONTENT_LENGTH'] ?? null) ? $_SERVER['CONTENT_LENGTH'] : '');
            if (ctype_digit($length) && (int) $length > self::MAX_BODY) {
                $tooLarge = true;
            } elseif (ctype_digit($length)) {
                $body = array_slice($_POST, 0, self::MAX_PAIRS, true);
            }
        }
        if (!$tooLarge && $raw !== '' && $hasBody) {
            $first = ltrim($raw)[0] ?? '';
            if (str_contains($ctype, 'json') || ($ctype === '' && ($first === '{' || $first === '['))) {
                $json = true;
                $decoded = strlen($raw) <= self::MAX_JSON ? json_decode($raw, true, 4) : null;
                if (is_array($decoded) && ($decoded === [] || !array_is_list($decoded))) {
                    $body = $decoded;
                } else {
                    $badJson = true;
                }
            } else {
                $body = self::pairs($raw);
            }
        }

        return new self(
            $method,
            $match['route'],
            $match['params'],
            $match['api'],
            $match['pattern'],
            $match['methods'],
            self::pairs($ctx->query),
            $body,
            $json,
            $tooLarge,
            $badJson,
            $headers,
            $ip,
            $ctx->scheme === 'https',
        );
    }

    /** @return array<string,mixed> the first 64 pairs of an urlencoded string */
    private static function pairs(string $s): array
    {
        if ($s === '') {
            return [];
        }
        $kept = implode('&', array_slice(explode('&', $s, self::MAX_PAIRS + 1), 0, self::MAX_PAIRS));
        $out = [];
        parse_str($kept, $out);

        return $out;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function cookie(string $name): ?string
    {
        $raw = $this->headers['cookie'] ?? '';
        if ($raw === '' || strlen($raw) > self::MAX_COOKIE) {
            return null;
        }
        foreach (explode(';', $raw, 32) as $part) {
            $eq = strpos($part, '=');
            if ($eq !== false && trim(substr($part, 0, $eq)) === $name) {
                return trim(substr($part, $eq + 1));
            }
        }

        return null;
    }

    /** A scalar body field (a JSON number or bool reads as missing). */
    public function str(string $name): ?string
    {
        $v = $this->body[$name] ?? null;

        return is_string($v) ? $v : null;
    }

    public function queryStr(string $name): ?string
    {
        $v = $this->query[$name] ?? null;

        return is_string($v) ? $v : null;
    }

    /**
     * A body field that must be a list of strings (`scopes[]=a&scopes[]=b`, or a JSON array). Any
     * other shape reads as null.
     *
     * @return list<string>|null
     */
    public function strList(string $name): ?array
    {
        $v = $this->body[$name] ?? null;
        if (!is_array($v) || !array_is_list($v) || count($v) > self::MAX_LIST) {
            return null;
        }
        foreach ($v as $item) {
            if (!is_string($item)) {
                return null;
            }
        }

        return $v;
    }

    public function isHead(): bool
    {
        return $this->method === 'HEAD';
    }

    /** GET and HEAD read the same way. */
    public function readMethod(): string
    {
        return $this->method === 'HEAD' ? 'GET' : $this->method;
    }

    public function id(): string
    {
        return (string) ($this->params['id'] ?? '');
    }
}
